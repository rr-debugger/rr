/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "gdb"

/**
 * Much of this implementation is based on the documentation at
 *
 * http://sourceware.org/gdb/onlinedocs/gdb/Packets.html
 */

#include "debugger_gdb.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <sstream>
#include <vector>

#include "log.h"
#include "session.h"
#include "types.h"

#define INTERRUPT_CHAR '\x03'

#ifdef DEBUGTAG
# define UNHANDLED_REQ(_g) FATAL()
#else
# define UNHANDLED_REQ(_g) write_packet(_g, ""); LOG(info)
#endif

using namespace std;

/**
 * This struct wraps up the state of the gdb protocol, so that we can
 * offer a (mostly) stateless interface to clients.
 */
struct dbg_context {
	// Current request to be processed.
	struct dbg_request req;
	// Thread to be resumed.
	dbg_threadid_t resume_thread;
	// Thread for get/set requests.
	dbg_threadid_t query_thread;
	// gdb and rr don't work well together in multi-process and
	// multi-exe-image debugging scenarios, so we pretend only
	// this task group exists when interfacing with gdb
	pid_t tgid;
	// Nonzero when we can request lookups.
	int serving_symbol_lookups;
	// nonzero when "no-ack mode" enabled, in which we don't have
	// to send ack packets back to gdb.  This is a huge perf win.
	int no_ack;
	// Server address we listen for a connection on.
	struct sockaddr_in addr;
	// Listen and client sockets created for |addr|.
	int listen_fd;
	int sock_fd;
	/* XXX probably need to dynamically size these */
	byte inbuf[32768];	/* buffered input from gdb */
	ssize_t inlen;		/* length of valid data */
	ssize_t insize;		/* total size of buffer */
	ssize_t packetend;	/* index of '#' character */
	byte outbuf[32768];	/* buffered output for gdb */
	ssize_t outlen;
	ssize_t outsize;
};

bool dbg_is_resume_request(const struct dbg_request* req)
{
	switch (req->type) {
	case DREQ_CONTINUE:
	case DREQ_STEP:
		return true;
	default:
		return false;
	}
}

inline static bool request_needs_immediate_response(const struct dbg_request* req)
{
	switch (req->type) {
	case DREQ_NONE:
	case DREQ_CONTINUE:
	case DREQ_STEP:
		return false;
	default:
		return true;
	}
}

static void make_cloexec(int fd)
{
	int flags = fcntl(fd, F_GETFD);
	if (-1 == flags) {
		FATAL() << "Can't GETFD flags";
	}
	if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC)) {
		FATAL() << "Can't make client socket CLOEXEC";
	}
}

static dbg_context* new_dbg_context()
{
	struct dbg_context* dbg = new dbg_context();
	dbg->insize = sizeof(dbg->inbuf);
	dbg->outsize = sizeof(dbg->outbuf);
	return dbg;
}

static void open_socket(struct dbg_context* dbg,
			const char* address, unsigned short port, int probe)
{
	int reuseaddr;
	int ret;

	dbg->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (dbg->listen_fd < 0) {
		FATAL() << "Couldn't create socket";
	}
	make_cloexec(dbg->listen_fd);

	dbg->addr.sin_family = AF_INET;
	dbg->addr.sin_addr.s_addr = inet_addr(address);
	reuseaddr = 1;
	ret = setsockopt(dbg->listen_fd, SOL_SOCKET, SO_REUSEADDR,
			 &reuseaddr, sizeof(reuseaddr));
	if (ret < 0) {
		FATAL() << "Couldn't set SO_REUSEADDR";
	}

	do {
		dbg->addr.sin_port = htons(port);
		ret = ::bind(dbg->listen_fd,
			     (struct sockaddr*)&dbg->addr, sizeof(dbg->addr));
		if (ret && (EADDRINUSE == errno || EACCES == errno)) {
			continue;
		}
		if (ret) {
			FATAL() << "Couldn't bind to port " << port;
		}

		ret = listen(dbg->listen_fd, 1/*backlogged connection*/);
		if (ret && EADDRINUSE == errno) {
			continue;
		}
		if (ret) {
			FATAL() << "Couldn't listen on port " << port;
		}
		break;
	} while (++port, probe);
}

/**
 * Wait for a debugger client to connect to |dbg|'s socket.  Blocks
 * indefinitely.
 */
static void await_debugger(struct dbg_context* dbg)
{
	struct sockaddr_in client_addr;
	socklen_t len = sizeof(client_addr);

	dbg->sock_fd =
		accept(dbg->listen_fd, (struct sockaddr*)&client_addr, &len);
	// We might restart this debugging session, so don't set the
	// socket fd CLOEXEC.
	if (fcntl(dbg->sock_fd, F_SETFL, O_NONBLOCK)) {
		FATAL() <<"Can't make client socket NONBLOCK";
	}
	close(dbg->listen_fd);
	dbg->listen_fd = -1;
}

struct debugger_params {
	char exe_image[PATH_MAX];
	char socket_addr[PATH_MAX];
	short port;
};

struct dbg_context* dbg_await_client_connection(const char* addr,
						unsigned short desired_port,
						int probe,
						pid_t tgid,
						const char* exe_image,
						pid_t client,
						int client_params_fd)
{
	struct dbg_context* dbg = new_dbg_context();
	open_socket(dbg, addr, desired_port, probe);
	int port = ntohs(dbg->addr.sin_port);
	if (exe_image) {
		// NB: the order of the kill() and write() is
		// sigificant.  The client can't start reading the
		// socket until it's awoken.  But the write() may
		// block, and only the client can finish it by
		// read()ing those bytes.  So the client be able to
		// reach read() before we write().
		kill(client, DBG_SOCKET_READY_SIG);

		struct debugger_params params;
		memset(&params, 0, sizeof(params));
		strcpy(params.exe_image, exe_image);
		strcpy(params.socket_addr, addr);
		params.port = port;

		ssize_t nwritten = write(client_params_fd,
					 &params, sizeof(params));
		assert(nwritten == sizeof(params));
	} else {
		fprintf(stderr,
			"Attach to the rr debug server with this command:\n"
			"  target remote %s:%d\n",
			!strcmp(addr, "127.0.0.1") ? "" : addr, port);
	}
	dbg->tgid = tgid;
	LOG(debug) <<"limiting debugger traffic to tgid "<< tgid;
	await_debugger(dbg);
	return dbg;
}

static string create_gdb_command_file(const char* macros)
{
	char tmp[] = "rr-gdb-commands-XXXXXX";
	// This fd is just leaked. That's fine since we only call this once
	// per rr invocation at the moment.
	int fd = mkstemp(tmp);
	unlink(tmp);

	ssize_t len = strlen(macros);
	int written = write(fd, macros, len);
	if (written != len) {
		FATAL() <<"Failed to write gdb command file";
	}

	stringstream procfile;
	procfile << "/proc/" << getpid() << "/fd/" << fd;
	return procfile.str();
}

void dbg_launch_debugger(int params_pipe_fd, const char* macros)
{
	struct debugger_params params;
	ssize_t nread = read(params_pipe_fd, &params, sizeof(params));
	assert(nread == sizeof(params));

	stringstream attach_cmd;
	attach_cmd << "target extended-remote " << params.socket_addr << ":"
		   << params.port;
	LOG(debug) <<"launching gdb with command '"<< attach_cmd.str() <<"'";

	vector<const char*> args;
	args.push_back("gdb");
	// The gdb protocol uses the "vRun" packet to reload
	// remote targets.  The packet is specified to be like
	// "vCont", in which gdb waits infinitely long for a
	// stop reply packet.  But in practice, gdb client
	// expects the vRun to complete within the remote-reply
	// timeout, after which it issues vCont.  The timeout
	// causes gdb<-->rr communication to go haywire.
	//
	// rr can take a very long time indeed to send the
	// stop-reply to gdb after restarting replay; the time
	// to reach a specified execution target is
	// theoretically unbounded.  Timing our on vRun is
	// technically a gdb bug, but because the rr replay and
	// the gdb reload models don't quite match up, we'll
	// work around it on the rr side by disabling the
	// remote-reply timeout.
	args.push_back("-l");
	args.push_back("-1");
	args.push_back(params.exe_image);
	const string& gdb_command_file_path =
		rr_flags()->gdb_command_file_path;
	if (gdb_command_file_path.length() > 0 ) {
		args.push_back("-x");
		args.push_back(gdb_command_file_path.c_str());
	}
	args.push_back("-l");
	args.push_back("-1");
	if (macros) {
		string gdb_command_file = create_gdb_command_file(macros);
		args.push_back("-x");
		args.push_back(gdb_command_file.c_str());
	}
	args.push_back("-ex");
	args.push_back(attach_cmd.str().c_str());
	args.push_back(nullptr);
	execvp("gdb", (char* const*)args.data());
	FATAL() <<"Failed to exec gdb.";
}

/**
 * Poll for data to or from gdb, waiting |timeoutMs|.  0 means "don't
 * wait", and -1 means "wait forever".  Return zero if no data is
 * ready by the end of the timeout, and nonzero if data is ready.
 */
static int poll_socket(const struct dbg_context* dbg,
		       short events, int timeoutMs)
{
	struct pollfd pfd;
	int ret;

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = dbg->sock_fd;
	pfd.events = events;

	ret = poll(&pfd, 1, timeoutMs);
	if (ret < 0) {
		FATAL() <<"Polling gdb socket failed";
	}
	return ret;
}

static int poll_incoming(const struct dbg_context* dbg, int timeoutMs)
{
	return poll_socket(dbg, POLLIN /* TODO: |POLLERR */, timeoutMs);
}

static int poll_outgoing(const struct dbg_context* dbg, int timeoutMs)
{
	return poll_socket(dbg, POLLOUT /* TODO: |POLLERR */, timeoutMs);
}

/**
 * read() incoming data exactly one time, successfully.  May block.
 */
static void read_data_once(struct dbg_context* dbg)
{
	ssize_t nread;
	/* Wait until there's data, instead of busy-looping on
	 * EAGAIN. */
	poll_incoming(dbg, -1/* wait forever */);
	nread = read(dbg->sock_fd, dbg->inbuf + dbg->inlen,
		     dbg->insize - dbg->inlen);
	if (0 == nread) {
		LOG(info) <<"(gdb closed debugging socket, exiting)";
		dbg_destroy_context(&dbg);
		exit(0);
	}
	if (nread <= 0) {
		FATAL() <<"Error reading from gdb";
	}
	dbg->inlen += nread;
	assert("Impl dynamic alloc if this fails (or double inbuf size)"
	       && dbg->inlen < dbg->insize);
}

/**
 * Send all pending output to gdb.  May block.
 */
static void write_flush(struct dbg_context* dbg)
{
	ssize_t write_index = 0;

#ifdef DEBUGTAG
	dbg->outbuf[dbg->outlen] = '\0';
	LOG(debug) <<"write_flush: '"<< dbg->outbuf <<"'";
#endif
	while (write_index < dbg->outlen) {
		ssize_t nwritten;

		poll_outgoing(dbg, -1/*wait forever*/);
		nwritten = write(dbg->sock_fd,
				 dbg->outbuf + write_index,
				 dbg->outlen - write_index);
		if (nwritten < 0) {
			FATAL() <<"Error writing to gdb";
		}
		write_index += nwritten;
	}
	dbg->outlen = 0;
}

static void write_data_raw(struct dbg_context* dbg,
			   const byte* data, ssize_t len)
{
	assert("Impl dynamic alloc if this fails (or double outbuf size)"
	       && (dbg->outlen + len) < dbg->insize);

	memcpy(dbg->outbuf + dbg->outlen, data, len);
	dbg->outlen += len;
}

static void write_hex(struct dbg_context* dbg, unsigned long hex)
{
	char buf[32];
	size_t len;

	len = snprintf(buf, sizeof(buf) - 1, "%02lx", hex);
	write_data_raw(dbg, (byte*)buf, len);
}

static void write_packet_bytes(struct dbg_context* dbg,
			       const byte* data, size_t num_bytes)
{
	byte checksum;
	size_t i;

	write_data_raw(dbg, (byte*)"$", 1);
	for (i = 0, checksum = 0; i < num_bytes; ++i) {
		checksum += data[i];
	}
	write_data_raw(dbg, (byte*)data, num_bytes);
	write_data_raw(dbg, (byte*)"#", 1);
	write_hex(dbg, checksum);
}

static void write_packet(struct dbg_context* dbg, const char* data)
{
	return write_packet_bytes(dbg, (const byte*)data, strlen(data));
}

static void write_binary_packet(struct dbg_context* dbg, const char* pfx,
				const byte* data, ssize_t num_bytes)
{
	ssize_t pfx_num_chars = strlen(pfx);
	byte buf[2 * num_bytes + pfx_num_chars];
	ssize_t buf_num_bytes = 0;
	int i;

	strncpy((char*)buf, pfx, sizeof(buf) - 1);
	buf_num_bytes += pfx_num_chars;

	for (i = 0; i < num_bytes; ++i) {
		byte b = data[i];

		if (buf_num_bytes + 2 > ssize_t(sizeof(buf))) {
			break;
		}
		switch (b) {
		case '#': case '$': case '}': case '*':
			buf[buf_num_bytes++] = '}';
			buf[buf_num_bytes++] = b ^ 0x20;
			break;
		default:
			buf[buf_num_bytes++] = b;
			break;
		}
	}

	LOG(debug) <<" ***** NOTE: writing binary data, upcoming debug output may be truncated";
	return write_packet_bytes(dbg, buf, buf_num_bytes);
}

static void write_hex_bytes_packet(struct dbg_context* dbg,
				   const byte* bytes, size_t len)
{
	if (0 == len) {
		write_packet(dbg, "");
		return;
	}

	char* buf = (char*)malloc(2 * len + 1);
	for (size_t i = 0; i < len; ++i) {
		unsigned long b = bytes[i];
		snprintf(&buf[2 * i], 3, "%02lx", b);
	}
	write_packet(dbg, buf);
	free(buf);
}

/**
 * Return a string decoded from |encoded|, which contains ASCII
 * characters encoded as pairs of hex digits, f.e. '1' -> "31".
 */
static string decode_ascii_encoded_hex_str(const char* encoded)
{
	ssize_t enc_len = strlen(encoded);
	assert(enc_len % 2 == 0);
	string str;
	for (int i = 0; i < enc_len / 2; ++i) {
		char enc_byte[] = { encoded[2 * i], encoded[2 * i + 1], '\0' };
		char* endp;
		int c = strtol(enc_byte, &endp, 16);
		assert(c < 128);
		str += static_cast<char>(c);
	}
	return str;
}

/**
 * Consume bytes in the input buffer until start-of-packet ('$') or
 * the interrupt character is seen.  Does not block.  Return zero if
 * seen, nonzero if not.
 */
static int skip_to_packet_start(struct dbg_context* dbg)
{
	byte* p = NULL;
	int i;

	/* XXX we want memcspn() here ... */
	for (i = 0; i < dbg->inlen; ++i) {
		if (dbg->inbuf[i] == '$' || dbg->inbuf[i] == INTERRUPT_CHAR) {
			p = &dbg->inbuf[i];
			break;
		}
	}

	if (!p) {
		/* Discard all read bytes, which we don't care
		 * about. */
		dbg->inlen = 0;
		return 1;
	}
	/* Discard bytes up to start-of-packet. */
	memmove(dbg->inbuf, p, dbg->inlen - (p - dbg->inbuf));
	dbg->inlen -= (p - dbg->inbuf);

	assert(1 <= dbg->inlen);
	assert('$' == dbg->inbuf[0] || INTERRUPT_CHAR == dbg->inbuf[0]);
	return 0;
}

/**
 * Return zero if there's a new packet to be read/process (whether
 * incomplete or not), and nonzero if there isn't one.
 */
static int sniff_packet(struct dbg_context* dbg)
{
	if (0 == skip_to_packet_start(dbg)) {
		/* We've already seen a (possibly partial) packet. */
		return 0;
	}
	assert(0 == dbg->inlen);
	return !poll_incoming(dbg, 0/*don't wait*/);
}

/**
 * Block until the sequence of bytes
 *
 *    "[^$]*\$[^#]*#.*"
 *
 * has been read from the client fd.  This is one (or more) gdb
 * packet(s).
 */
static void read_packet(struct dbg_context* dbg)
{
	byte* p;
	size_t checkedlen;

	/* Read and discard bytes until we see the start of a
	 * packet.
	 *
	 * NB: we're ignoring "+/-" responses from gdb.  There doesn't
	 * seem to be any sane reason why we would send a damaged
	 * packet to gdb over TCP, then see a "-" reply from gdb and
	 * somehow magically fix our bug that led to the malformed
	 * packet in the first place.
	 */
	while (skip_to_packet_start(dbg)) {
		read_data_once(dbg);
	}

	if (dbg->inbuf[0] == INTERRUPT_CHAR) {
		/* Interrupts are kind of an ugly duckling in the gdb
		 * protocol ... */
		dbg->packetend = 1;
		return;
	}

	/* Read until we see end-of-packet. */
	for (checkedlen = 0;
	     !(p = (byte*)memchr(dbg->inbuf + checkedlen, '#', dbg->inlen));
	     checkedlen = dbg->inlen) {
		read_data_once(dbg);
	}
	dbg->packetend = (p - dbg->inbuf);
	/* NB: we're ignoring the gdb packet checksums here too.  If
	 * gdb is corrupted enough to garble a checksum over TCP, it's
	 * not really clear why asking for the packet again might make
	 * the bug go away. */
	assert('$' == dbg->inbuf[0] && dbg->packetend < dbg->inlen);

	/* Acknowledge receipt of the packet. */
	if (!dbg->no_ack) {
		write_data_raw(dbg, (byte*)"+", 1);
		write_flush(dbg);
	}
}

static void read_binary_data(const byte* payload, ssize_t data_len, byte* data)
{
	ssize_t payload_idx = 0;
	for (ssize_t i = 0; i < data_len; ++i) {
		byte b = payload[payload_idx++];
		if ('}' == b) {
			b = 0x20 ^ payload[payload_idx++];
		}
		data[i] = b;
	}
}

/**
 * Parse and return a gdb thread-id from |str|.  |endptr| points to
 * the character just after the last character in the thread-id.  It
 * may be NULL.
 */
static dbg_threadid_t parse_threadid(const char* str, char** endptr)
{
	dbg_threadid_t t;
	char* endp;

	if ('p' == *str) {
		++str;
	}
	t.pid = strtol(str, &endp, 16);
	assert(endp);
	if ('\0' == *endp) {
		t.tid = -1;
		*endptr = endp;
		return t;
	}

	assert('.' == *endp);
	str = endp + 1;
	t.tid = strtol(str, &endp, 16);

	*endptr = endp;
	return t;
}

static int xfer(struct dbg_context* dbg, const char* name, char* args)
{
	LOG(debug) <<"gdb asks us to transfer "<< name <<"("<< args <<")";

	if (!strcmp(name, "auxv")) {
		assert(!strncmp(args, "read::",	sizeof("read::") - 1));

		dbg->req.type = DREQ_GET_AUXV;
		dbg->req.target = dbg->query_thread;
		return 1;
	}

	UNHANDLED_REQ(dbg) <<"Unhandled gdb xfer request: "<< name <<"("<< args <<")";
	return 0;
}

static int query(struct dbg_context* dbg, char* payload)
{
	const char* name;
	char* args;

	args = strchr(payload, ':');
	if (args) {
		*args++ = '\0';
	}
	name = payload;

	if (!strcmp(name, "C")) {
		LOG(debug) <<"gdb requests current thread ID";
		dbg->req.type = DREQ_GET_CURRENT_THREAD;
		return 1;
	}
	if (!strcmp(name, "Attached")) {
		LOG(debug) <<"gdb asks if this is a new or existing process";
		/* Tell gdb this is an existing process; it might be
		 * (see emergency_debug()). */
		write_packet(dbg, "1");
		return 0;
	}
	if (!strcmp(name, "fThreadInfo")) {
		LOG(debug) <<"gdb asks for thread list";
		dbg->req.type = DREQ_GET_THREAD_LIST;
		return 1;
	}
	if (!strcmp(name, "sThreadInfo")) {
		write_packet(dbg, "l"); /* "end of list" */
		return 0;
	}
	if (!strcmp(name, "GetTLSAddr")) {
		LOG(debug) <<"gdb asks for TLS addr";
		/* TODO */
		write_packet(dbg, "");
		return 0;
	}
	if (!strcmp(name, "Offsets")) {
		LOG(debug) <<"gdb asks for section offsets";
		dbg->req.type = DREQ_GET_OFFSETS;
		dbg->req.target = dbg->query_thread;
		return 1;
	}
	if ('P' == name[0]) {
		/* The docs say not to use this packet ... */
		write_packet(dbg, "");
		return 0;
	}
	if (!strcmp(name, "Supported")) {
		char supported[1024];

		/* TODO process these */
		LOG(debug) <<"gdb supports "<< args;

		snprintf(supported, sizeof(supported) - 1,
			 "PacketSize=%x;QStartNoAckMode+;qXfer:auxv:read+"
			 ";multiprocess+",
			 dbg->outsize);
		write_packet(dbg, supported);
		return 0;
	}
	if (!strcmp(name, "Symbol")) {
		LOG(debug) <<"gdb is ready for symbol lookups";
		dbg->serving_symbol_lookups = 1;
		write_packet(dbg, "OK");
		return 0;
	}
	if (strstr(name, "ThreadExtraInfo") == name) {
		// ThreadExtraInfo is a special snowflake that
		// delimits its args with ','.
		assert(!args);
		args = payload;
		args = 1 + strchr(args, ','/*sic*/);

		dbg->req.type = DREQ_GET_THREAD_EXTRA_INFO;
		dbg->req.target = parse_threadid(args, &args);
		assert('\0' == *args);
		return 1;
	}
	if (!strcmp(name, "TStatus")) {
		LOG(debug) <<"gdb asks for trace status";
		/* XXX from the docs, it appears that we should reply
		 * with "T0" here.  But if we do, gdb keeps bothering
		 * us with trace queries.  So pretend we don't know
		 * what it's talking about. */
		write_packet(dbg, "");
		return 0;
	}
	if (!strcmp(name, "Xfer")) {
		name = args;
		args = strchr(args, ':');
		if (args) {
			*args++ = '\0';
		}
		return xfer(dbg, name, args);
	}

	UNHANDLED_REQ(dbg) <<"Unhandled gdb query: q"<< name;
	return 0;
}

static int set_var(struct dbg_context* dbg, char* payload)
{
	const char* name;
	char* args;

	args = strchr(payload, ':');
	if (args) {
		*args++ = '\0';
	}
	name = payload;

	if (!strcmp(name, "StartNoAckMode")) {
		write_packet(dbg, "OK");
		dbg->no_ack = 1;
		return 0;
	}

	UNHANDLED_REQ(dbg) <<"Unhandled gdb set: Q"<< name;
	return 0;
}

static void consume_request(struct dbg_context* dbg)
{
	memset(&dbg->req, 0, sizeof(dbg->req));
	write_flush(dbg);
}

static int process_vpacket(struct dbg_context* dbg, char* payload)
{
	const char* name;
	char* args;

	args = strchr(payload, ';');
	if (args) {
		*args++ = '\0';
	}
	name = payload;

	if (!strcmp("Cont", name)) {
		char cmd = *args++;
		if ('\0' != args[1]) {
			*args++ = '\0';
		}

		switch (cmd) {
		case 'C':
			LOG(warn) <<"Ignoring request to deliver signal ("
				  << args <<")";
			/* fall through */
		case 'c':
			dbg->req.type = DREQ_CONTINUE;
			dbg->req.target = dbg->resume_thread;
			return 1;
		case 'S':
			LOG(warn) <<"Ignoring request to deliver signal ("
				  << args <<")";
			args = strchr(args, ':');
			if (args) {
				++args;
			}
			/* fall through */
		case 's':
			dbg->req.type = DREQ_STEP;
			if (args) {
				dbg->req.target = parse_threadid(args, &args);
				// If we get a step request for a
				// thread, we just assume that
				// requests for all other threads are
				// 'c' (if any).  That's all we can
				// support anyway.
				assert('\0' == *args
				       || args == strstr(args, ";c"));
			} else {
				dbg->req.target = dbg->resume_thread;
			}
			return 1;
		default:
			UNHANDLED_REQ(dbg) <<"Unhandled vCont command "
					   << cmd <<"("<< args <<")";
			return 0;
		}
	}

	if (!strcmp("Cont?", name)) {
		LOG(debug) <<"gdb queries which continue commands we support";
		write_packet(dbg, "vCont;c;C;s;S;t;");
		return 0;
	}

	if (!strcmp("Kill", name)) {
		// We can't kill tracees or replay can diverge.  We
		// assume that this kill request is being made because
		// a "vRun" restart is coming right up.  We know how
		// to implement vRun, so we'll ignore this one.
		LOG(debug) <<"gdb asks us to kill tracee(s); ignoring";
		write_packet(dbg, "OK");
		return 0;
	}

	if (!strcmp("Run", name)) {
		dbg->req.type = DREQ_RESTART;
		dbg->req.restart.type = RESTART_FROM_PREVIOUS;

		if ('\0' == *args) {
			return 1;
		}
		const char* filename = args;
		*args++ = '\0';
		if (strlen(filename)) {
			FATAL() <<"gdb wants us to run the exe image `"
				<< filename << "', but we don't support that.";
		}
		if (strchr(args, ';')) {
			FATAL() <<"Extra arguments '"<< args
				<<"' passed to run. We don't support that.";
		}
		if (strlen(args)) {
			string event_str = decode_ascii_encoded_hex_str(args);
			char* endp;
			// TODO: ideally we would keep checkpointing
			// out of the gdb protocol translator, and
			// just pass up the run parameters, but that's
			// unnecessarily awkward due to the C-style
			// request struct and the way gdb encodes the
			// run args.
			if (event_str[0] == 'c') {
				int param = strtol(event_str.c_str() + 1, &endp, 0);
				dbg->req.restart.type = RESTART_FROM_CHECKPOINT;
				dbg->req.restart.param = param;
				LOG(debug) <<"next replayer restarting from checkpoint "
					   << dbg->req.restart.param;
			} else {
				dbg->req.restart.type = RESTART_FROM_EVENT;
				dbg->req.restart.param =
					strtol(event_str.c_str(), &endp, 0);
				LOG(debug) <<"next replayer advancing to event "
					   << dbg->req.restart.param;
			}
			if (!endp || *endp != '\0') {
				FATAL() <<"Couldn't parse event string `"
					<< event_str << "'";
			}
		}
		return 1;
	}

	UNHANDLED_REQ(dbg) <<"Unhandled gdb vpacket: v" << name;
	return 0;
}

static int process_packet(struct dbg_context* dbg)
{
	char request;
	char* payload = NULL;
	int ret;

	assert(INTERRUPT_CHAR == dbg->inbuf[0] ||
	       ('$' == dbg->inbuf[0]
		&& (((byte*)memchr(dbg->inbuf, '#', dbg->inlen) - dbg->inbuf)
		   == dbg->packetend)));

	if (INTERRUPT_CHAR == dbg->inbuf[0]) {
		request = INTERRUPT_CHAR;
	} else {
		request = dbg->inbuf[1];
		payload = (char*)&dbg->inbuf[2];
		dbg->inbuf[dbg->packetend] = '\0';
	}

	LOG(debug) <<"raw request "<< request <<"("<< payload <<")";

	switch(request) {
	case INTERRUPT_CHAR:
		LOG(debug) <<"gdb requests interrupt";
		dbg->req.type = DREQ_INTERRUPT;
		ret = 1;
		break;
	case 'D':
		LOG(debug) <<"gdb is detaching from us";
		dbg->req.type = DREQ_DETACH;
		ret = 1;
		break;
	case 'g':
		dbg->req.type = DREQ_GET_REGS;
		dbg->req.target = dbg->query_thread;
		LOG(debug) <<"gdb requests registers";
		ret = 1;
		break;
	case 'G':
		/* XXX we can't let gdb spray registers in general,
		 * because it may cause replay to diverge.  But some
		 * writes may be OK.  Let's see how far we can get
		 * with ignoring these requests. */
		write_packet(dbg, "");
		ret = 0;
		break;
	case 'H':
		if ('c' == *payload++) {
			dbg->req.type = DREQ_SET_CONTINUE_THREAD;
		} else {
			dbg->req.type = DREQ_SET_QUERY_THREAD;
		}
		dbg->req.target = parse_threadid(payload, &payload);
		assert('\0' == *payload);

		LOG(debug) <<"gdb selecting "<< dbg->req.target;

		ret = 1;
		break;
	case 'k':
		LOG(info) <<"gdb requests kill, exiting";
		write_packet(dbg, "OK");
		dbg_destroy_context(&dbg);
		exit(0);
	case 'm':
		dbg->req.type = DREQ_GET_MEM;
		dbg->req.target = dbg->query_thread;
		dbg->req.mem.addr = (void*)strtoul(payload, &payload, 16);
		++payload;
		dbg->req.mem.len = strtoul(payload, &payload, 16);
		assert('\0' == *payload);

		LOG(debug) <<"gdb requests memory (addr="<< dbg->req.mem.addr
			   <<", len="<< dbg->req.mem.len <<")";

		ret = 1;
		break;
	case 'M':
		/* We can't allow the debugger to write arbitrary data
		 * to memory, or the replay may diverge. */
		write_packet(dbg, "");
		ret = 0;
		break;
	case 'p':
		dbg->req.type = DREQ_GET_REG;
		dbg->req.target = dbg->query_thread;
		dbg->req.reg.name = strtoul(payload, &payload, 16);
		assert('\0' == *payload);
		LOG(debug) <<"gdb requests register value (" 
			   << dbg->req.reg.name <<")";
		ret = 1;
		break;
	case 'P':
		/* XXX we can't let gdb spray registers in general,
		 * because it may cause replay to diverge.  But some
		 * writes may be OK.  Let's see how far we can get
		 * with ignoring these requests. */
		write_packet(dbg, "");
		ret = 0;
		break;
	case 'q':
		ret = query(dbg, payload);
		break;
	case 'Q':
		ret = set_var(dbg, payload);
		break;
	case 'T':
		dbg->req.type = DREQ_GET_IS_THREAD_ALIVE;
		dbg->req.target = parse_threadid(payload, &payload);
		assert('\0' == *payload);
		LOG(debug) <<"gdb wants to know if "<< dbg->req.target
		<<" is alive";
		ret = 1;
		break;
	case 'v':
		ret = process_vpacket(dbg, payload);
		break;
	case 'X': {
		dbg->req.type = DREQ_SET_MEM;
		dbg->req.target = dbg->query_thread;
		dbg->req.mem.addr = (void*)strtoul(payload, &payload, 16);
		++payload;
		dbg->req.mem.len = strtoul(payload, &payload, 16);
		++payload;
		// This is freed by dbg_reply_set_mem().
		dbg->req.mem.data = (byte*)malloc(dbg->req.mem.len);
		// TODO: verify that the length of |payload| is as
		// expected in the presence of escaped data.  Right
		// now this call is potential-buffer-overrun-city.
		read_binary_data((const byte*)payload,
				 dbg->req.mem.len,
				 (byte*)dbg->req.mem.data);

		LOG(debug) <<"gdb setting memory (addr="<< dbg->req.mem.addr
			   <<", len="<< dbg->req.mem.len <<")";

		ret = 1;
 		break;
	}
	case 'z':
	case 'Z': {
		int type = strtol(payload, &payload, 16);
		assert(',' == *payload++);
		if (!(0 <= type && type <= 4)) {
			LOG(warn) << "Unknown watch type "<< type;
			write_packet(dbg, "");
			ret = 0;
			break;
		}
		dbg->req.type =	DbgRequestType(type + (request == 'Z' ?
						       DREQ_SET_SW_BREAK :
						       DREQ_REMOVE_SW_BREAK));
		dbg->req.mem.addr = (void*)strtoul(payload, &payload, 16);
		assert(',' == *payload++);
		dbg->req.mem.len = strtoul(payload, &payload, 16);
		assert('\0' == *payload);

		LOG(debug) <<"gdb requests "
			   << ('Z' == request ? "set" : "remove")
			   << "breakpoint (addr="<< dbg->req.mem.addr
			   << ", len=" << dbg->req.mem.len <<")";

		ret = 1;
		break;
	}
	case '!':
		LOG(debug) <<"gdb requests extended mode";
		write_packet(dbg, "OK");
		ret = 0;
		break;
	case '?':
		LOG(debug) <<"gdb requests stop reason";
		dbg->req.type = DREQ_GET_STOP_REASON;
		dbg->req.target = dbg->query_thread;
		ret = 1;
		break;
	default:
		UNHANDLED_REQ(dbg) <<"Unhandled gdb request '"
				   << dbg->inbuf[1] <<"'";
		ret = 0;
	}
	/* Erase the newly processed packet from the input buffer. */
	memmove(dbg->inbuf, dbg->inbuf + dbg->packetend,
		dbg->inlen - dbg->packetend);
	dbg->inlen = (dbg->inlen - dbg->packetend);

	/* If we processed the request internally, consume it. */
	if (ret == 0) {
		consume_request(dbg);
	}
	return ret;
}

void dbg_notify_no_such_thread(struct dbg_context* dbg,
			       const struct dbg_request* req)
{
	assert(!memcmp(&dbg->req, req, sizeof(dbg->req)));

	/* '10' is the errno ECHILD.  We use it as a magic code to
	 * notify the user that the thread that was the target of this
	 * request has died, and either gdb didn't notice that, or rr
	 * didn't notify gdb.  Either way, the user should restart
	 * their debugging session. */
	LOG(error) <<
"Targeted thread no longer exists; this is the result of either a gdb or\n"
"rr bug.  Please restart your debugging session and avoid doing whatever\n"
"triggered this bug.";
	write_packet(dbg, "E10");
	consume_request(dbg);
}

/**
 * Finish a DREQ_RESTART request.  Should be invoked after replay
 * restarts and prior dbg_context has been restored as |dbg|.
 */
static void dbg_notify_restart(struct dbg_context* dbg)
{
	assert(DREQ_RESTART == dbg->req.type);

	// These threads may not exist at the first trace-stop after
	// restart.  The gdb client should reset this state, but help
	// it out just in case.
	dbg->resume_thread = DBG_ANY_THREAD;
	dbg->query_thread = DBG_ANY_THREAD;

	memset(&dbg->req, 0, sizeof(dbg->req));
}

struct dbg_request dbg_get_request(struct dbg_context* dbg)
{
	if (DREQ_RESTART == dbg->req.type) {
		LOG(debug) <<"consuming RESTART request";
		dbg_notify_restart(dbg);
		// gdb wants to be notified with a stop packet when
		// the process "relaunches".  In rr's case, the
		// traceee may be very far away from process creation,
		// but that's OK.
		dbg->req.type = DREQ_GET_STOP_REASON;
		dbg->req.target = dbg->query_thread;
		return dbg->req;
	}

	/* Can't ask for the next request until you've satisfied the
	 * current one, for requests that need an immediate
	 * response. */
	assert(!request_needs_immediate_response(&dbg->req));

	if (sniff_packet(dbg) && dbg_is_resume_request(&dbg->req)) {
		/* There's no new request data available and gdb has
		 * already asked us to resume.  OK, do that (or keep
		 * doing that) now. */
		return dbg->req;
	}

	while (1) {
		/* There's either new request data, or we have nothing
		 * to do.  Either way, block until we read a complete
		 * packet from gdb. */
		read_packet(dbg);

		if (process_packet(dbg)) {
			/* We couldn't process the packet internally,
			 * so the target has to do something. */
			return dbg->req;
		}
		/* The packet we got was "internal", gdb details.
		 * Nothing for the target to do yet.  Keep waiting. */
	}
}

void dbg_notify_exit_code(struct dbg_context* dbg, int code)
{
	char buf[64];

	assert(dbg_is_resume_request(&dbg->req)
	       || dbg->req.type == DREQ_INTERRUPT);

	snprintf(buf, sizeof(buf) - 1, "W%02x", code);
	write_packet(dbg, buf);

	consume_request(dbg);
}

void dbg_notify_exit_signal(struct dbg_context* dbg, int sig)
{
	char buf[64];

	assert(dbg_is_resume_request(&dbg->req)
	       || dbg->req.type == DREQ_INTERRUPT);

	snprintf(buf, sizeof(buf) - 1, "X%02x", sig);
	write_packet(dbg, buf);

	consume_request(dbg);
}

/**
 * Translate linux-x86 |sig| to gdb's internal numbering.  Translation
 * made according to gdb/include/gdb/signals.def.
 */
static int to_gdb_signum(int sig)
{
	if (SIGRTMIN <= sig && sig <= SIGRTMAX) {
		/* GDB_SIGNAL_REALTIME_34 is numbered 46, hence this
		 * offset. */
		return sig + 12;
	}
	switch (sig) {
	case 0: return 0;
	case SIGHUP: return 1;
	case SIGINT: return 2;
	case SIGQUIT: return 3;
	case SIGILL: return 4;
	case SIGTRAP: return 5;
	case SIGABRT/*case SIGIOT*/: return 6;
	case SIGBUS: return 10;
	case SIGFPE: return 8;
	case SIGKILL: return 9;
	case SIGUSR1: return 30;
	case SIGSEGV: return 11;
	case SIGUSR2: return 31;
	case SIGPIPE: return 13;
	case SIGALRM: return 14;
	case SIGTERM: return 15;
		/* gdb hasn't heard of SIGSTKFLT, so this is
		 * arbitrarily made up.  SIGDANGER just sounds cool.*/
	case SIGSTKFLT: return 38/*GDB_SIGNAL_DANGER*/;
	/*case SIGCLD*/case SIGCHLD: return 20;
	case SIGCONT: return 19;
	case SIGSTOP: return 17;
	case SIGTSTP: return 18;
	case SIGTTIN: return 21;
	case SIGTTOU: return 22;
	case SIGURG: return 16;
	case SIGXCPU: return 24;
	case SIGXFSZ: return 25;
	case SIGVTALRM: return 26;
	case SIGPROF: return 27;
	case SIGWINCH: return 28;
	/*case SIGPOLL*/case SIGIO: return 23;
	case SIGPWR: return 32;
	case SIGSYS: return 12;
	default:
		FATAL() << "Unknown signal " << sig;
		return -1;	// not reached
	}
}

static void send_stop_reply_packet(struct dbg_context* dbg,
				   dbg_threadid_t thread, int sig,
				   void* watch_addr = nullptr)
{
	if (sig < 0) {
		write_packet(dbg, "E01");
		return;
	}
	char watch[1024];
	if (watch_addr) {
		snprintf(watch, sizeof(watch) - 1, "watch:%x;",
			 uintptr_t(watch_addr));
	} else {
		watch[0] = '\0';
	}
	char buf[PATH_MAX];
	snprintf(buf, sizeof(buf) - 1, "T%02xthread:p%02x.%02x;%s",
		 to_gdb_signum(sig), thread.pid, thread.tid, watch);
	write_packet(dbg, buf);
}

void dbg_notify_stop(struct dbg_context* dbg, dbg_threadid_t thread, int sig,
		     void* watch_addr)
{
	assert(dbg_is_resume_request(&dbg->req)
	       || dbg->req.type == DREQ_INTERRUPT);

	if (dbg->tgid != thread.pid) {
		LOG(debug) <<"ignoring stop of "<< thread
			   <<" because we're debugging tgid "<< dbg->tgid;
		// Re-use the existing continue request to advance to
		// the next stop we're willing to tell gdb about.
		return;
	}
	send_stop_reply_packet(dbg, thread, sig, watch_addr);

	// This isn't documented in the gdb remote protocol, but if we
	// don't do this, gdb will sometimes continue to send requests
	// for the previously-stopped thread when it obviously intends
	// to making requests about the stopped thread.
	LOG(debug) <<"forcing query/resume thread to "<< thread;
	dbg->query_thread = thread;
	dbg->resume_thread = thread;

	consume_request(dbg);
}

void dbg_notify_restart_failed(struct dbg_context* dbg)
{
	assert(DREQ_RESTART == dbg->req.type);

	// TODO: it's not known by this author whether gdb knows how
	// to recover from a failed "run" request.
	write_packet(dbg, "E01");

	consume_request(dbg);
}

void dbg_reply_get_current_thread(struct dbg_context* dbg,
				  dbg_threadid_t thread)
{
	assert(DREQ_GET_CURRENT_THREAD == dbg->req.type);

	char buf[1024];
	snprintf(buf, sizeof(buf), "QCp%02x.%02x", thread.pid, thread.tid);
	write_packet(dbg, buf);

	consume_request(dbg);
}

void dbg_reply_get_auxv(struct dbg_context* dbg,
			const struct dbg_auxv_pair* auxv, ssize_t len)
{
	assert(DREQ_GET_AUXV == dbg->req.type);

	if (len > 0) {
		write_binary_packet(dbg, "l",
				    (byte*)auxv, len * sizeof(auxv[0]));
	} else {
		write_packet(dbg, "E01");
	}

	consume_request(dbg);
}

void dbg_reply_get_is_thread_alive(struct dbg_context* dbg, int alive)
{
	assert(DREQ_GET_IS_THREAD_ALIVE == dbg->req.type);

	write_packet(dbg, alive ? "OK" : "E01");

	consume_request(dbg);
}

void dbg_reply_get_thread_extra_info(struct dbg_context* dbg,
				     const char* info)
{
	assert(DREQ_GET_THREAD_EXTRA_INFO == dbg->req.type);

	LOG(debug) <<"thread extra info: '" << info << "'";
	// XXX docs don't say whether we should send the null
	// terminator.  See what happens.
	write_hex_bytes_packet(dbg, (const byte*)info, 1 + strlen(info));

	consume_request(dbg);
}

void dbg_reply_select_thread(struct dbg_context* dbg, int ok)
{
	assert(DREQ_SET_CONTINUE_THREAD == dbg->req.type
	       || DREQ_SET_QUERY_THREAD == dbg->req.type);

	if (ok && DREQ_SET_CONTINUE_THREAD == dbg->req.type) {
		dbg->resume_thread = dbg->req.target;
	} else if (ok && DREQ_SET_QUERY_THREAD == dbg->req.type) {
		dbg->query_thread = dbg->req.target;
	}
	write_packet(dbg, ok ? "OK" : "E01");

	consume_request(dbg);
}

void dbg_reply_get_mem(struct dbg_context* dbg, const byte* mem, size_t len)
{
	assert(DREQ_GET_MEM == dbg->req.type);
	assert(len <= dbg->req.mem.len);

	write_hex_bytes_packet(dbg, mem, len);

	consume_request(dbg);
}

void dbg_reply_set_mem(struct dbg_context* dbg, int ok)
{
	assert(DREQ_SET_MEM == dbg->req.type);

	write_packet(dbg, ok ? "OK" : "E01");
	free((byte*)dbg->req.mem.data);

	consume_request(dbg);
}

void dbg_reply_get_offsets(struct dbg_context* dbg/*, TODO */)
{
	assert(DREQ_GET_OFFSETS == dbg->req.type);

	/* XXX FIXME TODO */
	write_packet(dbg, "");

	consume_request(dbg);
}

/**
 * Format |value| into |buf| in the manner gdb expects.  |buf| must
 * point at a buffer with at least |1 + 2*DBG_MAX_REG_SIZE| bytes
 * available.  Fewer bytes than that may be written, but |buf| is
 * guaranteed to be null-terminated.
 */
static size_t print_reg_value(const DbgRegister& reg, char* buf) {
	assert(reg.size <= DBG_MAX_REG_SIZE);
	if (reg.defined) {
		/* gdb wants the register value in native endianness.
		 * reg.value read in native endianness is exactly that.
		 */
		for (size_t i = 0; i < reg.size; ++i) {
			snprintf(&buf[2 * i], 3, "%02lx", (unsigned long)reg.value[i]);
		}
	} else {
		for (size_t i = 0; i < reg.size; ++i) {
			strcpy(&buf[2 * i], "xx");
		}
	}
	return reg.size * 2;
}

void dbg_reply_get_reg(struct dbg_context* dbg, const DbgRegister& reg)
{
	char buf[2 * DBG_MAX_REG_SIZE + 1];

	assert(DREQ_GET_REG == dbg->req.type);

	print_reg_value(reg, buf);
	write_packet(dbg, buf);

	consume_request(dbg);
}

void dbg_reply_get_regs(struct dbg_context* dbg, const DbgRegfile& file)
{
	size_t n_regs = file.total_registers();
	char buf[n_regs * 2 * DBG_MAX_REG_SIZE + 1];

	assert(DREQ_GET_REGS == dbg->req.type);

	size_t offset = 0;
	for (auto it = file.regs.begin(), end = file.regs.end();
	     it != end; ++it) {
		offset += print_reg_value(*it, &buf[offset]);
	}
	write_packet(dbg, buf);

	consume_request(dbg);
}

void dbg_reply_get_stop_reason(struct dbg_context* dbg,
			       dbg_threadid_t which, int sig)
{
	assert(DREQ_GET_STOP_REASON == dbg->req.type);

	send_stop_reply_packet(dbg, which, sig);

	consume_request(dbg);
}

void dbg_reply_get_thread_list(struct dbg_context* dbg,
			       const dbg_threadid_t* threads, ssize_t len)
{
	assert(DREQ_GET_THREAD_LIST == dbg->req.type);

	if (0 == len) {
		write_packet(dbg, "l");
	} else {
		ssize_t maxlen = 1/*m char*/ +
				 len * (1/*p*/ + 2 * sizeof(*threads) + 1/*,*/) +
				 1/*\0*/;
		char* str = (char*)malloc(maxlen);
		int offset = 0;

		str[offset++] = 'm';
		for (int i = 0; i < len; ++i) {
			const dbg_threadid_t& t = threads[i];
			if (dbg->tgid != t.pid) {
				continue;
			}
			offset += snprintf(&str[offset], maxlen - offset,
					   "p%02x.%02x,", t.pid, t.tid);
		}
		/* Overwrite the trailing ',' */
		str[offset - 1] = '\0';

		write_packet(dbg, str);
		free(str);
	}

	consume_request(dbg);
}

void dbg_reply_watchpoint_request(struct dbg_context* dbg, int code)
{
	assert(DREQ_WATCH_FIRST <= dbg->req.type
	       && dbg->req.type <= DREQ_WATCH_LAST);

	write_packet(dbg, code ? "E01" : "OK");

	consume_request(dbg);
}

void dbg_reply_detach(struct dbg_context* dbg)
{
	assert(DREQ_DETACH <= dbg->req.type);

	write_packet(dbg, "OK");

	consume_request(dbg);
}

void dbg_destroy_context(struct dbg_context** dbg)
{
	struct dbg_context* d;
	if (!(d = *dbg)) {
		return;
	}
	close(d->listen_fd);
	close(d->sock_fd);
	free(d);
	*dbg = NULL;
}
