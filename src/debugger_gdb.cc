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
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <sstream>

#include "dbg.h"
#include "sys.h"
#include "task.h"

#define INTERRUPT_CHAR '\x03'

#ifdef DEBUGTAG
# define unhandled_req(_g, _m, ...)		\
	fatal(_m, ## __VA_ARGS__)
#else
# define unhandled_req(_g, _m, ...)		\
	do {					\
		log_info(_m, ##__VA_ARGS__);	\
		write_packet(_g, "");		\
	} while (0)
#endif

using namespace std;

/**
 * This struct wraps up the state of the gdb protocol, so that we can
 * offer a (mostly) stateless interface to clients.
 *
 * dbg_contexts are mapped into their own (unlinked) shmem.  We do
 * this in order to save/restore debugger state across replay
 * restarts, which is pretty tricky do otherwise.  Before replay
 * restart, we save a cookie in the environment that lets us find the
 * fd of our mapping.  Then after exec(), we re-init our state by
 * finding the cookie and remapping the region (then unsetting the
 * cookie, of course).
 */
struct dbg_context {
	int desc_fd;		// fd of dbg_context mapping
	struct dbg_request req;	/* current request to be processed */
	dbg_threadid_t resume_thread; /* thread to be resumed */
	dbg_threadid_t query_thread;  /* thread for get/set */
	int serving_symbol_lookups;	    /* nonzero when we can
					     * request lookups */
	int no_ack;		/* nonzero when "no-ack mode" is
				 * enabled */
	struct sockaddr_in addr;	    /* server address */
	int listen_fd;			    /* listen socket */
	int sock_fd;			    /* client socket fd */
	/* XXX probably need to dynamically size these */
	byte inbuf[4096];	/* buffered input from gdb */
	ssize_t inlen;		/* length of valid data */
	ssize_t insize;		/* total size of buffer */
	ssize_t packetend;	/* index of '#' character */
	byte outbuf[4096];	/* buffered output for gdb */
	ssize_t outlen;
	ssize_t outsize;
};

bool dbg_is_resume_request(const struct dbg_request* req)
{
	switch (req->type) {
	case DREQ_CONTINUE:
	case DREQ_STEP:
	case DREQ_DETACH:
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
		fatal("Can't GETFD flags");
	}
	if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC)) {
		fatal("Can't make client socket CLOEXEC");
	}
}

static size_t dbg_context_mapped_size()
{
	return ceil_page_size(sizeof(struct dbg_context));
}

static dbg_context* map_dbg_context(int desc_fd)
{
	void* m = mmap(nullptr, dbg_context_mapped_size(),
		       PROT_READ | PROT_WRITE, MAP_SHARED, desc_fd, 0);
	if ((void*)-1 == m) {
		fatal("Couldn't mmap dbg_context desc_fd %d", desc_fd);
	}
	debug("mmap dbg_context desc_fd %d at %p", desc_fd, m);
	return reinterpret_cast<struct dbg_context*>(m);
}

static dbg_context* new_dbg_context()
{
	static int counter = 0;
	stringstream ss;
	ss << "rr-dbg-ctx-" << getpid() << "-" << ++counter;
	// NB: we don't set CLOEXEC here because we may need to
	// preserve the backing segment across exec(), if replay
	// restarts.
	int desc_fd = create_shmem_segment(ss.str().c_str(),
					   dbg_context_mapped_size(),
					   O_NO_CLOEXEC);
	struct dbg_context* dbg = map_dbg_context(desc_fd);
	dbg->desc_fd = desc_fd;
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
	make_cloexec(dbg->listen_fd);

	dbg->addr.sin_family = AF_INET;
	dbg->addr.sin_addr.s_addr = inet_addr(address);
	reuseaddr = 1;
	setsockopt(dbg->listen_fd, SOL_SOCKET, SO_REUSEADDR,
		   &reuseaddr, sizeof(reuseaddr));
	do {
		dbg->addr.sin_port = htons(port);
		ret = ::bind(dbg->listen_fd,
			     (struct sockaddr*)&dbg->addr, sizeof(dbg->addr));
		if (ret && (EADDRINUSE == errno || EACCES == errno)) {
			continue;
		}
		if (ret != 0) {
			break;
		}

		ret = listen(dbg->listen_fd, 1/*backlogged connection*/);
		if (ret == 0 || EADDRINUSE != errno) {
			break;
		}
	} while (++port, probe);
	if (ret) {
		fatal("Couldn't bind to port %d", port);
	}
}

static string make_exec_cookie_envvar()
{
	stringstream ss;
	ss << "_RR_DBG_CONTEXT_EXEC_COOKIE_" << getpid();
	return ss.str();
}

/**
 * If an exec cookie is found, restore and return the context it
 * points at.  Otherwise return nullptr.
 */
static struct dbg_context* try_load_from_exec_cookie()
{
	string envvar = make_exec_cookie_envvar();
	const char* cookiep = getenv(envvar.c_str());
	if (!cookiep) {
		return nullptr;
	}
	string cookie = cookiep;
	unsetenv(envvar.c_str());

	assert('\0' != cookie[0]);
	int desc_fd = stoi(cookie);
	debug("found exec cookie %s=%d", envvar.c_str(), desc_fd);

	struct dbg_context* dbg = map_dbg_context(desc_fd);
	// Sanity-check the restored mapping.
	assert(dbg->desc_fd == desc_fd);
	assert(dbg->listen_fd == -1);
	assert(dbg->sock_fd >= 0);
	assert(dbg->insize == sizeof(dbg->inbuf));
	assert(dbg->outsize == sizeof(dbg->outbuf));
	return dbg;
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
		fatal("Can't make client socket NONBLOCK");
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
						const char* exe_image,
						pid_t client,
						int client_params_fd)
{
	if (struct dbg_context* dbg = try_load_from_exec_cookie()) {
		// Replay just restarted.  |dbg| is now restored to
		// what it was in the prior session.
		return dbg;
	}

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
	await_debugger(dbg);
	return dbg;
}

void dbg_launch_debugger(int params_pipe_fd)
{
	struct debugger_params params;
	ssize_t nread = read(params_pipe_fd, &params, sizeof(params));
	assert(nread == sizeof(params));

	stringstream attach_cmd;
	attach_cmd << "target extended-remote " << params.socket_addr << ":"
		   << params.port;
	debug("launching gdb with command '%s'", attach_cmd.str().c_str());
	execlp("gdb", "gdb",
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
	       "-l", "-1",
	       params.exe_image,
	       "-ex", attach_cmd.str().c_str(), NULL);
	fatal("Failed to exec gdb.");
}

void dbg_prepare_restore_after_exec_restart(struct dbg_context* dbg)
{
	string envvar = make_exec_cookie_envvar();
	assert(!getenv(envvar.c_str()));

	stringstream ss;
	ss << dbg->desc_fd;
	setenv(envvar.c_str(), ss.str().c_str(), 1/*override*/);
	debug("set exec cookie to %s=%s", envvar.c_str(), ss.str().c_str());
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
		fatal("Polling gdb socket failed");
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
		log_info("(gdb closed debugging socket, exiting)");
		exit(0);
	}
	if (nread <= 0) {
		fatal("Error reading from gdb");
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
	debug("write_flush: '%s'", dbg->outbuf);
#endif
	while (write_index < dbg->outlen) {
		ssize_t nwritten;

		poll_outgoing(dbg, -1/*wait forever*/);
		nwritten = write(dbg->sock_fd,
				 dbg->outbuf + write_index,
				 dbg->outlen - write_index);
		if (nwritten < 0) {
			fatal("Error writing to gdb");
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

	debug(" ***** NOTE: writing binary data, upcoming debug output may be truncated");
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
	assert(endp && '\0' == *endp);

	*endptr = endp;
	return t;
}

static int xfer(struct dbg_context* dbg, const char* name, char* args)
{
	debug("gdb asks us to transfer %s(%s)", name, args);

	if (!strcmp(name, "auxv")) {
		assert(!strncmp(args, "read::",	sizeof("read::") - 1));

		dbg->req.type = DREQ_GET_AUXV;
		dbg->req.target = dbg->query_thread;
		return 1;
	}

	unhandled_req(dbg, "Unhandled gdb xfer request: %s(%s)", name, args);
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
		debug("gdb requests current thread ID");
		dbg->req.type = DREQ_GET_CURRENT_THREAD;
		return 1;
	}
	if (!strcmp(name, "Attached")) {
		debug("gdb asks if this is a new or existing process");
		/* Tell gdb this is an existing process; it might be
		 * (see emergency_debug()). */
		write_packet(dbg, "1");
		return 0;
	}
	if (!strcmp(name, "fThreadInfo")) {
		debug("gdb asks for thread list");
		dbg->req.type = DREQ_GET_THREAD_LIST;
		return 1;
	}
	if (!strcmp(name, "sThreadInfo")) {
		write_packet(dbg, "l"); /* "end of list" */
		return 0;
	}
	if (!strcmp(name, "GetTLSAddr")) {
		debug("gdb asks for TLS addr");
		/* TODO */
		write_packet(dbg, "");
		return 0;
	}
	if (!strcmp(name, "Offsets")) {
		debug("gdb asks for section offsets");
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
		debug("gdb supports %s", args);

		snprintf(supported, sizeof(supported) - 1,
			 "PacketSize=%x;QStartNoAckMode+;qXfer:auxv:read+"
			 ";multiprocess+",
			 sizeof(dbg->outbuf));
		write_packet(dbg, supported);
		return 0;
	}
	if (!strcmp(name, "Symbol")) {
		debug("gdb is ready for symbol lookups");
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
		debug("gdb asks for trace status");
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

	unhandled_req(dbg, "Unhandled gdb query: q%s", name);
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

	unhandled_req(dbg, "Unhandled gdb set: Q%s", name);
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
			log_warn("Ignoring request to deliver signal (%s)",
				 args);
			/* fall through */
		case 'c':
			dbg->req.type = DREQ_CONTINUE;
			dbg->req.target = dbg->resume_thread;
			return 1;
		case 'S':
			log_warn("Ignoring request to deliver signal (%s)",
				 args);
			args = strchr(args, ':');
			if (args) {
				++args;
			}
			/* fall through */
		case 's':
			dbg->req.type = DREQ_STEP;
			if (args) {
				dbg->req.target = parse_threadid(args, &args);
				assert('\0' == *args || !strcmp(args, ";c"));
			} else {
				dbg->req.target = dbg->resume_thread;
			}
			return 1;
		default:
			unhandled_req(dbg, "Unhandled vCont command %c(%s)",
				      cmd, args);
			return 0;
		}
	}

	if (!strcmp("Cont?", name)) {
		debug("gdb queries which continue commands we support");
		write_packet(dbg, "vCont;c;C;s;S;t;");
		return 0;
	}

	if (!strcmp("Kill", name)) {
		// We can't kill tracees or replay can diverge.  We
		// assume that this kill request is being made because
		// a "vRun" restart is coming right up.  We know how
		// to implement vRun, so we'll ignore this one.
		debug("gdb asks us to kill tracee(s); ignoring");
		write_packet(dbg, "OK");
		return 0;
	}

	if (!strcmp("Run", name)) {
		dbg->req.type = DREQ_RESTART;
		dbg->req.restart.event = -1;
		dbg->req.restart.port = ntohs(dbg->addr.sin_port);

		if ('\0' == *args) {
			return 1;
		}
		const char* filename = args;
		*args++ = '\0';
		if (strlen(filename)) {
			fatal("gdb wants us to run the exe image `%s', but we don't support that.",
				filename);
		}
		if (strchr(args, ';')) {
			fatal("Extra arguments '%s' passed to run. We don't support that.",
			      args);
		}
		if (strlen(args)) {
			string event_str = decode_ascii_encoded_hex_str(args);
			char* endp;
			dbg->req.restart.event =
				strtol(event_str.c_str(), &endp, 0);
			if (!endp || *endp != '\0') {
				fatal("Couldn't parse event string `%s'",
				      event_str.c_str());
			}
		}
		debug("next replayer advancing to event %d",
		      dbg->req.restart.event);
		return 1;
	}

	unhandled_req(dbg, "Unhandled gdb vpacket: v%s", name);
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

	debug("raw request %c(%s)", request, payload);

	switch(request) {
	case INTERRUPT_CHAR:
		debug("gdb requests interrupt");
		dbg->req.type = DREQ_INTERRUPT;
		ret = 1;
		break;
	case 'D':
		debug("gdb is detaching from us");
		dbg->req.type = DREQ_DETACH;
		ret = 1;
		break;
	case 'g':
		dbg->req.type = DREQ_GET_REGS;
		dbg->req.target = dbg->query_thread;
		debug("gdb requests registers");
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

		debug("gdb selecting %d.%d",
		      dbg->req.target.tid, dbg->req.target.pid);

		ret = 1;
		break;
	case 'k':
		log_info("gdb requests kill, exiting");
		write_packet(dbg, "OK");
		exit(0);
	case 'm':
		dbg->req.type = DREQ_GET_MEM;
		dbg->req.target = dbg->query_thread;
		dbg->req.mem.addr = (byte*)strtoul(payload, &payload, 16);
		++payload;
		dbg->req.mem.len = strtoul(payload, &payload, 16);
		assert('\0' == *payload);

		debug("gdb requests memory (addr=0x%p, len=%u)",
			  dbg->req.mem.addr, dbg->req.mem.len);

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
		dbg->req.reg = DbgRegister(strtoul(payload, &payload, 16));
		assert('\0' == *payload);
		debug("gdb requests register value (%d)", dbg->req.reg);
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
		debug("gdb wants to know if %d.%d is alive",
		      dbg->req.target.pid, dbg->req.target.tid);
		ret = 1;
		break;
	case 'v':
		ret = process_vpacket(dbg, payload);
		break;
	case 'X':
		/* We can't allow the debugger to write arbitrary data
		 * to memory, or the replay may diverge. */
		write_packet(dbg, "");
		ret = 0;
		break;
	case 'z':
	case 'Z': {
		int type = strtol(payload, &payload, 16);
		assert(',' == *payload++);
		if (!(0 <= type && type <= 4)) {
			log_warn("Unknown watch type %d", type);
			write_packet(dbg, "");
			ret = 0;
			break;
		}
		dbg->req.type =	DbgRequestType(type + (request == 'Z' ?
						       DREQ_SET_SW_BREAK :
						       DREQ_REMOVE_SW_BREAK));
		dbg->req.mem.addr = (byte*)strtoul(payload, &payload, 16);
		assert(',' == *payload++);
		dbg->req.mem.len = strtoul(payload, &payload, 16);
		assert('\0' == *payload);

		debug("gdb requests %s breakpoint (addr=%p, len=%u)",
		      'Z' == request ? "set" : "remove",
		      dbg->req.mem.addr, dbg->req.mem.len);

		ret = 1;
		break;
	}
	case '!':
		debug("gdb requests extended mode");
		write_packet(dbg, "OK");
		ret = 0;
		break;
	case '?':
		debug("gdb requests stop reason");
		dbg->req.type = DREQ_GET_STOP_REASON;
		dbg->req.target = dbg->query_thread;
		ret = 1;
		break;
	default:
		unhandled_req(dbg, "Unhandled gdb request '%c'", dbg->inbuf[1]);
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
	log_err(
"Targeted thread no longer exists; this is the result of either a gdb or\n"
"rr bug.  Please restart your debugging session and avoid doing whatever\n"
"triggered this bug.");
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
		debug("consuming RESTART request");
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
		fatal("Unknown signal %d", sig);
	}
}

static void send_stop_reply_packet(struct dbg_context* dbg,
				   dbg_threadid_t thread, int sig)
{
	if (sig >= 0) {
		char buf[64];
		snprintf(buf, sizeof(buf) - 1, "T%02xthread:p%02x.%02x;",
			 to_gdb_signum(sig), thread.pid, thread.tid);
		write_packet(dbg, buf);
	} else {
		write_packet(dbg, "E01");
	}
}

void dbg_notify_stop(struct dbg_context* dbg, dbg_threadid_t thread, int sig)
{
	assert(dbg_is_resume_request(&dbg->req)
	       || dbg->req.type == DREQ_INTERRUPT);

	send_stop_reply_packet(dbg, thread, sig);

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

	debug("thread extra info: '%s'", info);
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

void dbg_reply_get_offsets(struct dbg_context* dbg/*, TODO */)
{
	assert(DREQ_GET_OFFSETS == dbg->req.type);

	/* XXX FIXME TODO */
	write_packet(dbg, "");

	consume_request(dbg);
}

/**
 * Format |value| into |buf| in the manner gdb expects.  |buf| must
 * point at a buffer with at least |1 + 2*sizeof(long)| bytes
 * available.  Exactly that many bytes (including '\0' terminator)
 * will be written by this function.
 */
static void print_reg(dbg_regvalue_t value, char* buf) {
	if (value.defined) {
		/* gdb wants the register value in native endianness, so
		 * swizzle to big-endian so that printf gives us a
		 * little-endian string.  (Network order is big-endian.) */
		long v = htonl(value.value);
		sprintf(buf, "%08lx", v);
	} else {
		strcpy(buf, "xxxxxxxx");
	}
}

void dbg_reply_get_reg(struct dbg_context* dbg, dbg_regvalue_t value)
{
	char buf[32];

	assert(DREQ_GET_REG == dbg->req.type);

	print_reg(value, buf);
	write_packet(dbg, buf);

	consume_request(dbg);
}

void dbg_reply_get_regs(struct dbg_context* dbg,
			const struct dbg_regfile* file)
{
	/* XXX this will be wrong on x64 WINNT */
	char buf[1 + DREG_NUM_LINUX_I386 * 2 * sizeof(long)];
	int i;

	assert(DREQ_GET_REGS == dbg->req.type);

	for (i = 0; i < DREG_NUM_LINUX_I386; ++i) {
		print_reg(file->regs[i], &buf[i * 2 * sizeof(long)]);
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

	write_packet(dbg, code ? "" : "OK");

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
	*dbg = NULL;
	close(d->desc_fd);
	close(d->listen_fd);
	close(d->sock_fd);
	munmap(d, dbg_context_mapped_size());
	*dbg = NULL;
}
