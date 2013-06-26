/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

/**
 * Much of this implementation is based on the documentation at
 *
 * http://sourceware.org/gdb/onlinedocs/gdb/Packets.html
 */

#include "dbg_gdb.h"

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

#include "../share/dbg.h"
#include "../share/sys.h"

#define INTERRUPT_CHAR '\x03'

/* When debugging an "expect" test failure, it's often useful to see
 * full debug logging, but unfortunately that scrambles the brains of
 * pexpect's O(n^2) main loop.  So define this macro to redirect the
 * verbose stuff and avoid degenerate pexpect behavior. */
#ifdef REDIRECT_DEBUGLOG
# undef debug
# define debug(M, ...)							\
	do {								\
		fprintf(out, "DEBUG %s:%d: " M "\n",			\
			__FILE__, __LINE__, ##__VA_ARGS__);		\
	} while(0)
static FILE* out;
#endif

/**
 * This struct wraps up the state of the gdb protocol, so that we can
 * offer a (mostly) stateless interface to clients.
 */
struct dbg_context {
	struct dbg_request req;	/* current request to be processed */
	dbg_threadid_t resume_thread; /* thread to be resumed */
	dbg_threadid_t query_thread;  /* thread for get/set */
	int serving_symbol_lookups;	    /* nonzero when we can
					     * request lookups */
	int no_ack;		/* nonzero when "no-ack mode" is
				 * enabled */
	struct sockaddr_in addr;	    /* server address */
	int fd;				    /* client socket fd */
	/* XXX probably need to dynamically size these */
	byte inbuf[4096];	/* buffered input from gdb */
	size_t inlen;		/* length of valid data */
	size_t insize;		/* total size of buffer */
	size_t packetend;	/* index of '#' character */
	byte outbuf[4096];	/* buffered output for gdb */
	size_t outlen;
	size_t outsize;
};

int dbg_is_resume_request(const struct dbg_request* req)
{
	switch (req->type) {
	case DREQ_CONTINUE:
	case DREQ_STEP:
		return TRUE;
	default:
		return FALSE;
	}
}

inline static int request_needs_immediate_response(const struct dbg_request* req)
{
	switch (req->type) {
	case DREQ_NONE:
	case DREQ_CONTINUE:
	case DREQ_STEP:
		return FALSE;
	default:
		return TRUE;
	}
}

struct dbg_context* dbg_await_client_connection(const char* address, short port)
{
	struct dbg_context* dbg;
	int listen_fd;
	int reuseaddr;
	int autoprobe;
	struct sockaddr_in client_addr;
	int ret;
	socklen_t len;
	int flags;

#ifdef REDIRECT_DEBUGLOG
	out = fopen("/tmp/rr.debug.log", "w");
#endif

	dbg = sys_malloc_zero(sizeof(*dbg));
	dbg->insize = sizeof(dbg->inbuf);
	dbg->outsize = sizeof(dbg->outbuf);

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	dbg->addr.sin_family = AF_INET;
	dbg->addr.sin_addr.s_addr = inet_addr(address);
	reuseaddr = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
		   &reuseaddr, sizeof(reuseaddr));

	if (port <= 0) {
		autoprobe = 1;
		port = getpid();
	} else {
		autoprobe = 0;
	}
	do {
		dbg->addr.sin_port = htons(port);
		ret = bind(listen_fd,
			   (struct sockaddr*)&dbg->addr, sizeof(dbg->addr));
		if (ret == EADDRINUSE) {
			continue;
		} else if (ret != 0) {
			break;
		}
		ret = listen(listen_fd, 1/*backlogged connection*/);
		if (ret == 0 || ret != EADDRINUSE) {
			break;
		}
	} while (++port, autoprobe);
	if (ret) {
		fatal("Couldn't bind to server address");
	}
	log_info("rr debug server listening on %s:%d",
		 !strcmp(address, "127.0.0.1") ? "" : address,
		 ntohs(dbg->addr.sin_port));
	/* block until debugging client connects to us */
	len = sizeof(client_addr);
	dbg->fd = accept(listen_fd, (struct sockaddr*)&client_addr, &len);

	if (-1 == (flags = fcntl(dbg->fd, F_GETFD))) {
		fatal("Can't GETFD flags");
	}
	if (fcntl(dbg->fd, F_SETFD, flags | FD_CLOEXEC)) {
		fatal("Can't make client socket CLOEXEC");
	}
	if (fcntl(dbg->fd, F_SETFL, O_NONBLOCK)) {
		fatal("Can't make client socket NONBLOCK");
	}
	return dbg;
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
	pfd.fd = dbg->fd;
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
	nread = read(dbg->fd, dbg->inbuf + dbg->inlen,
		     dbg->insize - dbg->inlen);
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

#ifdef DEBUGRR
	dbg->outbuf[dbg->outlen] = '\0';
	debug("write_flush: '%s'", dbg->outbuf);
#endif
	while (write_index < dbg->outlen) {
		ssize_t nwritten;

		poll_outgoing(dbg, -1/*wait forever*/);
		nwritten = write(dbg->fd,
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
			   const byte* data, size_t len)
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

static void write_packet(struct dbg_context* dbg, const char* data)
{
	byte checksum;
	size_t len, i;

	write_data_raw(dbg, (byte*)"$", 1);
	len = strlen(data);
	for (i = 0, checksum = 0; i < len; ++i) {
		checksum += data[i];
	}
	write_data_raw(dbg, (byte*)data, len);
	write_data_raw(dbg, (byte*)"#", 1);
	write_hex(dbg, checksum);
}

static void write_hex_packet(struct dbg_context* dbg, unsigned long hex)
{
	char buf[32];

	snprintf(buf, sizeof(buf) - 1, "%02lx", hex);
	write_packet(dbg, buf);	
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
	     !(p = memchr(dbg->inbuf + checkedlen, '#', dbg->inlen));
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
		/* TODO process these */
		debug("gdb supports %s", args);
		write_packet(dbg, "QStartNoAckMode+");
		return 0;
	}
	if (!strcmp(name, "Symbol")) {
		debug("gdb is ready for symbol lookups");
		dbg->serving_symbol_lookups = 1;
		write_packet(dbg, "OK");
		return 0;
	}
	if (strstr(name, "ThreadExtraInfo") == name) {
		/* TODO */
		write_packet(dbg, "");
		return 0;
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



	fatal("Unhandled gdb query: q%s", name);



	log_warn("Unhandled gdb query: q%s", name);
	write_packet(dbg, "");
	return 0;
}

static int set(struct dbg_context* dbg, char* payload)
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


	fatal("Unhandled gdb set: Q%s", name);


	log_warn("Unhandled gdb set: Q%s", name);
	write_packet(dbg, "");
	return 0;
}

/**
 * Parse and return a gdb thread-id from |str|.  |endptr| points to
 * the character just after the last character in the thread-id.  It
 * may be NULL.
 */
static dbg_threadid_t parse_threadid(const char* str, char** endptr)
{
	return strtol(str, endptr, 16);
}

static int set_selected_thread(struct dbg_context* dbg, char* payload)
{
	char op;
	dbg_threadid_t thread;

	op = *payload++;

	thread = parse_threadid(payload, &payload);
	assert('\0' == *payload);

	debug("gdb selecting thread %d for %c", thread, op);

	if (op == 'c') {
		dbg->resume_thread = thread;
	} else if (op == 'g') {
		dbg->query_thread = thread;
	}
	write_packet(dbg, "OK");
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
		case 'c':
			dbg->req.type = DREQ_CONTINUE;
			dbg->req.target = dbg->resume_thread;
			return 1;
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
			fatal("Unhandled vCont command %c(%s)", cmd, args);
		}
	}

	if (!strcmp("Cont?", name)) {
		debug("gdb queries which continue commands we support");
		write_packet(dbg, "vCont;c;C;s;S;t;");
		return 0;
	}


	fatal("Unhandled gdb vpacket: v%s", name);


	//log_warn("Unhandled gdb vpacket: v%s", name);
	write_packet(dbg, "");
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
		log_info("gdb is detaching from us, exiting");
		write_packet(dbg, "OK");
		exit(0);
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
		ret = set_selected_thread(dbg, payload);
		break;
	case 'k':
		log_info("gdb requests kill, exiting");
		write_packet(dbg, "OK");
		exit(0);
	case 'm':
		dbg->req.type = DREQ_GET_MEM;
		dbg->req.target = dbg->query_thread;
		dbg->req.params.mem.addr =
			(void*)strtoul(payload, &payload, 16);
		++payload;
		dbg->req.params.mem.len = strtoul(payload, &payload, 16);
		assert('\0' == *payload);

		debug("gdb requests memory (addr=0x%p, len=%u)",
			  dbg->req.params.mem.addr, dbg->req.params.mem.len);

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
		dbg->req.params.reg = strtoul(payload, &payload, 16);
		assert('\0' == *payload);
		debug("gdb requests register value (%d)", dbg->req.params.reg);
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
		ret = set(dbg, payload);
		break;
	case 'T':
		dbg->req.type = DREQ_GET_IS_THREAD_ALIVE;
		dbg->req.target = parse_threadid(payload, &payload);
		assert('\0' == *payload);
		debug("gdb wants to know if %d is alive", dbg->req.target);
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
		dbg->req.type =	type + (request == 'Z' ?
					DREQ_SET_SW_BREAK :
					DREQ_REMOVE_SW_BREAK);
		dbg->req.params.mem.addr =
			(void*)strtoul(payload, &payload, 16);
		assert(',' == *payload++);
		dbg->req.params.mem.len = strtoul(payload, &payload, 16);
		assert('\0' == *payload);

		debug("gdb requests %s breakpoint (addr=%p, len=%u)",
		      'Z' == request ? "set" : "remove",
		      dbg->req.params.mem.addr, dbg->req.params.mem.len);

		ret = 1;
		break;
	}
	case '?':
		debug("gdb requests stop reason");
		dbg->req.type = DREQ_GET_STOP_REASON;
		dbg->req.target = dbg->query_thread;
		ret = 1;
		break;
	default:


		fatal("Unhandled gdb request '%c'", dbg->inbuf[1]);


		//log_warn("Unhandled gdb request '%c'", dbg->inbuf[1]);
		/* Play dumb and hope gdb doesn't /really/ need this
		 * request ... */
		write_packet(dbg, "");
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

struct dbg_request dbg_get_request(struct dbg_context* dbg)
{
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

static void send_stop_reply_packet(struct dbg_context* dbg,
				   dbg_threadid_t thread, int sig)
{
	if (sig >= 0) {
		char buf[64];
		snprintf(buf, sizeof(buf) - 1, "T%02xthread:%02x;",
			 sig, thread);
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

	/* TODO multiprocess */
	write_hex_packet(dbg, thread);

	consume_request(dbg);
}

void dbg_reply_get_is_thread_alive(struct dbg_context* dbg, int alive)
{
	assert(DREQ_GET_IS_THREAD_ALIVE == dbg->req.type);

	write_packet(dbg, alive ? "OK" : "E01");

	consume_request(dbg);
}

void dbg_reply_get_mem(struct dbg_context* dbg, const byte* mem)
{
	char* buf;
	size_t i, len;

	assert(DREQ_GET_MEM == dbg->req.type);

	if (mem) {
		len = dbg->req.params.mem.len;
		buf = sys_malloc(2 * len + 1);
		for (i = 0; i < len; ++i) {
			unsigned long b = mem[i];
			snprintf(&buf[2 * i], 3, "%02lx", b);
		}
		write_packet(dbg, buf);
		sys_free((void**)&buf);
	} else {
		write_packet(dbg, "");
	}

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
			       const dbg_threadid_t* threads, size_t len)
{
	assert(DREQ_GET_THREAD_LIST == dbg->req.type);

	if (0 == len) {
		write_packet(dbg, "l");
	} else {
		size_t maxlen =	1/*m char*/ +
				(2 * sizeof(pid_t) + 1/*,*/) * len +
				1/*\0*/;
		char* str = sys_malloc(maxlen);
		int i, offset = 0;

		str[offset++] = 'm';
		for (i = 0; i < len; ++i) {
			offset += snprintf(&str[offset], maxlen - offset,
					   "%02x,", threads[i]);
		}
		/* Overwrite the trailing ',' */
		str[offset - 1] = '\0';

		write_packet(dbg, str);
		sys_free((void**)&str);
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

void dbg_destroy_context(struct dbg_context** dbg)
{
	struct dbg_context* d;
	if (!(d = *dbg)) {
		return;
	}
	*dbg = NULL;
	close(d->fd);
	sys_free((void**)&d);
}
