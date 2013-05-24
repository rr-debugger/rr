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

/**
 * This struct wraps up the state of the gdb protocol, so that we can
 * offer a (mostly) stateless interface to clients.
 */
struct dbg_context {
	struct dbg_request req;	/* current request to be processed */
	struct dbg_thread_id resume_thread; /* thread to be resumed */
	struct dbg_thread_id query_thread;  /* thread for get/set */
	int serving_symbol_lookups;	    /* nonzero when we can
					     * request lookups */
	struct sockaddr_in addr;	    /* server address */
	int fd;				    /* client socket fd */
	/* XXX probably need to dynamically size these */
	char inbuf[4096];	/* buffered input from gdb */
	size_t inlen;		/* length of valid data */
	size_t insize;		/* total size of buffer */
	size_t packetend;	/* index of '#' character */
	char outbuf[4096];	/* buffered output for gdb */
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

static int request_needs_immediate_response(const struct dbg_request* req)
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

struct dbg_context* dbg_await_client_connection(const char* address)
{
	struct dbg_context* dbg;
	int listen_fd;
	short port;
	struct sockaddr_in client_addr;
	int ret;
	socklen_t len;
	int flags;

	dbg = sys_malloc_zero(sizeof(*dbg));
	dbg->insize = sizeof(dbg->inbuf);
	dbg->outsize = sizeof(dbg->outbuf);

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	dbg->addr.sin_family = AF_INET;
	dbg->addr.sin_addr.s_addr = inet_addr(address);
	for (port = getpid(); ; ++port) {
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
	}
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
			   const char* data, size_t len)
{
	assert("Impl dynamic alloc if this fails (or double outbuf size)"
	       && (dbg->outlen + len) < dbg->insize);

	memcpy(dbg->outbuf + dbg->outlen, data, len);
	dbg->outlen += len;
}

static void write_hex(struct dbg_context* dbg, long hex)
{
	char buf[32];
	size_t len;

	len = snprintf(buf, sizeof(buf) - 1, "%02lX", hex);
	write_data_raw(dbg, buf, len);
}

static void write_packet(struct dbg_context* dbg, const char* data)
{
	int checksum;
	size_t len, i;

	write_data_raw(dbg, "$", 1);
	len = strlen(data);
	for (i = 0, checksum = 0; i < len; ++i) {
		checksum += data[i];
	}
	write_data_raw(dbg, data, len);
	write_data_raw(dbg, "#", 1);
	write_hex(dbg, checksum % 256);
}

static void write_hex_packet(struct dbg_context* dbg, long hex)
{
	char buf[32];

	snprintf(buf, sizeof(buf) - 1, "%02lX", hex);
	write_packet(dbg, buf);	
}

/**
 * Consume bytes in the input buffer until start-of-packet ('$') is
 * seen.  Does not block.  Return zero if start-of-packet is seen,
 * nonzero if not.
 */
static int skip_to_packet_start(struct dbg_context* dbg)
{
	char* p;

	p = memchr(dbg->inbuf, '$', dbg->inlen);
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
	assert('$' == dbg->inbuf[0]);
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
	char* p;
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
	write_data_raw(dbg, "+", 1);
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
		/* Tell gdb we created a new process on its behalf.
		 * We could go either way, but there's not much point
		 * in continuing replay after gdb detaches, so this
		 * seems to make the most sense. */
		write_packet(dbg, "0");
		return 0;
	}
	if (!strcmp(name, "Offsets")) {
		debug("gdb asks for section offsets");
		dbg->req.type = DREQ_GET_OFFSETS;
		return 1;
	}
	if (!strcmp(name, "Supported")) {
		/* TODO process these */
		debug("gdb supports %s", args);
		write_packet(dbg, "");
		return 0;
	}
	if (!strcmp(name, "Symbol")) {
		debug("gdb is ready for symbol lookups");
		dbg->serving_symbol_lookups = 1;
		write_packet(dbg, "OK");
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

	log_warn("Unhandled gdb query: q%s", name);
	write_packet(dbg, "");
	return 0;
}

static int set_selected_thread(struct dbg_context* dbg, const char* payload)
{
	char op;
	pid_t pid, tid;

	op = *payload++;
	pid = 0;		/* TODO multiprocess */
	tid = atoi(payload);

	debug("gdb selecting thread %d:%d for %c", pid, tid, op);

	if (op == 'c') {
		dbg->resume_thread.pid = pid;
		dbg->resume_thread.tid = tid;
	} else if (op == 'g') {
		dbg->query_thread.pid = pid;
		dbg->query_thread.tid = tid;
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
	} else {
		*strchr(payload, '?') = '\0';
	}
	name = payload;

	if (!strcmp("Cont", name)) {
		/* TODO parse args */
		if (!args || !strcmp("c", args)) {
			debug("gdb requests 'continue'");
			/* XXX does no-args mean 'c'? */
			dbg->req.type = DREQ_CONTINUE;
			dbg->req.target = dbg->resume_thread;
			memset(&dbg->req.params.resume, 0,
			       sizeof(dbg->req.params.resume));
			return 1;
		}
		fatal("vCont unparsed args %s", args);
		return 0;
	}

	log_warn("Unhandled gdb vpacket: v%s", name);
	write_packet(dbg, "");
	return 0;
}

static int process_packet(struct dbg_context* dbg)
{
	char request;
	char* payload;
	int ret;

	assert('$' == dbg->inbuf[0]
	       && (((char*)memchr(dbg->inbuf, '#', dbg->inlen) - dbg->inbuf)
		   == dbg->packetend));

	dbg->inbuf[dbg->packetend] = '\0';
	request = dbg->inbuf[1];
	payload = &dbg->inbuf[2];
	switch(request) {
	case 'g':
		dbg->req.type = DREQ_GET_REGS;
		dbg->req.target = dbg->query_thread;
		debug("gdb requests registers");
		ret = 1;
		break;
	case 'H':
		ret = set_selected_thread(dbg, payload);
		break;
	case 'm':
		dbg->req.type = DREQ_GET_MEM;
		dbg->req.target = dbg->query_thread;
		dbg->req.params.mem.addr = strtol(payload, &payload, 16);
		++payload;
		dbg->req.params.mem.len = strtol(payload, &payload, 16);
		assert('\0' == *payload);

		debug("gdb requests memory (addr=%lX, len=%X)",
			  dbg->req.params.mem.addr, dbg->req.params.mem.len);

		ret = 1;
		break;
	case 'p':
		debug("gdb requests register value (%s)", payload);
		dbg->req.type = DREQ_GET_REG;
		dbg->req.target = dbg->query_thread;
		dbg->req.params.reg = strtol(payload, &payload, 16);
		assert('\0' == *payload);
		ret = 1;
		break;
	case 'q':
		ret = query(dbg, payload);
		break;
	case 'v':
		ret = process_vpacket(dbg, payload);
		break;
	case 'Z':
		/* TODO set breakpoint */
		write_packet(dbg, "");
		debug("gdb requests breakpoint (%s)", payload);
		ret = 0;
		break;
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

void dbg_notify_stop(struct dbg_context* dbg/*, TODO */)
{
	assert(dbg_is_resume_request(&dbg->req));

	/* XXX FIXME TODO */
	write_packet(dbg, "S00");

	consume_request(dbg);
}

void dbg_reply_get_current_thread(struct dbg_context* dbg,
				  struct dbg_thread_id thread)
{
	assert(DREQ_GET_CURRENT_THREAD == dbg->req.type);

	/* TODO multiprocess */
	write_hex_packet(dbg, thread.tid);

	consume_request(dbg);
}

void dbg_reply_get_mem(struct dbg_context* dbg/*, TODO */)
{
	assert(DREQ_GET_MEM == dbg->req.type);

	/* XXX FIXME TODO */
	write_packet(dbg, "");

	consume_request(dbg);
}

void dbg_reply_get_offsets(struct dbg_context* dbg/*, TODO */)
{
	assert(DREQ_GET_OFFSETS == dbg->req.type);

	/* XXX FIXME TODO */
	write_packet(dbg, "");

	consume_request(dbg);
}

void dbg_reply_get_regs(struct dbg_context* dbg/*, TODO */)
{
	assert(DREQ_GET_REGS == dbg->req.type);

	/* XXX FIXME TODO */
	write_packet(dbg, "xxxx");

	consume_request(dbg);
}

void dbg_reply_get_reg(struct dbg_context* dbg, long value)
{
	assert(DREQ_GET_REG == dbg->req.type);

	write_hex_packet(dbg, value);

	consume_request(dbg);
}

void dbg_reply_get_stop_reason(struct dbg_context* dbg/*, TODO */)
{
	assert(DREQ_GET_STOP_REASON == dbg->req.type);
	debug("Replying with stop reason TODO");

	/* XXX FIXME TODO */
	write_packet(dbg, "S00");

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
