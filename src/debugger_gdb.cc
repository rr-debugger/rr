/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

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
#include <inttypes.h>
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
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "StringVectorToCharArray.h"

static const char INTERRUPT_CHAR = '\x03';

#ifdef DEBUGTAG
#define UNHANDLED_REQ() FATAL()
#else
#define UNHANDLED_REQ()                                                        \
  write_packet("");                                                            \
  LOG(info)
#endif

using namespace std;

const GdbThreadId GdbThreadId::ANY = { 0, 0 };
const GdbThreadId GdbThreadId::ALL = { -1, -1 };

static bool request_needs_immediate_response(const GdbRequest* req) {
  switch (req->type) {
    case DREQ_NONE:
    case DREQ_CONTINUE:
    case DREQ_STEP:
      return false;
    default:
      return true;
  }
}

GdbContext::GdbContext(pid_t tgid)
    : tgid(tgid), no_ack(false), inlen(0), outlen(0) {
  memset(&req, 0, sizeof(req));
}

static ScopedFd open_socket(const char* address, unsigned short* port,
                            GdbContext::ProbePort probe) {
  ScopedFd listen_fd(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (!listen_fd.is_open()) {
    FATAL() << "Couldn't create socket";
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(address);
  int reuseaddr = 1;
  int ret = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                       sizeof(reuseaddr));
  if (ret < 0) {
    FATAL() << "Couldn't set SO_REUSEADDR";
  }

  do {
    addr.sin_port = htons(*port);
    ret = ::bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret && (EADDRINUSE == errno || EACCES == errno || EINVAL == errno)) {
      continue;
    }
    if (ret) {
      FATAL() << "Couldn't bind to port " << *port;
    }

    ret = listen(listen_fd, 1 /*backlogged connection*/);
    if (ret && EADDRINUSE == errno) {
      continue;
    }
    if (ret) {
      FATAL() << "Couldn't listen on port " << *port;
    }
    break;
  } while (++(*port), probe == GdbContext::PROBE_PORT);
  return listen_fd;
}

void GdbContext::await_debugger(ScopedFd& listen_fd) {
  struct sockaddr_in client_addr;
  socklen_t len = sizeof(client_addr);

  sock_fd = ScopedFd(
      accept4(listen_fd, (struct sockaddr*)&client_addr, &len, SOCK_NONBLOCK));
  // We might restart this debugging session, so don't set the
  // socket fd CLOEXEC.
}

static const char connection_addr[] = "127.0.0.1";

struct DebuggerParams {
  char exe_image[PATH_MAX];
  short port;
};

unique_ptr<GdbContext> GdbContext::await_client_connection(
    unsigned short desired_port, ProbePort probe, pid_t tgid,
    const string* exe_image, ScopedFd* client_params_fd) {
  auto dbg = unique_ptr<GdbContext>(new GdbContext(tgid));
  unsigned short port = desired_port;
  ScopedFd listen_fd = open_socket(connection_addr, &port, probe);
  if (exe_image) {
    DebuggerParams params;
    memset(&params, 0, sizeof(params));
    strncpy(params.exe_image, exe_image->c_str(), sizeof(params.exe_image) - 1);
    params.port = port;

    ssize_t nwritten = write(*client_params_fd, &params, sizeof(params));
    assert(nwritten == sizeof(params));
  } else {
    fprintf(stderr, "Attach to the rr debug server with this command:\n"
                    "  target remote :%d\n",
            port);
  }
  LOG(debug) << "limiting debugger traffic to tgid " << tgid;
  dbg->await_debugger(listen_fd);
  return dbg;
}

static string create_gdb_command_file(const char* macros) {
  char tmp[] = "/tmp/rr-gdb-commands-XXXXXX";
  // This fd is just leaked. That's fine since we only call this once
  // per rr invocation at the moment.
  int fd = mkstemp(tmp);
  unlink(tmp);

  ssize_t len = strlen(macros);
  int written = write(fd, macros, len);
  if (written != len) {
    FATAL() << "Failed to write gdb command file";
  }

  stringstream procfile;
  procfile << "/proc/" << getpid() << "/fd/" << fd;
  return procfile.str();
}

void GdbContext::launch_gdb(ScopedFd& params_pipe_fd, const char* macros) {
  DebuggerParams params;
  ssize_t nread = read(params_pipe_fd, &params, sizeof(params));
  if (nread == 0) {
    // pipe was closed. Probably rr failed/died.
    return;
  }
  assert(nread == sizeof(params));

  stringstream attach_cmd;
  attach_cmd << "target extended-remote " << connection_addr << ":"
             << params.port;
  LOG(debug) << "launching gdb with command '" << attach_cmd.str() << "'";

  vector<string> args;
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
  // theoretically unbounded.  Timing out on vRun is
  // technically a gdb bug, but because the rr replay and
  // the gdb reload models don't quite match up, we'll
  // work around it on the rr side by disabling the
  // remote-reply timeout.
  args.push_back("-l");
  args.push_back("-1");
  args.push_back(params.exe_image);
  const string& gdb_command_file_path = Flags::get().gdb_command_file_path;
  if (gdb_command_file_path.length() > 0) {
    args.push_back("-x");
    args.push_back(gdb_command_file_path);
  }
  args.push_back("-l");
  args.push_back("-1");
  if (macros) {
    string gdb_command_file = create_gdb_command_file(macros);
    args.push_back("-x");
    args.push_back(gdb_command_file);
  }
  args.push_back("-ex");
  args.push_back(attach_cmd.str());

  StringVectorToCharArray c_args(args);
  execvp("gdb", c_args.get());
  FATAL() << "Failed to exec gdb.";
}

/**
 * Poll for data to or from gdb, waiting |timeoutMs|.  0 means "don't
 * wait", and -1 means "wait forever".  Return zero if no data is
 * ready by the end of the timeout, and nonzero if data is ready.
 */
static int poll_socket(const ScopedFd& sock_fd, short events, int timeoutMs) {
  struct pollfd pfd;
  memset(&pfd, 0, sizeof(pfd));
  pfd.fd = sock_fd;
  pfd.events = events;

  int ret = poll(&pfd, 1, timeoutMs);
  if (ret < 0) {
    FATAL() << "Polling gdb socket failed";
  }
  return ret;
}

static int poll_incoming(const ScopedFd& sock_fd, int timeoutMs) {
  return poll_socket(sock_fd, POLLIN /* TODO: |POLLERR */, timeoutMs);
}

static int poll_outgoing(const ScopedFd& sock_fd, int timeoutMs) {
  return poll_socket(sock_fd, POLLOUT /* TODO: |POLLERR */, timeoutMs);
}

/**
 * read() incoming data exactly one time, successfully.  May block.
 */
void GdbContext::read_data_once() {
  ssize_t nread;
  /* Wait until there's data, instead of busy-looping on
   * EAGAIN. */
  poll_incoming(sock_fd, -1 /* wait forever */);
  nread = read(sock_fd, inbuf + inlen, sizeof(inbuf) - inlen);
  if (0 == nread) {
    LOG(info) << "(gdb closed debugging socket, exiting)";
    exit(0);
  }
  if (nread <= 0) {
    FATAL() << "Error reading from gdb";
  }
  inlen += nread;
  assert("Impl dynamic alloc if this fails (or double inbuf size)" &&
         inlen < int(sizeof(inbuf)));
}

/**
 * Send all pending output to gdb.  May block.
 */
void GdbContext::write_flush() {
  ssize_t write_index = 0;

#ifdef DEBUGTAG
  outbuf[outlen] = '\0';
  LOG(debug) << "write_flush: '" << outbuf << "'";
#endif
  while (write_index < outlen) {
    ssize_t nwritten;

    poll_outgoing(sock_fd, -1 /*wait forever*/);
    nwritten = write(sock_fd, outbuf + write_index, outlen - write_index);
    if (nwritten < 0) {
      FATAL() << "Error writing to gdb";
    }
    write_index += nwritten;
  }
  outlen = 0;
}

void GdbContext::write_data_raw(const uint8_t* data, ssize_t len) {
  assert("Impl dynamic alloc if this fails (or double outbuf size)" &&
         (outlen + len) < int(sizeof(inbuf)));

  memcpy(outbuf + outlen, data, len);
  outlen += len;
}

void GdbContext::write_hex(unsigned long hex) {
  char buf[32];
  size_t len;

  len = snprintf(buf, sizeof(buf) - 1, "%02lx", hex);
  write_data_raw((uint8_t*)buf, len);
}

void GdbContext::write_packet_bytes(const uint8_t* data, size_t num_bytes) {
  uint8_t checksum;
  size_t i;

  write_data_raw((uint8_t*)"$", 1);
  for (i = 0, checksum = 0; i < num_bytes; ++i) {
    checksum += data[i];
  }
  write_data_raw((uint8_t*)data, num_bytes);
  write_data_raw((uint8_t*)"#", 1);
  write_hex(checksum);
}

void GdbContext::write_packet(const char* data) {
  return write_packet_bytes((const uint8_t*)data, strlen(data));
}

void GdbContext::write_binary_packet(const char* pfx, const uint8_t* data,
                                     ssize_t num_bytes) {
  ssize_t pfx_num_chars = strlen(pfx);
  uint8_t buf[2 * num_bytes + pfx_num_chars];
  ssize_t buf_num_bytes = 0;
  int i;

  strncpy((char*)buf, pfx, sizeof(buf) - 1);
  buf_num_bytes += pfx_num_chars;

  for (i = 0; i < num_bytes; ++i) {
    uint8_t b = data[i];

    if (buf_num_bytes + 2 > ssize_t(sizeof(buf))) {
      break;
    }
    switch (b) {
      case '#':
      case '$':
      case '}':
      case '*':
        buf[buf_num_bytes++] = '}';
        buf[buf_num_bytes++] = b ^ 0x20;
        break;
      default:
        buf[buf_num_bytes++] = b;
        break;
    }
  }

  LOG(debug) << " ***** NOTE: writing binary data, upcoming debug output may "
                "be truncated";
  return write_packet_bytes(buf, buf_num_bytes);
}

void GdbContext::write_hex_bytes_packet(const uint8_t* bytes, size_t len) {
  if (0 == len) {
    write_packet("");
    return;
  }

  char buf[2 * len + 1];
  for (size_t i = 0; i < len; ++i) {
    unsigned long b = bytes[i];
    snprintf(&buf[2 * i], 3, "%02lx", b);
  }
  write_packet(buf);
}

/**
 * Return a string decoded from |encoded|, which contains ASCII
 * characters encoded as pairs of hex digits, f.e. '1' -> "31".
 */
static string decode_ascii_encoded_hex_str(const char* encoded) {
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
int GdbContext::skip_to_packet_start() {
  uint8_t* p = nullptr;
  int i;

  /* XXX we want memcspn() here ... */
  for (i = 0; i < inlen; ++i) {
    if (inbuf[i] == '$' || inbuf[i] == INTERRUPT_CHAR) {
      p = &inbuf[i];
      break;
    }
  }

  if (!p) {
    /* Discard all read bytes, which we don't care
     * about. */
    inlen = 0;
    return 1;
  }
  /* Discard bytes up to start-of-packet. */
  memmove(inbuf, p, inlen - (p - inbuf));
  inlen -= (p - inbuf);

  assert(1 <= inlen);
  assert('$' == inbuf[0] || INTERRUPT_CHAR == inbuf[0]);
  return 0;
}

/**
 * Return zero if there's a new packet to be read/process (whether
 * incomplete or not), and nonzero if there isn't one.
 */
int GdbContext::sniff_packet() {
  if (0 == skip_to_packet_start()) {
    /* We've already seen a (possibly partial) packet. */
    return 0;
  }
  assert(0 == inlen);
  return !poll_incoming(sock_fd, 0 /*don't wait*/);
}

/**
 * Block until the sequence of bytes
 *
 *    "[^$]*\$[^#]*#.*"
 *
 * has been read from the client fd.  This is one (or more) gdb
 * packet(s).
 */
void GdbContext::read_packet() {
  uint8_t* p;
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
  while (skip_to_packet_start()) {
    read_data_once();
  }

  if (inbuf[0] == INTERRUPT_CHAR) {
    /* Interrupts are kind of an ugly duckling in the gdb
     * protocol ... */
    packetend = 1;
    return;
  }

  /* Read until we see end-of-packet. */
  for (checkedlen = 0; !(p = (uint8_t*)memchr(inbuf + checkedlen, '#', inlen));
       checkedlen = inlen) {
    read_data_once();
  }
  packetend = (p - inbuf);
  /* NB: we're ignoring the gdb packet checksums here too.  If
   * gdb is corrupted enough to garble a checksum over TCP, it's
   * not really clear why asking for the packet again might make
   * the bug go away. */
  assert('$' == inbuf[0] && packetend < inlen);

  /* Acknowledge receipt of the packet. */
  if (!no_ack) {
    write_data_raw((uint8_t*)"+", 1);
    write_flush();
  }
}

static void read_binary_data(const uint8_t* payload, ssize_t data_len,
                             uint8_t* data) {
  ssize_t payload_idx = 0;
  for (ssize_t i = 0; i < data_len; ++i) {
    uint8_t b = payload[payload_idx++];
    if ('}' == b) {
      b = 0x20 ^ payload[payload_idx++];
    }
    data[i] = b;
  }
}

/**
 * Parse and return a gdb thread-id from |str|.  |endptr| points to
 * the character just after the last character in the thread-id.  It
 * may be nullptr.
 */
static GdbThreadId parse_threadid(const char* str, char** endptr) {
  GdbThreadId t;
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

int GdbContext::xfer(const char* name, char* args) {
  LOG(debug) << "gdb asks us to transfer " << name << "(" << args << ")";

  if (!strcmp(name, "auxv")) {
    assert(!strncmp(args, "read::", sizeof("read::") - 1));

    req.type = DREQ_GET_AUXV;
    req.target = query_thread;
    return 1;
  }
  if (name == strstr(name, "siginfo")) {
    if (args == strstr(args, "read")) {
      req.type = DREQ_READ_SIGINFO;
      args += strlen("read");
      assert(':' == *args++);
      assert(':' == *args++);

      req.mem.addr = strtoul(args, &args, 16);
      assert(',' == *args++);

      req.mem.len = strtoul(args, &args, 16);
      assert('\0' == *args);

      return 1;
    }
    if (args == strstr(args, "write")) {
      req.type = DREQ_WRITE_SIGINFO;
      return 1;
    }
    UNHANDLED_REQ() << "Unhandled 'siginfo' request: " << args;
    return 0;
  }

  UNHANDLED_REQ() << "Unhandled gdb xfer request: " << name << "(" << args
                  << ")";
  return 0;
}

/**
 * Format |value| into |buf| in the manner gdb expects.  |buf| must
 * point at a buffer with at least |1 + 2*DBG_MAX_REG_SIZE| bytes
 * available.  Fewer bytes than that may be written, but |buf| is
 * guaranteed to be null-terminated.
 */
static size_t print_reg_value(const GdbRegisterValue& reg, char* buf) {
  assert(reg.size <= GdbRegisterValue::MAX_SIZE);
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

/**
 * Read the encoded register value in |strp| into |reg|.  |strp| may
 * be mutated.
 */
static void read_reg_value(char** strp, GdbRegisterValue* reg) {
  char* str = *strp;

  if ('x' == str[0]) {
    reg->defined = false;
    reg->size = 0;
    return;
  }

  reg->defined = true;
  reg->size = strlen(str) / 2;
  for (size_t i = 0; i < reg->size; ++i) {
    char tmp = str[2];
    str[2] = '\0';

    reg->value[i] = strtoul(str, &str, 16);
    assert('\0' == *str);

    str[0] = tmp;
  }

  *strp = str;
}

int GdbContext::query(char* payload) {
  const char* name;
  char* args;

  args = strchr(payload, ':');
  if (args) {
    *args++ = '\0';
  }
  name = payload;

  if (!strcmp(name, "C")) {
    LOG(debug) << "gdb requests current thread ID";
    req.type = DREQ_GET_CURRENT_THREAD;
    return 1;
  }
  if (!strcmp(name, "Attached")) {
    LOG(debug) << "gdb asks if this is a new or existing process";
    /* Tell gdb this is an existing process; it might be
     * (see emergency_debug()). */
    write_packet("1");
    return 0;
  }
  if (!strcmp(name, "fThreadInfo")) {
    LOG(debug) << "gdb asks for thread list";
    req.type = DREQ_GET_THREAD_LIST;
    return 1;
  }
  if (!strcmp(name, "sThreadInfo")) {
    write_packet("l"); /* "end of list" */
    return 0;
  }
  if (!strcmp(name, "GetTLSAddr")) {
    LOG(debug) << "gdb asks for TLS addr";
    /* TODO */
    write_packet("");
    return 0;
  }
  if (!strcmp(name, "Offsets")) {
    LOG(debug) << "gdb asks for section offsets";
    req.type = DREQ_GET_OFFSETS;
    req.target = query_thread;
    return 1;
  }
  if ('P' == name[0]) {
    /* The docs say not to use this packet ... */
    write_packet("");
    return 0;
  }
  if (!strcmp(name, "Supported")) {
    char supported[1024];

    /* TODO process these */
    LOG(debug) << "gdb supports " << args;

    snprintf(supported, sizeof(supported) - 1,
             "PacketSize=%zd;QStartNoAckMode+;qXfer:auxv:read+"
             ";qXfer:siginfo:read+;qXfer:siginfo:write+"
             ";multiprocess+",
             sizeof(outbuf));
    write_packet(supported);
    return 0;
  }
  if (!strcmp(name, "Symbol")) {
    LOG(debug) << "gdb is ready for symbol lookups";
    write_packet("OK");
    return 0;
  }
  if (strstr(name, "ThreadExtraInfo") == name) {
    // ThreadExtraInfo is a special snowflake that
    // delimits its args with ','.
    assert(!args);
    args = payload;
    args = 1 + strchr(args, ',' /*sic*/);

    req.type = DREQ_GET_THREAD_EXTRA_INFO;
    req.target = parse_threadid(args, &args);
    assert('\0' == *args);
    return 1;
  }
  if (!strcmp(name, "TStatus")) {
    LOG(debug) << "gdb asks for trace status";
    /* XXX from the docs, it appears that we should reply
     * with "T0" here.  But if we do, gdb keeps bothering
     * us with trace queries.  So pretend we don't know
     * what it's talking about. */
    write_packet("");
    return 0;
  }
  if (!strcmp(name, "Xfer")) {
    name = args;
    args = strchr(args, ':');
    if (args) {
      *args++ = '\0';
    }
    return xfer(name, args);
  }

  UNHANDLED_REQ() << "Unhandled gdb query: q" << name;
  return 0;
}

int GdbContext::set_var(char* payload) {
  const char* name;
  char* args;

  args = strchr(payload, ':');
  if (args) {
    *args++ = '\0';
  }
  name = payload;

  if (!strcmp(name, "StartNoAckMode")) {
    write_packet("OK");
    no_ack = true;
    return 0;
  }

  UNHANDLED_REQ() << "Unhandled gdb set: Q" << name;
  return 0;
}

void GdbContext::consume_request() {
  memset(&req, 0, sizeof(req));
  write_flush();
}

int GdbContext::process_vpacket(char* payload) {
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
        LOG(warn) << "Ignoring request to deliver signal (" << args << ")";
      /* fall through */
      case 'c':
        req.type = DREQ_CONTINUE;
        req.target = resume_thread;
        return 1;
      case 'S':
        LOG(warn) << "Ignoring request to deliver signal (" << args << ")";
        args = strchr(args, ':');
        if (args) {
          ++args;
        }
      /* fall through */
      case 's':
        req.type = DREQ_STEP;
        if (args) {
          req.target = parse_threadid(args, &args);
          // If we get a step request for a
          // thread, we just assume that
          // requests for all other threads are
          // 'c' (if any).  That's all we can
          // support anyway.
          assert('\0' == *args || args == strstr(args, ";c"));
        } else {
          req.target = resume_thread;
        }
        return 1;
      default:
        UNHANDLED_REQ() << "Unhandled vCont command " << cmd << "(" << args
                        << ")";
        return 0;
    }
  }

  if (!strcmp("Cont?", name)) {
    LOG(debug) << "gdb queries which continue commands we support";
    write_packet("vCont;c;C;s;S;t;");
    return 0;
  }

  if (!strcmp("Kill", name)) {
    // We can't kill tracees or replay can diverge.  We
    // assume that this kill request is being made because
    // a "vRun" restart is coming right up.  We know how
    // to implement vRun, so we'll ignore this one.
    LOG(debug) << "gdb asks us to kill tracee(s); ignoring";
    write_packet("OK");
    return 0;
  }

  if (!strcmp("Run", name)) {
    req.type = DREQ_RESTART;
    req.restart.type = RESTART_FROM_PREVIOUS;

    if ('\0' == *args) {
      return 1;
    }
    const char* filename = args;
    *args++ = '\0';
    if (strlen(filename)) {
      FATAL() << "gdb wants us to run the exe image `" << filename
              << "', but we don't support that.";
    }
    if (strchr(args, ';')) {
      FATAL() << "Extra arguments '" << args
              << "' passed to run. We don't support that.";
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
        req.restart.type = RESTART_FROM_CHECKPOINT;
        req.restart.param = param;
        LOG(debug) << "next replayer restarting from checkpoint "
                   << req.restart.param;
      } else {
        req.restart.type = RESTART_FROM_EVENT;
        req.restart.param = strtol(event_str.c_str(), &endp, 0);
        LOG(debug) << "next replayer advancing to event " << req.restart.param;
      }
      if (!endp || *endp != '\0') {
        FATAL() << "Couldn't parse event string `" << event_str << "'";
      }
    }
    return 1;
  }

  UNHANDLED_REQ() << "Unhandled gdb vpacket: v" << name;
  return 0;
}

int GdbContext::process_packet() {
  char request;
  char* payload = nullptr;
  int ret;

  assert(INTERRUPT_CHAR == inbuf[0] ||
         ('$' == inbuf[0] &&
          (((uint8_t*)memchr(inbuf, '#', inlen) - inbuf) == packetend)));

  if (INTERRUPT_CHAR == inbuf[0]) {
    request = INTERRUPT_CHAR;
  } else {
    request = inbuf[1];
    payload = (char*)&inbuf[2];
    inbuf[packetend] = '\0';
  }

  LOG(debug) << "raw request " << request << "(" << payload << ")";

  switch (request) {
    case INTERRUPT_CHAR:
      LOG(debug) << "gdb requests interrupt";
      req.type = DREQ_INTERRUPT;
      ret = 1;
      break;
    case 'D':
      LOG(debug) << "gdb is detaching from us";
      req.type = DREQ_DETACH;
      ret = 1;
      break;
    case 'g':
      req.type = DREQ_GET_REGS;
      req.target = query_thread;
      LOG(debug) << "gdb requests registers";
      ret = 1;
      break;
    case 'G':
      /* XXX we can't let gdb spray registers in general,
       * because it may cause replay to diverge.  But some
       * writes may be OK.  Let's see how far we can get
       * with ignoring these requests. */
      write_packet("");
      ret = 0;
      break;
    case 'H':
      if ('c' == *payload++) {
        req.type = DREQ_SET_CONTINUE_THREAD;
      } else {
        req.type = DREQ_SET_QUERY_THREAD;
      }
      req.target = parse_threadid(payload, &payload);
      assert('\0' == *payload);

      LOG(debug) << "gdb selecting " << req.target;

      ret = 1;
      break;
    case 'k':
      LOG(info) << "gdb requests kill, exiting";
      write_packet("OK");
      exit(0);
    case 'm':
      req.type = DREQ_GET_MEM;
      req.target = query_thread;
      req.mem.addr = strtoul(payload, &payload, 16);
      ++payload;
      req.mem.len = strtoul(payload, &payload, 16);
      assert('\0' == *payload);

      LOG(debug) << "gdb requests memory (addr=" << req.mem.addr
                 << ", len=" << req.mem.len << ")";

      ret = 1;
      break;
    case 'M':
      /* We can't allow the debugger to write arbitrary data
       * to memory, or the replay may diverge. */
      // TODO: parse this packet in case some oddball gdb
      // decides to send it instead of 'X'
      write_packet("");
      ret = 0;
      break;
    case 'p':
      req.type = DREQ_GET_REG;
      req.target = query_thread;
      req.reg.name = GDBRegister(strtoul(payload, &payload, 16));
      assert('\0' == *payload);
      LOG(debug) << "gdb requests register value (" << req.reg.name << ")";
      ret = 1;
      break;
    case 'P':
      req.type = DREQ_SET_REG;
      req.target = query_thread;
      req.reg.name = GDBRegister(strtoul(payload, &payload, 16));
      assert('=' == *payload++);

      read_reg_value(&payload, &req.reg);

      assert('\0' == *payload);

      ret = 1;
      break;
    case 'q':
      ret = query(payload);
      break;
    case 'Q':
      ret = set_var(payload);
      break;
    case 'T':
      req.type = DREQ_GET_IS_THREAD_ALIVE;
      req.target = parse_threadid(payload, &payload);
      assert('\0' == *payload);
      LOG(debug) << "gdb wants to know if " << req.target << " is alive";
      ret = 1;
      break;
    case 'v':
      ret = process_vpacket(payload);
      break;
    case 'X': {
      req.type = DREQ_SET_MEM;
      req.target = query_thread;
      req.mem.addr = strtoul(payload, &payload, 16);
      ++payload;
      req.mem.len = strtoul(payload, &payload, 16);
      ++payload;
      // This is freed by reply_set_mem().
      req.mem.data = (uint8_t*)malloc(req.mem.len);
      // TODO: verify that the length of |payload| is as
      // expected in the presence of escaped data.  Right
      // now this call is potential-buffer-overrun-city.
      read_binary_data((const uint8_t*)payload, req.mem.len,
                       (uint8_t*)req.mem.data);

      LOG(debug) << "gdb setting memory (addr=" << req.mem.addr
                 << ", len=" << req.mem.len << ")";

      ret = 1;
      break;
    }
    case 'z':
    case 'Z': {
      int type = strtol(payload, &payload, 16);
      assert(',' == *payload++);
      if (!(0 <= type && type <= 4)) {
        LOG(warn) << "Unknown watch type " << type;
        write_packet("");
        ret = 0;
        break;
      }
      req.type = GdbRequestType(
          type + (request == 'Z' ? DREQ_SET_SW_BREAK : DREQ_REMOVE_SW_BREAK));
      req.mem.addr = strtoul(payload, &payload, 16);
      assert(',' == *payload++);
      req.mem.len = strtoul(payload, &payload, 16);
      assert('\0' == *payload);

      LOG(debug) << "gdb requests " << ('Z' == request ? "set" : "remove")
                 << "breakpoint (addr=" << req.mem.addr
                 << ", len=" << req.mem.len << ")";

      ret = 1;
      break;
    }
    case '!':
      LOG(debug) << "gdb requests extended mode";
      write_packet("OK");
      ret = 0;
      break;
    case '?':
      LOG(debug) << "gdb requests stop reason";
      req.type = DREQ_GET_STOP_REASON;
      req.target = query_thread;
      ret = 1;
      break;
    default:
      UNHANDLED_REQ() << "Unhandled gdb request '" << inbuf[1] << "'";
      ret = 0;
  }
  /* Erase the newly processed packet from the input buffer. */
  memmove(inbuf, inbuf + packetend, inlen - packetend);
  inlen = (inlen - packetend);

  /* If we processed the request internally, consume it. */
  if (ret == 0) {
    consume_request();
  }
  return ret;
}

void GdbContext::notify_no_such_thread(const GdbRequest& req) {
  assert(!memcmp(&req, &this->req, sizeof(this->req)));

  /* '10' is the errno ECHILD.  We use it as a magic code to
   * notify the user that the thread that was the target of this
   * request has died, and either gdb didn't notice that, or rr
   * didn't notify gdb.  Either way, the user should restart
   * their debugging session. */
  LOG(error) << "Targeted thread no longer exists; this is the result of "
                "either a gdb or\n"
                "rr bug.  Please restart your debugging session and avoid "
                "doing whatever\n"
                "triggered this bug.";
  write_packet("E10");
  consume_request();
}

void GdbContext::notify_restart() {
  assert(DREQ_RESTART == req.type);

  // These threads may not exist at the first trace-stop after
  // restart.  The gdb client should reset this state, but help
  // it out just in case.
  resume_thread = GdbThreadId::ANY;
  query_thread = GdbThreadId::ANY;

  memset(&req, 0, sizeof(req));
}

GdbRequest GdbContext::get_request() {
  if (DREQ_RESTART == req.type) {
    LOG(debug) << "consuming RESTART request";
    notify_restart();
    // gdb wants to be notified with a stop packet when
    // the process "relaunches".  In rr's case, the
    // traceee may be very far away from process creation,
    // but that's OK.
    req.type = DREQ_GET_STOP_REASON;
    req.target = query_thread;
    return req;
  }

  /* Can't ask for the next request until you've satisfied the
   * current one, for requests that need an immediate
   * response. */
  assert(!request_needs_immediate_response(&req));

  if (sniff_packet() && req.is_resume_request()) {
    /* There's no new request data available and gdb has
     * already asked us to resume.  OK, do that (or keep
     * doing that) now. */
    return req;
  }

  while (1) {
    /* There's either new request data, or we have nothing
     * to do.  Either way, block until we read a complete
     * packet from gdb. */
    read_packet();

    if (process_packet()) {
      /* We couldn't process the packet internally,
       * so the target has to do something. */
      return req;
    }
    /* The packet we got was "internal", gdb details.
     * Nothing for the target to do yet.  Keep waiting. */
  }
}

void GdbContext::notify_exit_code(int code) {
  char buf[64];

  assert(req.is_resume_request() || req.type == DREQ_INTERRUPT);

  snprintf(buf, sizeof(buf) - 1, "W%02x", code);
  write_packet(buf);

  consume_request();
}

void GdbContext::notify_exit_signal(int sig) {
  char buf[64];

  assert(req.is_resume_request() || req.type == DREQ_INTERRUPT);

  snprintf(buf, sizeof(buf) - 1, "X%02x", sig);
  write_packet(buf);

  consume_request();
}

/**
 * Translate linux-x86 |sig| to gdb's internal numbering.  Translation
 * made according to gdb/include/gdb/signals.def.
 */
static int to_gdb_signum(int sig) {
  if (SIGRTMIN <= sig && sig <= SIGRTMAX) {
    /* GDB_SIGNAL_REALTIME_34 is numbered 46, hence this
     * offset. */
    return sig + 12;
  }
  switch (sig) {
    case 0:
      return 0;
    case SIGHUP:
      return 1;
    case SIGINT:
      return 2;
    case SIGQUIT:
      return 3;
    case SIGILL:
      return 4;
    case SIGTRAP:
      return 5;
    case SIGABRT /*case SIGIOT*/:
      return 6;
    case SIGBUS:
      return 10;
    case SIGFPE:
      return 8;
    case SIGKILL:
      return 9;
    case SIGUSR1:
      return 30;
    case SIGSEGV:
      return 11;
    case SIGUSR2:
      return 31;
    case SIGPIPE:
      return 13;
    case SIGALRM:
      return 14;
    case SIGTERM:
      return 15;
    /* gdb hasn't heard of SIGSTKFLT, so this is
     * arbitrarily made up.  SIGDANGER just sounds cool.*/
    case SIGSTKFLT:
      return 38 /*GDB_SIGNAL_DANGER*/;
    /*case SIGCLD*/ case SIGCHLD:
      return 20;
    case SIGCONT:
      return 19;
    case SIGSTOP:
      return 17;
    case SIGTSTP:
      return 18;
    case SIGTTIN:
      return 21;
    case SIGTTOU:
      return 22;
    case SIGURG:
      return 16;
    case SIGXCPU:
      return 24;
    case SIGXFSZ:
      return 25;
    case SIGVTALRM:
      return 26;
    case SIGPROF:
      return 27;
    case SIGWINCH:
      return 28;
    /*case SIGPOLL*/ case SIGIO:
      return 23;
    case SIGPWR:
      return 32;
    case SIGSYS:
      return 12;
    default:
      FATAL() << "Unknown signal " << sig;
      return -1; // not reached
  }
}

void GdbContext::send_stop_reply_packet(GdbThreadId thread, int sig,
                                        uintptr_t watch_addr) {
  if (sig < 0) {
    write_packet("E01");
    return;
  }
  char watch[1024];
  if (watch_addr) {
    snprintf(watch, sizeof(watch) - 1, "watch:%" PRIxPTR ";", watch_addr);
  } else {
    watch[0] = '\0';
  }
  char buf[PATH_MAX];
  snprintf(buf, sizeof(buf) - 1, "T%02xthread:p%02x.%02x;%s",
           to_gdb_signum(sig), thread.pid, thread.tid, watch);
  write_packet(buf);
}

void GdbContext::notify_stop(GdbThreadId thread, int sig,
                             uintptr_t watch_addr) {
  assert(req.is_resume_request() || req.type == DREQ_INTERRUPT);

  if (tgid != thread.pid) {
    LOG(debug) << "ignoring stop of " << thread
               << " because we're debugging tgid " << tgid;
    // Re-use the existing continue request to advance to
    // the next stop we're willing to tell gdb about.
    return;
  }
  send_stop_reply_packet(thread, sig, watch_addr);

  // This isn't documented in the gdb remote protocol, but if we
  // don't do this, gdb will sometimes continue to send requests
  // for the previously-stopped thread when it obviously intends
  // to making requests about the stopped thread.
  LOG(debug) << "forcing query/resume thread to " << thread;
  query_thread = thread;
  resume_thread = thread;

  consume_request();
}

void GdbContext::notify_restart_failed() {
  assert(DREQ_RESTART == req.type);

  // TODO: it's not known by this author whether gdb knows how
  // to recover from a failed "run" request.
  write_packet("E01");

  consume_request();
}

void GdbContext::reply_get_current_thread(GdbThreadId thread) {
  assert(DREQ_GET_CURRENT_THREAD == req.type);

  char buf[1024];
  snprintf(buf, sizeof(buf), "QCp%02x.%02x", thread.pid, thread.tid);
  write_packet(buf);

  consume_request();
}

void GdbContext::reply_get_auxv(const vector<GdbAuxvPair>& auxv) {
  assert(DREQ_GET_AUXV == req.type);

  if (!auxv.empty()) {
    write_binary_packet("l", (uint8_t*)auxv.data(),
                        auxv.size() * sizeof(auxv[0]));
  } else {
    write_packet("E01");
  }

  consume_request();
}

void GdbContext::reply_get_is_thread_alive(bool alive) {
  assert(DREQ_GET_IS_THREAD_ALIVE == req.type);

  write_packet(alive ? "OK" : "E01");

  consume_request();
}

void GdbContext::reply_get_thread_extra_info(const string& info) {
  assert(DREQ_GET_THREAD_EXTRA_INFO == req.type);

  LOG(debug) << "thread extra info: '" << info.c_str() << "'";
  // XXX docs don't say whether we should send the null
  // terminator.  See what happens.
  write_hex_bytes_packet((const uint8_t*)info.c_str(), 1 + info.length());

  consume_request();
}

void GdbContext::reply_select_thread(bool ok) {
  assert(DREQ_SET_CONTINUE_THREAD == req.type ||
         DREQ_SET_QUERY_THREAD == req.type);

  if (ok && DREQ_SET_CONTINUE_THREAD == req.type) {
    resume_thread = req.target;
  } else if (ok && DREQ_SET_QUERY_THREAD == req.type) {
    query_thread = req.target;
  }
  write_packet(ok ? "OK" : "E01");

  consume_request();
}

void GdbContext::reply_get_mem(const vector<uint8_t>& mem) {
  assert(DREQ_GET_MEM == req.type);
  assert(mem.size() <= req.mem.len);

  write_hex_bytes_packet(mem.data(), mem.size());

  consume_request();
}

void GdbContext::reply_set_mem(bool ok) {
  assert(DREQ_SET_MEM == req.type);

  write_packet(ok ? "OK" : "E01");
  free((uint8_t*)req.mem.data);

  consume_request();
}

void GdbContext::reply_get_offsets(/* TODO */) {
  assert(DREQ_GET_OFFSETS == req.type);

  /* XXX FIXME TODO */
  write_packet("");

  consume_request();
}

void GdbContext::reply_get_reg(const GdbRegisterValue& reg) {
  char buf[2 * GdbRegisterValue::MAX_SIZE + 1];

  assert(DREQ_GET_REG == req.type);

  print_reg_value(reg, buf);
  write_packet(buf);

  consume_request();
}

void GdbContext::reply_get_regs(const GdbRegisterFile& file) {
  size_t n_regs = file.total_registers();
  char buf[n_regs * 2 * GdbRegisterValue::MAX_SIZE + 1];

  assert(DREQ_GET_REGS == req.type);

  size_t offset = 0;
  for (auto it = file.regs.begin(), end = file.regs.end(); it != end; ++it) {
    offset += print_reg_value(*it, &buf[offset]);
  }
  write_packet(buf);

  consume_request();
}

void GdbContext::reply_set_reg(bool ok) {
  assert(DREQ_SET_REG == req.type);

  // TODO: what happens if we're forced to reply to a
  // set-register request with |ok = false|, leading us to
  // pretend not to understand the packet?  If, later, an
  // experimental session needs the set-register request will it
  // not be sent?
  //
  // We can't reply with an error packet here because gdb thinks
  // that failed set-register requests are catastrophic.
  write_packet(ok ? "OK" : "");

  consume_request();
}

void GdbContext::reply_get_stop_reason(GdbThreadId which, int sig) {
  assert(DREQ_GET_STOP_REASON == req.type);

  send_stop_reply_packet(which, sig);

  consume_request();
}

void GdbContext::reply_get_thread_list(const vector<GdbThreadId>& threads) {
  assert(DREQ_GET_THREAD_LIST == req.type);

  if (threads.empty()) {
    write_packet("l");
  } else {
    ssize_t maxlen =
        1 /*m char*/ +
        threads.size() * (1 /*p*/ + 2 * sizeof(threads[0]) + 1 /*,*/) +
        1 /*\0*/;
    char* str = (char*)malloc(maxlen);
    int offset = 0;

    str[offset++] = 'm';
    for (size_t i = 0; i < threads.size(); ++i) {
      const GdbThreadId& t = threads[i];
      if (tgid != t.pid) {
        continue;
      }
      offset +=
          snprintf(&str[offset], maxlen - offset, "p%02x.%02x,", t.pid, t.tid);
    }
    /* Overwrite the trailing ',' */
    str[offset - 1] = '\0';

    write_packet(str);
    free(str);
  }

  consume_request();
}

void GdbContext::reply_watchpoint_request(bool ok) {
  assert(DREQ_WATCH_FIRST <= req.type && req.type <= DREQ_WATCH_LAST);

  write_packet(ok ? "OK" : "E01");

  consume_request();
}

void GdbContext::reply_detach() {
  assert(DREQ_DETACH <= req.type);

  write_packet("OK");

  consume_request();
}

void GdbContext::reply_read_siginfo(const uint8_t* si_bytes,
                                    ssize_t num_bytes) {
  assert(DREQ_READ_SIGINFO == req.type);

  if (num_bytes < 0) {
    write_packet("E01");
  } else {
    write_binary_packet("l", si_bytes, num_bytes);
  }

  consume_request();
}

void GdbContext::reply_write_siginfo(/* TODO*/) {
  assert(DREQ_WRITE_SIGINFO == req.type);

  write_packet("E01");

  consume_request();
}
