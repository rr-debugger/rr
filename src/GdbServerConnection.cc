/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#define REVERSE_EXECUTION

/**
 * Much of this implementation is based on the documentation at
 *
 * http://sourceware.org/gdb/onlinedocs/gdb/Packets.html
 * See also
 * https://github.com/llvm/llvm-project/blob/main/lldb/docs/lldb-gdb-remote.txt
 */

#include "GdbServerConnection.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <iomanip>
#include <sstream>
#include <vector>

#include "DebuggerExtensionCommandHandler.h"
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "core.h"
#include "log.h"

using namespace std;

namespace rr {

static const char INTERRUPT_CHAR = '\x03';

#define UNHANDLED_REQ()                                                        \
  write_packet("");                                                            \
  LOG(info)

const GdbThreadId GdbThreadId::ANY(0, 0);
const GdbThreadId GdbThreadId::ALL(-1, -1);

#ifdef DEBUG
static bool request_needs_immediate_response(const GdbRequest* req) {
  switch (req->type) {
    case DREQ_NONE:
    case DREQ_CONT:
      return false;
    default:
      return true;
  }
}
#endif

GdbServerConnection::GdbServerConnection(ThreadGroupUid tguid, const Features& features)
    : tguid(tguid),
      cpu_features_(0),
      no_ack(false),
      features_(features),
      connection_alive_(true),
      multiprocess_supported_(false),
      hwbreak_supported_(false),
      swbreak_supported_(false),
      list_threads_in_stop_reply_(false) {
#ifndef REVERSE_EXECUTION
  features_.reverse_execution = false;
#endif
}

static uint32_t get_cpu_features(SupportedArch arch) {
  uint32_t cpu_features;
  switch (arch) {
    case x86:
    case x86_64: {
      cpu_features = arch == x86_64 ? GdbServerConnection::CPU_X86_64 : 0;
      unsigned int AVX_cpuid_flags = AVX_FEATURE_FLAG | OSXSAVE_FEATURE_FLAG;
      auto cpuid_data = cpuid(CPUID_GETEXTENDEDFEATURES, 0);
      if ((cpuid_data.ecx & PKU_FEATURE_FLAG) == PKU_FEATURE_FLAG) {
        // PKU (Skylake) implies AVX (Sandy Bridge).
        cpu_features |= GdbServerConnection::CPU_AVX | GdbServerConnection::CPU_AVX512 | GdbServerConnection::CPU_PKU;
        break;
      }

      if((cpuid_data.ebx & AVX_512_FOUNDATION_FLAG) == AVX_512_FOUNDATION_FLAG) {
        cpu_features |= GdbServerConnection::CPU_AVX512 | GdbServerConnection::CPU_AVX;
      }

      cpuid_data = cpuid(CPUID_GETFEATURES, 0);
      // We're assuming here that AVX support on the system making the recording
      // is the same as the AVX support during replay. But if that's not true,
      // rr is totally broken anyway.
      if ((cpuid_data.ecx & AVX_cpuid_flags) == AVX_cpuid_flags) {
        cpu_features |= GdbServerConnection::CPU_AVX;
      }
      break;
    }
    case aarch64:
      cpu_features = GdbServerConnection::CPU_AARCH64;
      break;
    default:
      FATAL() << "Unknown architecture";
      return 0;
  }

  return cpu_features;
}

unique_ptr<GdbServerConnection> GdbServerConnection::await_connection(
    Task* t, ScopedFd& listen_fd, const GdbServerConnection::Features& features) {
  auto dbg = unique_ptr<GdbServerConnection>(
    new GdbServerConnection(t->thread_group()->tguid(), features));
  dbg->set_cpu_features(get_cpu_features(t->arch()));
  dbg->await_debugger(listen_fd);
  return dbg;
}

void GdbServerConnection::await_debugger(ScopedFd& listen_fd) {
  sock_fd = ScopedFd(accept(listen_fd, nullptr, nullptr));
  // We might restart this debugging session, so don't set the
  // socket fd CLOEXEC.
}

/**
 * Poll for data to or from gdb, waiting |timeoutMs|.  0 means "don't
 * wait", and -1 means "wait forever".  Return true if data is ready.
 */
static bool poll_socket(const ScopedFd& sock_fd, short events, int timeoutMs) {
  struct pollfd pfd;
  memset(&pfd, 0, sizeof(pfd));
  pfd.fd = sock_fd;
  pfd.events = events;

  int ret = poll(&pfd, 1, timeoutMs);
  if (ret < 0 && errno != EINTR) {
    LOG(info) << "debugger socket has been closed";
  }
  return ret > 0;
}

static bool poll_incoming(const ScopedFd& sock_fd, int timeoutMs) {
  return poll_socket(sock_fd, POLLIN /* TODO: |POLLERR */, timeoutMs);
}

static void poll_outgoing(const ScopedFd& sock_fd, int timeoutMs) {
  poll_socket(sock_fd, POLLOUT /* TODO: |POLLERR */, timeoutMs);
}

/**
 * read() incoming data exactly one time, successfully.  May block.
 */
void GdbServerConnection::read_data_once() {
  ssize_t nread;
  /* Wait until there's data, instead of busy-looping on
   * EAGAIN. */
  poll_incoming(sock_fd, -1 /* wait forever */);
  uint8_t buf[4096];
  nread = read(sock_fd, buf, sizeof(buf));
  if (nread <= 0) {
    LOG(info) << "Could not read data from debugger socket, "
                 "marking connection as closed";
    connection_alive_ = false;
  } else {
    inbuf.insert(inbuf.end(), buf, buf + nread);
  }
}

void GdbServerConnection::write_flush() {
  size_t write_index = 0;

  outbuf.push_back(0);
  LOG(debug) << "write_flush: '" << outbuf.data() << "'";
  outbuf.pop_back();

  while (write_index < outbuf.size()) {
    ssize_t nwritten;

    poll_outgoing(sock_fd, -1 /*wait forever*/);
    nwritten = write(sock_fd, outbuf.data() + write_index,
                     outbuf.size() - write_index);
    if (nwritten < 0) {
      LOG(info) << "Could not write data to debugger socket, "
                   "marking connection as closed";
      connection_alive_ = false;
      outbuf.clear();
      return;
    } else {
      write_index += nwritten;
    }
  }
  outbuf.clear();
}

void GdbServerConnection::write_data_raw(const uint8_t* data, ssize_t len) {
  outbuf.insert(outbuf.end(), data, data + len);
}

void GdbServerConnection::write_hex(unsigned long hex) {
  char buf[32];
  size_t len;

  len = snprintf(buf, sizeof(buf) - 1, "%02lx", hex);
  write_data_raw((uint8_t*)buf, len);
}

void GdbServerConnection::write_packet_bytes(const uint8_t* data, size_t num_bytes) {
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

void GdbServerConnection::write_packet(const char* data) {
  return write_packet_bytes((const uint8_t*)data, strlen(data));
}

void GdbServerConnection::write_binary_packet(const char* pfx, const uint8_t* data,
                                              ssize_t num_bytes) {
  ssize_t pfx_num_chars = strlen(pfx);
  vector<uint8_t> buf;
  buf.resize(2 * num_bytes + pfx_num_chars + 1);
  ssize_t buf_num_bytes = 0;
  int i;

  memcpy((char*)buf.data(), pfx, pfx_num_chars);
  buf_num_bytes += pfx_num_chars;

  for (i = 0; i < num_bytes; ++i) {
    uint8_t b = data[i];

    if (buf_num_bytes + 2 > ssize_t(buf.size())) {
      break;
    }
    switch (b) {
      case '#':
      case '$':
      case '}':
      case '*':
        buf.data()[buf_num_bytes++] = '}';
        buf.data()[buf_num_bytes++] = b ^ 0x20;
        break;
      default:
        buf.data()[buf_num_bytes++] = b;
        break;
    }
  }

  LOG(debug) << " ***** NOTE: writing binary data, upcoming debug output may "
                "be truncated";
  return write_packet_bytes(buf.data(), buf_num_bytes);
}

static string string_to_hex(const string& s) {
  stringstream sstr;
  for (char ch : s) {
    char buf[16];
    sprintf(buf, "%02x", ch);
    sstr << buf;
  }
  return sstr.str();
}

void GdbServerConnection::write_hex_bytes_packet(const char* prefix,
                                           const uint8_t* bytes, size_t len) {
  if (prefix[0] == '\0' && 0 == len) {
    write_packet("");
    return;
  }

  ssize_t pfx_num_chars = strlen(prefix);
  vector<char> buf;
  buf.resize(pfx_num_chars + 2 * len + 1);
  memcpy(buf.data(), prefix, pfx_num_chars);
  for (size_t i = 0; i < len; ++i) {
    unsigned long b = bytes[i];
    snprintf(&buf.data()[pfx_num_chars + 2 * i], 3, "%02lx", b);
  }
  write_packet(buf.data());
}

void GdbServerConnection::write_hex_bytes_packet(const uint8_t* bytes, size_t len) {
  write_hex_bytes_packet("", bytes, len);
}

static void parser_assert(bool cond) {
  if (!cond) {
    fputs("Failed to parse debugger request\n", stderr);
    DEBUG_ASSERT(false);
    exit(2);
  }
}

static string decode_ascii_encoded_hex_str(const char* encoded) {
  ssize_t enc_len = strlen(encoded);
  parser_assert(enc_len % 2 == 0);
  string str;
  for (int i = 0; i < enc_len / 2; ++i) {
    char enc_byte[] = { encoded[2 * i], encoded[2 * i + 1], '\0' };
    char* endp;
    int c = strtol(enc_byte, &endp, 16);
    parser_assert(c < 128);
    str += static_cast<char>(c);
  }
  return str;
}

bool GdbServerConnection::skip_to_packet_start() {
  ssize_t end = -1;
  /* XXX we want memcspn() here ... */
  for (size_t i = 0; i < inbuf.size(); ++i) {
    if (inbuf[i] == '$' || inbuf[i] == INTERRUPT_CHAR) {
      end = i;
      break;
    }
  }

  if (end < 0) {
    /* Discard all read bytes, which we don't care
     * about. */
    inbuf.clear();
    return false;
  }
  /* Discard bytes up to start-of-packet. */
  inbuf.erase(inbuf.begin(), inbuf.begin() + end);

  parser_assert(1 <= inbuf.size());
  parser_assert('$' == inbuf[0] || INTERRUPT_CHAR == inbuf[0]);
  return true;
}

bool GdbServerConnection::sniff_packet() {
  if (skip_to_packet_start()) {
    /* We've already seen a (possibly partial) packet. */
    return true;
  }
  parser_assert(inbuf.empty());
  return poll_incoming(sock_fd, 0 /*don't wait*/);
}

void GdbServerConnection::read_packet() {
  /* Read and discard bytes until we see the start of a
   * packet.
   *
   * NB: we're ignoring "+/-" responses from gdb.  There doesn't
   * seem to be any sane reason why we would send a damaged
   * packet to gdb over TCP, then see a "-" reply from gdb and
   * somehow magically fix our bug that led to the malformed
   * packet in the first place.
   */
  while (!skip_to_packet_start() && connection_alive_) {
    read_data_once();
  }

  if (!connection_alive_) {
    return;
  }

  if (inbuf[0] == INTERRUPT_CHAR) {
    /* Interrupts are kind of an ugly duckling in the gdb
     * protocol ... */
    packetend = 1;
    return;
  }

  /* Read until we see end-of-packet. */
  size_t checkedlen = 0;
  while (true) {
    uint8_t* p = (uint8_t*)memchr(inbuf.data() + checkedlen, '#',
                                  inbuf.size() - checkedlen);
    if (p) {
      packetend = p - inbuf.data();
      break;
    }
    checkedlen = inbuf.size();
    read_data_once();
    if (!connection_alive_) {
      return;
    }
  }

  /* NB: we're ignoring the gdb packet checksums here too.  If
   * gdb is corrupted enough to garble a checksum over TCP, it's
   * not really clear why asking for the packet again might make
   * the bug go away. */
  parser_assert('$' == inbuf[0] && packetend < inbuf.size());

  /* Acknowledge receipt of the packet. */
  if (!no_ack) {
    write_data_raw((uint8_t*)"+", 1);
    write_flush();
  }
}

static void read_hex_data(const char* payload, const char* payload_end,
                          vector<uint8_t>& data) {
  data.clear();
  char buf[3] = { 0, 0, 0 };
  while (payload + 2 <= payload_end) {
    buf[0] = *payload++;
    buf[1] = *payload++;
    char* endp;
    int value = strtol(buf, &endp, 16);
    parser_assert(endp == buf + 2);
    data.push_back(value);
  }
}

static void read_binary_data(const uint8_t* payload, const uint8_t* payload_end,
                             vector<uint8_t>& data) {
  data.clear();
  while (payload < payload_end) {
    uint8_t b = *payload++;
    if ('}' == b) {
      parser_assert(payload < payload_end);
      b = 0x20 ^ *payload++;
    }
    data.push_back(b);
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
  bool multiprocess = false;

  if ('p' == *str) {
    multiprocess = true;
    ++str;
  }
  t.pid = strtol(str, &endp, 16);
  parser_assert(endp);

  /* terminators (single process, no PID or TID, depending on 'p' prefix) */ 
  if (*endp == '\0' || *endp == ';' || *endp == ',') {
    if (multiprocess) {
      t.tid = -1;
    } else {
      t.tid = t.pid;
      t.pid = -1;
    }
  /* multiprocess syntax "<pid>.<tid>" */
  } else if (*endp == '.') {
    str = endp + 1;
    t.tid = strtol(str, &endp, 16);
  }

  parser_assert(*endp == '\0' || *endp == ';' || *endp == ',');

  *endptr = endp;
  return t;
}

void GdbServerConnection::write_xfer_response(const void* data, size_t size,
                                        uint64_t offset, uint64_t len) {
  if (offset > size) {
    write_packet("E01");
    return;
  }
  if (offset == size) {
    write_packet("l");
    return;
  }
  if (offset + len < size) {
    write_binary_packet("m", static_cast<const uint8_t*>(data) + offset, len);
    return;
  }
  write_binary_packet("l", static_cast<const uint8_t*>(data) + offset,
                      size - offset);
}

static string read_target_desc(const char* file_name) {
#ifdef __BIONIC__
  const char* share_path = "usr/share/rr/";
#else
  const char* share_path = "share/rr/";
#endif
  string path = resource_path() + share_path + string(file_name);
  stringstream ss;
  FILE* f = fopen(path.c_str(), "r");
  if (f == NULL) {
      FATAL() << "Failed to load target description file: " << file_name;
  }
  while (true) {
    int ch = getc(f);
    if (ch == EOF) {
      break;
    }
    ss << (char)ch;
  }
  fclose(f);
  return ss.str();
}

static const char* target_description_name(uint32_t cpu_features) {
  // This doesn't scale, but it's what gdb does...
  switch (cpu_features) {
    case 0:
      return "i386-linux.xml";
    case GdbServerConnection::CPU_X86_64:
      return "amd64-linux.xml";
    case GdbServerConnection::CPU_AVX:
      return "i386-avx-linux.xml";
    case GdbServerConnection::CPU_AVX | GdbServerConnection::CPU_AVX512:
      return "i386-avx512-linux.xml";
    case GdbServerConnection::CPU_X86_64 | GdbServerConnection::CPU_AVX:
      return "amd64-avx-linux.xml";
    case GdbServerConnection::CPU_X86_64 | GdbServerConnection::CPU_AVX | GdbServerConnection::CPU_AVX512:
      return "amd64-avx512-linux.xml";
    case GdbServerConnection::CPU_PKU | GdbServerConnection::CPU_AVX | GdbServerConnection::CPU_AVX512:
      return "i386-pkeys-linux.xml";
    case GdbServerConnection::CPU_X86_64 | GdbServerConnection::CPU_PKU | GdbServerConnection::CPU_AVX | GdbServerConnection::CPU_AVX512:
      return "amd64-pkeys-linux.xml";
    case GdbServerConnection::CPU_AARCH64:
      return "aarch64-core.xml";
    default:
      FATAL() << "Unknown features";
      return nullptr;
  }
}

bool GdbServerConnection::xfer(const char* name, char* args) {
  const char* mode = args;
  args = strchr(args, ':');
  parser_assert(args);
  *args++ = '\0';

  if (strcmp(mode, "read") && strcmp(mode, "write")) {
    write_packet("");
    return false;
  }

  const char* annex = args;
  args = strchr(args, ':');
  parser_assert(args);
  *args++ = '\0';

  uint64_t offset = strtoul(args, &args, 16);

  uint64_t len = 0;
  if (!strcmp(mode, "read")) {
    parser_assert(',' == *args++);
    len = strtoul(args, &args, 16);
    parser_assert(!*args);
  } else {
    parser_assert(*args == ':');
    ++args;
  }

  LOG(debug) << "debugger asks us to transfer " << name << " mode=" << mode
             << ", annex=" << annex << ", offset=" << offset << " len=" << len;

  if (!strcmp(name, "auxv")) {
    if (strcmp(annex, "")) {
      write_packet("E00");
      return false;
    }
    if (strcmp(mode, "read")) {
      write_packet("");
      return false;
    }

    req = GdbRequest(DREQ_GET_AUXV);
    req.target = query_thread;
    // XXX handle offset/len here!
    return true;
  }

  if (!strcmp(name, "exec-file")) {
    if (strcmp(mode, "read")) {
      write_packet("");
      return false;
    }

    req = GdbRequest(DREQ_GET_EXEC_FILE);
    req.target.pid = req.target.tid = strtoul(annex, nullptr, 16);
    // XXX handle offset/len here!
    return true;
  }

  if (!strcmp(name, "siginfo")) {
    if (strcmp(annex, "")) {
      write_packet("E00");
      return false;
    }
    if (!strcmp(mode, "read")) {
      req = GdbRequest(DREQ_READ_SIGINFO);
      req.target = query_thread;
      req.mem().addr = offset;
      req.mem().len = len;
      return true;
    }

    req = GdbRequest(DREQ_WRITE_SIGINFO);
    req.target = query_thread;
    return true;
  }

  if (!strcmp(name, "features")) {
    if (strcmp(mode, "read")) {
      write_packet("");
      return false;
    }

    string target_desc =
        read_target_desc((strcmp(annex, "") && strcmp(annex, "target.xml"))
                             ? annex
                             : target_description_name(cpu_features_));
    write_xfer_response(target_desc.c_str(), target_desc.size(), offset, len);
    return false;
  }

  write_packet("");
  return false;
}

/**
 * Format |value| into |buf| in the manner gdb expects.  |buf| must
 * point at a buffer with at least |1 + 2*DBG_MAX_REG_SIZE| bytes
 * available.  Fewer bytes than that may be written, but |buf| is
 * guaranteed to be null-terminated.
 */
static size_t print_reg_value(const GdbServerRegisterValue& reg, char* buf) {
  parser_assert(reg.size <= GdbServerRegisterValue::MAX_SIZE);
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
static void read_reg_value(char** strp, GdbServerRegisterValue* reg) {
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
    parser_assert('\0' == *str);

    str[0] = tmp;
  }

  *strp = str;
}

bool GdbServerConnection::query(char* payload) {
  const char* name;
  char* args;

  args = strchr(payload, ':');
  if (args) {
    *args++ = 0;
  }
  name = payload;

  if (strstr(name, "RRCmd") == name) {
    LOG(debug) << "debugger requests rr cmd: " << name;
    req = GdbRequest(DREQ_RR_CMD);
    parser_assert(args && *args);
    char* endp = strchr(args, ':');
    parser_assert(endp);
    *endp = 0;
    req.rr_cmd_.name = string(args);
    args = endp + 1;
    req.rr_cmd_.target_tid = strtol(args, &endp, 10);
    if (*endp) {
      parser_assert(*endp == ':');
      args = endp + 1;
      while (args) {
        endp = strchr(args, ':');
        if (endp) {
          *endp++ = 0;
        }
        req.rr_cmd_.args.emplace_back(args);
        args = endp;
      }
    }
    return true;
  }
  if (!strcmp(name, "C")) {
    LOG(debug) << "debugger requests current thread ID";
    req = GdbRequest(DREQ_GET_CURRENT_THREAD);
    return true;
  }
  if (!strcmp(name, "Attached")) {
    LOG(debug) << "debugger asks if this is a new or existing process";
    /* Tell gdb this is an existing process; it might be
     * (see emergency_debug()). */
    write_packet("1");
    return false;
  }
  if (!strcmp(name, "fThreadInfo")) {
    LOG(debug) << "debugger asks for thread list";
    req = GdbRequest(DREQ_GET_THREAD_LIST);
    return true;
  }
  if (!strcmp(name, "sThreadInfo")) {
    write_packet("l"); /* "end of list" */
    return false;
  }
  if (!strcmp(name, "GetTLSAddr")) {
    LOG(debug) << "debugger asks for TLS addr";
    req = GdbRequest(DREQ_TLS);
    req.target = parse_threadid(args, &args);
    parser_assert(*args == ',');
    ++args;
    size_t offset = strtoul(args, &args, 16);
    parser_assert(*args == ',');
    ++args;
    remote_ptr<void> load_module = strtoul(args, &args, 16);
    parser_assert(*args == '\0');
    req.tls().offset = offset;
    req.tls().load_module = load_module;
    return true;
  }
  if (!strcmp(name, "Offsets")) {
    LOG(debug) << "debugger asks for section offsets";
    req = GdbRequest(DREQ_GET_OFFSETS);
    req.target = query_thread;
    return true;
  }
  if (!strcmp(name, "Supported")) {
    /* TODO process these */
    LOG(debug) << "debugger supports " << args;

    multiprocess_supported_ = strstr(args, "multiprocess+") != nullptr;
    hwbreak_supported_ = strstr(args, "hwbreak+") != nullptr;
    swbreak_supported_ = strstr(args, "swbreak+") != nullptr;

    stringstream supported;
    // Encourage gdb to use very large packets since we support any packet size
    supported << "PacketSize=1048576"
                 ";QStartNoAckMode+"
                 ";qXfer:features:read+"
                 ";qXfer:auxv:read+"
                 ";qXfer:exec-file:read+"
                 ";qXfer:siginfo:read+"
                 ";qXfer:siginfo:write+"
                 ";multiprocess+"
                 ";hwbreak+"
                 ";swbreak+"
                 ";ConditionalBreakpoints+"
                 ";vContSupported+"
                 ";QPassSignals+";
    if (features().reverse_execution) {
      supported << ";ReverseContinue+"
                   ";ReverseStep+";
    }
    write_packet(supported.str().c_str());
    return false;
  }
  if (!strcmp(name, "Symbol")) {
#ifdef PROC_SERVICE_H
    LOG(debug) << "debugger is ready for symbol lookups";
    const char* colon = strchr(args, ':');
    parser_assert(colon != nullptr);
    req = GdbRequest(DREQ_QSYMBOL);
    if (*args == ':') {
      req.sym().has_address = false;
    } else {
      req.sym().has_address = true;
      req.sym().address = strtoul(args, &args, 16);
    }
    parser_assert(*args == ':');
    ++args;
    req.sym().name = decode_ascii_encoded_hex_str(args);
    return true;
#else
    LOG(debug) << "debugger is ready for symbol lookups, but we don't support them";
    write_packet("");
    return false;
#endif
  }
  if (strstr(name, "ThreadExtraInfo") == name) {
    // ThreadExtraInfo is a special snowflake that
    // delimits its args with ','.
    parser_assert(!args);
    args = payload;
    args = 1 + strchr(args, ',' /*sic*/);

    req = GdbRequest(DREQ_GET_THREAD_EXTRA_INFO);
    req.target = parse_threadid(args, &args);
    parser_assert('\0' == *args);
    return true;
  }
  if (!strcmp(name, "TStatus")) {
    LOG(debug) << "debugger asks for trace status";
    /* XXX from the docs, it appears that we should reply
     * with "T0" here.  But if we do, gdb keeps bothering
     * us with trace queries.  So pretend we don't know
     * what it's talking about. */
    write_packet("");
    return false;
  }
  if (!strcmp(name, "Xfer")) {
    name = args;
    args = strchr(args, ':');
    parser_assert(args);
    *args++ = '\0';

    return xfer(name, args);
  }
  if (!strcmp(name, "Search")) {
    name = args;
    args = strchr(args, ':');
    if (args) {
      *args++ = '\0';
    }
    if (!strcmp(name, "memory") && args) {
      req = GdbRequest(DREQ_SEARCH_MEM_BINARY);
      req.target = query_thread;
      req.mem().addr = strtoul(args, &args, 16);
      parser_assert(';' == *args++);
      req.mem().len = strtoull(args, &args, 16);
      parser_assert(';' == *args++);
      read_binary_data((const uint8_t*)args, inbuf.data() + packetend,
                       req.mem().data);

      LOG(debug) << "debugger searching memory (addr=" << HEX(req.mem().addr)
                 << ", len=" << req.mem().len << ")";
      return true;
    }
    write_packet("");
    return false;
  }
  if (!strcmp(name, "MemoryRegionInfo") && args) {
    req = GdbRequest(DREQ_MEM_INFO);
    req.target = query_thread;
    req.mem().addr = strtoul(args, &args, 16);
    parser_assert(!*args);
    req.mem().len = 1;
    LOG(debug) << "debugger requesting mem info (addr="
        << HEX(req.mem().addr) << ")";
    return true;
  }

  // Packets that we intentionally don't support

  if (!strcmp(name, "P")) {
    /* The docs say not to use this packet ... */
    write_packet("");
    return false;
  }
  if (!strcmp(name, "HostInfo")) {
    // lldb-server sends a reply like
    // triple:7838365f36342d2d6c696e75782d676e75;ptrsize:8;distribution_id:6665646f7261;
    // watchpoint_exceptions_received:after;endian:little;os_version:6.6.13;
    // os_build:362e362e31332d3230302e666333392e7838365f3634;
    // os_kernel:233120534d5020505245454d50545f44594e414d494320536174204a616e2032302031383a30333a3238205554432032303234;
    // hostname:6c6f63616c686f73742e6c6f63616c646f6d61696e
    // So far there is no benefit for handling it AFAICT.
    write_packet("");
    return false;
  }
  if (!strcmp(name, "VAttachOrWaitSupported")) {
    // We don't handle vAttach and variants.
    write_packet("");
    return false;
  }
  if (!strcmp(name, "ProcessInfo")) {
    // lldb-server sends a reply like
    // pid:3663df;parent-pid:3663de;real-uid:3e8;real-gid:3e8;effective-uid:3e8;effective-gid:3e8;
    // triple:7838365f36342d2d6c696e75782d676e75;ostype:linux;endian:little;ptrsize:8
    // Currently we don't have the parent PID or uids, so we're
    // not going to handle this.
    write_packet("");
    return false;
  }
  if (!strcmp(name, "StructuredDataPlugins")) {
    // This isn't documented and lldb-server doesn't support it
    write_packet("");
    return false;
  }
  if (!strcmp(name, "ShlibInfoAddr")) {
    // This isn't documented and lldb-server doesn't seem to support it
    write_packet("");
    return false;
  }

  UNHANDLED_REQ() << "Unhandled debugger query: q" << name;
  return false;
}

// LLDB QThreadSuffixSupported extension
static void parse_thread_suffix_threadid(char* payload, GdbThreadId* out) {
  char* semicolon = strrchr(payload, ';');
  if (!semicolon) {
    return;
  }
  if (!semicolon[1]) {
    semicolon[0] = 0;
    semicolon = strrchr(payload, ';');
    if (!semicolon) {
      return;
    }
  }
  if (strncmp(semicolon + 1, "thread:", 7)) {
    return;
  }
  char* endptr;
  *out = parse_threadid(semicolon + 8, &endptr);
  *semicolon = 0;
}

bool GdbServerConnection::set_var(char* payload) {
  GdbThreadId target = query_thread;
  parse_thread_suffix_threadid(payload, &target);

  char* args = strchr(payload, ':');
  if (args) {
    *args++ = '\0';
  }
  const char* name = payload;

  if (!strcmp(name, "StartNoAckMode")) {
    write_packet("OK");
    no_ack = true;
    return false;
  }
  if (!strncmp(name, "PassSignals", sizeof("PassSignals"))) {
    pass_signals.clear();
    while (*args != '\0') {
      char *next = nullptr;
      int sig = std::strtol(args, &next, 16);
      parser_assert(next != nullptr);

      LOG(debug) << "registered " << sig << " by QPassSignal";
      pass_signals.insert(sig);

      args = next;
      if (*args == '\0') {
        break;
      }

      parser_assert(*args == ';');
      args++;
    }

    write_packet("OK");
    return false;
  }
  if (!strcmp(name, "ListThreadsInStopReply")) {
    write_packet("OK");
    list_threads_in_stop_reply_ = true;
    return false;
  }

  if (!strcmp(name, "ThreadSuffixSupported")) {
    write_packet("OK");
    return false;
  }
  if (!strcmp(name, "EnableErrorStrings")) {
    // We don't support human-readable error strings.
    write_packet("");
    return false;
  }
  if (!strcmp(name, "SaveRegisterState")) {
    req = GdbRequest(DREQ_SAVE_REGISTER_STATE);
    req.target = target;
    return true;
  }
  if (!strcmp(name, "RestoreRegisterState")) {
    req = GdbRequest(DREQ_RESTORE_REGISTER_STATE);
    req.target = target;
    char* end;
    req.restore_register_state().state_index = strtol(args, &end, 16);
    parser_assert(!*end || *end == ';');
    return true;
  }

  UNHANDLED_REQ() << "Unhandled debugger set: Q" << name;
  return false;
}

bool GdbServerConnection::process_underscore(char* payload) {
  char* args = payload + 1;

  switch (payload[0]) {
    case 'M': {
      char* end = nullptr;
      req = GdbRequest(DREQ_MEM_ALLOC);
      req.mem_alloc().size = strtol(args, &end, 16);
      parser_assert(*end == ',');
      int prot = 0;
      ++end;
      if (*end == 'r') {
        prot |= PROT_READ;
        ++end;
      }
      if (*end == 'w') {
        prot |= PROT_WRITE;
        ++end;
      }
      if (*end == 'x') {
        prot |= PROT_EXEC;
      }
      req.mem_alloc().prot = prot;
      return true;
    }
    case 'm': {
      char* end = nullptr;
      req = GdbRequest(DREQ_MEM_FREE);
      req.mem_free().address = strtol(args, &end, 16);
      parser_assert(!*end);
      return true;
    }
    default:
      break;
  }

  UNHANDLED_REQ() << "Unhandled debugger request: _" << payload;
  return false;
}

void GdbServerConnection::consume_request() {
  req = GdbRequest();
  write_flush();
}

bool GdbServerConnection::process_bpacket(char* payload) {
  if (strcmp(payload, "c") == 0) {
    req = GdbRequest(DREQ_CONT);
    req.cont().run_direction = RUN_BACKWARD;
    req.cont().actions.push_back(GdbContAction(ACTION_CONTINUE, resume_thread));
    return true;
  } else if (strcmp(payload, "s") == 0) {
    req = GdbRequest(DREQ_CONT);
    req.cont().run_direction = RUN_BACKWARD;
    req.cont().actions.push_back(GdbContAction(ACTION_STEP, resume_thread));
    return true;
  } else {
    UNHANDLED_REQ() << "Unhandled debugger bpacket: b" << payload;
    return false;
  }
}

static int gdb_open_flags_to_system_flags(int64_t flags) {
  int ret;
  switch (flags & 3) {
    case 0:
      ret = O_RDONLY;
      break;
    case 1:
      ret = O_WRONLY;
      break;
    case 2:
      ret = O_RDWR;
      break;
    default:
      parser_assert(false);
      return 0;
  }
  parser_assert(!(flags & ~int64_t(3 | 0x8 | 0x200 | 0x400 | 0x800)));
  if (flags & 0x8) {
    ret |= O_APPEND;
  }
  if (flags & 0x200) {
    ret |= O_CREAT;
  }
  if (flags & 0x400) {
    ret |= O_TRUNC;
  }
  if (flags & 0x800) {
    ret |= O_EXCL;
  }
  return ret;
}

bool GdbServerConnection::process_vpacket(char* payload) {
  const char* name;
  char* args;

  args = strchr(payload, ';');
  if (args) {
    *args++ = '\0';
  }
  name = payload;

  if (!strcmp("Cont", name)) {
    vector<GdbContAction> actions;
    bool has_default_action = false;
    GdbContAction default_action;

    while (args) {
      char* cmd = args;
      while (*args != ':' && *args != ';') {
        if (!*args) {
          args = nullptr;
          break;
        }
        ++args;
      }
      bool is_default = true;
      GdbThreadId target;
      if (args) {
        if (*args == ':') {
          is_default = false;
          *args = '\0';
          target = parse_threadid(args + 1, &args);
        }
        args = strchr(args, ';');
        if (args) {
          *args = '\0';
          ++args;
        }
      }

      GdbActionType action;
      int signal_to_deliver = 0;
      char* endptr = NULL;
      switch (cmd[0]) {
        case 'C':
          action = ACTION_CONTINUE;
          signal_to_deliver = strtol(cmd + 1, &endptr, 16);
          break;
        case 'c':
          action = ACTION_CONTINUE;
          break;
        case 'S':
          action = ACTION_STEP;
          signal_to_deliver = strtol(cmd + 1, &cmd, 16);
          break;
        case 's':
          action = ACTION_STEP;
          break;
        default:
          UNHANDLED_REQ() << "Unhandled vCont command " << cmd << "(" << args
                          << ")";
          return false;
      }
      if (endptr && *endptr) {
        UNHANDLED_REQ() << "Unhandled vCont command parameters " << cmd;
        return false;
      }
      if (is_default) {
        if (has_default_action) {
          UNHANDLED_REQ()
              << "Unhandled vCont command with multiple default actions";
          return false;
        }
        has_default_action = true;
        default_action =
            GdbContAction(action, GdbThreadId::ALL, signal_to_deliver);
      } else {
        actions.push_back(GdbContAction(action, target, signal_to_deliver));
      }
    }

    if (has_default_action) {
      actions.push_back(default_action);
    }
    req = GdbRequest(DREQ_CONT);
    req.cont().run_direction = RUN_FORWARD;
    req.cont().actions = std::move(actions);
    return true;
  }

  if (!strcmp("Cont?", name)) {
    LOG(debug) << "debugger queries which continue commands we support";
    write_packet("vCont;c;C;s;S;");
    return false;
  }

  if (!strcmp("Kill", name)) {
    // We can't kill tracees or replay can diverge.  We
    // assume that this kill request is being made because
    // a "vRun" restart is coming right up.  We know how
    // to implement vRun, so we'll ignore this one.
    LOG(debug) << "debugger asks us to kill tracee(s); ignoring";
    write_packet("OK");
    return false;
  }

  if (!strcmp("Run", name)) {
    req = GdbRequest(DREQ_RESTART);

    const char* filename = args;
    args = strchr(args, ';');
    if (args) {
      *args++ = '\0';
    }
    if (strlen(filename)) {
      FATAL() << "debugger wants us to run the exe image `" << filename
              << "', but we don't support that.";
    }
    if (!args) {
      req.restart().type = RESTART_FROM_PREVIOUS;
      return true;
    }
    const char* arg1 = args;
    args = strchr(args, ';');
    if (args) {
      *args++ = 0;
      LOG(debug) << "Ignoring extra parameters " << args;
    }
    string event_str = decode_ascii_encoded_hex_str(arg1);
    char* endp;
    if (event_str[0] == 'c') {
      int64_t param = strtoll(event_str.c_str() + 1, &endp, 0);
      req.restart().type = RESTART_FROM_CHECKPOINT;
      req.restart().param_str = event_str.substr(1);
      req.restart().param = param;
      LOG(debug) << "next replayer restarting from checkpoint "
                 << param;
    } else if (event_str[0] == 't') {
      int64_t param = strtoll(event_str.c_str() + 1, &endp, 0);
      req.restart().type = RESTART_FROM_TICKS;
      req.restart().param_str = event_str.substr(1);
      req.restart().param = param;
      LOG(debug) << "next replayer restarting from tick count "
                 << param;
    } else {
      req.restart().type = RESTART_FROM_EVENT;
      req.restart().param = strtoll(event_str.c_str(), &endp, 0);
      LOG(debug) << "next replayer advancing to event " << req.restart().param;
    }
    if (!endp || *endp != '\0') {
      LOG(debug) << "Couldn't parse event string `" << event_str << "'"
                 << "; restarting from previous";
      req.restart().type = RESTART_FROM_PREVIOUS;
      req.restart().param = -1;
    }
    return true;
  }

  if (name == strstr(name, "File:")) {
    char* operation = payload + 5;
    if (operation == strstr(operation, "open:")) {
      char* file_name_end = strchr(operation + 5, ',');
      parser_assert(file_name_end != nullptr);
      *file_name_end = 0;
      req = GdbRequest(DREQ_FILE_OPEN);
      req.file_open().file_name = decode_ascii_encoded_hex_str(operation + 5);
      char* flags_end;
      int64_t flags = strtol(file_name_end + 1, &flags_end, 16);
      parser_assert(*flags_end == ',');
      req.file_open().flags = gdb_open_flags_to_system_flags(flags);
      char* mode_end;
      int64_t mode = strtol(flags_end + 1, &mode_end, 16);
      parser_assert(*mode_end == 0);
      parser_assert((mode & ~(int64_t)0777) == 0);
      req.file_open().mode = mode;
      return true;
    } else if (operation == strstr(operation, "close:")) {
      char* endptr;
      int64_t fd = strtol(operation + 6, &endptr, 16);
      parser_assert(*endptr == 0);
      req = GdbRequest(DREQ_FILE_CLOSE);
      req.file_close().fd = fd;
      parser_assert(req.file_close().fd == fd);
      return true;
    } else if (operation == strstr(operation, "pread:")) {
      char* fd_end;
      int64_t fd = strtol(operation + 6, &fd_end, 16);
      parser_assert(*fd_end == ',');
      req = GdbRequest(DREQ_FILE_PREAD);
      req.file_pread().fd = fd;
      parser_assert(req.file_pread().fd == fd);
      char* size_end;
      int64_t size = strtol(fd_end + 1, &size_end, 16);
      parser_assert(*size_end == ',');
      parser_assert(size >= 0);
      req.file_pread().size = size;
      char* offset_end;
      int64_t offset = strtol(size_end + 1, &offset_end, 16);
      parser_assert(*offset_end == 0);
      parser_assert(offset >= 0);
      req.file_pread().offset = offset;
      return true;
    } else if (operation == strstr(operation, "setfs:")) {
      char* endptr;
      int64_t pid = strtol(operation + 6, &endptr, 16);
      parser_assert(*endptr == 0);
      req = GdbRequest(DREQ_FILE_SETFS);
      req.file_setfs().pid = pid;
      parser_assert(req.file_setfs().pid == pid);
      return true;
    } else {
      write_packet("");
      return false;
    }
  }

  UNHANDLED_REQ() << "Unhandled debugger vpacket: v" << name;
  return false;
}

static string to_string(const vector<uint8_t>& bytes, size_t max_len) {
  stringstream ss;
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i >= max_len) {
      ss << "...";
      break;
    }
    char buf[3];
    sprintf(buf, "%02x", bytes[i]);
    ss << buf;
  }
  return ss.str();
}

bool GdbServerConnection::process_packet() {
  parser_assert(
      INTERRUPT_CHAR == inbuf[0] ||
      ('$' == inbuf[0] && (uint8_t*)memchr(inbuf.data(), '#', inbuf.size()) ==
                              inbuf.data() + packetend));

  if (INTERRUPT_CHAR == inbuf[0]) {
    LOG(debug) << "debugger requests interrupt";
    req = GdbRequest(DREQ_INTERRUPT);
    inbuf.erase(inbuf.begin());
    return true;
  }

  char request = inbuf[1];
  char* payload = (char*)&inbuf[2];
  inbuf[packetend] = '\0';
  LOG(debug) << "raw request " << request << payload;

  bool ret;
  switch (request) {
    case 'b':
      ret = process_bpacket(payload);
      break;
    case 'c':
      LOG(debug) << "debugger is asking to continue";
      req = GdbRequest(DREQ_CONT);
      req.cont().run_direction = RUN_FORWARD;
      req.cont().actions.push_back(GdbContAction(ACTION_CONTINUE));
      ret = true;
      break;
    case 'D':
      LOG(debug) << "debugger is detaching from us";
      req = GdbRequest(DREQ_DETACH);
      ret = true;
      break;
    case 'g':
      req = GdbRequest(DREQ_GET_REGS);
      req.target = query_thread;
      parse_thread_suffix_threadid(payload, &req.target);
      LOG(debug) << "debugger requests registers in thread "
          << req.target;
      ret = true;
      break;
    case 'G':
      /* XXX we can't let gdb spray registers in general,
       * because it may cause replay to diverge.  But some
       * writes may be OK.  Let's see how far we can get
       * with ignoring these requests. */
      write_packet("");
      ret = false;
      break;
    case 'H':
      if ('c' == *payload++) {
        req = GdbRequest(DREQ_SET_CONTINUE_THREAD);
      } else {
        req = GdbRequest(DREQ_SET_QUERY_THREAD);
      }
      req.target = parse_threadid(payload, &payload);
      parser_assert('\0' == *payload);

      LOG(debug) << "debugger selecting " << req.target;

      ret = true;
      break;
    case 'j':
      // Prefer to avoid implementing any JSON-formatted-output
      // packets unless we have to
      write_packet("");
      ret = false;
      break;
    case 'k':
      LOG(info) << "debugger requests kill, exiting";
      write_packet("OK");
      exit(0);
    case 'm':
      req = GdbRequest(DREQ_GET_MEM);
      req.target = query_thread;
      req.mem().addr = strtoul(payload, &payload, 16);
      parser_assert(',' == *payload++);
      req.mem().len = strtoul(payload, &payload, 16);
      parser_assert('\0' == *payload);

      LOG(debug) << "debugger requests memory (addr=" << HEX(req.mem().addr)
                 << ", len=" << req.mem().len << ")";

      ret = true;
      break;
    case 'M':
      req = GdbRequest(DREQ_SET_MEM);
      req.target = query_thread;
      req.mem().addr = strtoul(payload, &payload, 16);
      parser_assert(',' == *payload++);
      req.mem().len = strtoul(payload, &payload, 16);
      parser_assert(':' == *payload++);
      read_hex_data(payload, reinterpret_cast<const char*>(inbuf.data() + packetend),
                    req.mem().data);
      parser_assert(req.mem().len == req.mem().data.size());

      LOG(debug) << "debugger setting memory (addr=" << HEX(req.mem().addr)
                 << ", len=" << req.mem().len
                 << ", data=" << to_string(req.mem().data, 32) << ")";

      ret = true;
      break;
    case 'p':
      req = GdbRequest(DREQ_GET_REG);
      req.target = query_thread;
      parse_thread_suffix_threadid(payload, &req.target);
      req.reg().name = GdbServerRegister(strtoul(payload, &payload, 16));
      parser_assert('\0' == *payload);
      LOG(debug) << "debugger requests register value (" << req.reg().name
          << ") in thread " << req.target;
      ret = true;
      break;
    case 'P':
      req = GdbRequest(DREQ_SET_REG);
      req.target = query_thread;
      parse_thread_suffix_threadid(payload, &req.target);
      req.reg().name = GdbServerRegister(strtoul(payload, &payload, 16));
      parser_assert('=' == *payload++);

      read_reg_value(&payload, &req.reg());

      parser_assert('\0' == *payload);
      LOG(debug) << "debugger requests set register value (" << req.reg().name
          << ") in thread " << req.target;

      ret = true;
      break;
    case 'q':
      ret = query(payload);
      break;
    case 'Q':
      ret = set_var(payload);
      break;
    case 'T':
      req = GdbRequest(DREQ_GET_IS_THREAD_ALIVE);
      req.target = parse_threadid(payload, &payload);
      parser_assert('\0' == *payload);
      LOG(debug) << "debugger wants to know if " << req.target << " is alive";
      ret = true;
      break;
    case 'v':
      ret = process_vpacket(payload);
      break;
    case 'x':
      req = GdbRequest(DREQ_GET_MEM_BINARY);
      req.target = query_thread;
      req.mem().addr = strtoul(payload, &payload, 16);
      parser_assert(',' == *payload++);
      req.mem().len = strtoul(payload, &payload, 16);
      parser_assert(!*payload);
      LOG(debug) << "debugger requests binary memory (addr=" << HEX(req.mem().addr)
                 << ", len=" << req.mem().len << ")";
      ret = true;
      break;
    case 'X':
      req = GdbRequest(DREQ_SET_MEM_BINARY);
      req.target = query_thread;
      req.mem().addr = strtoul(payload, &payload, 16);
      parser_assert(',' == *payload++);
      req.mem().len = strtoul(payload, &payload, 16);
      parser_assert(':' == *payload++);
      read_binary_data((const uint8_t*)payload, inbuf.data() + packetend,
                       req.mem().data);
      parser_assert(req.mem().len == req.mem().data.size());

      LOG(debug) << "debugger setting memory (addr=" << HEX(req.mem().addr)
                 << ", len=" << req.mem().len
                 << ", data=" << to_string(req.mem().data, 32) << ")";

      ret = true;
      break;
    case 'z':
    case 'Z': {
      int type = strtol(payload, &payload, 16);
      parser_assert(',' == *payload++);
      if (!(0 <= type && type <= 4)) {
        LOG(warn) << "Unknown watch type " << type;
        write_packet("");
        ret = false;
        break;
      }
      req = GdbRequest(GdbRequestType(
          type + (request == 'Z' ? DREQ_SET_SW_BREAK : DREQ_REMOVE_SW_BREAK)));
      req.watch().addr = strtoul(payload, &payload, 16);
      parser_assert(',' == *payload);
      payload++;
      req.watch().kind = strtoul(payload, &payload, 16);
      if (';' == *payload) {
        ++payload;
        while ('X' == *payload) {
          ++payload;
          int len = strtol(payload, &payload, 16);
          parser_assert(',' == *payload);
          payload++;
          vector<uint8_t> bytes;
          for (int i = 0; i < len; ++i) {
            parser_assert(payload[0] && payload[1]);
            char tmp = payload[2];
            payload[2] = '\0';
            bytes.push_back(strtol(payload, &payload, 16));
            parser_assert('\0' == *payload);
            payload[0] = tmp;
          }
          req.watch().conditions.push_back(std::move(bytes));
        }
      }
      parser_assert('\0' == *payload);

      LOG(debug) << "debugger requests " << ('Z' == request ? "set" : "remove")
                 << "breakpoint (addr=" << HEX(req.watch().addr)
                 << ", len=" << req.watch().kind << ")";

      ret = true;
      break;
    }
    case '!':
      LOG(debug) << "debugger requests extended mode";
      write_packet("OK");
      ret = false;
      break;
    case '?':
      LOG(debug) << "debugger requests stop reason";
      req = GdbRequest(DREQ_GET_STOP_REASON);
      req.target = query_thread;
      ret = true;
      break;
    case '_':
      ret = process_underscore(payload);
      break;
    default:
      UNHANDLED_REQ() << "Unhandled debugger request '" << inbuf[1] << "'";
      ret = false;
  }
  /* Erase the newly processed packet from the input buffer. The checksum
   * after the '#' will be skipped later as we look for the next packet start.
   */
  inbuf.erase(inbuf.begin(), inbuf.begin() + packetend + 1);

  /* If we processed the request internally, consume it. */
  if (!ret) {
    consume_request();
  }
  return ret;
}

void GdbServerConnection::notify_no_such_thread(const GdbRequest& req) {
  DEBUG_ASSERT(req.target == this->req.target && req.type == this->req.type);

  /* '10' is the errno ECHILD.  We use it as a magic code to
   * notify the user that the thread that was the target of this
   * request has died, and either gdb didn't notice that, or rr
   * didn't notify gdb.  Either way, the user should restart
   * their debugging session. */
  LOG(error) << "Targeted thread no longer exists; this is the result of "
                "either a debugger or\n"
                "rr bug.  Please restart your debugging session and avoid "
                "doing whatever\n"
                "triggered this bug.";
  write_packet("E10");
  consume_request();
}

void GdbServerConnection::notify_restart() {
  DEBUG_ASSERT(DREQ_RESTART == req.type);

  // These threads may not exist at the first trace-stop after
  // restart.  The gdb client should reset this state, but help
  // it out just in case.
  resume_thread = GdbThreadId::ANY;
  query_thread = GdbThreadId::ANY;

  req = GdbRequest();
}

GdbRequest GdbServerConnection::get_request() {
  if (DREQ_RESTART == req.type) {
    LOG(debug) << "consuming RESTART request";
    notify_restart();
    // gdb wants to be notified with a stop packet when
    // the process "relaunches".  In rr's case, the
    // traceee may be very far away from process creation,
    // but that's OK.
    req = GdbRequest(DREQ_GET_STOP_REASON);
    req.target = query_thread;
    return req;
  }

/* Can't ask for the next request until you've satisfied the
 * current one, for requests that need an immediate
 * response. */
#ifdef DEBUG
  DEBUG_ASSERT(!request_needs_immediate_response(&req));
#endif

  if (!sniff_packet() && req.is_resume_request()) {
    /* There's no new request data available and the debugger has
     * already asked us to resume.  OK, do that (or keep
     * doing that) now. */
    return req;
  }

  while (true) {
    /* There's either new request data, or we have nothing
     * to do.  Either way, block until we read a complete
     * packet from the debugger. */
    read_packet();

    if (!connection_alive_) {
      return req = GdbRequest(DREQ_DETACH);
    }

    if (process_packet()) {
      /* We couldn't process the packet internally,
       * so the target has to do something. */
      return req;
    }
    /* The packet we got was "internal", debugger details.
     * Nothing for the target to do yet.  Keep waiting. */
  }
}

void GdbServerConnection::notify_exit_code(int code) {
  char buf[64];

  DEBUG_ASSERT(req.is_resume_request() || req.type == DREQ_INTERRUPT);

  snprintf(buf, sizeof(buf) - 1, "W%02x", code);
  write_packet(buf);

  consume_request();
}

void GdbServerConnection::notify_exit_signal(int sig) {
  char buf[64];

  DEBUG_ASSERT(req.is_resume_request() || req.type == DREQ_INTERRUPT);

  snprintf(buf, sizeof(buf) - 1, "X%02x", sig);
  write_packet(buf);

  consume_request();
}

/**
 * Translate linux-x86 |sig| to gdb's internal numbering.  Translation
 * made according to gdb/include/gdb/signals.def.
 */
static int to_gdb_signum(int sig) {
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
    case 32:
      return 77;
    default:
      if (33 <= sig && sig <= 63) {
        /* GDB_SIGNAL_REALTIME_33 is numbered 45, hence this offset. */
        return sig + 12;
      }
      if (64 <= sig && sig <= 127) {
        /* GDB_SIGNAL_REALTIME_64 is numbered 78, hence this offset. */
        return sig + 14;
      }
      LOG(warn) << "Unknown signal " << sig;
      return 143; // GDB_SIGNAL_UNKNOWN
  }
}

void GdbServerConnection::send_stop_reply_packet(ExtendedTaskId thread, int sig,
                                                 const vector<ThreadInfo>& threads,
                                                 const string& reason) {
  if (sig < 0) {
    write_packet("E01");
    return;
  }
  stringstream sstr;
  sstr << "T" << std::setfill('0') << std::setw(2) << std::hex
      << to_gdb_signum(sig) << std::setw(0);
  sstr << "thread:" << format_thread_id(thread) << ";" << reason;
  if (list_threads_in_stop_reply_) {
    sstr << "threads:";
    bool first = true;
    for (const auto& thread : threads) {
      if (thread.id.tguid != tguid) {
        continue;
      }
      if (!first) {
        sstr << ",";
      }
      first = false;
      sstr << thread.id.tuid.tid();
    }
    sstr << ";thread-pcs:";
    first = true;
    for (const auto& thread : threads) {
      if (thread.id.tguid != tguid) {
        continue;
      }
      if (!first) {
        sstr << ",";
      }
      first = false;
      sstr << thread.pc;
    }
    sstr << ";";
  }

  write_packet(sstr.str().c_str());
}

void GdbServerConnection::notify_stop(ExtendedTaskId thread, int sig,
                                      const vector<ThreadInfo>& threads,
                                      const string& reason) {
  DEBUG_ASSERT(req.is_resume_request() || req.type == DREQ_INTERRUPT);

  // don't pass this signal to gdb if it is specified not to
  if (pass_signals.find(to_gdb_signum(sig)) != pass_signals.end()) {
    LOG(debug) << "discarding stop notification for signal " << sig 
                << " on thread " << thread << " as specified by QPassSignal";

    return;
  }

  if (tguid != thread.tguid) {
    LOG(debug) << "ignoring stop of " << thread
               << " because we're debugging tgid " << tguid.tid();
    // Re-use the existing continue request to advance to
    // the next stop we're willing to tell gdb about.
    return;
  }

  send_stop_reply_packet(thread, sig, threads, reason);

  // This isn't documented in the gdb remote protocol, but if we
  // don't do this, gdb will sometimes continue to send requests
  // for the previously-stopped thread when it obviously intends
  // to be making requests about the stopped thread.
  // To make things even better, gdb expects different behavior
  // for forward continue/interrupt and reverse continue.
  if (req.is_resume_request() && req.cont().run_direction == RUN_BACKWARD) {
    LOG(debug) << "Setting query/resume_thread to ANY after reverse continue";
    query_thread = resume_thread = GdbThreadId::ANY;
  } else {
    LOG(debug) << "Setting query/resume_thread to " << thread
               << " after forward continue or interrupt";
    query_thread = resume_thread = thread.to_debugger_thread_id();
  }

  consume_request();
}

void GdbServerConnection::notify_restart_failed() {
  DEBUG_ASSERT(DREQ_RESTART == req.type);

  // TODO: it's not known by this author whether gdb knows how
  // to recover from a failed "run" request.
  write_packet("E01");

  consume_request();
}

string GdbServerConnection::format_thread_id(ExtendedTaskId thread) {
  char buf[32];
  if (multiprocess_supported_) {
    snprintf(buf, sizeof(buf), "p%x.%x", thread.tguid.tid(),
             thread.tuid.tid());
  } else {
    snprintf(buf, sizeof(buf), "%x", thread.tuid.tid());
  }
  return buf;
}

void GdbServerConnection::reply_get_current_thread(ExtendedTaskId thread) {
  DEBUG_ASSERT(DREQ_GET_CURRENT_THREAD == req.type);

  write_packet(("QC" + format_thread_id(thread)).c_str());
  consume_request();
}

void GdbServerConnection::reply_get_auxv(const vector<uint8_t>& auxv) {
  DEBUG_ASSERT(DREQ_GET_AUXV == req.type);

  if (!auxv.empty()) {
    write_binary_packet("l", auxv.data(), auxv.size());
  } else {
    write_packet("E01");
  }

  consume_request();
}

void GdbServerConnection::reply_get_exec_file(const string& exec_file) {
  DEBUG_ASSERT(DREQ_GET_EXEC_FILE == req.type);

  if (!exec_file.empty()) {
    write_binary_packet("l",
                        reinterpret_cast<const uint8_t*>(exec_file.c_str()),
                        exec_file.size());
  } else {
    write_packet("E01");
  }

  consume_request();
}

void GdbServerConnection::reply_get_is_thread_alive(bool alive) {
  DEBUG_ASSERT(DREQ_GET_IS_THREAD_ALIVE == req.type);

  write_packet(alive ? "OK" : "E01");

  consume_request();
}

void GdbServerConnection::reply_get_thread_extra_info(const string& info) {
  DEBUG_ASSERT(DREQ_GET_THREAD_EXTRA_INFO == req.type);

  LOG(debug) << "thread extra info: '" << info.c_str() << "'";
  write_hex_bytes_packet((const uint8_t*)info.c_str(), 1 + info.length());

  consume_request();
}

void GdbServerConnection::reply_select_thread(bool ok) {
  DEBUG_ASSERT(DREQ_SET_CONTINUE_THREAD == req.type ||
               DREQ_SET_QUERY_THREAD == req.type);

  if (ok && DREQ_SET_CONTINUE_THREAD == req.type) {
    resume_thread = req.target;
  } else if (ok && DREQ_SET_QUERY_THREAD == req.type) {
    query_thread = req.target;
  }
  write_packet(ok ? "OK" : "E01");

  consume_request();
}

void GdbServerConnection::reply_get_mem(const vector<uint8_t>& mem) {
  DEBUG_ASSERT(DREQ_GET_MEM == req.type || DREQ_GET_MEM_BINARY == req.type);
  DEBUG_ASSERT(mem.size() <= req.mem().len);

  if (DREQ_GET_MEM == req.type) {
    if (req.mem().len > 0 && mem.size() == 0) {
      write_packet("E01");
    } else {
      write_hex_bytes_packet(mem.data(), mem.size());
    }
  } else {
    if (!req.mem().len) {
      write_packet("OK");
    } else if (!mem.size()) {
      write_packet("E01");
    } else {
      write_binary_packet("", mem.data(), mem.size());
    }
  }

  consume_request();
}

void GdbServerConnection::reply_set_mem(bool ok) {
  DEBUG_ASSERT(DREQ_SET_MEM == req.type || DREQ_SET_MEM_BINARY == req.type);

  write_packet(ok ? "OK" : "E01");

  consume_request();
}

void GdbServerConnection::reply_mem_alloc(remote_ptr<void> addr) {
  DEBUG_ASSERT(DREQ_MEM_ALLOC == req.type);

  if (addr.is_null()) {
    write_packet("E01");
  } else {
    char buf[256];
    sprintf(buf, "%llx", (long long)addr.as_int());
    write_packet(buf);
  }

  consume_request();
}

void GdbServerConnection::reply_mem_free(bool ok) {
  DEBUG_ASSERT(DREQ_MEM_FREE == req.type);

  write_packet(ok ? "OK" : "E01");

  consume_request();
}

void GdbServerConnection::reply_search_mem_binary(
      bool found, remote_ptr<void> addr) {
  DEBUG_ASSERT(DREQ_SEARCH_MEM_BINARY == req.type);

  if (found) {
    char buf[256];
    sprintf(buf, "1,%llx", (long long)addr.as_int());
    write_packet(buf);
  } else {
    write_packet("0");
  }

  consume_request();
}

void GdbServerConnection::reply_mem_info(MemoryRange range,
                                         int prot,
                                         const string& fs_name) {
  DEBUG_ASSERT(DREQ_MEM_INFO == req.type);

  stringstream sstr;
  sstr << hex << "start:" << range.start().as_int()
    << ";size:" << range.size() << ";";

  string permissions;
  if (prot & PROT_READ) {
    permissions += 'r';
  }
  if (prot & PROT_WRITE) {
    permissions += 'w';
  }
  if (prot & PROT_EXEC) {
    permissions += 'x';
  }
  if (!permissions.empty()) {
    sstr << "permissions:" << permissions << ";";
  }
  if (!fs_name.empty()) {
    sstr << "name:" << string_to_hex(fs_name) << ";";
  }

  write_packet(sstr.str().c_str());
  consume_request();
}

void GdbServerConnection::reply_get_offsets(/* TODO */) {
  DEBUG_ASSERT(DREQ_GET_OFFSETS == req.type);

  /* XXX FIXME TODO */
  write_packet("");

  consume_request();
}

void GdbServerConnection::reply_get_reg(const GdbServerRegisterValue& reg) {
  char buf[2 * GdbServerRegisterValue::MAX_SIZE + 1];

  DEBUG_ASSERT(DREQ_GET_REG == req.type);

  print_reg_value(reg, buf);
  write_packet(buf);

  consume_request();
}

void GdbServerConnection::reply_get_regs(const vector<GdbServerRegisterValue>& file) {
  std::unique_ptr<char[]> buf(
      new char[file.size() * 2 * GdbServerRegisterValue::MAX_SIZE + 1]);

  DEBUG_ASSERT(DREQ_GET_REGS == req.type);

  size_t offset = 0;
  for (auto& reg : file) {
    offset += print_reg_value(reg, &buf[offset]);
  }
  write_packet(buf.get());

  consume_request();
}

void GdbServerConnection::reply_set_reg(bool ok) {
  DEBUG_ASSERT(DREQ_SET_REG == req.type);

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

void GdbServerConnection::reply_get_stop_reason(ExtendedTaskId which, int sig,
                                                const std::vector<ThreadInfo>& threads) {
  DEBUG_ASSERT(DREQ_GET_STOP_REASON == req.type);

  send_stop_reply_packet(which, sig, threads, string());

  consume_request();
}

void GdbServerConnection::reply_get_thread_list(const vector<ExtendedTaskId>& threads) {
  DEBUG_ASSERT(DREQ_GET_THREAD_LIST == req.type);
  if (threads.empty()) {
    write_packet("l");
  } else {
    stringstream sstr;
    sstr << 'm';
    for (size_t i = 0; i < threads.size(); ++i) {
      const ExtendedTaskId& t = threads[i];
      if (tguid != t.tguid) {
        continue;
      }
      if (multiprocess_supported_) {
        sstr << 'p' << setw(2) << setfill('0') << hex << t.tguid.tid() << dec << '.'
            << setw(2) << setfill('0') << hex << t.tuid.tid() << ',';
      } else {
        sstr << setw(2) << setfill('0') << hex << t.tuid.tid() << ',';
      }
    }

    string str = sstr.str();
    /* Overwrite the trailing ',' */
    str.back() = 0;
    write_packet(str.c_str());
  }

  consume_request();
}

void GdbServerConnection::reply_watchpoint_request(bool ok) {
  DEBUG_ASSERT(DREQ_WATCH_FIRST <= req.type && req.type <= DREQ_WATCH_LAST);

  write_packet(ok ? "OK" : "E01");

  consume_request();
}

void GdbServerConnection::reply_detach() {
  DEBUG_ASSERT(DREQ_DETACH <= req.type);

  write_packet("OK");

  consume_request();
}

void GdbServerConnection::reply_read_siginfo(const vector<uint8_t>& si_bytes) {
  DEBUG_ASSERT(DREQ_READ_SIGINFO == req.type);

  if (si_bytes.empty()) {
    write_packet("E01");
  } else {
    write_binary_packet("l", si_bytes.data(), si_bytes.size());
  }

  consume_request();
}

void GdbServerConnection::reply_write_siginfo(/* TODO*/) {
  DEBUG_ASSERT(DREQ_WRITE_SIGINFO == req.type);

  write_packet("E01");

  consume_request();
}

void GdbServerConnection::reply_rr_cmd(const std::string& text) {
  DEBUG_ASSERT(DREQ_RR_CMD == req.type);

  write_packet(text.c_str());

  consume_request();
}

void GdbServerConnection::send_qsymbol(const std::string& name) {
  DEBUG_ASSERT(DREQ_QSYMBOL == req.type);

  const void* data = static_cast<const void*>(name.c_str());
  write_hex_bytes_packet("qSymbol:", static_cast<const uint8_t*>(data),
                         name.length());

  consume_request();
}

void GdbServerConnection::qsymbols_finished() {
  DEBUG_ASSERT(DREQ_QSYMBOL == req.type);

  write_packet("OK");

  consume_request();
}

void GdbServerConnection::reply_tls_addr(bool ok, remote_ptr<void> address) {
  DEBUG_ASSERT(DREQ_TLS == req.type);

  if (ok) {
    char buf[256];
    sprintf(buf, "%llx", (long long)address.as_int());
    write_packet(buf);
  } else {
    write_packet("E01");
  }

  consume_request();
}

void GdbServerConnection::reply_setfs(int err) {
  DEBUG_ASSERT(DREQ_FILE_SETFS == req.type);
  if (err) {
    send_file_error_reply(err);
  } else {
    write_packet("F0");
  }

  consume_request();
}

void GdbServerConnection::reply_open(int fd, int err) {
  DEBUG_ASSERT(DREQ_FILE_OPEN == req.type);
  if (err) {
    send_file_error_reply(err);
  } else {
    char buf[32];
    sprintf(buf, "F%x", fd);
    write_packet(buf);
  }

  consume_request();
}

void GdbServerConnection::reply_pread(const uint8_t* bytes, ssize_t len, int err) {
  DEBUG_ASSERT(DREQ_FILE_PREAD == req.type);
  if (err) {
    send_file_error_reply(err);
  } else {
    char buf[32];
    sprintf(buf, "F%llx;", (long long)len);
    write_binary_packet(buf, bytes, len);
  }

  consume_request();
}

void GdbServerConnection::reply_close(int err) {
  DEBUG_ASSERT(DREQ_FILE_CLOSE == req.type);
  if (err) {
    send_file_error_reply(err);
  } else {
    write_packet("F0");
  }

  consume_request();
}

void GdbServerConnection::send_file_error_reply(int system_errno) {
  int gdb_err;
  switch (system_errno) {
    case EPERM:
      gdb_err = 1;
      break;
    case ENOENT:
      gdb_err = 2;
      break;
    case EINTR:
      gdb_err = 4;
      break;
    case EBADF:
      gdb_err = 9;
      break;
    case EACCES:
      gdb_err = 13;
      break;
    case EFAULT:
      gdb_err = 14;
      break;
    case EBUSY:
      gdb_err = 16;
      break;
    case EEXIST:
      gdb_err = 17;
      break;
    case ENODEV:
      gdb_err = 19;
      break;
    case ENOTDIR:
      gdb_err = 20;
      break;
    case EISDIR:
      gdb_err = 21;
      break;
    case EINVAL:
      gdb_err = 22;
      break;
    case ENFILE:
      gdb_err = 23;
      break;
    case EMFILE:
      gdb_err = 24;
      break;
    case EFBIG:
      gdb_err = 27;
      break;
    case ENOSPC:
      gdb_err = 28;
      break;
    case ESPIPE:
      gdb_err = 29;
      break;
    case EROFS:
      gdb_err = 30;
      break;
    case ENAMETOOLONG:
      gdb_err = 91;
      break;
    default:
      gdb_err = 9999;
      break;
  }
  char buf[32];
  sprintf(buf, "F-01,%x", gdb_err);
  write_packet(buf);
}

void GdbServerConnection::reply_save_register_state(bool ok, int state_index) {
  DEBUG_ASSERT(DREQ_SAVE_REGISTER_STATE == req.type);

  if (ok) {
    char buf[256];
    sprintf(buf, "%llx", (long long)state_index);
    write_packet(buf);
  } else {
    write_packet("E01");
  }

  consume_request();
}

void GdbServerConnection::reply_restore_register_state(bool ok) {
  DEBUG_ASSERT(DREQ_RESTORE_REGISTER_STATE == req.type);

  write_packet(ok ? "OK" : "E01");

  consume_request();
}

bool GdbServerConnection::is_connection_alive() { return connection_alive_; }

bool GdbServerConnection::is_pass_signal(int sig) { return pass_signals.find(to_gdb_signum(sig)) != pass_signals.end(); }

} // namespace rr
