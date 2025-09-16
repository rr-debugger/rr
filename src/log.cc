/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "log.h"

#include <stdlib.h>
#include <string.h>

#include <deque>
#include <fstream>
#include <memory>
#include <sstream>
#include <unordered_map>

#include "DumpCommand.h"
#include "Flags.h"
#include "GdbServerConnection.h"
#include "GdbServer.h"
#include "RecordSession.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "core.h"
#include "ftrace.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "launch_debugger.h"
#include "processor_trace_check.h"
#include "util.h"

using namespace std;

ostream& operator<<(ostream& stream, const siginfo_t& siginfo) {
  stream << "{signo:" << rr::signal_name(siginfo.si_signo)
         << ",errno:" << rr::errno_name(siginfo.si_errno)
         << ",code:" << rr::sicode_name(siginfo.si_code, siginfo.si_signo);
  bool show_pid = false;
  switch (siginfo.si_signo) {
    case SIGILL:
    case SIGFPE:
    case SIGSEGV:
    case SIGBUS:
    case SIGTRAP:
      stream << ",addr:" << siginfo.si_addr;
      break;
    case SIGCHLD:
      show_pid = true;
      break;
    default:
      break;
  }
  switch (siginfo.si_code) {
    case SI_USER:
    case SI_QUEUE:
    case SI_TKILL:
      show_pid = true;
      break;
    default:
      break;
  }
  if (show_pid) {
    stream << ",pid:" << siginfo.si_pid;
  }
  stream << "}";
  return stream;
}

namespace rr {

struct LogModule {
  string name;
  LogLevel level;
};

static LogLevel to_log_level(const string& str) {
  if (str == "debug") {
    return LOG_debug;
  }
  if (str == "info") {
    return LOG_info;
  }
  if (str == "warn") {
    return LOG_warn;
  }
  if (str == "error") {
    return LOG_error;
  }
  if (str == "fatal") {
    return LOG_fatal;
  }
  fprintf(stderr, "Log level %s in RR_LOG is not valid, assuming 'fatal'\n",
          str.c_str());
  return LOG_fatal;
}

static char simple_to_lower(char ch) {
  // to_lower sucks because it's locale-dependent
  if (ch >= 'A' && ch <= 'Z') {
    return ch + 'a' - 'A';
  }
  return ch;
}

static string simple_to_lower(const string& s) {
  std::unique_ptr<char[]> buf(new char[s.size() + 1]);
  for (size_t i = 0; i < s.size(); ++i) {
    buf[i] = simple_to_lower(s[i]);
  }
  buf[s.size()] = 0;
  return string(buf.get());
}

#if __has_attribute(require_constant_initialization)
#define _CONSTANT_STATIC                                                       \
  __attribute__((__require_constant_initialization__)) static
#else
#define _CONSTANT_STATIC static
#endif

static bool log_globals_initialized = false;
static LogLevel default_level = LOG_error;

// These need to be available to other static constructors, so we need to be
// sure that they can be constant-initialized. Unfortunately some versions of
// C++ libraries have a bug that causes them not to be. _CONSTANT_STATIC should
// turn this into a compile error rather than a runtime crash for compilers
// that support the attribute.

// This is the assignment of log levels to module names.
// Any module name not mentioned here gets the default_log_level.
_CONSTANT_STATIC unique_ptr<unordered_map<string, LogLevel>> level_map;
// This is a cache mapping unlimited-lifetime file name pointers (usually
// derived from __FILE__) to the associated module name and log level.
// It's OK for this to contain multiple entries for the same string but
// with different pointers.
_CONSTANT_STATIC unique_ptr<unordered_map<const void*, LogModule>> log_modules;
// This collects a single log message.
_CONSTANT_STATIC unique_ptr<stringstream> logging_stream;
// When non-null, log messages are accumulated into this buffer.
_CONSTANT_STATIC unique_ptr<deque<char>> log_buffer;
// When non-null, log messages are flushed to this file.
_CONSTANT_STATIC ostream* log_file;
// Maximum size of `log_buffer`.
size_t log_buffer_size;

static void flush_log_file() { log_file->flush(); }

static void init_log_globals();

void apply_log_spec(const char *spec) {
  init_log_globals();
  char *env = strdup(spec);
  DEBUG_ASSERT(env);
  for (int i = 0; env[i]; ++i) {
    env[i] = simple_to_lower(env[i]);
  }
  char* p = env;
  while (*p) {
    char* end = strchrnul(p, ',');
    char* sep = strchrnul(p, ':');
    string n;
    LogLevel level;
    if (sep >= end) {
      n = string(p, end - p);
      level = LOG_debug;
    } else {
      n = string(p, sep - p);
      if (sep + 1 == end) {
        level = LOG_fatal;
      } else {
        level = to_log_level(string(sep + 1, end - (sep + 1)));
      }
    }
    if (n == "" || n == "all") {
      level_map->clear();
      default_level = level;
    } else {
      (*level_map)[n] = level;
    }
    if (*end) {
      p = end + 1;
    } else {
      p = end;
    }
  }
  free(env);
  log_modules->clear();
}

void apply_log_spec_from_env() {
  const char* log_env = "RR_LOG";
  if (running_under_rr()) {
    log_env = "RR_UNDER_RR_LOG";
  }
  char* env = getenv(log_env);
  if (env) {
    apply_log_spec(env);
  }
}

static void init_log_globals() {
  if (log_globals_initialized) {
    return;
  }
  log_globals_initialized = true;
  level_map = unique_ptr<unordered_map<string, LogLevel>>(
      new unordered_map<string, LogLevel>());
  log_modules = unique_ptr<unordered_map<const void*, LogModule>>(
      new unordered_map<const void*, LogModule>());
  logging_stream = unique_ptr<stringstream>(new stringstream());

  const char* buffer = getenv("RR_LOG_BUFFER");
  if (buffer) {
    log_buffer_size = atoi(buffer);
    if (log_buffer_size) {
      log_buffer = unique_ptr<deque<char>>(new deque<char>());
    }
  }

  const char* filename = getenv("RR_LOG_FILE");
  ios_base::openmode log_file_open_mode = std::ofstream::out;
  if (!filename) {
    filename = getenv("RR_APPEND_LOG_FILE");
    log_file_open_mode |= std::ofstream::app;
  }
  if (filename) {
    auto file = new ofstream(filename, log_file_open_mode);
    if (!file->good()) {
      delete file;
    } else {
      log_file = file;
      atexit(flush_log_file);
    }
  }

  if (!log_file) {
    log_file = &cerr;
  }

  apply_log_spec_from_env();
}

static LogLevel get_log_level(const string& name) {
  init_log_globals();

  auto it = level_map->find(simple_to_lower(name));
  if (it == level_map->end()) {
    return default_level;
  }
  return it->second;
}

static string file_to_name(const char* file) {
  const char* base = strrchr(file, '/');
  if (base) {
    ++base;
  } else {
    base = file;
  }
  const char* dot = strrchr(base, '.');
  string r;
  if (dot) {
    r = string(base, dot - base);
  } else {
    r = string(base);
  }
  return r;
}

LogModule& get_log_module(const char* file) {
  init_log_globals();

  auto it = log_modules->find(file);
  if (it != log_modules->end()) {
    return it->second;
  }
  LogModule m;
  m.name = file_to_name(file);
  m.level = get_log_level(m.name);
  (*log_modules)[file] = m;
  return (*log_modules)[file];
}

void set_all_logging(LogLevel level) {
  default_level = level;
  level_map->clear();
  log_modules->clear();
}

void set_logging(const char* name, LogLevel level) {
  (*level_map)[simple_to_lower(name)] = level;
  log_modules->clear();
}

static const char* log_name(LogLevel level) {
  switch (level) {
    case LOG_fatal:
      return "FATAL";
    case LOG_error:
      return "ERROR";
    case LOG_warn:
      return "WARN";
    case LOG_info:
      return "INFO";
    default:
      return "???";
  }
}

ostream& log_stream() {
  init_log_globals();
  return *logging_stream;
}

static void flush_log_stream() {
  string s = logging_stream->str();
  ftrace::write(s);
  if (log_buffer) {
    size_t len = s.size();
    if (len >= log_buffer_size) {
      log_buffer->clear();
      log_buffer->insert(log_buffer->end(), s.c_str() + (len - log_buffer_size),
                         s.c_str() + len);
    } else {
      if (log_buffer->size() + len > log_buffer_size) {
        log_buffer->erase(log_buffer->begin(),
                          log_buffer->begin() +
                              (log_buffer->size() + len - log_buffer_size));
      }
      log_buffer->insert(log_buffer->end(), s.c_str(), s.c_str() + len);
    }
  } else {
    *log_file << s;
  }

  logging_stream->str(string());
}

void flush_log_buffer(unique_ptr<deque<char>> &this_log_buffer) {
  if (this_log_buffer) {
    for (char c : *this_log_buffer) {
      // We could accumulate in a string to speed things up, but this could get
      // called in low-memory situations so be safe.
      *log_file << c;
    }
    this_log_buffer->clear();
  }
}

void flush_log_buffer() {
  flush_log_buffer(log_buffer);
}

template <typename T>
static void write_prefix(T& stream, LogLevel level, const char* file, int line,
                         const char* function) {
  int err = errno;
  stream << "[" << log_name(level) << " ";
  if (level <= LOG_error) {
    stream << file << ":" << line << ":";
  }
  stream << function << "()";
  if (level <= LOG_warn && err) {
    stream << " errno: " << errno_name(err);
  }
  stream << "] ";
}

bool is_logging_enabled(LogLevel level, const char* file) {
  LogModule& m = get_log_module(file);
  return level <= m.level;
}

NewlineTerminatingOstream::NewlineTerminatingOstream(LogLevel level,
                                                     const char* file, int line,
                                                     const char* function)
    : level(level) {
  LogModule& m = get_log_module(file);
  enabled = level <= m.level;
  if (enabled) {
    if (level == LOG_debug) {
      *this << "[" << m.name << "] ";
    } else {
      write_prefix(*this, level, file, line, function);
    }
  }
}

NewlineTerminatingOstream::NewlineTerminatingOstream(LogModule** m_ptr,
                                                     LogLevel level,
                                                     const char* file, int line,
                                                     const char* function)
    : level(level) {
  if (!*m_ptr) {
    *m_ptr = &get_log_module(file);
  }
  LogModule& m = **m_ptr;
  enabled = level <= m.level;
  if (enabled) {
    if (level == LOG_debug) {
      *this << "[" << m.name << "] ";
    } else {
      write_prefix(*this, level, file, line, function);
    }
  }
}

// We try not to allocate in here.
static void dump_stack_and_abort() {
  int pipes[2];
  int ret = pipe(pipes);
  if (ret >= 0) {
    // Default pipe size is 64K which should be enough
    {
      ScopedFd write_fd(pipes[1]);
      dump_rr_stack(write_fd);
    }
    ScopedFd read_fd(pipes[0]);
    while (true) {
      char buf[1024];
      ret = read(read_fd, buf, sizeof(buf) - 1);
      if (ret <= 0) {
        break;
      }
      log_stream().write(buf, ret);
    }
  }
  flush_log_stream();
  flush_log_file();
  notifying_abort();
}

NewlineTerminatingOstream::~NewlineTerminatingOstream() {
  if (enabled) {
    log_stream() << endl;
    if (Flags::get().fatal_errors_and_warnings && level <= LOG_warn) {
      dump_stack_and_abort();
    } else {
      flush_log_stream();
    }
  }
}

CleanFatalOstream::CleanFatalOstream(const char* file, int line,
                                     const char* function) {
  errno = 0;
  write_prefix(*this, LOG_fatal, file, line, function);
}

CleanFatalOstream::~CleanFatalOstream() {
  cerr << endl;
  flush_log_stream();
  flush_log_buffer();
  exit(1);
}

FatalOstream::FatalOstream(const char* file, int line, const char* function) {
  write_prefix(*this, LOG_fatal, file, line, function);
}

FatalOstream::~FatalOstream() {
  log_stream() << endl;
  dump_stack_and_abort();
}

static const int LAST_EVENT_COUNT = 20;

static void dump_last_events(const TraceStream& trace) {
  fputs("Tail of trace dump:\n", stderr);

  DumpFlags flags;
  flags.dump_syscallbuf = true;
  flags.dump_recorded_data_metadata = true;
  flags.dump_mmaps = true;
  FrameTime end = trace.time();
  vector<string> specs;
  char buf[100];
  sprintf(buf, "%lld-%lld", (long long)(end - LAST_EVENT_COUNT), (long long)(end + 1));
  specs.push_back(string(buf));
  dump(trace.dir(), flags, specs, stderr);
}

static void start_emergency_debug(Task* t) {
  ftrace::stop();

  // Enable SIGINT in case it was disabled. Users want to be able to ctrl-C
  // out of this.
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_DFL;
  sigaction(SIGINT, &sa, nullptr);

  RecordSession* record_session = t->session().as_record();
  if (record_session) {
    record_session->close_trace_writer(TraceWriter::CLOSE_ERROR);
  }
  if (t->session().is_replaying()) {
    emergency_check_intel_pt(static_cast<ReplayTask*>(t), log_stream());
  }

  // Capture the log buffer now to prevent the log messages from the trace
  // stream read below from overwriting any data from the actual failure.
  flush_log_stream();
  std::unique_ptr<deque<char>> captured_log_buffer = std::move(log_buffer);

  TraceStream* trace_stream = t->session().trace_stream();
  if (trace_stream) {
    dump_last_events(*trace_stream);
  }

  flush_log_buffer(captured_log_buffer);

  if (probably_not_interactive() && !Flags::get().force_things &&
      !getenv("RUNNING_UNDER_TEST_MONITOR")) {
    CLEAN_FATAL()
        << "(session doesn't look interactive, aborting emergency debugging)";
  }
  if (!t->thread_group()) {
    CLEAN_FATAL() << "(task is in a bad state, aborting emergency debugging)";
  }

  emergency_debug(t);
  CLEAN_FATAL() << "Can't resume execution from invalid state";
}

EmergencyDebugOstream::EmergencyDebugOstream(bool cond, const Task* t,
                                             const char* file, int line,
                                             const char* function,
                                             const char* cond_str)
    : t(const_cast<Task*>(t)), cond(cond) {
  if (!cond) {
    write_prefix(*this, LOG_fatal, file, line, function);
    *this << "\n (task " << t->tid << " (rec:" << t->rec_tid << ") at time "
          << t->trace_time() << ")"
          << "\n -> Assertion `" << cond_str << "' failed to hold. ";
  }
}

EmergencyDebugOstream::~EmergencyDebugOstream() {
  if (!cond) {
    log_stream() << endl;
    flush_log_stream();
    t->log_pending_events();
    start_emergency_debug(t);
  }
}

ostream& operator<<(ostream& stream, const vector<uint8_t>& bytes) {
  for (uint32_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) {
      stream << ' ';
    }
    stream << HEX(bytes[i]);
  }
  return stream;
}

} // namespace rr
