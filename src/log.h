/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_LOG_H
#define RR_LOG_H

#include <iostream>
#include <vector>

#include "Flags.h"
#include "task.h"

enum LogLevel { LOG_fatal, LOG_error, LOG_warn, LOG_info, LOG_debug };

inline static bool logging_enabled_for(LogLevel level) {
  switch (level) {
    case LOG_fatal:
    case LOG_error:
      return true;
    case LOG_warn:
    case LOG_info:
      return Flags::get().verbose;
    case LOG_debug:
// TODO make me dynamically-enable-able.
#ifdef DEBUGTAG
      return true;
#else
      return false;
#endif
    default:
      return false; // not reached
  }
}

inline static const char* log_name(LogLevel level) {
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

/**
 * Return the ostream to which log data will be written.
 *
 * Users can #define LOG_PATH to an arbitrary path, like
 * "/tmp/foo.log", to send data to that file instead of the default
 * stream (stderr).
 */
inline static std::ostream& log_stream() {
#ifdef LOG_PATH
  static std::ofstream log(LOG_PATH);
  return log;
#else
  return std::cerr;
#endif
}

void operator<<(std::ostream& stream, const std::vector<uint8_t>& bytes);

struct NewlineTerminatingOstream {
  NewlineTerminatingOstream(LogLevel level) : level(level) {}
  ~NewlineTerminatingOstream() {
    log_stream() << std::endl;
    if (Flags::get().fatal_errors_and_warnings && level <= LOG_warn) {
      abort();
    }
  }

  operator std::ostream&() { return log_stream(); }

  LogLevel level;
};
template <typename T>
NewlineTerminatingOstream& operator<<(NewlineTerminatingOstream& stream,
                                      const T& v) {
  log_stream() << v;
  return stream;
}
// TODO: support stream modifiers.

struct FatalOstream {
  ~FatalOstream() {
    log_stream() << std::endl;
    abort();
  }
};
template <typename T>
FatalOstream& operator<<(FatalOstream& stream, const T& v) {
  log_stream() << v;
  return stream;
}

struct EmergencyDebugOstream {
  EmergencyDebugOstream(const Task* t) : t(const_cast<Task*>(t)) {}
  ~EmergencyDebugOstream();
  Task* t;
};
template <typename T>
EmergencyDebugOstream& operator<<(EmergencyDebugOstream& stream, const T& v) {
  log_stream() << v;
  return stream;
}

template <typename T>
inline static T& prepare_log_stream(T&& stream, LogLevel level,
                                    const char* file, int line,
                                    const char* function,
                                    const Task* t = nullptr,
                                    const char* pfx = nullptr) {
  int err = errno;
#ifdef DEBUGTAG
  if (LOG_debug == level) {
#ifdef LOG_STREAM
    return LOG_STREAM << "[" << DEBUGTAG << "] ";
#else
    return stream << "[" << DEBUGTAG << "] ";
#endif
  }
#endif // DEBUGTAG

  stream << "[" << log_name(level) << " ";
  if (level <= LOG_error) {
    stream << file << ":" << line << ":";
  }
  stream << function << "()";
  if (level <= LOG_warn) {
    stream << " errno: " << err << " '" << strerror(err) << "'";
  }
  stream << "] ";
  if (t) {
    stream << "\n (task " << t->tid << " (rec:" << t->rec_tid << ") at time "
           << t->trace_time() << ")";
  }
  if (level <= LOG_error) {
    stream << "\n -> ";
  }
  if (pfx) {
    stream << pfx;
  }
  return stream;
}

/**
 * Write logging output at the given level, which can be one of |{
 * error, warn, info, debug }| in decreasing order of severity.
 */
#define LOG(_level)                                                            \
  if (logging_enabled_for(LOG_##_level))                                       \
  prepare_log_stream(NewlineTerminatingOstream(LOG_##_level), LOG_##_level,    \
                     __FILE__, __LINE__, __FUNCTION__)

/** A fatal error has occurred.  Log the error and exit. */
#define FATAL()                                                                \
  prepare_log_stream(FatalOstream(), LOG_fatal, __FILE__, __LINE__,            \
                     __FUNCTION__)

/**
 * Assert a condition related to a Task.  If the condition fails, an
 * emergency debugger for the task is launched.
 */
#define ASSERT(_t, _cond)                                                      \
  if (!(_cond))                                                                \
  prepare_log_stream(EmergencyDebugOstream(_t), LOG_fatal, __FILE__, __LINE__, \
                     __FUNCTION__, (_t),                                       \
                     " Assertion `" #_cond "' failed to hold. ")

/**
 * Ensure that |_v| is streamed in hex format.
 * We make sure that signed types are *not* sign-extended.
 */
inline void* HEX(uint64_t v) { return reinterpret_cast<void*>(v); }
inline void* HEX(int64_t v) { return reinterpret_cast<void*>(v); }
inline void* HEX(uint32_t v) { return reinterpret_cast<void*>(v); }
inline void* HEX(int32_t v) { return reinterpret_cast<void*>(uint32_t(v)); }

#endif // RR_LOG_H
