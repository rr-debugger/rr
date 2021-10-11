/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_LOG_H
#define RR_LOG_H

#include <features.h>

#include <iostream>
#include <type_traits>
#include <vector>

namespace rr {

class Task;

enum LogLevel { LOG_fatal, LOG_error, LOG_warn, LOG_info, LOG_debug };

/* A log module is just a string where any uppercase ASCII characters have
 * been lowercased. We assign a LogLevel for each log module; this assignment
 * can be configured via the `RR_LOG` environment variable and also modified
 * dynamically.
 *
 * We derive a log module name from a source file name (typically given in
 * __FILE__) by chopping off any directory parts and chopping off the trailing
 * file extension (if any), and lowercasing any uppercase ASCII characters.
 * e.g. <rr-dir>/src/Task.cc becomes the log module "task".
 *
 * This logging infrastructure is not thread safe. Use only on the main thread.
 */

/**
 * Return the ostream to which log data will be written.
 */
std::ostream& log_stream();

/**
 * Dynamically set all log levels to 'level'
 */
void set_all_logging(LogLevel level);

/**
 * Set log level for 'name' to 'level'
 */
void set_logging(const char* name, LogLevel level);

std::ostream& operator<<(std::ostream& stream,
                         const std::vector<uint8_t>& bytes);

std::ostream& operator<<(std::ostream& stream,
                         const std::vector<uint8_t>& bytes);

/**
 * Check whether logging is enabled for the given source file.
 * `file` must be a pointer that is valid forever, preferably
 * some value of `__FILE__`.
 */
bool is_logging_enabled(LogLevel level, const char* file);

/**
 * Flush the current log message in log_stream() to the log
 * output file or circular buffer.
 */
void flush_log_buffer();

struct NewlineTerminatingOstream {
  /**
   * `file` must be a pointer that is valid forever, preferably
   * some value of `__FILE__`.
   */
  NewlineTerminatingOstream(LogLevel level, const char* file, int line,
                            const char* function);
  ~NewlineTerminatingOstream();

  bool enabled;
  LogLevel level;
};
template <typename T>
const NewlineTerminatingOstream& operator<<(
    const NewlineTerminatingOstream& stream, const T& v) {
  if (stream.enabled) {
    log_stream() << v;
  }
  return stream;
}
// TODO: support stream modifiers.

/**
 * Print clean fatal errors. These include the file, line and function name
 * but not errno or a stack trace. They go to stderr instead of the log file.
 */
struct CleanFatalOstream {
  /**
   * `file` must be a pointer that is valid forever, preferably
   * some value of `__FILE__`.
   */
  CleanFatalOstream(const char* file, int line, const char* function);
  ~CleanFatalOstream();
};
template <typename T>
const CleanFatalOstream& operator<<(const CleanFatalOstream& stream,
                                    const T& v) {
  std::cerr << v;
  return stream;
}

/**
 * Print detailed fatal errors. These include the file, line and function name
 * plus errno and a stack trace. Used for fatal errors where detailed
 * diagnostics may be required.
 */
struct FatalOstream {
  FatalOstream(const char* file, int line, const char* function);
  ~FatalOstream();
};
template <typename T>
const FatalOstream& operator<<(const FatalOstream& stream, const T& v) {
  log_stream() << v;
  return stream;
}

struct EmergencyDebugOstream {
  /**
   * `file` must be a pointer that is valid forever, preferably
   * some value of `__FILE__`.
   */
  EmergencyDebugOstream(bool cond, const Task* t, const char* file, int line,
                        const char* function, const char* cond_str);
  ~EmergencyDebugOstream();
  Task* t;
  bool cond;
};
template <typename T>
const EmergencyDebugOstream& operator<<(const EmergencyDebugOstream& stream,
                                        const T& v) {
  if (!stream.cond) {
    log_stream() << v;
  }
  return stream;
}

/**
 * Write logging output at the given level, which can be one of |{
 * error, warn, info, debug }| in decreasing order of severity.
 */
#define LOG(_level)                                                            \
  NewlineTerminatingOstream(LOG_##_level, __FILE__, __LINE__, __FUNCTION__)

#define IS_LOGGING(_level) is_logging_enabled(LOG_##_level, __FILE__)

/** A fatal error has occurred.  Log the error and exit. */
#define FATAL() FatalOstream(__FILE__, __LINE__, __FUNCTION__)

#define CLEAN_FATAL() CleanFatalOstream(__FILE__, __LINE__, __FUNCTION__)

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif
#if __has_builtin(__builtin_expect) || __GNUC_PREREQ(4, 0)
#define RR_UNLIKELY(EXPR) __builtin_expect((bool)(EXPR), false)
#else
#define RR_UNLIKELY(EXPR) (EXPR)
#endif

/**
 * Assert a condition related to a Task.  If the condition fails, an
 * emergency debugger for the task is launched.
 */
#define ASSERT(_t, _cond)                                                      \
  EmergencyDebugOstream(_cond, _t, __FILE__, __LINE__, __FUNCTION__, #_cond)
#define ASSERT_ACTIONS(_t, _cond, _actions)                                    \
  do {                                                                         \
    bool _ASSERT_cond = _cond;                                                 \
    if (RR_UNLIKELY(!_ASSERT_cond)) {                                          \
      EmergencyDebugOstream(_ASSERT_cond, _t, __FILE__, __LINE__,              \
                            __FUNCTION__, #_cond) _actions;                    \
    }                                                                          \
  } while (0)

/**
 * Ensure that |_v| is streamed in hex format.
 * We make sure that signed types are *not* sign-extended.
 */
template <typename T> inline void* HEX(T v) {
  return reinterpret_cast<void*>(
      static_cast<typename std::make_unsigned<T>::type>(v));
}

} // namespace rr

#endif // RR_LOG_H
