/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_CHAOSUTIL_H
#define RR_CHAOSUTIL_H

#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 2

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>

/**
 * Print the printf-like arguments to stdout as atomic-ly as we can
 * manage.  Async-signal-safe.  Does not flush stdio buffers (doing so
 * isn't signal safe).
 */
__attribute__((format(printf, 1, 2))) inline static int atomic_printf(
    const char* fmt, ...) {
  va_list args;
  char buf[1024];
  int len;

  va_start(args, fmt);
  len = vsnprintf(buf, sizeof(buf) - 1, fmt, args);
  va_end(args);
  return write(STDOUT_FILENO, buf, len);
}

inline static int check_cond(int cond) {
  if (!cond) {
    atomic_printf("FAILED: errno=%d (%s)\n", errno, strerror(errno));
  }
  return cond;
}

/**
 * Write |str| on its own line to stdout as atomic-ly as we can
 * manage.  Async-signal-safe.  Does not flush stdio buffers (doing so
 * isn't signal safe).
 */
inline static int atomic_puts(const char* str) {
  return atomic_printf("%s\n", str);
}

#define test_assert(cond)                                                      \
  do {                                                                         \
    if (!check_cond(cond))                                                     \
      abort();                                                                 \
  } while (0)

__attribute__((format(printf, 1, 2))) inline static void caught_test_failure(
    const char* fmt, ...) {
  va_list args;
  char buf[1024];
  int len;

  atomic_printf("EXIT-FAIL: ");
  va_start(args, fmt);
  len = vsnprintf(buf, sizeof(buf) - 2, fmt, args);
  va_end(args);
  buf[len] = '\n';
  if (len + 1 != write(STDOUT_FILENO, buf, len + 1)) {
    abort();
  }
  exit(77);
}

inline static double now_double(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec / 1000000000.0;
}

inline static long get_page_size(void) { return sysconf(_SC_PAGE_SIZE); }

#endif
