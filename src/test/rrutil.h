/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RRUTIL_H
#define RRUTIL_H

#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 2

/* btrfs needs NULL but doesn't #include it */
#include <stdlib.h>

#include <arpa/inet.h>
#include <asm/prctl.h>
#include <assert.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/ethtool.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/if.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <linux/random.h>
#include <linux/seccomp.h>
#include <linux/sockios.h>
#include <linux/unistd.h>
#include <linux/videodev2.h>
#include <linux/wireless.h>
#include <poll.h>
#include <pthread.h>
#include <pty.h>
#include <sched.h>
#include <signal.h>
#include <sound/asound.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <sys/file.h>
#include <sys/xattr.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/fsuid.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/quota.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/sendfile.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>
#include <utime.h>
#include <x86intrin.h>

#if defined(__i386__)
#include "SyscallEnumsForTestsX86.generated"
#elif defined(__x86_64__)
#include "SyscallEnumsForTestsX64.generated"
#else
#error Unknown architecture
#endif

#include <rr/rr.h>

typedef unsigned char uint8_t;

#define ALEN(_a) (sizeof(_a) / sizeof(_a[0]))

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

/**
 * Write |str| on its own line to stdout as atomic-ly as we can
 * manage.  Async-signal-safe.  Does not flush stdio buffers (doing so
 * isn't signal safe).
 */
inline static int atomic_puts(const char* str) {
  return atomic_printf("%s\n", str);
}

#define fprintf(...) USE_dont_write_stderr
#define printf(...) USE_atomic_printf_INSTEAD
#define puts(...) USE_atomic_puts_INSTEAD

inline static int check_cond(int cond) {
  if (!cond) {
    atomic_printf("FAILED: errno=%d (%s)\n", errno, strerror(errno));
  }
  return cond;
}

#define test_assert(cond) assert("FAILED: !" && check_cond(cond))

/**
 * Return the calling task's id.
 */
inline static pid_t sys_gettid(void) { return syscall(SYS_gettid); }

/**
 * Ensure that |len| bytes of |buf| are the same across recording and
 * replay.
 */
inline static void check_data(void* buf, size_t len) {
  syscall(SYS_write, RR_MAGIC_SAVE_DATA_FD, buf, len);
  atomic_printf("Wrote %zu bytes to magic fd\n", len);
}

/**
 * Return the current value of the time-stamp counter.
 */
inline static uint64_t rdtsc(void) { return __rdtsc(); }

/**
 * Perform some syscall that writes an event, i.e. is not syscall-buffered.
 */
inline static void event_syscall(void) { syscall(-1); }

static uint64_t GUARD_VALUE = 0xdeadbeeff00dbaad;

/**
 * Allocate 'size' bytes, fill with 'value', and place canary values before
 * and after the allocated block.
 */
inline static void* allocate_guard(size_t size, char value) {
  char* cp =
      (char*)malloc(size + 2 * sizeof(GUARD_VALUE)) + sizeof(GUARD_VALUE);
  memcpy(cp - sizeof(GUARD_VALUE), &GUARD_VALUE, sizeof(GUARD_VALUE));
  memcpy(cp + size, &GUARD_VALUE, sizeof(GUARD_VALUE));
  memset(cp, value, size);
  return cp;
}

/**
 * Verify that canary values before and after the block allocated at 'p'
 * (of size 'size') are still valid.
 */
inline static void verify_guard(size_t size, void* p) {
  char* cp = (char*)p;
  test_assert(
      memcmp(cp - sizeof(GUARD_VALUE), &GUARD_VALUE, sizeof(GUARD_VALUE)) == 0);
  test_assert(memcmp(cp + size, &GUARD_VALUE, sizeof(GUARD_VALUE)) == 0);
}

/**
 * Verify that canary values before and after the block allocated at 'p'
 * (of size 'size') are still valid, and free the block.
 */
inline static void free_guard(size_t size, void* p) {
  verify_guard(size, p);
  free((char*)p - sizeof(GUARD_VALUE));
}

inline static void crash_null_deref(void) { *(volatile int*)NULL = 0; }

#define ALLOCATE_GUARD(p, v) p = allocate_guard(sizeof(*p), v)
#define VERIFY_GUARD(p) verify_guard(sizeof(*p), p)
#define FREE_GUARD(p) free_guard(sizeof(*p), p)

#ifndef SECCOMP_SET_MODE_STRICT
#define SECCOMP_SET_MODE_STRICT 0
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

/* Old systems don't have linux/kcmp.h */
#define RR_KCMP_FILE 0
#define RR_KCMP_FILES 2

#endif /* RRUTIL_H */
