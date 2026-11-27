/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "libc.h"

// Some headers define |fstat| as an inline function. Set aside that definition.
#define fstat __system_fstat

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "engine.h"
#include "remix_util.h"

REMIX_TARGET_BEGIN

struct stat;

namespace std {
typedef ::size_t size_t;
}

template <typename T> static T fix_result(long v) {
  if (v < 0 && v > -4096) {
    errno = -v;
    return -1;
  }
  return (T)v;
}

extern "C" {

__asm__(".text\n\t"
        ".global syscall\n\t"
        "syscall:\n\n"
        "mov %rdi,%rax\n\t"
        "mov %rsi,%rdi\n\t"
        "mov %rdx,%rsi\n\t"
        "mov %rcx,%rdx\n\t"
        "mov %r8,%r10\n\t"
        "mov %r9,%r8\n\t"
        "mov 8(%rsp),%r9\n\t"
        "syscall\n\t"
        "ret");

int futex(int* uaddr, int futex_op, int val, const struct timespec* timeout,
          int* uaddr2, int val3) {
  return fix_result<int>(
      syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3));
}

size_t strlen(const char* s) {
  size_t i;
  for (i = 0; s[i]; ++i) {
  }
  return i;
}

char* strncpy(char* dest, const char* src, size_t n) {
  char* ret = dest;
  while (n > 0) {
    *dest = *src;
    if (!*src) {
      break;
    }
    ++dest;
    ++src;
    --n;
  }
  return ret;
}

int open(const char* path, int flags, ...) {
  va_list ap;
  va_start(ap, flags);
  int mode = va_arg(ap, int);
  va_end(ap);

  return fix_result<int>(syscall(SYS_open, path, flags, mode));
}

ssize_t write(int fd, const void* buf, size_t count) {
  return fix_result<ssize_t>(syscall(SYS_write, fd, (long)buf, count));
}

ssize_t writev(int fd, const struct iovec* iov, int iovcnt) {
  return fix_result<ssize_t>(syscall(SYS_writev, fd, (long)iov, iovcnt));
}

int ftruncate(int fd, off_t length) {
  return fix_result<int>(syscall(SYS_ftruncate, fd, length));
}

#undef fstat

int fstat(int fd, struct stat* stat) {
  return fix_result<int>(syscall(SYS_fstat, fd, stat));
}

int fstat64(int fd, struct stat* stat) {
  return fix_result<int>(syscall(SYS_fstat, fd, stat));
}

int __fxstat(int, int fd, struct stat* stat) {
  return fix_result<int>(syscall(SYS_fstat, fd, stat));
}

int __fxstat64(int, int fd, struct stat64* stat) {
  return fix_result<int>(syscall(SYS_fstat, fd, stat));
}

int close(int fd) { return fix_result<int>(syscall(SYS_close, fd)); }

int mprotect(void* addr, size_t size, int prot) {
  return fix_result<int>(syscall(SYS_mprotect, addr, size, prot));
}

int rpl_vsnprintf(char* str, size_t size, const char* format, va_list args);

int vsnprintf(char* str, size_t size, const char* format, va_list args) {
  return rpl_vsnprintf(str, size, format, args);
}

int printf_internal(const char* format, va_list args) {
  char buf[0x10000];
  int ret = vsnprintf(buf, sizeof(buf), format, args);
  if (ret > (int)sizeof(buf)) {
    ret = sizeof(buf);
  }
  write(STDOUT_FILENO, buf, ret);
  return ret;
}

int printf(const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  int ret = printf_internal(format, ap);
  va_end(ap);
  return ret;
}

int printf_stderr(const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  char buf[0x10000];
  int ret = vsnprintf(buf, sizeof(buf), format, ap);
  va_end(ap);
  if (ret > (int)sizeof(buf)) {
    ret = sizeof(buf);
  }
  write(STDERR_FILENO, buf, ret);
  return ret;
}

int puts(const char* s) {
  write(STDOUT_FILENO, s, strlen(s));
  write(STDOUT_FILENO, "\n", 1);
  return 0;
}

char* strcpy(char* dst, const char* s) {
  char* d = dst;
  char ch;
  do {
    ch = *s;
    *d = ch;
    ++d;
    ++s;
  } while (ch);
  return dst;
}

int snprintf(char* buf, size_t size, const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  int ret = vsnprintf(buf, size, format, ap);
  va_end(ap);
  return ret;
}

pid_t getpid() { return syscall(SYS_getpid); }

int madvise(void* addr, size_t length, int advice) {
  return fix_result<int>(syscall(SYS_madvise, (long)addr, length, advice));
}

int kill(pid_t pid, int sig) {
  return fix_result<int>(syscall(SYS_kill, pid, sig));
}

int sched_yield() { return fix_result<int>(syscall(SYS_sched_yield)); }

void abort(void) {
  kill(getpid(), SIGABRT);
  while (1) {
  }
}

static int __errno;

int* __errno_location(void) { return &__errno; }

void __cxa_pure_virtual() { remix_abort("pure virtual function called"); }

int __printf_chk(int, const char* __restrict format, ...) {
  va_list ap;
  va_start(ap, format);
  int ret = printf_internal(format, ap);
  va_end(ap);
  return ret;
}
int __vsnprintf_chk(char* str, size_t, int, size_t size, const char* format,
                    va_list args) {
  return vsnprintf(str, size, format, args);
}
int __snprintf_chk(char* __restrict buf, size_t, int, size_t size,
                   const char* __restrict format, ...) {
  va_list ap;
  va_start(ap, format);
  int ret = vsnprintf(buf, size, format, ap);
  va_end(ap);
  return ret;
}
}

void* operator new(size_t count) { return malloc(count); }
void* operator new[](size_t count) { return malloc(count); }

void operator delete(void* ptr) noexcept { free(ptr); }
void operator delete(void* ptr, std::size_t) noexcept { free(ptr); }
void operator delete[](void* ptr) noexcept { free(ptr); }
void operator delete[](void* ptr, std::size_t) noexcept { free(ptr); }

REMIX_TARGET_END
