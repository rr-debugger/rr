/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int main_to_thread_fds[2];
static int thread_to_main_fds[2];

static void breakpoint(void) {}

static void breakpoint_thread(void) {}

static size_t my_read(int fd, void* buf, size_t size) {
  size_t ret;
#ifdef __x86_64__
  __asm__("syscall\n\t"
          : "=a"(ret)
          : "a"(SYS_read), "D"(fd), "S"(buf), "d"(size)
          : "memory");
#elif defined(__i386__)
  __asm__("xchg %%ebx,%%edi\n\t"
          "int $0x80\n\t"
          "xchg %%ebx,%%edi\n\t"
          : "=a"(ret)
          : "a"(SYS_read), "c"(buf), "d"(size), "D"(fd)
          : "memory");
#elif defined(__aarch64__)
  register uint64_t x0 __asm__ ("x0") = fd;
  register void *x1 __asm__ ("x1") = buf;
  register uint64_t x2 __asm__ ("x2") = size;
  register uint64_t x8 __asm__ ("x8") = SYS_read;
  __asm__("svc #0\n\t"
          : "+r"(x0)
          : "r"(x1), "r"(x2), "r"(x8)
          : "memory");
  ret = x0;
#else
#error define syscall here
#endif
  return ret;
}

static void* do_thread(__attribute__((unused)) void* p) {
  char ch;
  breakpoint_thread();
  test_assert(1 == write(thread_to_main_fds[1], "y", 1));
  test_assert(1 == read(main_to_thread_fds[0], &ch, 1));
  return NULL;
}

int main(void) {
  pthread_t thread;
  char ch;

  test_assert(0 == pipe(thread_to_main_fds));
  test_assert(0 == pipe(main_to_thread_fds));

  pthread_create(&thread, NULL, do_thread, NULL);

  test_assert(1 == my_read(thread_to_main_fds[0], &ch, 1));
  breakpoint();
  test_assert(1 == write(main_to_thread_fds[1], "x", 1));

  pthread_join(thread, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
