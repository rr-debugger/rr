/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static int var;

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static void mutate_var(void) {
  var = 22;
  atomic_printf("var is %d\n", var);
}

static void print_nums(void) {
  int i;
  for (i = 1; i <= 5; ++i) {
    atomic_printf("%d ", i);
  }
  atomic_puts("");
}

static void alloc_and_print(void) {
  static const int num_bytes = 4096;
  char* str = mmap(NULL, num_bytes, PROT_WRITE | PROT_READ,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  snprintf(str, num_bytes, "Hello %d", var);
  atomic_puts(str);

  munmap(str, num_bytes);
}

static void make_unhandled_syscall(void) {
  ssize_t ret = kill(getpid(), SIGKILL);
  /* XXX the error return is somewhat arbitrary here, but as
   * long as |splice()| remains unimplemented in experiment
   * mode, it's reasonable to assume that the libc wrapper will
   * return -1 back to us. */
  atomic_printf("return from kill: %zd\n", ret);
}

static void print_time(void) {
  struct timespec ts = { -1, -1 };
  double now_sec;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  now_sec = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
  atomic_printf("now is %g sec\n", now_sec);
}

int main(void) {
  var = -42;

  breakpoint();

  atomic_printf("var is %d\n", var);
  test_assert(var == -42);

  atomic_puts("EXIT-SUCCESS");
  return 0;

  /* not reached */
  mutate_var();
  print_nums();
  alloc_and_print();
  make_unhandled_syscall();
  print_time();
}
