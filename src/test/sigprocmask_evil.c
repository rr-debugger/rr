/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void exit_handler(__attribute__((unused)) int sig) {
  atomic_puts("EXIT-SUCCESS");
  exit(0);
}

int main(void) {
  uint64_t old, new;
  signal(SIGSEGV, exit_handler);
  new = (uint64_t)-1;
  test_assert(0 == syscall(SYS_rt_sigprocmask, 2, &new, (void*)0, sizeof(new)));
  test_assert(new == (uint64_t)-1);
  new = 0x4226;
  test_assert(0 == syscall(SYS_rt_sigprocmask, 2, &new, (void*)0, sizeof(new)));
  test_assert(0 == syscall(SYS_rt_sigprocmask, 0, (void*)0, &old, sizeof(old)));
  new = (uint64_t)-1;
  test_assert(0 == syscall(SYS_rt_sigprocmask, 2, &new, &new, sizeof(new)));
  test_assert(new == old);
  test_assert(0 == syscall(SYS_rt_sigprocmask, 2, &new, (void*)0, sizeof(new)));
  crash_null_deref();
  test_assert(0);
}
