/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static int v;
static int* p;
static int pipe_fds[2];

static void* run_thread(__attribute__((unused)) void* p) {
  test_assert(sys_gettid() == syscall(SYS_set_tid_address, &v));
  return NULL;
}

static void* run_thread2(__attribute__((unused)) void* q) {
  test_assert(sys_gettid() == syscall(SYS_set_tid_address, p));
  test_assert(1 == write(pipe_fds[1], "x", 1));
  return NULL;
}

int main(void) {
  pthread_t thread;
  char ch;

  v = 1;
  pthread_create(&thread, NULL, run_thread, NULL);
  test_assert(0 == syscall(SYS_futex, &v, FUTEX_WAIT, 1, NULL, NULL, 0));
  test_assert(0 == v);

  p = mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);
  test_assert(0 == munmap(p, PAGE_SIZE));

  test_assert(0 == pipe(pipe_fds));
  pthread_create(&thread, NULL, run_thread2, NULL);
  test_assert(1 == read(pipe_fds[0], &ch, 1));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
