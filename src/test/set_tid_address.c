/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int v;
static int* p;
static int pipe_fds[2];

static void* run_thread(__attribute__((unused)) void* p) {
  char ch;
  test_assert(1 == read(pipe_fds[0], &ch, 1));
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

  test_assert(0 == pipe(pipe_fds));

  v = 1;
  pthread_create(&thread, NULL, run_thread, NULL);
  test_assert(1 == write(pipe_fds[1], "x", 1));
  int ret = syscall(SYS_futex, &v, FUTEX_WAIT, 1, NULL, NULL, 0);
  // The above is slightly racy. If the thread finishes before we enter
  // the syscall we will exit with EAGAIN. This is unfortunate, but there
  // is no much we can do. Luckily this failure mode is different from
  // the one we really care about (the FUTEX_WAKE not happening), which
  // would manifest itself as a hang in the call above.
  test_assert(0 == ret || (-1 == ret && errno == EAGAIN));
  test_assert(0 == v);

  size_t page_size = sysconf(_SC_PAGESIZE);
  p = mmap(NULL, page_size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);
  test_assert(0 == munmap(p, page_size));

  pthread_create(&thread, NULL, run_thread2, NULL);
  test_assert(1 == read(pipe_fds[0], &ch, 1));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
