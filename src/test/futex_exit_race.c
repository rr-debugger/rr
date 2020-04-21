/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int futex(int* uaddr, int op, int val, const struct timespec* timeout,
                 int* uaddr2, int val2) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val2);
}

static void* do_thread(void* futex_addr) {
  futex(futex_addr, FUTEX_WAIT, 0, NULL, NULL, 0);
  return NULL;
}

#define NUM_THREADS 20

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  int* futex_addr = (int*)mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                               MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  *futex_addr = 0;

  if (fork() == 0) {
    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; ++i) {
      pthread_create(&threads[i], NULL, do_thread, futex_addr);
    }
    // Give the thredas a chance to run and block in the futex call
    for (int i = 0; i < 2*NUM_THREADS; ++i) {
      sched_yield();
    }
    futex(futex_addr, FUTEX_WAKE, NUM_THREADS + 1, NULL, NULL, 0);
    syscall(SYS_exit_group, 10);
    test_assert(0);
  }

  atomic_puts("EXIT-SUCCESS");
  int ret = futex(futex_addr, FUTEX_WAIT, 0, NULL, NULL, 0);
  // Minimize the number of instructions/syscalls between the return of that
  // futex call, to try to race the kernel to the cleanup of the child's
  // threads. In that spirit,  we don't assert ret here.
  // Rather, if the futex call failed, then `ret` will be non-zero, so we will
  // see that in the exit code.
  _exit(ret);
  test_assert(0);
}
