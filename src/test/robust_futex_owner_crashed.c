/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A child process crashes (SIGSEGV, which dumps core) holding a
   process-shared robust mutex while its parent is blocked in
   pthread_mutex_lock() on it. The kernel marks the mutex FUTEX_OWNER_DIED
   and wakes the parent, whose lock returns EOWNERDEAD. SIGCHLD is blocked so
   that the child's exit doesn't interrupt the parent's lock. */

struct shared {
  pthread_mutex_t mutex;
  int child_locked;
};

int main(void) {
  pthread_mutexattr_t attr;
  struct shared* s;
  sigset_t sigchld;
  pid_t parent;
  pid_t child;
  int status;

  s = (struct shared*)mmap(NULL, sizeof(*s), PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  test_assert(s != MAP_FAILED);
  test_assert(0 == pthread_mutexattr_init(&attr));
  test_assert(0 == pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED));
  test_assert(0 == pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST));
  test_assert(0 == pthread_mutex_init(&s->mutex, &attr));

  sigemptyset(&sigchld);
  sigaddset(&sigchld, SIGCHLD);
  test_assert(0 == sigprocmask(SIG_BLOCK, &sigchld, NULL));

  parent = getpid();
  test_assert(parent > 1);
  child = fork();
  test_assert(child >= 0);
  if (!child) {
    test_assert(0 == pthread_mutex_lock(&s->mutex));
    __atomic_store_n(&s->child_locked, 1, __ATOMIC_SEQ_CST);
    /* The parent sleeps only in its pthread_mutex_lock(). */
    while (get_task_state(parent) != 'S') {
      sched_yield();
    }
    *(volatile int*)NULL = 0;
    _exit(0); /* not reached */
  }

  while (!__atomic_load_n(&s->child_locked, __ATOMIC_SEQ_CST)) {
    sched_yield();
  }
  test_assert(EOWNERDEAD == pthread_mutex_lock(&s->mutex));
  test_assert(0 == pthread_mutex_consistent(&s->mutex));
  test_assert(0 == pthread_mutex_unlock(&s->mutex));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
