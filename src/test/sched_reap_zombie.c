/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A thread-group leader that exits before the group's other threads can't be
 * reaped until they are gone too, so rr keeps it to reap later, when the
 * scheduler picks it. If the scheduler picks it when another task's timeslice
 * expires, rr must still record that task's SCHED event: the tasks that run
 * next may run before that task continues, and replay must not run them
 * before the part of the task's execution that preceded the expiry.
 *
 * The main thread spins until the waiter thread sets `done`, which the waiter
 * does once waitpid() reports the child's exit, i.e. after rr has reaped the
 * child's leader. We arrange for rr to reap the leader when the main thread's
 * timeslice expires, and to run the waiter next:
 * - The child thread waits until the main thread is blocked, then blocks
 *   itself, so rr last ran the main thread before it.
 * - The child's leader wakes both and exits. rr runs the main thread first.
 * - The main thread calls sched_yield(), so rr runs the child thread, which
 *   exits (now the leader can be reaped), then the main thread again.
 * - The main thread spins until its timeslice expires. Then rr picks the
 *   leader (exiting tasks have the highest priority) and reaps it, which
 *   lets the waiter's waitpid() return, and runs the waiter, which sets
 *   `done`.
 * Replay must run the main thread's spin up to the expiry before the waiter's
 * store to `done`. rr doesn't always schedule as described, so we try a few
 * times. */

#define ROUNDS 4

struct waiting {
  /* Set to wake the task. */
  int go;
  /* Set by the task just before it waits for `go`. */
  pid_t tid;
};

struct shared {
  struct waiting thread;
  struct waiting main;
};

struct waiter_state {
  pid_t child;
  /* Set once waitpid() has reported the child's exit. */
  int done;
};

static void wait_for_go(struct waiting* w) {
  __atomic_store_n(&w->tid, sys_gettid(), __ATOMIC_SEQ_CST);
  while (!__atomic_load_n(&w->go, __ATOMIC_SEQ_CST)) {
    syscall(SYS_futex, &w->go, FUTEX_WAIT, 0, NULL, NULL, 0);
  }
}

static void go(struct waiting* w) {
  __atomic_store_n(&w->go, 1, __ATOMIC_SEQ_CST);
  test_assert(syscall(SYS_futex, &w->go, FUTEX_WAKE, 1, NULL, NULL, 0) >= 0);
}

/* Wait until the task that waits with `w` is blocked in its futex wait. We
 * observe that while we run, so rr last ran it before us. */
static void wait_until_waiting(struct waiting* w) {
  struct timespec ts = { 0, 1000000 };
  pid_t tid;
  while (!(tid = __atomic_load_n(&w->tid, __ATOMIC_SEQ_CST)) ||
         get_task_state(tid) != 'S') {
    nanosleep(&ts, NULL);
  }
}

static void* waiter(void* p) {
  struct waiter_state* state = p;
  pid_t child = __atomic_load_n(&state->child, __ATOMIC_SEQ_CST);
  int status;
  test_assert(child > 1);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  __atomic_store_n(&state->done, 1, __ATOMIC_SEQ_CST);
  return NULL;
}

static void* child_thread(void* p) {
  struct shared* s = p;
  wait_until_waiting(&s->main);
  wait_for_go(&s->thread);
  /* The child's last thread: the child exits with the leader's status 0. */
  syscall(SYS_exit, 0);
  return NULL;
}

static void do_round(struct shared* s) {
  struct waiter_state state;
  pthread_t thread;
  uint64_t iterations = 0;
  pid_t child;

  __atomic_store_n(&s->thread.go, 0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&s->thread.tid, 0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&s->main.go, 0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&s->main.tid, 0, __ATOMIC_SEQ_CST);
  child = fork();
  test_assert(child >= 0);
  if (!child) {
    pthread_t t;
    test_assert(0 == pthread_create(&t, NULL, child_thread, s));
    wait_until_waiting(&s->thread);
    go(&s->thread);
    go(&s->main);
    /* The thread-group leader exits first. */
    syscall(SYS_exit, 0);
    exit(1);
  }

  __atomic_store_n(&state.child, child, __ATOMIC_SEQ_CST);
  __atomic_store_n(&state.done, 0, __ATOMIC_SEQ_CST);
  test_assert(0 == pthread_create(&thread, NULL, waiter, &state));
  wait_for_go(&s->main);
  sched_yield();
  while (!__atomic_load_n(&state.done, __ATOMIC_SEQ_CST)) {
    ++iterations;
  }
  test_assert(0 == pthread_join(thread, NULL));
  atomic_printf("spun %s\n", iterations > 0 ? "a while" : "not at all");
}

int main(void) {
  struct shared* s;
  int i;

  s = (struct shared*)mmap(NULL, sizeof(*s), PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  test_assert(s != MAP_FAILED);
  for (i = 0; i < ROUNDS; ++i) {
    do_round(s);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
