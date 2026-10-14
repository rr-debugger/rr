/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef SYS_futex_waitv
#define SYS_futex_waitv 449
#endif

#define RR_FUTEX2_SIZE_U32 0x02
#define RR_FUTEX2_PRIVATE 128

struct rr_futex_waitv {
  uint64_t val;
  uint64_t uaddr;
  uint32_t flags;
  uint32_t reserved;
};

/* The kernel always uses a 64-bit timespec for futex_waitv */
struct rr_kernel_timespec {
  int64_t tv_sec;
  int64_t tv_nsec;
};

static uint32_t ftx[2];

static long futex_waitv(struct rr_futex_waitv* waiters, unsigned int count,
                        struct rr_kernel_timespec* timeout) {
  return syscall(SYS_futex_waitv, waiters, count, 0, timeout, CLOCK_MONOTONIC);
}

static void init_waiters(struct rr_futex_waitv* waiters, uint32_t val) {
  int i;
  memset(waiters, 0, sizeof(*waiters) * 2);
  for (i = 0; i < 2; ++i) {
    waiters[i].val = val;
    waiters[i].uaddr = (uintptr_t)&ftx[i];
    waiters[i].flags = RR_FUTEX2_SIZE_U32 | RR_FUTEX2_PRIVATE;
  }
}

static void* waiter_thread(__attribute__((unused)) void* p) {
  struct rr_futex_waitv waiters[2];
  long ret;
  init_waiters(waiters, 0);
  ret = futex_waitv(waiters, 2, NULL);
  /* If the main thread changed ftx[1] before we started waiting, we
     get EAGAIN. */
  test_assert(ret == 1 || (ret == -1 && errno == EAGAIN && ftx[1] == 1));
  return NULL;
}

int main(void) {
  struct rr_futex_waitv waiters[2];
  struct rr_kernel_timespec timeout;
  struct timespec now;
  pthread_t thread;
  long ret;

  init_waiters(waiters, 1);
  ret = futex_waitv(waiters, 2, NULL);
  if (ret == -1 && errno == ENOSYS) {
    atomic_puts("futex_waitv not supported, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  /* Values don't match */
  test_assert(ret == -1 && errno == EAGAIN);

  init_waiters(waiters, 0);
  clock_gettime(CLOCK_MONOTONIC, &now);
  timeout.tv_sec = now.tv_sec;
  timeout.tv_nsec = now.tv_nsec + 1000000;
  if (timeout.tv_nsec >= 1000000000) {
    timeout.tv_sec++;
    timeout.tv_nsec -= 1000000000;
  }
  ret = futex_waitv(waiters, 2, &timeout);
  test_assert(ret == -1 && errno == ETIMEDOUT);

  test_assert(0 == pthread_create(&thread, NULL, waiter_thread, NULL));
  usleep(10000);
  ftx[1] = 1;
  syscall(SYS_futex, &ftx[1], FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
  test_assert(0 == pthread_join(thread, NULL));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
