/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fut = 0;
  int ret;

  ret = syscall(SYS_futex, &fut, FUTEX_LOCK_PI, (void*)0, (void*)0, 0);
  test_assert(ret == -1 && errno == ENOSYS);
  ret = syscall(SYS_futex, &fut, FUTEX_TRYLOCK_PI, (void*)0, (void*)0, 0);
  test_assert(ret == -1 && errno == ENOSYS);
  ret = syscall(SYS_futex, &fut, FUTEX_UNLOCK_PI, (void*)0, (void*)0, 0);
  test_assert(ret == -1 && errno == ENOSYS);
  ret = syscall(SYS_futex, &fut, FUTEX_CMP_REQUEUE_PI, (void*)0, (void*)0, 0);
  test_assert(ret == -1 && errno == ENOSYS);
  ret = syscall(SYS_futex, &fut, FUTEX_WAIT_REQUEUE_PI, (void*)0, (void*)0, 0);
  test_assert(ret == -1 && errno == ENOSYS);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
