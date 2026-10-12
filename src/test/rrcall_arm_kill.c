/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* Checks what SYS_rrcall_arm_kill accepts and returns. This doesn't make rr
   kill anything: we disarm each kill point right after arming it, before we
   do anything that could reach it. rrcall_arm_kill_inherit makes rr kill,
   and the tests of the fixes that the kill points are for use the rest. */

static long arm_kill(long point, long arg, long flags, long arg4, long arg5,
                     long arg6) {
  return syscall(SYS_rrcall_arm_kill, point, arg, flags, arg4, arg5, arg6);
}

static void check_einval(long point, long flags, long arg4, long arg5,
                         long arg6) {
  test_assert(-1 == arm_kill(point, 0, flags, arg4, arg5, arg6));
  test_assert(errno == EINVAL);
}

int main(void) {
  /* No signal or syscall has this number, and no countdown gets there. */
  const long unmatched_arg = 0x7fffffff;
  long point;

  if (-1 == arm_kill(RRCALL_KILL_NONE, 0, 0, 0, 0, 0)) {
    test_assert(errno == ENOSYS);
    atomic_puts("rr isn't running");
    test_assert(-1 == arm_kill(RRCALL_KILL_NUM_POINTS, 0, 2, 1, 1, 1));
    test_assert(errno == ENOSYS);
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  for (point = RRCALL_KILL_NONE; point < RRCALL_KILL_NUM_POINTS; ++point) {
    test_assert(0 == arm_kill(point, unmatched_arg, 0, 0, 0, 0));
    test_assert(0 == arm_kill(RRCALL_KILL_NONE, 0, 0, 0, 0, 0));
    test_assert(0 == arm_kill(point, unmatched_arg, RRCALL_ARM_KILL_INHERIT,
                              0, 0, 0));
    test_assert(0 == arm_kill(RRCALL_KILL_NONE, 0, 0, 0, 0, 0));
  }

  check_einval(RRCALL_KILL_NUM_POINTS, 0, 0, 0, 0);
  check_einval(-1, 0, 0, 0, 0);
  check_einval(RRCALL_KILL_NONE, 2, 0, 0, 0);
  check_einval(RRCALL_KILL_NONE, RRCALL_ARM_KILL_INHERIT | 2, 0, 0, 0);
  check_einval(RRCALL_KILL_NONE, 0, 1, 0, 0);
  check_einval(RRCALL_KILL_NONE, 0, 0, 1, 0);
  check_einval(RRCALL_KILL_NONE, 0, 0, 0, 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
