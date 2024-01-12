/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RRUTIL_INTERNAL_H
#define RRUTIL_INTERNAL_H

#include "util.h"
#include "rrcalls.h"

int running_under_rr(void) {
  return 0 == syscall(SYS_rrcall_check_presence, (long)0, (long)0,
      (long)0, (long)0, (long)0, (long)0);
}

void rr_detach_teleport(void) {
  int err = syscall(SYS_rrcall_detach_teleport, (long)0, (long)0,
      (long)0, (long)0, (long)0, (long)0);
  test_assert(err == 0);
}

void rr_freeze_tid(pid_t tid, int freeze) {
  int err = syscall(SYS_rrcall_freeze_tid, tid, freeze,
      (long)0, (long)0, (long)0, (long)0);
  test_assert(err == 0 && "Failed to freeze tid");
}

#endif /* RRUTIL_INTERNAL_H */
