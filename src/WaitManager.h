/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_WAIT_MANAGER_H_
#define RR_WAIT_MANAGER_H_

#include <unordered_map>

#include "WaitStatus.h"

namespace rr {

enum {
  // Ten years.
  WAIT_BLOCK_MAX = 315360000
};

// The problem with waiting for arbitrary tasks is that we'll reap them and that exposes us
// to pid reuse issues. So we really need to wait for non-exit only and handle exits specially,
// when we're ready and we can ensure those tasks aren't touched again.

struct WaitOptions {
  // Default options: wait for any task, block indefinitely.
  WaitOptions() :
      tid(-1),
      block_seconds(WAIT_BLOCK_MAX),
      unblock_on_other_tasks(false),
      consume(true),
      can_perform_syscall(true) {}
  // Default options, but wait for a specific task and don't stop
  // waiting if other tasks return a status.
  explicit WaitOptions(pid_t tid) :
      tid(tid),
      block_seconds(WAIT_BLOCK_MAX),
      unblock_on_other_tasks(false),
      consume(true),
      can_perform_syscall(true) {}
  // -1 to accept the status of any tid, otherwise returns only the
  // status of 'tid'.
  pid_t tid;
  // Number of seconds we should block waiting for a result.
  double block_seconds;
  // True if we should stop blocking and return WAIT_NO_STATUS if,
  // while blocking, we observe a task other than the requested task(s)
  // return a status.
  bool unblock_on_other_tasks;
  // True if we should consume the wait status. Otherwise we leave it
  // pending, either in the WaitManager (if it already was in the WaitManager)
  // or in the kernel itself. Exit status are never stashed in the WaitManager.
  bool consume;
  // True if we should allow syscalls, false if we should only return cached
  // status. If this is false, consume/block_seconds/unblock_on_other_tasks are ignored.
  bool can_perform_syscall;
};

enum WaitResultCode {
  // Got a valid WaitStatus
  WAIT_OK,
  // No matching task exists
  WAIT_NO_CHILD,
  // There is at least one matching child task but it hasn't reported a wait status.
  WAIT_NO_STATUS,
};
struct WaitResult {
  WaitResultCode code;
  // The tid for which we got a wait status, or -1 if we didn't get one.
  // If options.tid > 0 and the `options.tid` task changes its tid during the wait call,
  // e.g. due to execve tid changes, this may not match options.tid.
  pid_t tid;
  WaitStatus status;
};

// All waits must go through methods on this class.
class WaitManager {
public:
  // Wait for a WSTOPPED notification.
  static WaitResult wait_stop(const WaitOptions& options);
  // Wait for a WEXITED exit notification.
  // unblock_on_other_tasks must be false. perform_syscall must be true
  // (we only cache stops).
  // If `consume` is false then tid must be >= 0 and
  // blocking must be 0: WEXITED returns stops as well for ptracees, so if there
  // is a stop and we don't consume it we won't be able to see an exit notification
  // on that task or a different task.
  static WaitResult wait_exit(const WaitOptions& options);
  // Wait for a WSTOPPED or WEXITED notification.
  // unblock_on_other_tasks must be false. perform_syscall must be true
  // (we only cache stops).
  static WaitResult wait_stop_or_exit(const WaitOptions& options);

  // Gather stop notifications from all tasks without blocking.
  static void poll_stops();
};

}

#endif
