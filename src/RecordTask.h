/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RECORD_TASK_H_
#define RR_RECORD_TASK_H_

#include "Registers.h"
#include "Task.h"
#include "TraceFrame.h"

class RecordTask : public Task {
public:
  RecordTask(Session& session, pid_t _tid, pid_t _rec_tid, uint32_t serial,
             SupportedArch a)
      : Task(session, _tid, _rec_tid, serial, a),
        time_at_start_of_last_timeslice(0),
        priority(0),
        in_round_robin_queue(false) {}

  virtual Task* clone(int flags, remote_ptr<void> stack, remote_ptr<void> tls,
                      remote_ptr<int> cleartid_addr, pid_t new_tid,
                      pid_t new_rec_tid, uint32_t new_serial,
                      Session* other_session);

  RecordSession& session() const;

  /**
   * Emulate 'tracer' ptracing this task.
   */
  void set_emulated_ptracer(RecordTask* tracer);
  /**
   * Call this when an event occurs that should stop a ptraced task.
   * If we're emulating ptrace of the task, stop the task and wake the ptracer
   * if it's waiting, and queue "code" as an status code to be reported to the
   * ptracer.
   * Returns true if the task is stopped-for-emulated-ptrace, false otherwise.
   */
  bool emulate_ptrace_stop(int code, EmulatedStopType stop_type);
  /**
   * Force the ptrace-stop state no matter what state the task is currently in.
   */
  void force_emulate_ptrace_stop(int code, EmulatedStopType stop_type);
  /**
   * Called when we're about to deliver a signal to this task. If it's a
   * synthetic SIGCHLD and there's a ptraced task that needs to SIGCHLD,
   * update the siginfo to reflect the status and note that that
   * ptraced task has had its SIGCHLD sent.
   */
  void set_siginfo_for_synthetic_SIGCHLD(siginfo_t* si);

  /**
   * Returns true if it looks like this task has been spinning on an atomic
   * access/lock.
   */
  bool maybe_in_spinlock();

  // Scheduler state

  Registers registers_at_start_of_last_timeslice;
  TraceFrame::Time time_at_start_of_last_timeslice;
  /* Task 'nice' value set by setpriority(2).
     We use this to drive scheduling decisions. rr's scheduler is
     deliberately simple and unfair; a task never runs as long as there's
     another runnable task with a lower nice value. */
  int priority;
  /* Tasks with in_round_robin_queue set are in the session's
   * in_round_robin_queue instead of its task_priority_set.
   */
  bool in_round_robin_queue;
};

#endif /* RR_RECORD_TASK_H_ */
