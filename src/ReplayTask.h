/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAY_TASK_H_
#define RR_REPLAY_TASK_H_

#include "Task.h"

class ReplayTask : public Task {
public:
  ReplayTask(ReplaySession& session, pid_t _tid, pid_t _rec_tid,
             uint32_t serial, SupportedArch a);

  ReplaySession& session() const;

  enum {
    /* The x86 linux 3.5.0-36 kernel packaged with Ubuntu
     * 12.04 has been observed to mutate $esi across
     * syscall entry/exit.  (This has been verified
     * outside of rr as well; not an rr bug.)  It's not
     * clear whether this is a ptrace bug or a kernel bug,
     * but either way it's not supposed to happen.  So we
     * allow validate_args to cover up that bug. */
    IGNORE_ESI = 0x01
  };
  /** Assert that the current register values match the values in the
   *  current trace record.
   */
  void validate_regs(uint32_t flags = 0);
};

#endif /* RR_REPLAY_TASK_H_ */
