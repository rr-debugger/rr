/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAY_TASK_H_
#define RR_REPLAY_TASK_H_

#include "Task.h"

class ReplayTask : public Task {
public:
  ReplayTask(ReplaySession& session, pid_t _tid, pid_t _rec_tid,
             uint32_t serial, SupportedArch a);

  ReplaySession& session() const;
};

#endif /* RR_REPLAY_TASK_H_ */
