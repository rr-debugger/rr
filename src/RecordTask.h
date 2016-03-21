/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RECORD_TASK_H_
#define RR_RECORD_TASK_H_

#include "Task.h"

class RecordTask : public Task {
public:
  RecordTask(Session& session, pid_t _tid, pid_t _rec_tid, uint32_t serial,
             int _priority, SupportedArch a)
      : Task(session, _tid, _rec_tid, serial, _priority, a) {}
};

#endif /* RR_RECORD_TASK_H_ */
