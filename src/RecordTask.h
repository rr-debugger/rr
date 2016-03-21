/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RECORD_TASK_H_
#define RR_RECORD_TASK_H_

#include "Registers.h"
#include "Task.h"
#include "TraceFrame.h"

class RecordTask : public Task {
public:
  RecordTask(Session& session, pid_t _tid, pid_t _rec_tid, uint32_t serial,
             int _priority, SupportedArch a)
      : Task(session, _tid, _rec_tid, serial, _priority, a),
        time_at_start_of_last_timeslice(0) {}

  RecordSession& session() const;

  /**
   * Returns true if it looks like this task has been spinning on an atomic
   * access/lock.
   */
  bool maybe_in_spinlock();

  Registers registers_at_start_of_last_timeslice;
  TraceFrame::Time time_at_start_of_last_timeslice;
};

#endif /* RR_RECORD_TASK_H_ */
