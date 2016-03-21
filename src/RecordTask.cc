/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RecordTask.h"

#include "RecordSession.h"

RecordSession& RecordTask::session() const {
  return *Task::session().as_record();
}

bool RecordTask::maybe_in_spinlock() {
  return time_at_start_of_last_timeslice == session().trace_writer().time() &&
         regs().matches(registers_at_start_of_last_timeslice);
}
