/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RecordTask.h"

#include "RecordSession.h"

RecordSession& RecordTask::session() const {
  return *Task::session().as_record();
}

Task* RecordTask::clone(int flags, remote_ptr<void> stack, remote_ptr<void> tls,
                        remote_ptr<int> cleartid_addr, pid_t new_tid,
                        pid_t new_rec_tid, uint32_t new_serial,
                        Session* other_session) {
  Task* t = Task::clone(flags, stack, tls, cleartid_addr, new_tid, new_rec_tid,
                        new_serial, other_session);
  if (t->session().is_recording()) {
    RecordTask* rt = static_cast<RecordTask*>(t);
    rt->priority = priority;
  }
  return t;
}

bool RecordTask::maybe_in_spinlock() {
  return time_at_start_of_last_timeslice == session().trace_writer().time() &&
         regs().matches(registers_at_start_of_last_timeslice);
}
