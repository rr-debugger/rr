/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RecordTask.h"

#include "log.h"
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

void RecordTask::set_emulated_ptracer(RecordTask* tracer) {
  if (tracer) {
    ASSERT(this, !emulated_ptracer);
    emulated_ptracer = tracer;
    emulated_ptracer->emulated_ptrace_tracees.insert(this);
  } else {
    ASSERT(this, emulated_ptracer);
    ASSERT(this, emulated_stop_type == NOT_STOPPED ||
                     emulated_stop_type == GROUP_STOP);
    emulated_ptracer->emulated_ptrace_tracees.erase(this);
    emulated_ptracer = nullptr;
  }
}

bool RecordTask::emulate_ptrace_stop(int code, EmulatedStopType stop_type) {
  ASSERT(this, emulated_stop_type == NOT_STOPPED);
  ASSERT(this, stop_type != NOT_STOPPED);
  if (!emulated_ptracer) {
    return false;
  }
  force_emulate_ptrace_stop(code, stop_type);
  return true;
}

void RecordTask::force_emulate_ptrace_stop(int code,
                                           EmulatedStopType stop_type) {
  emulated_stop_type = stop_type;
  emulated_ptrace_stop_code = code;
  emulated_ptrace_SIGCHLD_pending = true;

  emulated_ptracer->send_synthetic_SIGCHLD_if_necessary();
  // The SIGCHLD will eventually be reported to rr via a ptrace stop,
  // interrupting wake_task's syscall (probably a waitpid) if necessary. At
  // that point, we'll fix up the siginfo data with values that match what
  // the kernel would have delivered for a real ptracer's SIGCHLD. When the
  // signal handler (if any) returns, if wake_task was in a blocking wait that
  // wait will be resumed, at which point rec_prepare_syscall_arch will
  // discover the pending ptrace result and emulate the wait syscall to
  // return that result immediately.
}

bool RecordTask::maybe_in_spinlock() {
  return time_at_start_of_last_timeslice == session().trace_writer().time() &&
         regs().matches(registers_at_start_of_last_timeslice);
}
