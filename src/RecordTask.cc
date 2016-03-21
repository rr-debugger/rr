/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RecordTask.h"

#include <sys/syscall.h>

#include "log.h"
#include "RecordSession.h"
#include "record_signal.h"

RecordTask::~RecordTask() {
  if (emulated_ptracer) {
    emulated_ptracer->emulated_ptrace_tracees.erase(this);
  }
  for (RecordTask* t : emulated_ptrace_tracees) {
    // XXX emulate PTRACE_O_EXITKILL
    ASSERT(this, t->emulated_ptracer == this);
    t->emulated_ptracer = nullptr;
    t->emulated_stop_type = NOT_STOPPED;
  }
}

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

void RecordTask::signal_delivered(int sig) {
  Task::signal_delivered(sig);

  send_synthetic_SIGCHLD_if_necessary();
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

void RecordTask::send_synthetic_SIGCHLD_if_necessary() {
  RecordTask* wake_task = nullptr;
  bool need_signal = false;
  for (RecordTask* tracee : emulated_ptrace_tracees) {
    if (tracee->emulated_ptrace_SIGCHLD_pending) {
      need_signal = true;
      // check to see if any thread in the ptracer process is in a waitpid that
      // could read the status of 'tracee'. If it is, we should wake up that
      // thread. Otherwise we send SIGCHLD to the ptracer thread.
      for (Task* t : task_group()->task_set()) {
        auto rt = static_cast<RecordTask*>(t);
        if (rt->is_waiting_for_ptrace(tracee)) {
          wake_task = rt;
          break;
        }
      }
      if (wake_task) {
        break;
      }
    }
  }
  if (!need_signal) {
    return;
  }

  // ptrace events trigger SIGCHLD in the ptracer's wake_task.
  // We can't set all the siginfo values to their correct values here, so
  // we'll patch this up when the signal is received.
  // If there's already a pending SIGCHLD, this signal will be ignored,
  // but at some point the pending SIGCHLD will be delivered and then
  // send_synthetic_SIGCHLD_if_necessary will be called again to deliver a new
  // SIGCHLD if necessary.
  siginfo_t si;
  memset(&si, 0, sizeof(si));
  si.si_code = SI_QUEUE;
  si.si_value.sival_int = SIGCHLD_SYNTHETIC;
  int ret;
  if (wake_task) {
    ASSERT(wake_task, !wake_task->is_sig_blocked(SIGCHLD))
        << "Waiting task has SIGCHLD blocked so we have no way to wake it up "
           ":-(";
    // We must use the raw SYS_rt_tgsigqueueinfo syscall here to ensure the
    // signal is sent to the correct thread by tid.
    ret = syscall(SYS_rt_tgsigqueueinfo, wake_task->tgid(), wake_task->tid,
                  SIGCHLD, &si);
    LOG(debug) << "Sending synthetic SIGCHLD to tid " << wake_task->tid;
  } else {
    // Send the signal to the process as a whole and let the kernel
    // decide which thread gets it.
    ret = syscall(SYS_rt_sigqueueinfo, tgid(), SIGCHLD, &si);
    LOG(debug) << "Sending synthetic SIGCHLD to pid " << tgid();
  }
  ASSERT(this, ret == 0);
}

void RecordTask::set_siginfo_for_synthetic_SIGCHLD(siginfo_t* si) {
  if (si->si_signo != SIGCHLD || si->si_value.sival_int != SIGCHLD_SYNTHETIC) {
    return;
  }

  for (RecordTask* tracee : emulated_ptrace_tracees) {
    if (tracee->emulated_ptrace_SIGCHLD_pending) {
      tracee->emulated_ptrace_SIGCHLD_pending = false;
      si->si_code = CLD_TRAPPED;
      si->si_pid = tracee->tgid();
      si->si_uid = tracee->getuid();
      si->si_status = WSTOPSIG(tracee->emulated_ptrace_stop_code);
      si->si_value.sival_int = 0;
      return;
    }
  }
}

bool RecordTask::is_waiting_for_ptrace(RecordTask* t) {
  // This task's process must be a ptracer of t.
  if (!t->emulated_ptracer ||
      t->emulated_ptracer->task_group() != task_group()) {
    return false;
  }
  switch (in_wait_type) {
    case WAIT_TYPE_NONE:
      return false;
    case WAIT_TYPE_ANY:
      return true;
    case WAIT_TYPE_SAME_PGID:
      return getpgid(t->tgid()) == getpgid(tgid());
    case WAIT_TYPE_PGID:
      return getpgid(t->tgid()) == in_wait_pid;
    case WAIT_TYPE_PID:
      // When waiting for a ptracee, a specific pid is interpreted as the
      // exact tid.
      return t->tid == in_wait_pid;
    default:
      ASSERT(this, false);
      return false;
  }
}

bool RecordTask::is_waiting_for(RecordTask* t) {
  // t must be a child of this task.
  if (t->task_group()->parent() != task_group().get()) {
    return false;
  }
  switch (in_wait_type) {
    case WAIT_TYPE_NONE:
      return false;
    case WAIT_TYPE_ANY:
      return true;
    case WAIT_TYPE_SAME_PGID:
      return getpgid(t->tgid()) == getpgid(tgid());
    case WAIT_TYPE_PGID:
      return getpgid(t->tgid()) == in_wait_pid;
    case WAIT_TYPE_PID:
      return t->tgid() == in_wait_pid;
    default:
      ASSERT(this, false);
      return false;
  }
}

bool RecordTask::may_be_blocked() const {
  return (EV_SYSCALL == ev().type() &&
          PROCESSING_SYSCALL == ev().Syscall().state) ||
         emulated_stop_type != NOT_STOPPED;
}

bool RecordTask::maybe_in_spinlock() {
  return time_at_start_of_last_timeslice == session().trace_writer().time() &&
         regs().matches(registers_at_start_of_last_timeslice);
}
