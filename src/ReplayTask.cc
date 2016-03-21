/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ReplayTask.h"

#include "log.h"
#include "ReplaySession.h"

using namespace rr;
using namespace std;

ReplayTask::ReplayTask(ReplaySession& session, pid_t _tid, pid_t _rec_tid,
                       uint32_t serial, SupportedArch a)
    : Task(session, _tid, _rec_tid, serial, a) {}

ReplaySession& ReplayTask::session() const {
  return *Task::session().as_replay();
}

void ReplayTask::validate_regs(uint32_t flags) {
  /* don't validate anything before execve is done as the actual
   * process did not start prior to this point */
  if (!session().done_initial_exec()) {
    return;
  }

  Registers rec_regs = current_trace_frame().regs();

  if (flags & IGNORE_ESI) {
    if (regs().arg4() != rec_regs.arg4()) {
      LOG(warn) << "Probably saw kernel bug mutating $esi across pread/write64 "
                   "call: recorded:"
                << HEX(rec_regs.arg4()) << "; replaying:" << regs().arg4()
                << ".  Fudging registers.";
      rec_regs.set_arg4(regs().arg4());
    }
  }

  /* TODO: add perf counter validations (hw int, page faults, insts) */
  Registers::compare_register_files(this, "replaying", regs(), "recorded",
                                    rec_regs, BAIL_ON_MISMATCH);
}

const TraceFrame& ReplayTask::current_trace_frame() {
  return replay_session().current_trace_frame();
}

ssize_t ReplayTask::set_data_from_trace() {
  auto buf = trace_reader().read_raw_data();
  if (!buf.addr.is_null() && buf.data.size() > 0) {
    write_bytes_helper(buf.addr, buf.data.size(), buf.data.data());
  }
  return buf.data.size();
}

void ReplayTask::apply_all_data_records_from_trace() {
  TraceReader::RawData buf;
  while (trace_reader().read_raw_data_for_frame(current_trace_frame(), buf)) {
    if (!buf.addr.is_null() && buf.data.size() > 0) {
      write_bytes_helper(buf.addr, buf.data.size(), buf.data.data());
    }
  }
}

void ReplayTask::set_return_value_from_trace() {
  Registers r = regs();
  r.set_syscall_result(current_trace_frame().regs().syscall_result());
  // In some cases (e.g. syscalls forced to return an error by tracee
  // seccomp filters) we need to emulate a change to the original_syscallno
  // (to -1 in that case).
  r.set_original_syscallno(current_trace_frame().regs().original_syscallno());
  set_regs(r);
}
