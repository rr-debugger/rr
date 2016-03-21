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
