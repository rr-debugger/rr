/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DIVERSION_SESSION_H_
#define RR_DIVERSION_SESSION_H_

#include "EmuFs.h"
#include "Session.h"

namespace rr {

class ReplaySession;

/**
 * A DiversionSession lets you run task(s) forward without replay.
 * Clone a ReplaySession to a DiversionSession to execute some arbitrary
 * code for its side effects.
 *
 * Diversion allows tracees to execute freely, as in "recorder"
 * mode, but doesn't attempt to record any data.  Diverter
 * emulates the syscalls it's able to (such as writes to stdio fds),
 * and essentially ignores the syscalls it doesn't know how to
 * implement.  Tracees can easily get into inconsistent states within
 * diversion mode, and no attempt is made to detect or rectify that.
 *
 * Diverter mode is designed to support short-lived diversions from
 * "replayer" sessions, as required to support gdb's |call foo()|
 * feature.  A diversion is created for the call frame, then discarded
 * when the call finishes (loosely speaking).
 */
class DiversionSession : public Session {
public:
  typedef std::shared_ptr<DiversionSession> shr_ptr;

  ~DiversionSession();

  EmuFs& emufs() const { return *emu_fs; }

  enum DiversionStatus {
    // Some execution was done. diversion_step() can be called again.
    DIVERSION_CONTINUE,
    // All tracees are dead. diversion_step() should not be called again.
    DIVERSION_EXITED
  };
  struct DiversionResult {
    DiversionStatus status;
    BreakStatus break_status;
  };
  /**
   * Try make progress in this diversion session. Run task t if possible.
   */
  DiversionResult diversion_step(Task* t, RunCommand command = RUN_CONTINUE,
                                 int signal_to_deliver = 0);

  virtual DiversionSession* as_diversion() override { return this; }

private:
  friend class ReplaySession;

  DiversionSession();

  std::shared_ptr<EmuFs> emu_fs;
};

} // namespace rr

#endif // RR_DIVERSION_SESSION_H_
