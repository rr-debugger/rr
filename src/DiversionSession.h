/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DIVERSION_SESSION_H_
#define RR_DIVERSION_SESSION_H_

#include "EmuFs.h"
#include "Session.h"

class ReplaySession;

/**
 * A DiversionSession lets you run task(s) forward without replay.
 * Clone a ReplaySession to a DiversionSession to execute some arbitrary
 * code for its side effects.
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
    // When status == STEP_CONTINUE
    BreakStatus break_status;
    // When status == STEP_EXITED. -1 means abnormal termination.
    int exit_code;
  };
  /**
   * Try make progress in this diversion session. Run task t if possible.
   */
  DiversionResult diversion_step(Task* t, RunCommand command = RUN_CONTINUE);

  virtual DiversionSession* as_diversion() { return this; }

private:
  friend class ReplaySession;

  DiversionSession(const ReplaySession& other);

  std::shared_ptr<EmuFs> emu_fs;
};

#endif // RR_DIVERSION_SESSION_H_
