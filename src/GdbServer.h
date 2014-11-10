/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_GDB_SERVER_H_
#define RR_GDB_SERVER_H_

#include <map>
#include <memory>
#include <string>

#include "DiversionSession.h"
#include "GdbContext.h"
#include "ReplaySession.h"
#include "ScopedFd.h"

class GdbServer {
public:
  GdbServer() : diversion_refcount(0) {}

  GdbRequest process_debugger_requests(GdbContext& dbg, Task* t);
  void serve_replay_with_debugger(const std::string& trace_dir,
                                  ScopedFd* debugger_params_write_pipe);

  static void launch_gdb(ScopedFd& params_pipe_fd);

private:
  void maybe_singlestep_for_event(Task* t, GdbRequest* req);
  /**
   * If |req| is a magic-write command, interpret it and return true.
   * Otherwise, do nothing and return false.
   */
  bool maybe_process_magic_command(Task* t, GdbContext& dbg,
                                   const GdbRequest& req);
  /**
   * Process the single debugger request |req|, made by |dbg| targeting
   * |t|, inside the session |session|.
   *
   * Callers should implement any special semantics they want for
   * particular debugger requests before calling this helper, to do
   * generic processing.
   */
  void dispatch_debugger_request(Session& session, GdbContext& dbg, Task* t,
                                 const GdbRequest& req);
  /**
   * If the trace has reached the event at which the user wanted a debugger
   * started, then create one and store it in `dbg` if we don't already
   * have one there, and return true. Otherwise return false.
   *
   * This must be called before scheduling the task for the next event
   * (and thereby mutating the TraceIfstream for that event).
   */
  bool maybe_connect_debugger(std::unique_ptr<GdbContext>* dbg,
                              ScopedFd* debugger_params_write_pipe);
  void restart_session(GdbContext& dbg, GdbRequest* req, bool* debugger_active);
  void replay_one_step(GdbContext* dbg, GdbRequest* restart_request);

  /**
   * Process debugger requests made through |dbg| in
   * |diversion_session| until action needs to
   * be taken by the caller (a resume-execution request is received).
   * The returned Task* is the target of the resume-execution request.
   *
   * The received request is returned through |req|.
   */
  Task* diverter_process_debugger_requests(GdbContext& dbg, Task* t,
                                           GdbRequest* req);
  /**
   * Create a new diversion session using |replay| session as the
   * template.  The |replay| session isn't mutated.
   *
   * Execution begins in the new diversion session under the control of
   * |dbg| starting with initial thread target |task|.  The diversion
   * session ends at the request of |dbg|, and |req| returns the first
   * request made that wasn't handled by the diversion session.  That
   * is, the first request that should be handled by |replay| upon
   * resuming execution in that session.
   */
  void divert(ReplaySession& replay, GdbContext& dbg, pid_t task,
              GdbRequest* req);

  /**
   * Return the checkpoint stored as |checkpoint_id| or nullptr if there
   * isn't one.
   */
  ReplaySession::shr_ptr get_checkpoint(int checkpoint_id);

  /**
   * Delete the checkpoint stored as |checkpoint_id| if it exists, or do
   * nothing if it doesn't exist.
   */
  void delete_checkpoint(int checkpoint_id);

  // |session| is used to drive replay.
  ReplaySession::shr_ptr session;
  // If we're being controlled by a debugger, then |last_debugger_start| is
  // the saved session we forked 'session' from.
  ReplaySession::shr_ptr debugger_restart_checkpoint;
  // Checkpoints, indexed by checkpoint ID
  std::map<int, ReplaySession::shr_ptr> checkpoints;

  // The diversion session.
  DiversionSession::shr_ptr diversion_session;
  // Number of client references to diversion_session.
  // When there are 0 refs it is considered to be dying.
  int diversion_refcount;
};

#endif /* RR_GDB_SERVER_H_ */
