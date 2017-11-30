/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_GDB_SERVER_H_
#define RR_GDB_SERVER_H_

#include <map>
#include <memory>
#include <string>

#include "DiversionSession.h"
#include "GdbConnection.h"
#include "ReplaySession.h"
#include "ReplayTimeline.h"
#include "ScopedFd.h"
#include "ThreadDb.h"
#include "TraceFrame.h"

namespace rr {

static std::string localhost_addr = "127.0.0.1";

class GdbServer {
  // Not ideal but we can't inherit friend from GdbCommand
  friend std::string invoke_checkpoint(GdbServer&, Task*,
                                       const std::vector<std::string>&);
  friend std::string invoke_delete_checkpoint(GdbServer&, Task*,
                                              const std::vector<std::string>&);
  friend std::string invoke_info_checkpoints(GdbServer&, Task*,
                                             const std::vector<std::string>&);

public:
  struct Target {
    Target() : pid(0), require_exec(false), event(0) {}
    // Target process to debug, or 0 to just debug the first process
    pid_t pid;
    // If true, wait for the target process to exec() before attaching debugger
    bool require_exec;
    // Wait until at least 'event' has elapsed before attaching
    FrameTime event;
  };

  struct ConnectionFlags {
    // -1 to let GdbServer choose the port, a positive integer to select a
    // specific port to listen on. If keep_listening is on, wait for another
    // debugger connection after the first one is terminated.
    int dbg_port;
    std::string dbg_host;
    bool keep_listening;
    // If non-null, then when the gdbserver is set up, we write its connection
    // parameters through this pipe. GdbServer::launch_gdb is passed the
    // other end of this pipe to exec gdb with the parameters.
    ScopedFd* debugger_params_write_pipe;
    // Name of the debugger to suggest. Only used if debugger_params_write_pipe
    // is null.
    std::string debugger_name;

    ConnectionFlags()
        : dbg_port(-1),
          dbg_host(localhost_addr),
          keep_listening(false),
          debugger_params_write_pipe(nullptr) {}
  };

  /**
   * Create a gdbserver serving the replay of 'session'.
   */
  GdbServer(std::shared_ptr<ReplaySession> session,
            const ReplaySession::Flags& flags, const Target& target)
      : target(target),
        final_event(UINT32_MAX),
        in_debuggee_end_state(false),
        stop_replaying_to_target(false),
        interrupt_pending(false),
        timeline(std::move(session), flags),
        emergency_debug_session(nullptr) {
    memset(&stop_siginfo, 0, sizeof(stop_siginfo));
  }

  /**
   * Actually run the server. Returns only when the debugger disconnects.
   */
  void serve_replay(const ConnectionFlags& flags);

  /**
   * exec()'s gdb using parameters read from params_pipe_fd (and sent through
   * the pipe passed to serve_replay_with_debugger).
   */
  static void launch_gdb(ScopedFd& params_pipe_fd,
                         const std::string& gdb_binary_file_path,
                         const std::vector<std::string>& gdb_options);

  /**
   * Start a debugging connection for |t| and return when there are no
   * more requests to process (usually because the debugger detaches).
   *
   * This helper doesn't attempt to determine whether blocking rr on a
   * debugger connection might be a bad idea.  It will always open the debug
   * socket and block awaiting a connection.
   */
  static void emergency_debug(Task* t);

  /**
   * A string containing the default gdbinit script that we load into gdb.
   */
  static std::string init_script();

  /**
   * Called from a signal handler (or other thread) during serve_replay,
   * this will cause the replay-to-target phase to be interrupted and
   * debugging started wherever the replay happens to be.
   */
  void interrupt_replay_to_target() { stop_replaying_to_target = true; }

  /**
   * Return the register |which|, which may not have a defined value.
   */
  static GdbRegisterValue get_reg(const Registers& regs,
                                  const ExtraRegisters& extra_regs,
                                  GdbRegister which);

  ReplayTimeline& get_timeline() { return timeline; }

private:
  GdbServer(std::unique_ptr<GdbConnection>& dbg, Task* t);

  Session& current_session() {
    return timeline.is_running() ? timeline.current_session()
                                 : *emergency_debug_session;
  }

  void dispatch_regs_request(const Registers& regs,
                             const ExtraRegisters& extra_regs);
  enum ReportState { REPORT_NORMAL, REPORT_THREADS_DEAD };
  void maybe_intercept_mem_request(Task* target, const GdbRequest& req,
                                   std::vector<uint8_t>* result);
  /**
   * Process the single debugger request |req| inside the session |session|.
   *
   * Callers should implement any special semantics they want for
   * particular debugger requests before calling this helper, to do
   * generic processing.
   */
  void dispatch_debugger_request(Session& session, const GdbRequest& req,
                                 ReportState state);
  bool at_target();
  void activate_debugger();
  void restart_session(const GdbRequest& req);
  GdbRequest process_debugger_requests(ReportState state = REPORT_NORMAL);
  enum ContinueOrStop { CONTINUE_DEBUGGING, STOP_DEBUGGING };
  bool detach_or_restart(const GdbRequest& req, ContinueOrStop* s);
  ContinueOrStop handle_exited_state(GdbRequest& last_resume_request);
  ContinueOrStop debug_one_step(GdbRequest& last_resume_request);
  /**
   * If 'req' is a reverse-singlestep, try to obtain the resulting state
   * directly from ReplayTimeline's mark database. If that succeeds,
   * report the singlestep break status to gdb and process any get-registers
   * requests. Repeat until we get a request that isn't reverse-singlestep
   * or get-registers, returning that request in 'req'.
   * During reverse-next commands, gdb tends to issue a series of
   * reverse-singlestep/get-registers pairs, and this makes those much
   * more efficient by avoiding having to actually reverse-singlestep the
   * session.
   */
  void try_lazy_reverse_singlesteps(GdbRequest& req);

  /**
   * Process debugger requests made in |diversion_session| until action needs
   * to be taken by the caller (a resume-execution request is received).
   * The received request is returned through |req|.
   * Returns true if diversion should continue, false if it should end.
   */
  bool diverter_process_debugger_requests(DiversionSession& diversion_session,
                                          uint32_t& diversion_refcount,
                                          GdbRequest* req);
  /**
   * Create a new diversion session using |replay| session as the
   * template.  The |replay| session isn't mutated.
   *
   * Execution begins in the new diversion session under the control of
   * |dbg| starting with initial thread target |task|.  The diversion
   * session ends at the request of |dbg|, and |divert| returns the first
   * request made that wasn't handled by the diversion session.  That
   * is, the first request that should be handled by |replay| upon
   * resuming execution in that session.
   */
  GdbRequest divert(ReplaySession& replay);

  /**
   * If |break_status| indicates a stop that we should report to gdb,
   * report it. |req| is the resume request that generated the stop.
   */
  void maybe_notify_stop(const GdbRequest& req,
                         const BreakStatus& break_status);

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

  /**
   * Handle GDB file open requests. If we can serve this read request, add
   * an entry to `files` with the file contents and return our internal
   * file descriptor.
   */
  int open_file(Session& session, const std::string& file_name);

  Target target;
  // dbg is initially null. Once the debugger connection is established, it
  // never changes.
  std::unique_ptr<GdbConnection> dbg;
  // When dbg is non-null, the ThreadGroupUid of the task being debugged. Never
  // changes once the connection is established --- we don't currently
  // support switching gdb between debuggee processes.
  ThreadGroupUid debuggee_tguid;
  // ThreadDb for debuggee ThreadGroup
  std::unique_ptr<ThreadDb> thread_db;
  // The TaskUid of the last continued task.
  TaskUid last_continue_tuid;
  // The TaskUid of the last queried task.
  TaskUid last_query_tuid;
  FrameTime final_event;
  // siginfo for last notified stop.
  siginfo_t stop_siginfo;
  bool in_debuggee_end_state;
  // True when the user has interrupted replaying to a target event.
  volatile bool stop_replaying_to_target;
  // True when a DREQ_INTERRUPT has been received but not handled, or when
  // we've restarted and want the first continue to be interrupted immediately.
  bool interrupt_pending;

  ReplayTimeline timeline;
  Session* emergency_debug_session;

  struct Checkpoint {
    enum Explicit { EXPLICIT, NOT_EXPLICIT };
    Checkpoint(ReplayTimeline& timeline, TaskUid last_continue_tuid, Explicit e,
               const std::string& where)
        : last_continue_tuid(last_continue_tuid), is_explicit(e), where(where) {
      if (e == EXPLICIT) {
        mark = timeline.add_explicit_checkpoint();
      } else {
        mark = timeline.mark();
      }
    }
    Checkpoint() : is_explicit(NOT_EXPLICIT) {}
    ReplayTimeline::Mark mark;
    TaskUid last_continue_tuid;
    Explicit is_explicit;
    std::string where;
  };
  // |debugger_restart_mark| is the point where we will restart from with
  // a no-op debugger "run" command.
  Checkpoint debugger_restart_checkpoint;

  // gdb checkpoints, indexed by ID
  std::map<int, Checkpoint> checkpoints;

  // Set of symbols to look up, for qSymbol.
  std::set<std::string> symbols;
  // Iterator into |symbols|.
  std::set<std::string>::iterator symbols_iter;

  // Contents of opened files. Maps our internal file descriptor to a real
  // file descriptor. Exposing our real file descriptor values is probably a
  // bad idea.
  std::map<int, ScopedFd> files;
  // The pid for gdb's last vFile:setfs
  pid_t file_scope_pid;
};

} // namespace rr

#endif /* RR_GDB_SERVER_H_ */
