/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_GDB_SERVER_H_
#define RR_GDB_SERVER_H_

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "AddressSpace.h"
#include "DiversionSession.h"
#include "GdbServerConnection.h"
#include "ReplaySession.h"
#include "ReplayTimeline.h"
#include "ScopedFd.h"
#ifdef PROC_SERVICE_H
#include "ThreadDb.h"
#endif
#include "TraceFrame.h"

namespace rr {

class GdbServer {
  // Not ideal but we can't inherit friend from DebuggerExtensionCommand
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
    bool serve_files;
    // If non-null, then when the gdbserver is set up, we write its connection
    // parameters through this pipe. GdbServer::launch_gdb is passed the
    // other end of this pipe to exec gdb with the parameters.
    ScopedFd* debugger_params_write_pipe;
    // Name of the debugger to suggest. Only used if debugger_params_write_pipe
    // is null.
    std::string debugger_name;

    ConnectionFlags();
  };

  /**
   * Serve the replay of 'session'.
   * When `stop_replaying_to_target` is non-null, setting it to true
   * (e.g. in a signal handler) will interrupt the replay.
   * Returns only when the debugger disconnects.
   */
  static void serve_replay(std::shared_ptr<ReplaySession> session,
                           const Target& target,
                           volatile bool* stop_replaying_to_target,
                           const ConnectionFlags& flags);

  /**
   * Return the register |which|, which may not have a defined value.
   */
  static GdbServerRegisterValue get_reg(const Registers& regs,
                                  const ExtraRegisters& extra_regs,
                                  GdbServerRegister which);

  // Null if this is an emergency debug session.
  ReplayTimeline* timeline() { return timeline_; }

  static void serve_emergency_debugger(
        std::unique_ptr<GdbServerConnection> dbg, Task* t) {
    GdbServer(dbg, t, nullptr, Target()).process_debugger_requests();
  }

private:
  GdbServer(std::unique_ptr<GdbServerConnection>& connection, Task* t,
            ReplayTimeline* timeline, const Target& target);

  Session& current_session() {
    return timeline_ ? timeline_->current_session() :
        *emergency_debug_session;
  }
  ReplayTask* require_timeline_current_task();

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
  void maybe_notify_stop(const Session& session,
                         const GdbRequest& req,
                         const BreakStatus& break_status);

  void notify_stop_internal(const Session& session,
                            ExtendedTaskId which, int sig,
                            const std::string& reason = std::string());

  /**
   * Return the checkpoint stored as |checkpoint_id| or nullptr if there
   * isn't one.
   */
  ReplaySession::shr_ptr get_checkpoint(int checkpoint_id);

  /**
   * Handle GDB file open requests. If we can serve this read request, add
   * an entry to `files` with the file contents and return our internal
   * file descriptor.
   */
  int open_file(Session& session, Task *continue_task, const std::string& file_name);

  /**
   * Allocates debugger-owned memory region.
   * We pretend this memory exists in all sessions, but it actually only
   * exists in diversion sessions. When there is no diversion session,
   * we divert reads and writes to it to our internal storage.
   * During a diversion, the diversion session is the source of truth
   * and all reads and writes should go directly to the session.
   * If the diversion exits normally we update the memory values from
   * the diversion session, but if it crashes, we don't.
   */
  remote_ptr<void> allocate_debugger_mem(ThreadGroupUid tguid,
                                         size_t size, int prot);
  /**
   * Frees a debugger-owned memory region. Returns 0
   * if there is no such region, otherwise returns the size
   * of the freed region.
   */
  size_t free_debugger_mem(ThreadGroupUid tguid, remote_ptr<void> addr);
  // If the address is in debugger memory, return its size and prot and
  // return true.
  // Otherwise returns false.
  bool debugger_mem_region(ThreadGroupUid tguid, remote_ptr<void> addr, int* prot,
                           MemoryRange* mem_range);
  // Read from debugger memory. Returns false if the range is not in debugger memory.
  // Fatal error if the range partially overlaps debugger memory.
  // Don't call this if the session is a diversion, read from the diversion directly
  // since it has the values.
  bool read_debugger_mem(ThreadGroupUid tguid, MemoryRange range, uint8_t* values);
  // Write to debugger memory. Returns false if the range is not in debugger memory.
  // Fatal error if the range partially overlaps debugger memory.
  // Don't call this if the session is a diversion, write to the diversion directly
  // since it has the values.
  bool write_debugger_mem(ThreadGroupUid tguid, MemoryRange range, const uint8_t* values);
  // Add mappings of the debugger memory to the session.
  // If `addr` is null then all mappings are added, otherwise only mappings
  // at that address are added.
  void map_debugger_mem(DiversionSession& session, ThreadGroupUid tguid,
                        remote_ptr<void> addr);
  // Unmap mapping of a specific debugger memory region from the session.
  void unmap_debugger_mem(DiversionSession& session,
                          ThreadGroupUid tguid, remote_ptr<void> addr,
                          size_t size);
  // Read back the contents of all debugger memory regions from the session.
  void read_back_debugger_mem(DiversionSession& session);

  // Get the last GdbServerRegister for "this" arch. If it hasn't be determined, configure it.
  GdbServerRegister arch_reg_end(SupportedArch arch) noexcept;

  // dbg is never null.
  std::unique_ptr<GdbServerConnection> dbg;
  // The ThreadGroupUid of the task being debugged.
  // This should really not be needed and should go away so we can debug
  // multiple processes.
  ThreadGroupUid debuggee_tguid;
  // What we were trying to reach.
  Target target;
  // ThreadDb for debuggee ThreadGroup
#ifdef PROC_SERVICE_H
  std::unique_ptr<ThreadDb> thread_db;
#endif
  // The last continued task.
  ExtendedTaskId last_continue_task;
  // The last queried task.
  ExtendedTaskId last_query_task;
  FrameTime final_event;
  // siginfo for last notified stop.
  siginfo_t stop_siginfo;
  bool in_debuggee_end_state;
  // True when a restart was attempted but didn't succeed.
  bool failed_restart;
  // Set to true when the user has interrupted replaying to a target event.
  volatile bool* stop_replaying_to_target;
  // True when a DREQ_INTERRUPT has been received but not handled, or when
  // we've restarted and want the first continue to be interrupted immediately.
  bool interrupt_pending;
  // True when a user has run to exit before attaching the debugger.
  bool exit_sigkill_pending;

  // Exactly one of the following two pointers is null.
  ReplayTimeline* timeline_;
  Session* emergency_debug_session;

  struct Checkpoint {
    enum Explicit { EXPLICIT, NOT_EXPLICIT };
    Checkpoint(ReplayTimeline& timeline, ExtendedTaskId last_continue_task, Explicit e,
               const std::string& where)
        : last_continue_task(last_continue_task), is_explicit(e), where(where) {
      if (e == EXPLICIT) {
        mark = timeline.add_explicit_checkpoint();
      } else {
        mark = timeline.mark();
      }
    }
    Checkpoint() : is_explicit(NOT_EXPLICIT) {}
    ReplayTimeline::Mark mark;
    ExtendedTaskId last_continue_task;
    Explicit is_explicit;
    std::string where;
  };
  // |debugger_restart_mark| is the point where we will restart from with
  // a no-op debugger "run" command.
  Checkpoint debugger_restart_checkpoint;

  // gdb checkpoints, indexed by ID
  std::map<int64_t, Checkpoint> checkpoints;

  // Set of symbols to look up, for qSymbol.
  std::set<std::string> symbols;
  // Iterator into |symbols|.
  std::set<std::string>::iterator symbols_iter;

  // Contents of opened files. Maps our internal file descriptor to a real
  // file descriptor. Exposing our real file descriptor values is probably a
  // bad idea.
  std::map<int, ScopedFd> files;
  std::map<int, FileId> memory_files;
  // The pid for gdb's last vFile:setfs
  pid_t file_scope_pid;

  // LLDB wants to allocate memory in tracees. Instead of modifying tracee ReplaySessions,
  // we store the memory outside the session and copy it into DiversionSessions as needed.
  struct DebuggerMemRegion {
    std::vector<uint8_t> values;
    int prot;
  };
  struct DebuggerMem {
    std::map<MemoryRange, DebuggerMemRegion, MappingComparator> regions;
    // Virtual memory ranges that are never used by any tracee, also excluding
    // memory used by debugger_mem and guard pages.
    ReplaySession::MemoryRanges free_memory;
    bool did_get_accurate_free_memory;
  };
  // Maps from tgid to the DebuggerMem.
  std::unordered_map<ThreadGroupUid, DebuggerMem> debugger_mem;

  struct SavedRegisters {
    Registers regs;
    ExtraRegisters extra_regs;
  };
  std::unordered_map<int, SavedRegisters> saved_register_states;

  GdbServerRegister target_regs_end = GdbServerRegister(0);
};

} // namespace rr

#endif /* RR_GDB_SERVER_H_ */
