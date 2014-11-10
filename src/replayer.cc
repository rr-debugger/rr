/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "Replayer"

#include "replayer.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include <limits>
#include <map>
#include <string>
#include <vector>

#include "Event.h"
#include "GdbContext.h"
#include "kernel_abi.h"
#include "log.h"
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "task.h"
#include "util.h"

using namespace rr;
using namespace std;

/**
 * 32-bit writes to DBG_COMMAND_MAGIC_ADDRESS by the debugger trigger
 * rr commands
 */
static const uintptr_t DBG_COMMAND_MAGIC_ADDRESS = 29298; // 'rr'

/**
 * The high-order byte of the 32-bit value indicates the specific command
 * message. Not-understood command messages are ignored.
 */
static const uintptr_t DBG_COMMAND_MSG_MASK = 0xFF000000;
/**
 * Create a checkpoint of the current state whose index is given by the
 * command parameter. If there is already a checkpoint with that index, it
 * is deleted first.
 */
static const uintptr_t DBG_COMMAND_MSG_CREATE_CHECKPOINT = 0x01000000;
/**
 * Delete the checkpoint of the current state whose index is given by the
 * command parameter.
 */
static const uintptr_t DBG_COMMAND_MSG_DELETE_CHECKPOINT = 0x02000000;
static const uintptr_t DBG_COMMAND_PARAMETER_MASK = 0x00FFFFFF;

class GdbServer {
public:
  void maybe_singlestep_for_event(Task* t, GdbRequest* req);
  /**
   * If |req| is a magic-write command, interpret it and return true.
   * Otherwise, do nothing and return false.
   */
  bool maybe_process_magic_command(Task* t, GdbContext& dbg,
                                   const GdbRequest& req);
  GdbRequest process_debugger_requests(GdbContext& dbg, Task* t);
  /**
   * If the trace has reached the event at which the user wanted a debugger
   * started, then create one and store it in `dbg` if we don't already
   * have one there, and return true. Otherwise return false.
   *
   * This must be called before scheduling the task for the next event
   * (and thereby mutating the TraceIfstream for that event).
   */
  bool maybe_connect_debugger(unique_ptr<GdbContext>* dbg,
                              ScopedFd* debugger_params_write_pipe);
  void restart_session(GdbContext& dbg, GdbRequest* req,
                       bool* debugger_active);
  void serve_replay_with_debugger(const string& trace_dir,
                                  ScopedFd* debugger_params_write_pipe);

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
  map<int, ReplaySession::shr_ptr> checkpoints;
};

static GdbServer gdb_server;

// Special-sauce macros defined by rr when launching the gdb client,
// which implement functionality outside of the gdb remote protocol.
// (Don't stare at them too long or you'll go blind ;).)
//
// See #define's above for origin of magic values below.
static const char gdb_rr_macros[] =
    // TODO define `document' sections for these
    "define checkpoint\n"
    "  init-if-undefined $_next_checkpoint_index = 1\n"
    /* Ensure the command echoes the checkpoint number, not the encoded message
       */
    "  p (*(int*)29298 = 0x01000000 | $_next_checkpoint_index), "
    "$_next_checkpoint_index++\n"
    "end\n"
    "define delete checkpoint\n"
    "  p (*(int*)29298 = 0x02000000 | $arg0), $arg0\n"
    "end\n"
    "define restart\n"
    "  run c$arg0\n"
    "end\n"
    "handle SIGURG stop\n";

// The parent process waits until the server, |waiting_for_child|, creates a
// debug socket. Then the parent exec()s the debugger over itself. While it's
// waiting for the child, this is the child's pid.
// This needs to be global because it's used by a signal handler.
static pid_t waiting_for_child;

// Setting these causes us to trace instructions after
// instruction_trace_at_event_start up to and including
// instruction_trace_at_event_last
static uint64_t instruction_trace_at_event_start = 0;
static uint64_t instruction_trace_at_event_last = 0;

/**
 * Return the register |which|, which may not have a defined value.
 */
static GdbRegisterValue get_reg(Task* t, GdbRegister which) {
  GdbRegisterValue reg;
  memset(&reg, 0, sizeof(reg));
  reg.name = which;
  reg.size = t->get_reg(&reg.value[0], which, &reg.defined);
  return reg;
}

static GdbThreadId get_threadid(Task* t) {
  GdbThreadId thread;
  thread.pid = t->tgid();
  thread.tid = t->rec_tid;
  return thread;
}

static WatchType watchpoint_type(GdbRequestType req) {
  switch (req) {
    case DREQ_SET_HW_BREAK:
    case DREQ_REMOVE_HW_BREAK:
      return WATCH_EXEC;
    case DREQ_SET_WR_WATCH:
    case DREQ_REMOVE_WR_WATCH:
      return WATCH_WRITE;
    case DREQ_REMOVE_RDWR_WATCH:
    case DREQ_SET_RDWR_WATCH:
    // NB: x86 doesn't support read-only watchpoints (who would
    // ever want to use one?) so we treat them as readwrite
    // watchpoints and hope that gdb can figure out what's going
    // on.  That is, if a user ever tries to set a read
    // watchpoint.
    case DREQ_REMOVE_RD_WATCH:
    case DREQ_SET_RD_WATCH:
      return WATCH_READWRITE;
    default:
      FATAL() << "Unknown dbg request " << req;
      return WatchType(-1); // not reached
  }
}

bool trace_instructions_up_to_event(uint64_t event) {
  return event > instruction_trace_at_event_start &&
         event <= instruction_trace_at_event_last;
}

void GdbServer::maybe_singlestep_for_event(Task* t, GdbRequest* req) {
  if (trace_instructions_up_to_event(session->current_trace_frame().time())) {
    fputs("Stepping: ", stderr);
    t->regs().print_register_file_compact(stderr);
    fprintf(stderr, " ticks:%" PRId64 "\n", t->tick_count());
    req->type = DREQ_STEP;
    req->target = get_threadid(t);
    req->suppress_debugger_stop = true;
  }
}

ReplaySession::shr_ptr GdbServer::get_checkpoint(int checkpoint_id) {
  auto it = checkpoints.find(checkpoint_id);
  if (it == checkpoints.end()) {
    return nullptr;
  }
  return it->second;
}

void GdbServer::delete_checkpoint(int checkpoint_id) {
  auto it = checkpoints.find(checkpoint_id);
  if (it == checkpoints.end()) {
    return;
  }

  it->second->kill_all_tasks();
  checkpoints.erase(it);
}

bool GdbServer::maybe_process_magic_command(Task* t, GdbContext& dbg,
                                            const GdbRequest& req) {
  if (!(req.mem.addr == DBG_COMMAND_MAGIC_ADDRESS && req.mem.len == 4)) {
    return false;
  }
  uint32_t cmd;
  memcpy(&cmd, req.mem.data, sizeof(cmd));
  uintptr_t param = cmd & DBG_COMMAND_PARAMETER_MASK;
  switch (cmd & DBG_COMMAND_MSG_MASK) {
    case DBG_COMMAND_MSG_CREATE_CHECKPOINT: {
      ReplaySession::shr_ptr checkpoint = session->clone();
      delete_checkpoint(param);
      checkpoints[param] = checkpoint;
      break;
    }
    case DBG_COMMAND_MSG_DELETE_CHECKPOINT:
      delete_checkpoint(param);
      break;
    default:
      return false;
  }
  dbg.reply_set_mem(true);
  return true;
}

void dispatch_debugger_request(Session& session, GdbContext& dbg, Task* t,
                               const GdbRequest& req) {
  assert(!req.is_resume_request());

  // These requests don't require a target task.
  switch (req.type) {
    case DREQ_RESTART:
      ASSERT(t, false) << "Can't handle RESTART request from here";
      return; // unreached
    case DREQ_GET_CURRENT_THREAD:
      dbg.reply_get_current_thread(get_threadid(t));
      return;
    case DREQ_GET_OFFSETS:
      /* TODO */
      dbg.reply_get_offsets();
      return;
    case DREQ_GET_THREAD_LIST: {
      auto tasks = t->session().tasks();
      vector<GdbThreadId> tids;
      for (auto& kv : tasks) {
        Task* t = kv.second;
        tids.push_back(get_threadid(t));
      }
      dbg.reply_get_thread_list(tids);
      return;
    }
    case DREQ_INTERRUPT:
      // Tell the debugger we stopped and await further
      // instructions.
      dbg.notify_stop(get_threadid(t), 0);
      return;
    case DREQ_DETACH:
      LOG(info) << ("(debugger detached from us, rr exiting)");
      dbg.reply_detach();
      // Don't orphan tracees: their VMs are inconsistent
      // because we've been using emulated tracing, so they
      // can't resume normal execution.  And we wouldn't
      // want them continuing to execute even if they could.
      exit(0);
    // not reached
    default:
      /* fall through to next switch stmt */
      break;
  }

  Task* target =
      (req.target.tid > 0) ? t->session().find_task(req.target.tid) : t;
  // These requests query or manipulate which task is the
  // target, so it's OK if the task doesn't exist.
  switch (req.type) {
    case DREQ_GET_IS_THREAD_ALIVE:
      dbg.reply_get_is_thread_alive(target != nullptr);
      return;
    case DREQ_GET_THREAD_EXTRA_INFO:
      dbg.reply_get_thread_extra_info(target->name());
      return;
    case DREQ_SET_CONTINUE_THREAD:
    case DREQ_SET_QUERY_THREAD:
      dbg.reply_select_thread(target != nullptr);
      return;
    default:
      // fall through to next switch stmt
      break;
  }

  // These requests require a valid target task.  We don't trust
  // the debugger to use the information provided above to only
  // query valid tasks.
  if (!target) {
    dbg.notify_no_such_thread(req);
    return;
  }
  switch (req.type) {
    case DREQ_GET_AUXV: {
      char filename[] = "/proc/01234567890/auxv";
      vector<GdbAuxvPair> auxv;
      auxv.resize(4096);

      snprintf(filename, sizeof(filename) - 1, "/proc/%d/auxv",
               target->real_tgid());
      ScopedFd fd(filename, O_RDONLY);
      if (0 > fd) {
        auxv.clear();
        dbg.reply_get_auxv(auxv);
        return;
      }

      ssize_t len = read(fd, auxv.data(), sizeof(auxv[0]) * auxv.size());
      if (0 > len) {
        auxv.clear();
        dbg.reply_get_auxv(auxv);
        return;
      }

      assert(0 == len % sizeof(auxv[0]));
      auxv.resize(len / sizeof(auxv[0]));
      dbg.reply_get_auxv(auxv);
      return;
    }
    case DREQ_GET_MEM: {
      vector<uint8_t> mem;
      mem.resize(req.mem.len);
      ssize_t nread =
          target->read_bytes_fallible(req.mem.addr, req.mem.len, mem.data());
      mem.resize(max(ssize_t(0), nread));
      dbg.reply_get_mem(mem);
      return;
    }
    case DREQ_SET_MEM: {
      // gdb has been observed to send requests of length 0 at
      // odd times
      // (e.g. before sending the magic write to create a checkpoint)
      if (req.mem.len == 0) {
        dbg.reply_set_mem(true);
        return;
      }
      if (gdb_server.maybe_process_magic_command(target, dbg, req)) {
        return;
      }
      // We only allow the debugger to write memory if the
      // memory will be written to an diversion session.
      // Arbitrary writes to replay sessions cause
      // divergence.
      if (!session.is_diversion()) {
        LOG(error) << "Attempt to write memory outside diversion session";
        dbg.reply_set_mem(false);
        return;
      }
      LOG(debug) << "Writing " << req.mem.len << " bytes to " << req.mem.addr;
      // TODO fallible
      target->write_bytes_helper(req.mem.addr, req.mem.len, req.mem.data);
      dbg.reply_set_mem(true);
      return;
    }
    case DREQ_GET_REG: {
      GdbRegisterValue reg = get_reg(target, req.reg.name);
      dbg.reply_get_reg(reg);
      return;
    }
    case DREQ_GET_REGS: {
      size_t n_regs = target->regs().total_registers();
      GdbRegisterFile file(n_regs);
      for (size_t i = 0; i < n_regs; ++i) {
        file.regs[i] = get_reg(target, GdbRegister(i));
      }
      dbg.reply_get_regs(file);
      return;
    }
    case DREQ_SET_REG: {
      if (!session.is_diversion()) {
        // gdb sets orig_eax to -1 during a restart. For a
        // replay session this is not correct (we might be
        // restarting from an rr checkpoint inside a system
        // call, and we must not tamper with replay state), so
        // just ignore it.
        if ((t->arch() == x86 && req.reg.name == DREG_ORIG_EAX) ||
            (t->arch() == x86_64 && req.reg.name == DREG_ORIG_RAX)) {
          dbg.reply_set_reg(true);
          return;
        }
        LOG(error) << "Attempt to write register outside diversion session";
        dbg.reply_set_reg(false);
        return;
      }
      if (req.reg.defined) {
        Registers regs = target->regs();
        regs.write_register(req.reg.name, req.reg.value, req.reg.size);
        target->set_regs(regs);
      }
      dbg.reply_set_reg(true /*currently infallible*/);
      return;
    }
    case DREQ_GET_STOP_REASON: {
      dbg.reply_get_stop_reason(get_threadid(target), target->child_sig);
      return;
    }
    case DREQ_SET_SW_BREAK: {
      ASSERT(target, (req.mem.len == sizeof(AddressSpace::breakpoint_insn)))
          << "Debugger setting bad breakpoint insn";
      bool ok = target->vm()->set_breakpoint(req.mem.addr, TRAP_BKPT_USER);
      dbg.reply_watchpoint_request(ok);
      return;
    }
    case DREQ_REMOVE_SW_BREAK:
      target->vm()->remove_breakpoint(req.mem.addr, TRAP_BKPT_USER);
      dbg.reply_watchpoint_request(true);
      return;
    case DREQ_REMOVE_HW_BREAK:
    case DREQ_REMOVE_RD_WATCH:
    case DREQ_REMOVE_WR_WATCH:
    case DREQ_REMOVE_RDWR_WATCH:
      target->vm()->remove_watchpoint(req.mem.addr, req.mem.len,
                                      watchpoint_type(req.type));
      dbg.reply_watchpoint_request(true);
      return;
    case DREQ_SET_HW_BREAK:
    case DREQ_SET_RD_WATCH:
    case DREQ_SET_WR_WATCH:
    case DREQ_SET_RDWR_WATCH: {
      bool ok = target->vm()->set_watchpoint(req.mem.addr, req.mem.len,
                                             watchpoint_type(req.type));
      dbg.reply_watchpoint_request(ok);
      return;
    }
    case DREQ_READ_SIGINFO:
      LOG(warn) << "READ_SIGINFO request outside of diversion session";
      dbg.reply_read_siginfo(vector<uint8_t>());
      return;
    case DREQ_WRITE_SIGINFO:
      LOG(warn) << "WRITE_SIGINFO request outside of diversion session";
      dbg.reply_write_siginfo();
      return;
    default:
      FATAL() << "Unknown debugger request " << req.type;
  }
}

bool is_ignored_replay_signal(int sig) {
  switch (sig) {
    // SIGCHLD can arrive after tasks die during replay.  We don't
    // care about SIGCHLD unless it was recorded, in which case
    // we'll emulate its delivery.
    case SIGCHLD:
    // SIGWINCH arrives when the user resizes the terminal window.
    // Not relevant to replay.
    case SIGWINCH:
      return true;
    default:
      return false;
  }
}

// The global diversion session, of which there can only be one at a
// time currently.  See long comment at the top of diverter.h.
static DiversionSession::shr_ptr diversion_session;
// Number of client references to this, if it's a diversion
// session.  When there are 0 refs this is considered to be
// dying.
static int diversion_refcount;

/**
 * Process debugger requests made through |dbg| until action needs to
 * be taken by the caller (a resume-execution request is received).
 * The returned Task* is the target of the resume-execution request.
 *
 * The received request is returned through |req|.
 */
static Task* diverter_process_debugger_requests(GdbContext& dbg, Task* t,
                                                GdbRequest* req) {
  while (true) {
    *req = dbg.get_request();

    if (req->is_resume_request()) {
      if (diversion_refcount == 0) {
        return nullptr;
      }
      return t;
    }

    switch (req->type) {
      case DREQ_RESTART:
        return nullptr;

      case DREQ_READ_SIGINFO: {
        LOG(debug) << "Adding ref to diversion session";
        ++diversion_refcount;
        // TODO: maybe share with replayer.cc?
        vector<uint8_t> si_bytes;
        si_bytes.resize(req->mem.len);
        memset(si_bytes.data(), 0, si_bytes.size());
        dbg.reply_read_siginfo(si_bytes);
        continue;
      }
      case DREQ_SET_QUERY_THREAD: {
        Task* next_task = t->session().find_task(req->target.tid);
        t = next_task ? next_task : t;
        break;
      }
      case DREQ_WRITE_SIGINFO:
        LOG(debug) << "Removing reference to diversion session ...";
        assert(diversion_refcount > 0);
        --diversion_refcount;
        if (diversion_refcount == 0) {
          LOG(debug) << "  ... dying at next continue request";
        }
        dbg.reply_write_siginfo();
        continue;

      case DREQ_REMOVE_SW_BREAK:
      case DREQ_REMOVE_HW_BREAK:
      case DREQ_REMOVE_RD_WATCH:
      case DREQ_REMOVE_WR_WATCH:
      case DREQ_REMOVE_RDWR_WATCH:
      case DREQ_SET_SW_BREAK:
      case DREQ_SET_HW_BREAK:
      case DREQ_SET_RD_WATCH:
      case DREQ_SET_WR_WATCH:
      case DREQ_SET_RDWR_WATCH: {
        // Setting breakpoints in a dying diversion is assumed
        // to be a user action intended for the replay
        // session, so return to it now.
        if (diversion_refcount == 0) {
          return nullptr;
        }
        break;
      }

      default:
        break;
    }

    dispatch_debugger_request(*diversion_session, dbg, t, *req);
  }
}

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
static void divert(ReplaySession& replay, GdbContext& dbg, pid_t task,
                   GdbRequest* req) {
  LOG(debug) << "Starting debugging diversion for " << &replay;
  assert(!diversion_session && diversion_refcount == 0);

  diversion_session = replay.clone_diversion();
  diversion_refcount = 1;

  Task* t = diversion_session->find_task(task);
  while (true) {
    if (!(t = diverter_process_debugger_requests(dbg, t, req))) {
      break;
    }

    ReplaySession::RunCommand command =
        (DREQ_STEP == req->type && get_threadid(t) == req->target)
            ? Session::RUN_SINGLESTEP
            : Session::RUN_CONTINUE;
    auto result = diversion_session->diversion_step(t, command);

    if (result.status == DiversionSession::DIVERSION_EXITED) {
      diversion_refcount = 0;
      dbg.notify_exit_code(0);
      break;
    }

    assert(result.status == DiversionSession::DIVERSION_CONTINUE);
    if (result.break_status.reason == Session::BREAK_NONE) {
      continue;
    }

    int sig = SIGTRAP;
    remote_ptr<void> watch_addr = nullptr;
    switch (result.break_status.reason) {
      case Session::BREAK_SIGNAL:
        sig = result.break_status.signal;
        break;
      case Session::BREAK_WATCHPOINT:
        watch_addr = result.break_status.watch_address;
        break;
      default:
        break;
    }
    /* Notify the debugger and process any new requests
     * that might have triggered before resuming. */
    dbg.notify_stop(get_threadid(result.break_status.task), sig,
                    watch_addr.as_int());
  }

  LOG(debug) << "... ending debugging diversion";
  assert(diversion_refcount == 0);
  diversion_session->kill_all_tasks();
  diversion_session = nullptr;
}

/**
 * Reply to debugger requests until the debugger asks us to resume
 * execution.
 */
GdbRequest GdbServer::process_debugger_requests(GdbContext& dbg, Task* t) {
  while (1) {
    GdbRequest req = dbg.get_request();
    req.suppress_debugger_stop = false;

    if (req.type == DREQ_READ_SIGINFO) {
      // TODO: we send back a dummy siginfo_t to gdb
      // so that it thinks the request succeeded.
      // If we don't, then it thinks the
      // READ_SIGINFO failed and won't attempt to
      // send WRITE_SIGINFO.  For |call foo()|
      // frames, that means we don't know when the
      // diversion session is ending.
      vector<uint8_t> si_bytes;
      si_bytes.resize(req.mem.len);
      memset(si_bytes.data(), 0, si_bytes.size());
      dbg.reply_read_siginfo(si_bytes);

      divert(*session, dbg, t->rec_tid, &req);
      // Carry on to process the request that was rejected by
      // the diversion session
    }

    if (req.is_resume_request()) {
      maybe_singlestep_for_event(t, &req);
      LOG(debug) << "  is resume request";
      return req;
    }

    if (req.type == DREQ_RESTART) {
      // Debugger client requested that we restart execution
      // from the beginning.  Restart our debug session.
      LOG(debug) << "  request to restart at event " << req.restart.param;
      // If the user requested restarting to a
      // different event, ensure that we change that
      // param for the next replay session.
      Flags::update_replay_target(-1, req.restart.param);
      return req;
    }

    dispatch_debugger_request(*session, dbg, t, req);
  }
}

static void replay_one_step(ReplaySession& session, GdbContext* dbg,
                            GdbRequest* restart_request) {
  restart_request->type = DREQ_NONE;

  GdbRequest req;
  Task* t = session.current_task();

  if (dbg) {
    req = gdb_server.process_debugger_requests(*dbg, t);
    if (DREQ_RESTART == req.type) {
      *restart_request = req;
      return;
    }
    assert(req.is_resume_request());
  } else {
    req.type = DREQ_CONTINUE;
  }

  ReplaySession::RunCommand command =
      (DREQ_STEP == req.type && get_threadid(t) == req.target)
          ? Session::RUN_SINGLESTEP
          : Session::RUN_CONTINUE;
  auto result = session.replay_step(command);

  if (result.status == ReplaySession::REPLAY_EXITED) {
    return;
  }
  assert(result.status == ReplaySession::REPLAY_CONTINUE);
  if (result.break_status.reason == Session::BREAK_NONE) {
    return;
  }

  if (dbg && !req.suppress_debugger_stop) {
    int sig = SIGTRAP;
    remote_ptr<void> watch_addr = nullptr;
    switch (result.break_status.reason) {
      case Session::BREAK_SIGNAL:
        sig = result.break_status.signal;
        break;
      case Session::BREAK_WATCHPOINT:
        watch_addr = result.break_status.watch_address;
        break;
      default:
        break;
    }
    /* Notify the debugger and process any new requests
     * that might have triggered before resuming. */
    dbg->notify_stop(get_threadid(result.break_status.task), sig,
                     watch_addr.as_int());
  }
}

/**
 * Return true if a side effect of creating the debugger interface
 * will be checkpointing the replay session.
 */
static bool will_checkpoint() { return !Flags::get().dont_launch_debugger; }

/**
 * Return true if |t| appears to have entered but not exited an atomic
 * syscall (one that can't be interrupted).
 */
static bool is_atomic_syscall(Task* t) {
  return (t->is_probably_replaying_syscall() &&
          (is_execve_syscall(t->regs().original_syscallno(), t->arch()) ||
           (-ENOSYS == t->regs().syscall_result_signed() &&
            !is_always_emulated_syscall(t->regs().original_syscallno(),
                                        t->arch()))));
}

/**
 * Return true if it's possible/meaningful to make a checkpoint at the
 * |frame| that |t| will replay.
 */
static bool can_checkpoint_at(Task* t, const TraceFrame& frame) {
  Event ev(frame.event());
  if (is_atomic_syscall(t)) {
    return false;
  }
  if (ev.has_ticks_slop()) {
    return false;
  }
  switch (ev.type()) {
    case EV_EXIT:
    case EV_UNSTABLE_EXIT:
    // At exits, we can't clone the exiting tasks, so
    // don't event bother trying to checkpoint.
    case EV_SYSCALLBUF_RESET:
    // RESETs are usually inserted in between syscall
    // entry/exit.  Help the |is_atomic_syscall()|
    // heuristics by not attempting to checkpoint at
    // RESETs.  Users would never want to do that anyway.
    case EV_TRACE_TERMINATION:
      // There's nothing to checkpoint at the end of an
      // early-terminated trace.
      return false;
    default:
      return true;
  }
}

/**
 * If the trace has reached the event at which the user wanted a debugger
 * started, then create one and store it in `dbg` if we don't already
 * have one there, and return true. Otherwise return false.
 *
 * This must be called before scheduling the task for the next event
 * (and thereby mutating the TraceIfstream for that event).
 */
bool GdbServer::maybe_connect_debugger(unique_ptr<GdbContext>* dbg,
                                       ScopedFd* debugger_params_write_pipe) {
  // Don't launch the debugger for the initial rr fork child.
  // No one ever wants that to happen.
  if (!session->can_validate()) {
    return false;
  }
  // When we decide to create the debugger, we may end up
  // creating a checkpoint.  In that case, we want the
  // checkpoint to retain the state it had *before* we started
  // replaying the next frame.  Otherwise, the TraceIfstream
  // will be one frame ahead of its tracee tree.
  //
  // So we make the decision to create the debugger based on the
  // frame we're *about to* replay, without modifying the
  // TraceIfstream.
  TraceFrame next_frame = session->current_trace_frame();
  Task* t = session->current_task();
  if (!t) {
    return false;
  }
  TraceFrame::Time event_now = next_frame.time();
  TraceFrame::Time goto_event = Flags::get().goto_event;
  pid_t target_process = Flags::get().target_process;
  bool require_exec = Flags::CREATED_EXEC == Flags::get().process_created_how;
  if (event_now < goto_event
          // NB: we'll happily attach to whichever task within the
          // group happens to be scheduled here.  We don't take
          // "attach to process" to mean "attach to thread-group
          // leader".
      ||
      (target_process && t->tgid() != target_process) ||
      (require_exec && !t->vm()->execed()) ||
      (will_checkpoint() && !can_checkpoint_at(t, next_frame))) {
    return false;
  }

  if (goto_event > 0 || target_process) {
    fprintf(stderr, "\a\n"
                    "--------------------------------------------------\n"
                    " ---> Reached target process %d at event %u.\n"
                    "--------------------------------------------------\n",
            target_process, event_now);
  }

  // Call set_debugged_tgid now so it will be cloned into the
  // checkpoint below if one is created.
  t->replay_session().set_debugged_tgid(t->tgid());

  if (will_checkpoint()) {
    // Have the "checkpoint" be the original replay
    // session, and then switch over to using the cloned
    // session.  The cloned tasks will look like children
    // of the clonees, so this scheme prevents |pstree|
    // output from getting /too/ far out of whack.
    debugger_restart_checkpoint = session;
    session = session->clone();
    t = session->find_task(t->rec_tid);
  }

  // Store the current tgid and event as the "execution target"
  // for the next replay session, if we end up restarting.  This
  // allows us to determine if a later session has reached this
  // target without necessarily replaying up to this point.
  Flags::update_replay_target(t->tgid(), event_now);

  if (!*dbg) {
    unsigned short port =
        (Flags::get().dbgport > 0) ? Flags::get().dbgport : getpid();
    // Don't probe if the user specified a port.  Explicitly
    // selecting a port is usually done by scripts, which would
    // presumably break if a different port were to be selected by
    // rr (otherwise why would they specify a port in the first
    // place).  So fail with a clearer error message.
    auto probe = (Flags::get().dbgport > 0) ? GdbContext::DONT_PROBE
                                            : GdbContext::PROBE_PORT;
    const string* exe =
        Flags::get().dont_launch_debugger ? nullptr : &t->vm()->exe_image();
    *dbg = GdbContext::await_client_connection(port, probe, t->tgid(), exe,
                                               debugger_params_write_pipe);
    if (debugger_params_write_pipe) {
      debugger_params_write_pipe->close();
    }
  }

  return true;
}

/**
 * Set the blocked-ness of |sig| to |blockedness|.
 */
static void set_sig_blockedness(int sig, int blockedness) {
  sigset_t sset;
  sigemptyset(&sset);
  sigaddset(&sset, sig);
  if (sigprocmask(blockedness, &sset, nullptr)) {
    FATAL() << "Didn't change sigmask.";
  }
}

void GdbServer::restart_session(GdbContext& dbg, GdbRequest* req,
                                bool* debugger_active) {
  assert(req->type == DREQ_RESTART);

  ReplaySession::shr_ptr checkpoint_to_restore;
  if (req->restart.type == RESTART_FROM_CHECKPOINT) {
    checkpoint_to_restore = get_checkpoint(req->restart.param);
    if (!checkpoint_to_restore) {
      LOG(info) << "Checkpoint " << req->restart.param << " not found.";
      dbg.notify_restart_failed();
      return;
    }
  } else if (req->restart.type == RESTART_FROM_PREVIOUS) {
    checkpoint_to_restore = debugger_restart_checkpoint;
  }
  if (checkpoint_to_restore) {
    debugger_restart_checkpoint = checkpoint_to_restore;
    session = checkpoint_to_restore->clone();
    *debugger_active = true;
    return;
  }

  *debugger_active = false;

  if (session->trace_reader().time() > Flags::get().goto_event) {
    // We weren't able to reuse a saved session, so
    // just discard it and create a fresh one that's back
    // at beginning-of-trace.
    session = ReplaySession::create(session->trace_reader().dir());
  }
}

void GdbServer::serve_replay_with_debugger(const string& trace_dir,
                                           ScopedFd* debugger_params_write_pipe) {
  session = ReplaySession::create(trace_dir);

  unique_ptr<GdbContext> dbg;
  // False while we're waiting for the session to reach some requested state
  // before talking to gdb.
  bool debugger_active = false;
  while (true) {
    while (!session->last_task()) {
      if (!debugger_active) {
        debugger_active =
            maybe_connect_debugger(&dbg, debugger_params_write_pipe);
      }

      GdbRequest restart_request;
      replay_one_step(*session, debugger_active ? dbg.get() : nullptr,
                      &restart_request);
      if (restart_request.type != DREQ_NONE) {
        restart_session(*dbg, &restart_request, &debugger_active);
      }
    }
    LOG(info) << ("Replayer successfully finished.");

    if (!dbg) {
      LOG(info) << "Debugger was not launched before end of trace";
      break;
    }

    // TODO return real exit code, if it's useful.
    dbg->notify_exit_code(0);
    GdbRequest req = process_debugger_requests(*dbg, session->last_task());
    if (DREQ_RESTART == req.type) {
      restart_session(*dbg, &req, &debugger_active);
      continue;
    }
    FATAL() << "Received continue request after end-of-trace.";
  }

  session = nullptr;
  LOG(debug) << "debugger server exiting ...";
}

static void serve_replay_no_debugger(const string& trace_dir) {
  ReplaySession::shr_ptr replay_session = ReplaySession::create(trace_dir);

  while (true) {
    auto result = replay_session->replay_step(ReplaySession::RUN_CONTINUE);

    if (result.status == ReplaySession::REPLAY_EXITED) {
      break;
    }
    assert(result.status == ReplaySession::REPLAY_CONTINUE);
    assert(result.break_status.reason == Session::BREAK_NONE ||
           result.break_status.reason == Session::BREAK_SIGNAL);
  }

  LOG(info) << ("Replayer successfully finished.");
}

static void handle_signal(int sig) {
  switch (sig) {
    case SIGINT:
      // Translate the SIGINT into SIGTERM for the debugger
      // server, because it's blocking SIGINT.  We don't use
      // SIGINT for anything, so all it's meant to do is
      // kill us, and SIGTERM works just as well for that.
      if (waiting_for_child > 0) {
        kill(waiting_for_child, SIGTERM);
      }
      break;
    default:
      FATAL() << "Unhandled signal " << signalname(sig);
  }
}

int replay(int argc, char* argv[], char** envp) {
  string trace_dir = argc > 0 ? argv[0] : "";

  // If we're not going to autolaunch the debugger, don't go
  // through the rigamarole to set that up.  All it does is
  // complicate the process tree and confuse users.
  if (Flags::get().dont_launch_debugger) {
    if (Flags::get().goto_event ==
        numeric_limits<decltype(Flags::get().goto_event)>::max()) {
      serve_replay_no_debugger(trace_dir);
    } else {
      gdb_server.serve_replay_with_debugger(trace_dir, nullptr);
    }
    return 0;
  }

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_signal;
  if (sigaction(SIGINT, &sa, nullptr)) {
    FATAL() << "Couldn't set sigaction for SIGINT.";
  }

  int debugger_params_pipe[2];
  if (pipe2(debugger_params_pipe, O_CLOEXEC)) {
    FATAL() << "Couldn't open debugger params pipe.";
  }
  if (0 == (waiting_for_child = fork())) {
    // Ensure only the parent has the read end of the pipe open. Then if
    // the parent dies, our writes to the pipe will error out.
    close(debugger_params_pipe[0]);
    ScopedFd debugger_params_write_pipe(debugger_params_pipe[1]);
    // The parent process (gdb) must be able to receive
    // SIGINT's to interrupt non-stopped tracees.  But the
    // debugger server isn't set up to handle SIGINT.  So
    // block it.
    set_sig_blockedness(SIGINT, SIG_BLOCK);
    gdb_server.serve_replay_with_debugger(trace_dir, &debugger_params_write_pipe);
    return 0;
  }
  // Ensure only the child has the write end of the pipe open. Then if
  // the child dies, our reads from the pipe will return EOF.
  close(debugger_params_pipe[1]);
  LOG(debug) << getpid() << ": forked debugger server " << waiting_for_child;

  {
    ScopedFd params_pipe_read_fd(debugger_params_pipe[0]);
    GdbContext::launch_gdb(params_pipe_read_fd, gdb_rr_macros);
  }

  // Child must have died before we were able to get debugger parameters
  // and exec gdb. Exit with the exit status of the child.
  while (true) {
    int status;
    int ret = waitpid(waiting_for_child, &status, 0);
    int err = errno;
    LOG(debug) << getpid() << ": waitpid(" << waiting_for_child << ") returned "
               << strerror(err) << "(" << err << "); status:" << HEX(status);
    if (waiting_for_child != ret) {
      if (EINTR == err) {
        continue;
      }
      FATAL() << getpid() << ": waitpid(" << waiting_for_child << ") failed";
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      LOG(info) << ("Debugger server died.  Exiting.");
      exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
    }
  }

  return 0;
}

void start_debug_server(Task* t) {
  // See the comment in |guard_overshoot()| explaining why we do
  // this.  Unlike in that context though, we don't know if |t|
  // overshot an internal breakpoint.  If it did, cover that
  // breakpoint up.
  t->vm()->destroy_all_breakpoints();

  // Don't launch a debugger on fatal errors; the user is most
  // likely already in a debugger, and wouldn't be able to
  // control another session.
  unique_ptr<GdbContext> dbg = GdbContext::await_client_connection(
      t->tid, GdbContext::PROBE_PORT, t->tgid());

  gdb_server.process_debugger_requests(*dbg, t);
}
