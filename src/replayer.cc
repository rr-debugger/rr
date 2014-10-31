/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "Replayer"

#include "replayer.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include <map>
#include <string>
#include <vector>

#include "debugger_gdb.h"
#include "diverter.h"
#include "Event.h"
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

// Arguments passed to rr by the user on the command line.  Used to
// create the initial session, and subsequently re-create that initial
// session when we do a full restart.
static int cmdline_argc;
static char** cmdline_argv;

// |session| is used to drive replay.
static ReplaySession::shr_ptr session;
// If we're being controlled by a debugger, then |last_debugger_start| is
// the saved session we forked 'session' from.
static ReplaySession::shr_ptr debugger_restart_checkpoint;
// When we restart a replay session, we stash the debug context here
// so that we can find it again in |maybe_create_debugger()|.  We want
// to reuse the context after the restart, but we don't want to notify
// the debugger about irrelevant stuff before our target
// process/event.
static GdbContext* stashed_dbg;

// Checkpoints, indexed by checkpoint ID
map<int, ReplaySession::shr_ptr> checkpoints;
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

// |parent| is the (potential) debugger client.  It waits until the
// server, |child|, creates a debug socket.  Then the client exec()s
// the debugger over itself.
static pid_t parent, child;
// The server writes debugger params to this pipe.
static ScopedFd debugger_params_write_pipe;

// Setting these causes us to trace instructions after
// instruction_trace_at_event_start up to and including
// instruction_trace_at_event_last
static uint64_t instruction_trace_at_event_start = 0;
static uint64_t instruction_trace_at_event_last = 0;

/**
 * Return the register |which|, which may not have a defined value.
 */
static GdbRegisterValue get_reg(Task* t, GDBRegister which) {
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

static void maybe_singlestep_for_event(Task* t, GdbRequest* req) {
  if (trace_instructions_up_to_event(session->current_trace_frame().time())) {
    fputs("Stepping: ", stderr);
    t->regs().print_register_file_compact(stderr);
    fprintf(stderr, " ticks:%" PRId64 "\n", t->tick_count());
    req->type = DREQ_STEP;
    req->target = get_threadid(t);
    req->suppress_debugger_stop = true;
  }
}

/**
 * Return the checkpoint stored as |checkpoint_id| or nullptr if there
 * isn't one.
 */
static ReplaySession::shr_ptr get_checkpoint(int checkpoint_id) {
  auto it = checkpoints.find(checkpoint_id);
  if (it == checkpoints.end()) {
    return nullptr;
  }
  return it->second;
}

/**
 * Delete the checkpoint stored as |checkpoint_id| if it exists, or do
 * nothing if it doesn't exist.
 */
static void delete_checkpoint(int checkpoint_id) {
  auto it = checkpoints.find(checkpoint_id);
  if (it == checkpoints.end()) {
    return;
  }

  it->second->kill_all_tasks();
  checkpoints.erase(it);
}

/**
 * If |req| is a magic-write command, interpret it and return true.
 * Otherwise, do nothing and return false.
 */
static bool maybe_process_magic_command(Task* t, GdbContext* dbg,
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
  dbg_reply_set_mem(dbg, true);
  return true;
}

void dispatch_debugger_request(Session& session, GdbContext* dbg, Task* t,
                               const GdbRequest& req) {
  assert(!req.is_resume_request());

  // These requests don't require a target task.
  switch (req.type) {
    case DREQ_RESTART:
      ASSERT(t, false) << "Can't handle RESTART request from here";
      return; // unreached
    case DREQ_GET_CURRENT_THREAD:
      dbg_reply_get_current_thread(dbg, get_threadid(t));
      return;
    case DREQ_GET_OFFSETS:
      /* TODO */
      dbg_reply_get_offsets(dbg);
      return;
    case DREQ_GET_THREAD_LIST: {
      auto tasks = t->session().tasks();
      size_t len = tasks.size();
      vector<GdbThreadId> tids;
      for (auto& kv : tasks) {
        Task* t = kv.second;
        tids.push_back(get_threadid(t));
      }
      dbg_reply_get_thread_list(dbg, tids.data(), len);
      return;
    }
    case DREQ_INTERRUPT:
      // Tell the debugger we stopped and await further
      // instructions.
      dbg_notify_stop(dbg, get_threadid(t), 0);
      return;
    case DREQ_DETACH:
      LOG(info) << ("(debugger detached from us, rr exiting)");
      dbg_reply_detach(dbg);
      dbg_destroy_context(&dbg);
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
      dbg_reply_get_is_thread_alive(dbg, !!target);
      return;
    case DREQ_GET_THREAD_EXTRA_INFO:
      dbg_reply_get_thread_extra_info(dbg, target->name().c_str());
      return;
    case DREQ_SET_CONTINUE_THREAD:
    case DREQ_SET_QUERY_THREAD:
      dbg_reply_select_thread(dbg, !!target);
      return;
    default:
      // fall through to next switch stmt
      break;
  }

  // These requests require a valid target task.  We don't trust
  // the debugger to use the information provided above to only
  // query valid tasks.
  if (!target) {
    dbg_notify_no_such_thread(dbg, &req);
    return;
  }
  switch (req.type) {
    case DREQ_GET_AUXV: {
      char filename[] = "/proc/01234567890/auxv";
      GdbAuxvPair auxv[4096];
      ssize_t len;

      snprintf(filename, sizeof(filename) - 1, "/proc/%d/auxv",
               target->real_tgid());
      ScopedFd fd(filename, O_RDONLY);
      if (0 > fd) {
        dbg_reply_get_auxv(dbg, nullptr, -1);
        return;
      }

      len = read(fd, auxv, sizeof(auxv));
      if (0 > len) {
        dbg_reply_get_auxv(dbg, nullptr, -1);
        return;
      }

      assert(0 == len % sizeof(auxv[0]));
      len /= sizeof(auxv[0]);
      dbg_reply_get_auxv(dbg, auxv, len);
      return;
    }
    case DREQ_GET_MEM: {
      uint8_t mem[req.mem.len];
      ssize_t nread =
          target->read_bytes_fallible(req.mem.addr, req.mem.len, mem);
      size_t len = max(ssize_t(0), nread);
      dbg_reply_get_mem(dbg, mem, len);
      return;
    }
    case DREQ_SET_MEM: {
      // gdb has been observed to send requests of length 0 at
      // odd times
      // (e.g. before sending the magic write to create a checkpoint)
      if (req.mem.len == 0) {
        dbg_reply_set_mem(dbg, true);
        return;
      }
      if (maybe_process_magic_command(target, dbg, req)) {
        return;
      }
      // We only allow the debugger to write memory if the
      // memory will be written to an diversion session.
      // Arbitrary writes to replay sessions cause
      // divergence.
      if (!session.is_diversion()) {
        LOG(error) << "Attempt to write memory outside diversion session";
        dbg_reply_set_mem(dbg, false);
        return;
      }
      LOG(debug) << "Writing " << req.mem.len << " bytes to " << req.mem.addr;
      // TODO fallible
      target->write_bytes_helper(req.mem.addr, req.mem.len, req.mem.data);
      dbg_reply_set_mem(dbg, true);
      return;
    }
    case DREQ_GET_REG: {
      GdbRegisterValue reg = get_reg(target, req.reg.name);
      dbg_reply_get_reg(dbg, reg);
      return;
    }
    case DREQ_GET_REGS: {
      size_t n_regs = target->regs().total_registers();
      GdbRegisterFile file(n_regs);
      for (size_t i = 0; i < n_regs; ++i) {
        file.regs[i] = get_reg(target, GDBRegister(i));
      }
      dbg_reply_get_regs(dbg, file);
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
          dbg_reply_set_reg(dbg, true);
          return;
        }
        LOG(error) << "Attempt to write register outside diversion session";
        dbg_reply_set_reg(dbg, false);
        return;
      }
      if (req.reg.defined) {
        Registers regs = target->regs();
        regs.write_register(req.reg.name, req.reg.value, req.reg.size);
        target->set_regs(regs);
      }
      dbg_reply_set_reg(dbg, true /*currently infallible*/);
      return;
    }
    case DREQ_GET_STOP_REASON: {
      dbg_reply_get_stop_reason(dbg, get_threadid(target), target->child_sig);
      return;
    }
    case DREQ_SET_SW_BREAK: {
      ASSERT(target, (req.mem.len == sizeof(AddressSpace::breakpoint_insn)))
          << "Debugger setting bad breakpoint insn";
      bool ok = target->vm()->set_breakpoint(req.mem.addr, TRAP_BKPT_USER);
      dbg_reply_watchpoint_request(dbg, ok ? 0 : 1);
      return;
    }
    case DREQ_REMOVE_SW_BREAK:
      target->vm()->remove_breakpoint(req.mem.addr, TRAP_BKPT_USER);
      dbg_reply_watchpoint_request(dbg, 0);
      return;
    case DREQ_REMOVE_HW_BREAK:
    case DREQ_REMOVE_RD_WATCH:
    case DREQ_REMOVE_WR_WATCH:
    case DREQ_REMOVE_RDWR_WATCH:
      target->vm()->remove_watchpoint(req.mem.addr, req.mem.len,
                                      watchpoint_type(req.type));
      dbg_reply_watchpoint_request(dbg, 0);
      return;
    case DREQ_SET_HW_BREAK:
    case DREQ_SET_RD_WATCH:
    case DREQ_SET_WR_WATCH:
    case DREQ_SET_RDWR_WATCH: {
      bool ok = target->vm()->set_watchpoint(req.mem.addr, req.mem.len,
                                             watchpoint_type(req.type));
      dbg_reply_watchpoint_request(dbg, ok ? 0 : 1);
      return;
    }
    case DREQ_READ_SIGINFO:
      LOG(warn) << "READ_SIGINFO request outside of diversion session";
      dbg_reply_read_siginfo(dbg, nullptr, -1);
      return;
    case DREQ_WRITE_SIGINFO:
      LOG(warn) << "WRITE_SIGINFO request outside of diversion session";
      dbg_reply_write_siginfo(dbg);
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

/**
 * Reply to debugger requests until the debugger asks us to resume
 * execution.
 */
static GdbRequest process_debugger_requests(GdbContext* dbg, Task* t) {
  if (!dbg) {
    GdbRequest continue_all_tasks;
    memset(&continue_all_tasks, 0, sizeof(continue_all_tasks));
    continue_all_tasks.type = DREQ_CONTINUE;
    continue_all_tasks.target = GdbThreadId::ALL;
    maybe_singlestep_for_event(t, &continue_all_tasks);
    return continue_all_tasks;
  }
  while (1) {
    GdbRequest req = dbg_get_request(dbg);
    req.suppress_debugger_stop = false;

    if (req.type == DREQ_READ_SIGINFO) {
      // TODO: we send back a dummy siginfo_t to gdb
      // so that it thinks the request succeeded.
      // If we don't, then it thinks the
      // READ_SIGINFO failed and won't attempt to
      // send WRITE_SIGINFO.  For |call foo()|
      // frames, that means we don't know when the
      // diversion session is ending.
      uint8_t si_bytes[req.mem.len];
      memset(si_bytes, 0, sizeof(si_bytes));
      dbg_reply_read_siginfo(dbg, si_bytes, sizeof(si_bytes));

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

static bool replay_one_step(ReplaySession& session, GdbContext* dbg,
                            GdbRequest* restart_request) {
  GdbRequest req;
  req.type = DREQ_NONE;

  Task* t = session.current_task();

  /* Advance the trace until we've exec()'d the tracee before
   * processing debugger requests.  Otherwise the debugger host
   * will be confused about the initial executable image,
   * rr's. */
  if (session.can_validate()) {
    req = process_debugger_requests(dbg, t);
    if (DREQ_RESTART == req.type) {
      *restart_request = req;
      return false;
    }
    assert(req.is_resume_request());
  }

  ReplaySession::RunCommand command =
      (DREQ_STEP == req.type && get_threadid(t) == req.target)
          ? Session::RUN_SINGLESTEP
          : Session::RUN_CONTINUE;
  auto result = session.replay_step(command);

  if (result.status == ReplaySession::REPLAY_EXITED) {
    return true;
  }
  assert(result.status == ReplaySession::REPLAY_CONTINUE);
  if (result.break_status.reason == Session::BREAK_NONE) {
    return true;
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
    dbg_notify_stop(dbg, get_threadid(result.break_status.task), sig,
                    watch_addr.as_int());
  }

  req = process_debugger_requests(dbg, result.break_status.task);
  if (DREQ_RESTART == req.type) {
    *restart_request = req;
    return false;
  }
  assert(req.is_resume_request());
  return true;
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
 * Return the previous debugger |dbg| if there was one.  Otherwise if
 * the trace has reached the event at which the user wanted a debugger
 * started, then create one and return it.  Otherwise return nullptr.
 *
 * This must be called before scheduling the task for the next event
 * (and thereby mutating the TraceIfstream for that event).
 */
GdbContext* maybe_create_debugger(GdbContext* dbg) {
  if (dbg) {
    return dbg;
  }
  // Don't launch the debugger for the initial rr fork child.
  // No one ever wants that to happen.
  if (!session->can_validate()) {
    return nullptr;
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
    return nullptr;
  }
  uint32_t event_now = next_frame.time();
  uint32_t goto_event = Flags::get().goto_event;
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
    return nullptr;
  }
  assert(!dbg);

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

  if (stashed_dbg) {
    dbg = stashed_dbg;
    stashed_dbg = nullptr;
    return dbg;
  }
  unsigned short port =
      (Flags::get().dbgport > 0) ? Flags::get().dbgport : getpid();
  // Don't probe if the user specified a port.  Explicitly
  // selecting a port is usually done by scripts, which would
  // presumably break if a different port were to be selected by
  // rr (otherwise why would they specify a port in the first
  // place).  So fail with a clearer error message.
  ProbePort probe = (Flags::get().dbgport > 0) ? DONT_PROBE : PROBE_PORT;
  const string* exe =
      Flags::get().dont_launch_debugger ? nullptr : &t->vm()->exe_image();
  return dbg_await_client_connection(port, probe, t->tgid(), exe, parent,
      &debugger_params_write_pipe);
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

/**
 * Return a session created and initialized from the user-supplied
 * command line params.
 */
ReplaySession::shr_ptr create_session_from_cmdline() {
  return ReplaySession::create(cmdline_argc, cmdline_argv);
}

static GdbContext* restart_session(GdbContext* dbg, GdbRequest* req) {
  assert(req->type == DREQ_RESTART);

  ReplaySession::shr_ptr checkpoint_to_restore;
  if (req->restart.type == RESTART_FROM_CHECKPOINT) {
    checkpoint_to_restore = get_checkpoint(req->restart.param);
    if (!checkpoint_to_restore) {
      LOG(info) << "Checkpoint " << req->restart.param << " not found.";
      dbg_notify_restart_failed(dbg);
      return dbg;
    }
  } else if (req->restart.type == RESTART_FROM_PREVIOUS) {
    checkpoint_to_restore = debugger_restart_checkpoint;
  }
  if (checkpoint_to_restore) {
    debugger_restart_checkpoint = checkpoint_to_restore;
    session = checkpoint_to_restore->clone();
    return dbg;
  }

  stashed_dbg = dbg;

  if (session->trace_reader().time() > Flags::get().goto_event) {
    // We weren't able to reuse the stashed session, so
    // just discard it and create a fresh one that's back
    // at beginning-of-trace.
    session = create_session_from_cmdline();
  }
  return nullptr;
}

static void replay_trace_frames(void) {
  GdbContext* dbg = nullptr;
  while (true) {
    while (!session->last_task()) {
      dbg = maybe_create_debugger(dbg);

      GdbRequest restart_request;
      if (!replay_one_step(*session, dbg, &restart_request)) {
        dbg = restart_session(dbg, &restart_request);
      }
    }
    LOG(info) << ("Replayer successfully finished.");
    fflush(stdout);

    if (dbg) {
      // TODO return real exit code, if it's useful.
      dbg_notify_exit_code(dbg, 0);
      GdbRequest req = process_debugger_requests(dbg, session->last_task());
      if (DREQ_RESTART == req.type) {
        dbg = restart_session(dbg, &req);
        continue;
      }
      FATAL() << "Received continue request after end-of-trace.";
    }
    dbg_destroy_context(&dbg);
    return;
  }
}

static void serve_replay(int argc, char* argv[], char** envp) {
  cmdline_argc = argc;
  cmdline_argv = argv;
  session = create_session_from_cmdline();

  replay_trace_frames();

  session = nullptr;
  LOG(debug) << "debugger server exiting ...";
}

static void handle_signal(int sig) {
  switch (sig) {
    case SIGINT:
      // Translate the SIGINT into SIGTERM for the debugger
      // server, because it's blocking SIGINT.  We don't use
      // SIGINT for anything, so all it's meant to do is
      // kill us, and SIGTERM works just as well for that.
      if (child > 0) {
        kill(child, SIGTERM);
      }
      break;
    default:
      FATAL() << "Unhandled signal " << signalname(sig);
  }
}

int replay(int argc, char* argv[], char** envp) {
  // If we're not going to autolaunch the debugger, don't go
  // through the rigamarole to set that up.  All it does is
  // complicate the process tree and confuse users.
  if (Flags::get().dont_launch_debugger) {
    serve_replay(argc, argv, envp);
    return 0;
  }

  parent = getpid();

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
  if (0 == (child = fork())) {
    // Ensure only the parent has the read end of the pipe open. Then if
    // the parent dies, our writes to the pipe will error out.
    close(debugger_params_pipe[0]);
    debugger_params_write_pipe = ScopedFd(debugger_params_pipe[1]);
    // The parent process (gdb) must be able to receive
    // SIGINT's to interrupt non-stopped tracees.  But the
    // debugger server isn't set up to handle SIGINT.  So
    // block it.
    set_sig_blockedness(SIGINT, SIG_BLOCK);
    serve_replay(argc, argv, envp);
    return 0;
  }
  // Ensure only the child has the write end of the pipe open. Then if
  // the child dies, our reads from the pipe will return EOF.
  close(debugger_params_pipe[1]);
  LOG(debug) << parent << ": forked debugger server " << child;

  dbg_launch_debugger(debugger_params_pipe[0], gdb_rr_macros);

  // Child must have died before we were able to get debugger parameters
  // and exec gdb. Exit with the exit status of the child.
  while (true) {
    int status;
    int ret = waitpid(child, &status, 0);
    int err = errno;
    LOG(debug) << getpid() << ": waitpid(" << child << ") returned "
               << strerror(err) << "(" << err << "); status:" << HEX(status);
    if (child != ret) {
      if (EINTR == err) {
        continue;
      }
      FATAL() << getpid() << ": waitpid(" << child << ") failed";
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
  GdbContext* dbg = dbg_await_client_connection(t->tid, PROBE_PORT, t->tgid());

  process_debugger_requests(dbg, t);

  dbg_destroy_context(&dbg);
}
