/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "GdbServer"

#include "GdbServer.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include <limits>
#include <map>
#include <string>
#include <vector>

#include "kernel_metadata.h"
#include "log.h"
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "task.h"
#include "util.h"

using namespace rr;
using namespace std;

/**
 * 32-bit writes to DBG_COMMAND_MAGIC_ADDRESS by the debugger trigger
 * rr commands.
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

/**
 * 64-bit reads from DBG_WHEN_MAGIC_ADDRESS return the current trace frame's
 * event number (the event we're working towards).
 */
static const uintptr_t DBG_WHEN_MAGIC_ADDRESS = DBG_COMMAND_MAGIC_ADDRESS + 4;

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
    "define when\n"
    "  p *(long long int*)(29298 + 4)\n"
    "end\n"
    // In gdb version "Fedora 7.8.1-30.fc21", a raw "run" command
    // issued before any user-generated resume-execution command
    // results in gdb hanging just after the inferior hits an internal
    // gdb breakpoint.  This happens outside of rr, with gdb
    // controlling gdbserver, as well.  We work around that by
    // ensuring *some* resume-execution command has been issued before
    // restarting the session.  But, only if the inferior hasn't
    // already finished execution ($_thread != 0).  If it has and we
    // issue the "stepi" command, then gdb refuses to restart
    // execution.
    "define hook-run\n"
    "  if $_thread != 0 && !$suppress_run_hook\n"
    "    stepi\n"
    "  end\n"
    "end\n"
    "define hookpost-continue\n"
    "  set $suppress_run_hook = 1\n"
    "end\n"
    "define hookpost-step\n"
    "  set $suppress_run_hook = 1\n"
    "end\n"
    "define hookpost-stepi\n"
    "  set $suppress_run_hook = 1\n"
    "end\n"
    "define hookpost-next\n"
    "  set $suppress_run_hook = 1\n"
    "end\n"
    "define hookpost-nexti\n"
    "  set $suppress_run_hook = 1\n"
    "end\n"
    "define hookpost-finish\n"
    "  set $suppress_run_hook = 1\n"
    "end\n"
    "define hookpost-reverse-continue\n"
    "  set $suppress_run_hook = 1\n"
    "end\n"
    "define hookpost-reverse-step\n"
    "  set $suppress_run_hook = 1\n"
    "end\n"
    "define hookpost-reverse-stepi\n"
    "  set $suppress_run_hook = 1\n"
    "end\n"
    "define hookpost-reverse-finish\n"
    "  set $suppress_run_hook = 1\n"
    "end\n"
    "define hookpost-run\n"
    "  set $suppress_run_hook = 0\n"
    "end\n"
    // Try both "set target-async" and "maint set target-async" since
    // that changed recently.
    "set target-async 0\n"
    "maint set target-async 0\n"
    "handle SIGURG stop\n";

/**
 * Attempt to find the value of |regname| (a DebuggerRegister
 * name), and if so (i) write it to |buf|; (ii)
 * set |*defined = true|; (iii) return the size of written
 * data.  If |*defined == false|, the value of |buf| is
 * meaningless.
 *
 * This helper can fetch the values of both general-purpose
 * and "extra" registers.
 *
 * NB: |buf| must be large enough to hold the largest register
 * value that can be named by |regname|.
 */
static size_t get_reg(const Registers& regs, const ExtraRegisters& extra_regs,
                      uint8_t* buf, GdbRegister regname, bool* defined) {
  size_t num_bytes = regs.read_register(buf, regname, defined);
  if (!*defined) {
    num_bytes = extra_regs.read_register(buf, regname, defined);
  }
  return num_bytes;
}

/**
 * Return the register |which|, which may not have a defined value.
 */
static GdbRegisterValue get_reg(const Registers& regs,
                                const ExtraRegisters& extra_regs,
                                GdbRegister which) {
  GdbRegisterValue reg;
  memset(&reg, 0, sizeof(reg));
  reg.name = which;
  reg.size = get_reg(regs, extra_regs, &reg.value[0], which, &reg.defined);
  return reg;
}

static GdbThreadId get_threadid(Task* t) {
  GdbThreadId thread;
  thread.pid = t->tgid();
  thread.tid = t->rec_tid;
  return thread;
}

static bool matches_threadid(Task* t, const GdbThreadId& target) {
  return (!target.pid || target.pid == t->tgid()) &&
         (!target.tid || target.tid == t->rec_tid);
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

static void maybe_singlestep_for_event(Task* t, GdbRequest* req) {
  if (trace_instructions_up_to_event(
          t->replay_session().current_trace_frame().time())) {
    fputs("Stepping: ", stderr);
    t->regs().print_register_file_compact(stderr);
    fprintf(stderr, " ticks:%" PRId64 "\n", t->tick_count());
    req->type = DREQ_STEP;
    req->target = get_threadid(t);
    req->suppress_debugger_stop = true;
  }
}

bool GdbServer::maybe_process_magic_command(Task* t, const GdbRequest& req) {
  if (!(req.mem.addr == DBG_COMMAND_MAGIC_ADDRESS && req.mem.len == 4)) {
    return false;
  }
  uint32_t cmd;
  memcpy(&cmd, req.mem.data, sizeof(cmd));
  uintptr_t param = cmd & DBG_COMMAND_PARAMETER_MASK;
  switch (cmd & DBG_COMMAND_MSG_MASK) {
    case DBG_COMMAND_MSG_CREATE_CHECKPOINT: {
      if (timeline.can_add_checkpoint()) {
        checkpoints[param] = timeline.add_explicit_checkpoint();
      }
      break;
    }
    case DBG_COMMAND_MSG_DELETE_CHECKPOINT: {
      auto it = checkpoints.find(param);
      if (it != checkpoints.end()) {
        timeline.remove_explicit_checkpoint(it->second);
        checkpoints.erase(it);
      }
      break;
    }
    default:
      return false;
  }
  dbg->reply_set_mem(true);
  return true;
}

bool GdbServer::maybe_process_magic_read(Task* t, const GdbRequest& req) {
  if (req.mem.addr == DBG_WHEN_MAGIC_ADDRESS && req.mem.len == 8) {
    vector<uint8_t> mem;
    mem.resize(req.mem.len);
    int64_t when = t->session().as_replay()
                       ? int64_t(t->current_trace_frame().time())
                       : int64_t(-1);
    memcpy(mem.data(), &when, mem.size());
    dbg->reply_get_mem(mem);
    return true;
  }
  return false;
}

void GdbServer::dispatch_regs_request(const Registers& regs,
                                      const ExtraRegisters& extra_regs) {
  size_t n_regs = regs.total_registers();
  GdbRegisterFile file(n_regs);
  for (size_t i = 0; i < n_regs; ++i) {
    file.regs[i] = get_reg(regs, extra_regs, GdbRegister(i));
  }
  dbg->reply_get_regs(file);
}

void GdbServer::dispatch_debugger_request(Session& session, Task* t,
                                          const GdbRequest& req) {
  assert(!req.is_resume_request());

  // These requests don't require a target task.
  switch (req.type) {
    case DREQ_RESTART:
      ASSERT(t, false) << "Can't handle RESTART request from here";
      return; // unreached
    case DREQ_GET_CURRENT_THREAD:
      dbg->reply_get_current_thread(get_threadid(t));
      return;
    case DREQ_GET_OFFSETS:
      /* TODO */
      dbg->reply_get_offsets();
      return;
    case DREQ_GET_THREAD_LIST: {
      vector<GdbThreadId> tids;
      // When replay ends, there is still the last_task() around.
      if (!session.as_replay() || !session.as_replay()->last_task()) {
        for (auto& kv : session.tasks()) {
          tids.push_back(get_threadid(kv.second));
        }
      }
      dbg->reply_get_thread_list(tids);
      return;
    }
    case DREQ_INTERRUPT:
      // Tell the debugger we stopped and await further
      // instructions.
      dbg->notify_stop(get_threadid(t), 0);
      return;
    case DREQ_DETACH:
      LOG(info) << ("(debugger detached from us, rr exiting)");
      dbg->reply_detach();
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
      dbg->reply_get_is_thread_alive(target != nullptr);
      return;
    case DREQ_GET_THREAD_EXTRA_INFO:
      dbg->reply_get_thread_extra_info(target->name());
      return;
    case DREQ_SET_CONTINUE_THREAD:
    case DREQ_SET_QUERY_THREAD:
      dbg->reply_select_thread(target != nullptr);
      return;
    default:
      // fall through to next switch stmt
      break;
  }

  // These requests require a valid target task.  We don't trust
  // the debugger to use the information provided above to only
  // query valid tasks.
  if (!target) {
    dbg->notify_no_such_thread(req);
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
        dbg->reply_get_auxv(auxv);
        return;
      }

      ssize_t len = read(fd, auxv.data(), sizeof(auxv[0]) * auxv.size());
      if (0 > len) {
        auxv.clear();
        dbg->reply_get_auxv(auxv);
        return;
      }

      assert(0 == len % sizeof(auxv[0]));
      auxv.resize(len / sizeof(auxv[0]));
      dbg->reply_get_auxv(auxv);
      return;
    }
    case DREQ_GET_MEM: {
      if (maybe_process_magic_read(target, req)) {
        return;
      }
      vector<uint8_t> mem;
      mem.resize(req.mem.len);
      ssize_t nread =
          target->read_bytes_fallible(req.mem.addr, req.mem.len, mem.data());
      mem.resize(max(ssize_t(0), nread));
      target->vm()->replace_breakpoints_with_original_values(
          mem.data(), mem.size(), req.mem.addr);
      dbg->reply_get_mem(mem);
      return;
    }
    case DREQ_SET_MEM: {
      // gdb has been observed to send requests of length 0 at
      // odd times
      // (e.g. before sending the magic write to create a checkpoint)
      if (req.mem.len == 0) {
        dbg->reply_set_mem(true);
        return;
      }
      if (maybe_process_magic_command(target, req)) {
        return;
      }
      // We only allow the debugger to write memory if the
      // memory will be written to an diversion session.
      // Arbitrary writes to replay sessions cause
      // divergence.
      if (!session.is_diversion()) {
        LOG(error) << "Attempt to write memory outside diversion session";
        dbg->reply_set_mem(false);
        return;
      }
      LOG(debug) << "Writing " << req.mem.len << " bytes to "
                 << HEX(req.mem.addr);
      // TODO fallible
      target->write_bytes_helper(req.mem.addr, req.mem.len, req.mem.data);
      dbg->reply_set_mem(true);
      return;
    }
    case DREQ_GET_REG: {
      GdbRegisterValue reg =
          get_reg(target->regs(), target->extra_regs(), req.reg.name);
      dbg->reply_get_reg(reg);
      return;
    }
    case DREQ_GET_REGS: {
      dispatch_regs_request(target->regs(), target->extra_regs());
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
          dbg->reply_set_reg(true);
          return;
        }
        LOG(error) << "Attempt to write register outside diversion session";
        dbg->reply_set_reg(false);
        return;
      }
      if (req.reg.defined) {
        Registers regs = target->regs();
        regs.write_register(req.reg.name, req.reg.value, req.reg.size);
        target->set_regs(regs);
      }
      dbg->reply_set_reg(true /*currently infallible*/);
      return;
    }
    case DREQ_GET_STOP_REASON: {
      dbg->reply_get_stop_reason(get_threadid(target), target->child_sig);
      return;
    }
    case DREQ_SET_SW_BREAK: {
      ASSERT(target, (req.mem.len == sizeof(AddressSpace::breakpoint_insn)))
          << "Debugger setting bad breakpoint insn";
      bool ok =
          &session == &timeline.current_session()
              ? timeline.add_breakpoint(target, req.mem.addr)
              : target->vm()->add_breakpoint(req.mem.addr, TRAP_BKPT_USER);
      dbg->reply_watchpoint_request(ok);
      return;
    }
    case DREQ_REMOVE_SW_BREAK:
      if (&session == &timeline.current_session()) {
        timeline.remove_breakpoint(target, req.mem.addr);
      } else {
        target->vm()->remove_breakpoint(req.mem.addr, TRAP_BKPT_USER);
      }
      dbg->reply_watchpoint_request(true);
      return;
    case DREQ_REMOVE_HW_BREAK:
    case DREQ_REMOVE_RD_WATCH:
    case DREQ_REMOVE_WR_WATCH:
    case DREQ_REMOVE_RDWR_WATCH:
      if (&session == &timeline.current_session()) {
        timeline.remove_watchpoint(target, req.mem.addr, req.mem.len,
                                   watchpoint_type(req.type));
      } else {
        target->vm()->remove_watchpoint(req.mem.addr, req.mem.len,
                                        watchpoint_type(req.type));
      }
      dbg->reply_watchpoint_request(true);
      return;
    case DREQ_SET_HW_BREAK:
    case DREQ_SET_RD_WATCH:
    case DREQ_SET_WR_WATCH:
    case DREQ_SET_RDWR_WATCH: {
      bool ok = &session == &timeline.current_session()
                    ? timeline.add_watchpoint(target, req.mem.addr, req.mem.len,
                                              watchpoint_type(req.type))
                    : target->vm()->add_watchpoint(req.mem.addr, req.mem.len,
                                                   watchpoint_type(req.type));
      dbg->reply_watchpoint_request(ok);
      return;
    }
    case DREQ_READ_SIGINFO:
      LOG(warn) << "READ_SIGINFO request outside of diversion session";
      dbg->reply_read_siginfo(vector<uint8_t>());
      return;
    case DREQ_WRITE_SIGINFO:
      LOG(warn) << "WRITE_SIGINFO request outside of diversion session";
      dbg->reply_write_siginfo();
      return;
    default:
      FATAL() << "Unknown debugger request " << req.type;
  }
}

/**
 * Process debugger requests made through |dbg| until action needs to
 * be taken by the caller (a resume-execution request is received).
 * The returned Task* is the target of the resume-execution request.
 *
 * The received request is returned through |req|.
 */
Task* GdbServer::diverter_process_debugger_requests(
    Task* t, DiversionSession& diversion_session, uint32_t& diversion_refcount,
    GdbRequest* req) {
  while (true) {
    *req = dbg->get_request();

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
        dbg->reply_read_siginfo(si_bytes);
        continue;
      }

      case DREQ_SET_QUERY_THREAD: {
        if (req->target.tid) {
          Task* next = t->session().find_task(req->target.tid);
          if (next) {
            t = next;
          }
        }
        break;
      }

      case DREQ_WRITE_SIGINFO:
        LOG(debug) << "Removing reference to diversion session ...";
        assert(diversion_refcount > 0);
        --diversion_refcount;
        if (diversion_refcount == 0) {
          LOG(debug) << "  ... dying at next continue request";
        }
        dbg->reply_write_siginfo();
        continue;

      default:
        break;
    }

    dispatch_debugger_request(diversion_session, t, *req);
  }
}

void GdbServer::maybe_notify_stop(const BreakStatus& break_status) {
  int sig = -1;
  remote_ptr<void> watch_addr;
  if (!break_status.watchpoints_hit.empty()) {
    sig = SIGTRAP;
    watch_addr = break_status.watchpoints_hit[0].addr;
  }
  if (break_status.breakpoint_hit || break_status.singlestep_complete) {
    sig = SIGTRAP;
  }
  if (break_status.signal) {
    sig = break_status.signal;
  }
  if (sig >= 0) {
    /* Notify the debugger and process any new requests
     * that might have triggered before resuming. */
    dbg->notify_stop(get_threadid(break_status.task), sig, watch_addr.as_int());
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
GdbRequest GdbServer::divert(ReplaySession& replay, pid_t task) {
  GdbRequest req;
  LOG(debug) << "Starting debugging diversion for " << &replay;

  DiversionSession::shr_ptr diversion_session = replay.clone_diversion();
  uint32_t diversion_refcount = 1;

  Task* t = diversion_session->find_task(task);
  while (true) {
    if (!(t = diverter_process_debugger_requests(t, *diversion_session,
                                                 diversion_refcount, &req))) {
      break;
    }

    if (req.run_direction == RUN_BACKWARD) {
      // We don't support reverse execution in a diversion. Just issue
      // an immediate stop.
      dbg->notify_stop(get_threadid(t), SIGTRAP, 0);
      continue;
    }

    RunCommand command =
        (DREQ_STEP == req.type && matches_threadid(t, req.target))
            ? RUN_SINGLESTEP
            : RUN_CONTINUE;
    auto result = diversion_session->diversion_step(t, command);

    if (result.status == DiversionSession::DIVERSION_EXITED) {
      diversion_refcount = 0;
      req.type = DREQ_NONE;
      dbg->notify_exit_code(0);
      break;
    }

    assert(result.status == DiversionSession::DIVERSION_CONTINUE);

    maybe_notify_stop(result.break_status);
  }

  LOG(debug) << "... ending debugging diversion";
  assert(diversion_refcount == 0);

  // Replace original task's breakpoints with the breakpoints set in the
  // diversion. gdb thinks they're the same, so keeping breakpoints in sync
  // is the right thing to do.
  t = diversion_session->find_task(task);
  Task* orig = replay.find_task(task);
  if (t && orig) {
    orig->vm()->copy_user_breakpoints_from(*t->vm());
    orig->vm()->copy_watchpoints_from(*t->vm());
  }

  diversion_session->kill_all_tasks();
  return req;
}

/**
 * Reply to debugger requests until the debugger asks us to resume
 * execution.
 */
GdbRequest GdbServer::process_debugger_requests(Task* t) {
  while (true) {
    GdbRequest req = dbg->get_request();
    req.suppress_debugger_stop = false;
    if (timeline.is_running() && t) {
      TaskUid tuid = t->tuid();
      try_lazy_reverse_singlesteps(t, req);
      t = timeline.current_session().find_task(tuid);
    }

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
      dbg->reply_read_siginfo(si_bytes);

      req = divert(t->replay_session(), t->rec_tid);
      if (req.type == DREQ_NONE) {
        continue;
      }
      // Carry on to process the request that was rejected by
      // the diversion session
    }

    if (req.is_resume_request()) {
      maybe_singlestep_for_event(t, &req);
      return req;
    }

    if (req.type == DREQ_RESTART) {
      // Debugger client requested that we restart execution
      // from the beginning.  Restart our debug session.
      LOG(debug) << "  request to restart at event " << req.restart.param;
      return req;
    }

    dispatch_debugger_request(t ? t->session() : timeline.current_session(), t,
                              req);
  }
}

void GdbServer::try_lazy_reverse_singlesteps(Task* t, GdbRequest& req) {
  ReplayTimeline::Mark now;
  bool need_seek = false;

  while (req.type == DREQ_STEP && req.run_direction == RUN_BACKWARD &&
         matches_threadid(t, req.target) && !req.suppress_debugger_stop &&
         debugger_active) {
    if (!now) {
      now = timeline.mark();
    }
    ReplayTimeline::Mark previous = timeline.lazy_reverse_singlestep(now, t);
    if (!previous) {
      break;
    }

    now = previous;
    need_seek = true;
    BreakStatus break_status;
    break_status.task = t;
    break_status.singlestep_complete = true;
    LOG(debug) << "  using lazy reverse-singlestep";
    maybe_notify_stop(break_status);

    while (true) {
      req = dbg->get_request();
      req.suppress_debugger_stop = false;
      if (req.type != DREQ_GET_REGS) {
        break;
      }
      LOG(debug) << "  using lazy reverse-singlestep registers";
      dispatch_regs_request(now.regs(), now.extra_regs());
    }
  }

  if (need_seek) {
    timeline.seek_to_mark(now);
  }
}

ReplayStatus GdbServer::replay_one_step() {
  ReplayResult result;
  bool suppress_debugger_stop = false;
  Task* t = timeline.current_session().current_task();

  if (debugger_active && t && t->task_group()->tguid() == debuggee_tguid) {
    TaskUid tuid = t->tuid();
    GdbRequest req = process_debugger_requests(t);
    t = timeline.current_session().find_task(tuid);
    if (DREQ_RESTART == req.type) {
      maybe_restart_session(req);
      return REPLAY_CONTINUE;
    }
    suppress_debugger_stop = req.suppress_debugger_stop;
    assert(req.is_resume_request());
    RunCommand command =
        (DREQ_STEP == req.type && matches_threadid(t, req.target))
            ? RUN_SINGLESTEP
            : RUN_CONTINUE;
    result = timeline.replay_step(
        command, req.run_direction,
        req.run_direction == RUN_FORWARD ? target.event : 0);
  } else {
    result = timeline.replay_step(RUN_CONTINUE, RUN_FORWARD, target.event);
  }

  if (result.status == REPLAY_EXITED) {
    return result.status;
  }
  assert(result.status == REPLAY_CONTINUE);

  if (debugger_active && !suppress_debugger_stop) {
    maybe_notify_stop(result.break_status);
  }
  return result.status;
}

/**
 * If the trace has reached the event at which the user wanted a debugger
 * started, then create one and store it in `dbg` if we don't already
 * have one there, and return true. Otherwise return false.
 *
 * This must be called before scheduling the task for the next event
 * (and thereby mutating the TraceIfstream for that event).
 */
void GdbServer::maybe_connect_debugger(const ConnectionFlags& flags) {
  if (debugger_active) {
    return;
  }
  // Don't launch the debugger for the initial rr fork child.
  // No one ever wants that to happen.
  if (!timeline.current_session().can_validate()) {
    return;
  }
  Task* t = timeline.current_session().current_task();
  if (!t) {
    return;
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
  TraceFrame next_frame = timeline.current_session().current_trace_frame();
  TraceFrame::Time event_now = next_frame.time();
  // NB: we'll happily attach to whichever task within the
  // group happens to be scheduled here.  We don't take
  // "attach to process" to mean "attach to thread-group
  // leader".
  if (event_now < target.event || (target.pid && t->tgid() != target.pid) ||
      (target.pid && target.require_exec && !t->vm()->execed()) ||
      !timeline.can_add_checkpoint()) {
    return;
  }

  if (target.event > 0 || target.pid) {
    fprintf(stderr, "\a\n"
                    "--------------------------------------------------\n"
                    " ---> Reached target process %d at event %u.\n"
                    "--------------------------------------------------\n",
            target.pid, event_now);
  }

  // Have the "checkpoint" be the original replay
  // session, and then switch over to using the cloned
  // session.  The cloned tasks will look like children
  // of the clonees, so this scheme prevents |pstree|
  // output from getting /too/ far out of whack.
  debugger_restart_mark = timeline.add_explicit_checkpoint();
  t = timeline.current_session().find_task(t->rec_tid);

  // Store the current tgid and event as the "execution target"
  // for the next replay session, if we end up restarting.  This
  // allows us to determine if a later session has reached this
  // target without necessarily replaying up to this point.
  target.pid = t->tgid();
  target.require_exec = false;
  target.event = event_now;

  if (!dbg) {
    unsigned short port = flags.dbg_port > 0 ? flags.dbg_port : getpid();
    // Don't probe if the user specified a port.  Explicitly
    // selecting a port is usually done by scripts, which would
    // presumably break if a different port were to be selected by
    // rr (otherwise why would they specify a port in the first
    // place).  So fail with a clearer error message.
    auto probe = flags.dbg_port > 0 ? GdbConnection::DONT_PROBE
                                    : GdbConnection::PROBE_PORT;
    dbg = GdbConnection::await_client_connection(
        port, probe, t->tgid(), t->vm()->exe_image(), GdbConnection::Features(),
        flags.debugger_params_write_pipe);
    if (flags.debugger_params_write_pipe) {
      flags.debugger_params_write_pipe->close();
    }
  }

  debuggee_tguid = t->task_group()->tguid();
  debugger_active = true;
}

void GdbServer::maybe_restart_session(const GdbRequest& req) {
  assert(req.type == DREQ_RESTART);
  assert(dbg);

  ReplayTimeline::Mark mark_to_restore;
  if (req.restart.type == RESTART_FROM_CHECKPOINT) {
    auto it = checkpoints.find(req.restart.param);
    if (it == checkpoints.end()) {
      LOG(info) << "Checkpoint " << req.restart.param << " not found.";
      dbg->notify_restart_failed();
      return;
    }
    mark_to_restore = it->second;
  } else if (req.restart.type == RESTART_FROM_PREVIOUS) {
    mark_to_restore = debugger_restart_mark;
  }
  timeline.remove_breakpoints_and_watchpoints();
  if (mark_to_restore) {
    timeline.seek_to_mark(mark_to_restore);
    if (debugger_restart_mark) {
      timeline.remove_explicit_checkpoint(debugger_restart_mark);
    }
    debugger_restart_mark = mark_to_restore;
    if (timeline.can_add_checkpoint()) {
      timeline.add_explicit_checkpoint();
    }
    return;
  }

  debugger_active = false;

  assert(req.restart.type == RESTART_FROM_EVENT);
  // Note that we don't reset the target pid; we intentionally keep targeting
  // the same process no matter what is running when we hit the event.
  target.event = req.restart.param;
  timeline.seek_to_before_event(target.event);
}

void GdbServer::serve_replay(const ConnectionFlags& flags) {
  while (true) {
    while (true) {
      maybe_connect_debugger(flags);

      if (debugger_active &&
          !timeline.current_session().find_task_group(debuggee_tguid)) {
        // Our debugee must have exited.
        break;
      }

      if (replay_one_step() == REPLAY_EXITED) {
        break;
      }
    }
    LOG(info) << ("Replayer successfully finished.");

    if (!dbg) {
      LOG(info) << "Debugger was not launched before end of trace";
      break;
    }

    // TODO return real exit code, if it's useful.
    dbg->notify_exit_code(0);
    GdbRequest req =
        process_debugger_requests(timeline.current_session().last_task());
    if (DREQ_RESTART == req.type) {
      maybe_restart_session(req);
      continue;
    }
    FATAL() << "Received continue request after end-of-trace.";
  }

  LOG(debug) << "debugger server exiting ...";
}

void GdbServer::launch_gdb(ScopedFd& params_pipe_fd,
                           const string& gdb_command_file_path) {
  GdbConnection::launch_gdb(params_pipe_fd, gdb_rr_macros,
                            gdb_command_file_path);
}

void GdbServer::emergency_debug(Task* t) {
  // See the comment in |guard_overshoot()| explaining why we do
  // this.  Unlike in that context though, we don't know if |t|
  // overshot an internal breakpoint.  If it did, cover that
  // breakpoint up.
  if (t->vm()) {
    t->vm()->remove_all_breakpoints();
  }

  // Don't launch a debugger on fatal errors; the user is most
  // likely already in a debugger, and wouldn't be able to
  // control another session. Instead, launch a new GdbServer and wait for
  // the user to connect from another window.
  GdbConnection::Features features;
  // Don't advertise reverse_execution to gdb becase a) it won't work and
  // b) some gdb versions will fail if the user doesn't turn off async
  // mode (and we don't want to require users to do that)
  features.reverse_execution = false;
  unique_ptr<GdbConnection> dbg = GdbConnection::await_client_connection(
      t->tid, GdbConnection::PROBE_PORT, t->tgid(), t->vm()->exe_image(),
      features);

  GdbServer(dbg).process_debugger_requests(t);
}

string GdbServer::init_script() { return gdb_rr_macros; }
