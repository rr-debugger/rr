/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "GdbServer.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "BreakpointCondition.h"
#include "GdbCommandHandler.h"
#include "GdbExpression.h"
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "StringVectorToCharArray.h"
#include "Task.h"
#include "ThreadGroup.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

GdbServer::GdbServer(std::unique_ptr<GdbConnection>& dbg, Task* t)
    : dbg(std::move(dbg)),
      debuggee_tguid(t->thread_group()->tguid()),
      last_continue_tuid(t->tuid()),
      last_query_tuid(t->tuid()),
      final_event(UINT32_MAX),
      stop_replaying_to_target(false),
      interrupt_pending(false),
      emergency_debug_session(&t->session()),
      file_scope_pid(0) {
  memset(&stop_siginfo, 0, sizeof(stop_siginfo));
}

// Special-sauce macros defined by rr when launching the gdb client,
// which implement functionality outside of the gdb remote protocol.
// (Don't stare at them too long or you'll go blind ;).)
static const string& gdb_rr_macros() {
  static string s;

  if (s.empty()) {
    stringstream ss;
    ss << "define restart\n"
       << "  run c$arg0\n"
       << "end\n"
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
       << "define hook-run\n"
       << "  if $_thread != 0 && !$suppress_run_hook\n"
       << "    stepi\n"
       << "  end\n"
       << "end\n"
       << "define hookpost-continue\n"
       << "  set $suppress_run_hook = 1\n"
       << "end\n"
       << "define hookpost-step\n"
       << "  set $suppress_run_hook = 1\n"
       << "end\n"
       << "define hookpost-stepi\n"
       << "  set $suppress_run_hook = 1\n"
       << "end\n"
       << "define hookpost-next\n"
       << "  set $suppress_run_hook = 1\n"
       << "end\n"
       << "define hookpost-nexti\n"
       << "  set $suppress_run_hook = 1\n"
       << "end\n"
       << "define hookpost-finish\n"
       << "  set $suppress_run_hook = 1\n"
       << "end\n"
       << "define hookpost-reverse-continue\n"
       << "  set $suppress_run_hook = 1\n"
       << "end\n"
       << "define hookpost-reverse-step\n"
       << "  set $suppress_run_hook = 1\n"
       << "end\n"
       << "define hookpost-reverse-stepi\n"
       << "  set $suppress_run_hook = 1\n"
       << "end\n"
       << "define hookpost-reverse-finish\n"
       << "  set $suppress_run_hook = 1\n"
       << "end\n"
       << "define hookpost-run\n"
       << "  set $suppress_run_hook = 0\n"
       << "end\n"
       << "set unwindonsignal on\n"
       << "handle SIGURG stop\n"
       << "set prompt (rr) \n"
       << GdbCommandHandler::gdb_macros()
       // Try both "set target-async" and "maint set target-async" since
       // that changed recently.
       << "python\n"
       << "import re\n"
       << "m = re.compile("
       << "'.* ([0-9]+)\\.([0-9]+)(\\.([0-9]+))?.*'"
       << ").match(gdb.execute('show version', False, True))\n"
       << "ver = int(m.group(1))*10000 + int(m.group(2))*100\n"
       << "if m.group(4):\n"
       << "    ver = ver + int(m.group(4))\n"
       << "\n"
       << "if ver == 71100:\n"
       << "    gdb.write("
       << "'This version of gdb (7.11.0) has known bugs that break rr. "
       << "Install 7.11.1 or later.\\n', gdb.STDERR)\n"
       << "\n"
       << "if ver < 71101:\n"
       << "    gdb.execute('set target-async 0')\n"
       << "    gdb.execute('maint set target-async 0')\n"
       << "end\n";
    s = ss.str();
  }
  return s;
}

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
GdbRegisterValue GdbServer::get_reg(const Registers& regs,
                                    const ExtraRegisters& extra_regs,
                                    GdbRegister which) {
  GdbRegisterValue reg;
  memset(&reg, 0, sizeof(reg));
  reg.name = which;
  reg.size = rr::get_reg(regs, extra_regs, &reg.value[0], which, &reg.defined);
  return reg;
}

static GdbThreadId get_threadid(const Session& session, const TaskUid& tuid) {
  Task* t = session.find_task(tuid);
  pid_t pid = t ? t->tgid() : GdbThreadId::ANY.pid;
  return GdbThreadId(pid, tuid.tid());
}

static GdbThreadId get_threadid(Task* t) {
  return GdbThreadId(t->tgid(), t->rec_tid);
}

static bool matches_threadid(Task* t, const GdbThreadId& target) {
  return (target.pid <= 0 || target.pid == t->tgid()) &&
         (target.tid <= 0 || target.tid == t->rec_tid);
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
  if (!t->session().is_replaying()) {
    return;
  }
  auto rt = static_cast<ReplayTask*>(t);
  if (trace_instructions_up_to_event(
          rt->session().current_trace_frame().time())) {
    fputs("Stepping: ", stderr);
    t->regs().print_register_file_compact(stderr);
    fprintf(stderr, " ticks:%" PRId64 "\n", t->tick_count());
    *req = GdbRequest(DREQ_CONT);
    req->suppress_debugger_stop = true;
    req->cont().actions.push_back(
        GdbContAction(ACTION_STEP, get_threadid(t->session(), t->tuid())));
  }
}

void GdbServer::dispatch_regs_request(const Registers& regs,
                                      const ExtraRegisters& extra_regs) {
  GdbRegister end;
  // Send values for all the registers we sent XML register descriptions for.
  // Those descriptions are controlled by GdbConnection::cpu_features().
  bool have_AVX = dbg->cpu_features() & GdbConnection::CPU_AVX;
  switch (regs.arch()) {
    case x86:
      end = have_AVX ? DREG_YMM7H : DREG_ORIG_EAX;
      break;
    case x86_64:
      end = have_AVX ? DREG_64_YMM15H : DREG_ORIG_RAX;
      break;
    default:
      FATAL() << "Unknown architecture";
      return;
  }
  vector<GdbRegisterValue> rs;
  for (GdbRegister r = GdbRegister(0); r <= end; r = GdbRegister(r + 1)) {
    rs.push_back(get_reg(regs, extra_regs, r));
  }
  dbg->reply_get_regs(rs);
}

class GdbBreakpointCondition : public BreakpointCondition {
public:
  GdbBreakpointCondition(const vector<vector<uint8_t>>& bytecodes) {
    for (auto& b : bytecodes) {
      expressions.push_back(GdbExpression(b.data(), b.size()));
    }
  }
  virtual bool evaluate(Task* t) const override {
    for (auto& e : expressions) {
      GdbExpression::Value v;
      // Break if evaluation fails or the result is nonzero
      if (!e.evaluate(t, &v) || v.i != 0) {
        return true;
      }
    }
    return false;
  }

private:
  vector<GdbExpression> expressions;
};

static unique_ptr<BreakpointCondition> breakpoint_condition(
    const GdbRequest& request) {
  if (request.watch().conditions.empty()) {
    return nullptr;
  }
  return unique_ptr<BreakpointCondition>(
      new GdbBreakpointCondition(request.watch().conditions));
}

static bool search_memory(Task* t, const MemoryRange& where,
                          const vector<uint8_t>& find,
                          remote_ptr<void>* result) {
  vector<uint8_t> buf;
  buf.resize(page_size() + find.size() - 1);
  for (const auto& m : t->vm()->maps()) {
    MemoryRange r = MemoryRange(m.map.start(), m.map.end() + find.size() - 1)
                        .intersect(where);
    // We basically read page by page here, but we read past the end of the
    // page to handle the case where a found string crosses page boundaries.
    // This approach isn't great for handling long search strings but gdb's find
    // command isn't really suited to that.
    // Reading page by page lets us avoid problems where some pages in a
    // mapping aren't readable (e.g. reading beyond end of file).
    while (r.size() >= find.size()) {
      ssize_t nread = t->read_bytes_fallible(
          r.start(), std::min(buf.size(), r.size()), buf.data());
      if (nread >= ssize_t(find.size())) {
        void* found = memmem(buf.data(), nread, find.data(), find.size());
        if (found) {
          *result = r.start() + (static_cast<uint8_t*>(found) - buf.data());
          return true;
        }
      }
      r = MemoryRange(
          std::min(r.end(), floor_page_size(r.start()) + page_size()), r.end());
    }
  }
  return false;
}

template <typename Arch> static size_t word_size_arch() {
  return sizeof(typename Arch::signed_long);
}

static size_t word_size(SupportedArch arch) {
  RR_ARCH_FUNCTION(word_size_arch, arch);
}

static bool is_in_patch_stubs(Task* t, remote_code_ptr ip) {
  auto p = ip.to_data_ptr<void>();
  return t->vm()->has_mapping(p) &&
         (t->vm()->mapping_flags_of(p) & AddressSpace::Mapping::IS_PATCH_STUBS);
}

void GdbServer::maybe_intercept_mem_request(Task* target, const GdbRequest& req,
                                            vector<uint8_t>* result) {
  /* Crazy hack!
   * When gdb tries to read the word at the top of the stack, and we're in our
   * dynamically-generated stub code, tell it the value is zero, so that gdb's
   * stack-walking code doesn't find a bogus value that it treats as a return
   * address and sets a breakpoint there, potentially corrupting program data.
   * gdb sometimes reads a whole block of memory around the stack pointer so
   * handle cases where the top-of-stack word is contained in a larger range.
   */
  size_t size = word_size(target->arch());
  if (target->regs().sp().as_int() >= req.mem_.addr &&
      target->regs().sp().as_int() + size <= req.mem_.addr + req.mem_.len &&
      is_in_patch_stubs(target, target->ip())) {
    memset(result->data() + target->regs().sp().as_int() - req.mem_.addr, 0,
           size);
  }
}

void GdbServer::dispatch_debugger_request(Session& session,
                                          const GdbRequest& req,
                                          ReportState state) {
  DEBUG_ASSERT(!req.is_resume_request());

  // These requests don't require a target task.
  switch (req.type) {
    case DREQ_RESTART:
      DEBUG_ASSERT(false);
      return; // unreached
    case DREQ_GET_CURRENT_THREAD:
      dbg->reply_get_current_thread(get_threadid(session, last_continue_tuid));
      return;
    case DREQ_GET_OFFSETS:
      /* TODO */
      dbg->reply_get_offsets();
      return;
    case DREQ_GET_THREAD_LIST: {
      vector<GdbThreadId> tids;
      if (state != REPORT_THREADS_DEAD) {
        for (auto& kv : session.tasks()) {
          tids.push_back(get_threadid(session, kv.second->tuid()));
        }
      }
      dbg->reply_get_thread_list(tids);
      return;
    }
    case DREQ_INTERRUPT: {
      Task* t = session.find_task(last_continue_tuid);
      ASSERT(t, session.is_diversion())
          << "Replay interrupts should be handled at a higher level";
      DEBUG_ASSERT(!t || t->thread_group()->tguid() == debuggee_tguid);
      dbg->notify_stop(t ? get_threadid(t) : GdbThreadId(), 0);
      memset(&stop_siginfo, 0, sizeof(stop_siginfo));
      if (t) {
        last_query_tuid = last_continue_tuid = t->tuid();
      }
      return;
    }
    case DREQ_GET_EXEC_FILE: {
      // We shouldn't normally receive this since we try to pass the exe file
      // name on gdb's command line, but the user might start gdb manually
      // and this is easy to support in case some other debugger or
      // configuration needs it.
      Task* t = nullptr;
      if (req.target.tid) {
        ThreadGroup* tg = session.find_thread_group(req.target.tid);
        if (tg) {
          t = *tg->task_set().begin();
        }
      } else {
        t = session.find_task(last_continue_tuid);
      }
      if (t) {
        dbg->reply_get_exec_file(t->vm()->exe_image());
      } else {
        dbg->reply_get_exec_file(string());
      }
      return;
    }
    case DREQ_FILE_SETFS:
      // Only the filesystem as seen by the remote stub is supported currently
      file_scope_pid = req.file_setfs().pid;
      dbg->reply_setfs(0);
      return;
    case DREQ_FILE_OPEN:
      // We only support reading files
      if (req.file_open().flags == O_RDONLY) {
        int fd = open_file(session, req.file_open().file_name);
        dbg->reply_open(fd, fd >= 0 ? 0 : ENOENT);
      } else {
        dbg->reply_open(-1, EACCES);
      }
      return;
    case DREQ_FILE_PREAD: {
      auto it = files.find(req.file_pread().fd);
      if (it != files.end()) {
        size_t size = min<uint64_t>(req.file_pread().size, 1024 * 1024);
        vector<uint8_t> data;
        data.resize(size);
        ssize_t bytes =
            read_to_end(it->second, req.file_pread().offset, data.data(), size);
        dbg->reply_pread(data.data(), bytes, bytes >= 0 ? 0 : errno);
      } else {
        dbg->reply_pread(nullptr, 0, EBADF);
      }
      return;
    }
    case DREQ_FILE_CLOSE: {
      auto it = files.find(req.file_close().fd);
      if (it != files.end()) {
        files.erase(it);
        dbg->reply_close(0);
      } else {
        dbg->reply_close(EBADF);
      }
      return;
    }
    default:
      /* fall through to next switch stmt */
      break;
  }

  bool is_query = req.type != DREQ_SET_CONTINUE_THREAD;
  Task* target =
      req.target.tid > 0
          ? session.find_task(req.target.tid)
          : session.find_task(is_query ? last_query_tuid : last_continue_tuid);
  if (target) {
    if (is_query) {
      last_query_tuid = target->tuid();
    } else {
      last_continue_tuid = target->tuid();
    }
  }
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
      dbg->reply_select_thread(target != nullptr);
      return;
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
      dbg->reply_get_auxv(target->vm()->saved_auxv());
      return;
    }
    case DREQ_GET_MEM: {
      vector<uint8_t> mem;
      mem.resize(req.mem().len);
      ssize_t nread = target->read_bytes_fallible(req.mem().addr, req.mem().len,
                                                  mem.data());
      mem.resize(max(ssize_t(0), nread));
      target->vm()->replace_breakpoints_with_original_values(
          mem.data(), mem.size(), req.mem().addr);
      maybe_intercept_mem_request(target, req, &mem);
      dbg->reply_get_mem(mem);
      return;
    }
    case DREQ_SET_MEM: {
      // gdb has been observed to send requests of length 0 at
      // odd times
      // (e.g. before sending the magic write to create a checkpoint)
      if (req.mem().len == 0) {
        dbg->reply_set_mem(true);
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
      LOG(debug) << "Writing " << req.mem().len << " bytes to "
                 << HEX(req.mem().addr);
      // TODO fallible
      target->write_bytes_helper(req.mem().addr, req.mem().len,
                                 req.mem().data.data());
      dbg->reply_set_mem(true);
      return;
    }
    case DREQ_SEARCH_MEM: {
      remote_ptr<void> addr;
      bool found =
          search_memory(target, MemoryRange(req.mem().addr, req.mem().len),
                        req.mem().data, &addr);
      dbg->reply_search_mem(found, addr);
      return;
    }
    case DREQ_GET_REG: {
      GdbRegisterValue reg =
          get_reg(target->regs(), target->extra_regs(), req.reg().name);
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
        if ((target->arch() == x86 && req.reg().name == DREG_ORIG_EAX) ||
            (target->arch() == x86_64 && req.reg().name == DREG_ORIG_RAX)) {
          dbg->reply_set_reg(true);
          return;
        }
        LOG(error) << "Attempt to write register outside diversion session";
        dbg->reply_set_reg(false);
        return;
      }
      if (req.reg().defined) {
        Registers regs = target->regs();
        regs.write_register(req.reg().name, req.reg().value, req.reg().size);
        target->set_regs(regs);
      }
      dbg->reply_set_reg(true /*currently infallible*/);
      return;
    }
    case DREQ_GET_STOP_REASON: {
      dbg->reply_get_stop_reason(get_threadid(session, last_continue_tuid),
                                 stop_siginfo.si_signo);
      return;
    }
    case DREQ_SET_SW_BREAK: {
      ASSERT(target, req.watch().kind == sizeof(AddressSpace::breakpoint_insn))
          << "Debugger setting bad breakpoint insn";
      // Mirror all breakpoint/watchpoint sets/unsets to the target process
      // if it's not part of the timeline (i.e. it's a diversion).
      ReplayTask* replay_task =
          timeline.current_session().find_task(target->tuid());
      bool ok = timeline.add_breakpoint(replay_task, req.watch().addr,
                                        breakpoint_condition(req));
      if (ok && &session != &timeline.current_session()) {
        bool diversion_ok =
            target->vm()->add_breakpoint(req.watch().addr, BKPT_USER);
        ASSERT(target, diversion_ok);
      }
      dbg->reply_watchpoint_request(ok);
      return;
    }
    case DREQ_SET_HW_BREAK:
    case DREQ_SET_RD_WATCH:
    case DREQ_SET_WR_WATCH:
    case DREQ_SET_RDWR_WATCH: {
      ReplayTask* replay_task =
          timeline.current_session().find_task(target->tuid());
      bool ok = timeline.add_watchpoint(
          replay_task, req.watch().addr, req.watch().kind,
          watchpoint_type(req.type), breakpoint_condition(req));
      if (ok && &session != &timeline.current_session()) {
        bool diversion_ok = target->vm()->add_watchpoint(
            req.watch().addr, req.watch().kind, watchpoint_type(req.type));
        ASSERT(target, diversion_ok);
      }
      dbg->reply_watchpoint_request(ok);
      return;
    }
    case DREQ_REMOVE_SW_BREAK: {
      ReplayTask* replay_task =
          timeline.current_session().find_task(target->tuid());
      timeline.remove_breakpoint(replay_task, req.watch().addr);
      if (&session != &timeline.current_session()) {
        target->vm()->remove_breakpoint(req.watch().addr, BKPT_USER);
      }
      dbg->reply_watchpoint_request(true);
      return;
    }
    case DREQ_REMOVE_HW_BREAK:
    case DREQ_REMOVE_RD_WATCH:
    case DREQ_REMOVE_WR_WATCH:
    case DREQ_REMOVE_RDWR_WATCH: {
      ReplayTask* replay_task =
          timeline.current_session().find_task(target->tuid());
      timeline.remove_watchpoint(replay_task, req.watch().addr,
                                 req.watch().kind, watchpoint_type(req.type));
      if (&session != &timeline.current_session()) {
        target->vm()->remove_watchpoint(req.watch().addr, req.watch().kind,
                                        watchpoint_type(req.type));
      }
      dbg->reply_watchpoint_request(true);
      return;
    }
    case DREQ_READ_SIGINFO: {
      vector<uint8_t> si_bytes;
      si_bytes.resize(req.mem().len);
      memset(si_bytes.data(), 0, si_bytes.size());
      memcpy(si_bytes.data(), &stop_siginfo,
             min(si_bytes.size(), sizeof(stop_siginfo)));
      dbg->reply_read_siginfo(si_bytes);
      return;
    }
    case DREQ_WRITE_SIGINFO:
      LOG(warn) << "WRITE_SIGINFO request outside of diversion session";
      dbg->reply_write_siginfo();
      return;
    case DREQ_RR_CMD:
      dbg->reply_rr_cmd(
          GdbCommandHandler::process_command(*this, target, req.text()));
      return;
    case DREQ_QSYMBOL: {
      // When gdb sends "qSymbol::", it means that gdb is ready to
      // respond to symbol requests.  This can be sent multiple times
      // during the course of a session -- gdb sends it whenever
      // something in the inferior has changed, making it possible
      // that previous failed symbol lookups could now succeed.  In
      // response to a qSymbol request from gdb, we either send back a
      // qSymbol response, requesting the address of a symbol; or we
      // send back OK.  We have to do this as an ordinary response and
      // maintain our own state explicitly, as opposed to simply
      // reading another packet from gdb, because when gdb looks up a
      // symbol it might send other requests that must be served.  So,
      // we keep a copy of the symbol names, and an iterator into this
      // copy.  When gdb sends a plain "qSymbol::" packet, because gdb
      // has detected some change in the inferior state that might
      // enable more symbol lookups, we restart the iterator.
      if (!thread_db) {
        thread_db =
            std::unique_ptr<ThreadDb>(new ThreadDb(debuggee_tguid.tid()));
      }

      const string& name = req.sym().name;
      if (req.sym().has_address) {
        // Got a response holding a previously-requested symbol's name
        // and address.
        thread_db->register_symbol(name, req.sym().address);
      } else if (name == "") {
        // Plain "qSymbol::" request.
        symbols =
            thread_db->get_symbols_and_clear_map(target->thread_group().get());
        symbols_iter = symbols.begin();
      }

      if (symbols_iter == symbols.end()) {
        dbg->qsymbols_finished();
      } else {
        string symbol = *symbols_iter++;
        dbg->send_qsymbol(symbol);
      }
      return;
    }
    case DREQ_TLS: {
      if (!thread_db) {
        thread_db =
            std::unique_ptr<ThreadDb>(new ThreadDb(debuggee_tguid.tid()));
      }
      remote_ptr<void> address;
      bool ok = thread_db->get_tls_address(target->thread_group().get(),
                                           target->rec_tid, req.tls().offset,
                                           req.tls().load_module, &address);
      dbg->reply_tls_addr(ok, address);
      return;
    }
    default:
      FATAL() << "Unknown debugger request " << req.type;
  }
}

bool GdbServer::diverter_process_debugger_requests(
    DiversionSession& diversion_session, uint32_t& diversion_refcount,
    GdbRequest* req) {
  while (true) {
    *req = dbg->get_request();

    if (req->is_resume_request()) {
      return diversion_refcount > 0;
    }

    switch (req->type) {
      case DREQ_RESTART:
      case DREQ_DETACH:
        diversion_refcount = 0;
        return false;

      case DREQ_READ_SIGINFO: {
        LOG(debug) << "Adding ref to diversion session";
        ++diversion_refcount;
        // TODO: maybe share with replayer.cc?
        vector<uint8_t> si_bytes;
        si_bytes.resize(req->mem().len);
        memset(si_bytes.data(), 0, si_bytes.size());
        dbg->reply_read_siginfo(si_bytes);
        continue;
      }

      case DREQ_SET_QUERY_THREAD: {
        if (req->target.tid) {
          Task* next = diversion_session.find_task(req->target.tid);
          if (next) {
            last_query_tuid = next->tuid();
          }
        }
        break;
      }

      case DREQ_WRITE_SIGINFO:
        LOG(debug) << "Removing reference to diversion session ...";
        DEBUG_ASSERT(diversion_refcount > 0);
        --diversion_refcount;
        if (diversion_refcount == 0) {
          LOG(debug) << "  ... dying at next continue request";
        }
        dbg->reply_write_siginfo();
        continue;

      case DREQ_RR_CMD: {
        DEBUG_ASSERT(req->type == DREQ_RR_CMD);
        Task* task = diversion_session.find_task(last_continue_tuid);
        if (task) {
          std::string reply =
              GdbCommandHandler::process_command(*this, task, req->text());
          // Certain commands cause the diversion to end immediately
          // while other commands must work within a diversion.
          if (reply == GdbCommandHandler::cmd_end_diversion()) {
            diversion_refcount = 0;
            return false;
          }
          dbg->reply_rr_cmd(reply);
          continue;
        } else {
          diversion_refcount = 0;
          return false;
        }
        break;
      }

      default:
        break;
    }
    dispatch_debugger_request(diversion_session, *req, REPORT_NORMAL);
  }
}

static bool is_last_thread_exit(const BreakStatus& break_status) {
  return break_status.task_exit &&
         break_status.task->thread_group()->task_set().size() == 1;
}

static Task* is_in_exec(ReplayTimeline& timeline) {
  Task* t = timeline.current_session().current_task();
  if (!t) {
    return nullptr;
  }
  return timeline.current_session().next_step_is_successful_syscall_exit(
             syscall_number_for_execve(t->arch()))
             ? t
             : nullptr;
}

void GdbServer::maybe_notify_stop(const GdbRequest& req,
                                  const BreakStatus& break_status) {
  bool do_stop = false;
  remote_ptr<void> watch_addr;
  if (!break_status.watchpoints_hit.empty()) {
    do_stop = true;
    memset(&stop_siginfo, 0, sizeof(stop_siginfo));
    stop_siginfo.si_signo = SIGTRAP;
    watch_addr = break_status.watchpoints_hit[0].addr;
    LOG(debug) << "Stopping for watchpoint at " << watch_addr;
  }
  if (break_status.breakpoint_hit || break_status.singlestep_complete) {
    do_stop = true;
    memset(&stop_siginfo, 0, sizeof(stop_siginfo));
    stop_siginfo.si_signo = SIGTRAP;
    if (break_status.breakpoint_hit) {
      LOG(debug) << "Stopping for breakpoint";
    } else {
      LOG(debug) << "Stopping for singlestep";
    }
  }
  if (break_status.signal) {
    do_stop = true;
    stop_siginfo = *break_status.signal;
    LOG(debug) << "Stopping for signal " << stop_siginfo;
  }
  if (is_last_thread_exit(break_status) && dbg->features().reverse_execution) {
    do_stop = true;
    memset(&stop_siginfo, 0, sizeof(stop_siginfo));
    if (req.cont().run_direction == RUN_FORWARD) {
      // The exit of the last task in a thread group generates a fake SIGKILL,
      // when reverse-execution is enabled, because users often want to run
      // backwards from the end of the task.
      stop_siginfo.si_signo = SIGKILL;
      LOG(debug) << "Stopping for synthetic SIGKILL";
    } else {
      // The start of the debuggee task-group should trigger a silent stop.
      stop_siginfo.si_signo = 0;
      LOG(debug) << "Stopping at start of execution while running backwards";
    }
  }
  Task* t = break_status.task;
  Task* in_exec_task = is_in_exec(timeline);
  if (in_exec_task) {
    do_stop = true;
    memset(&stop_siginfo, 0, sizeof(stop_siginfo));
    t = in_exec_task;
    LOG(debug) << "Stopping at exec";
  }
  if (do_stop && t->thread_group()->tguid() == debuggee_tguid) {
    /* Notify the debugger and process any new requests
     * that might have triggered before resuming. */
    dbg->notify_stop(get_threadid(t), stop_siginfo.si_signo,
                     watch_addr.as_int());
    last_query_tuid = last_continue_tuid = t->tuid();
  }
}

static RunCommand compute_run_command_from_actions(Task* t,
                                                   const GdbRequest& req,
                                                   int* signal_to_deliver) {
  for (auto& action : req.cont().actions) {
    if (matches_threadid(t, action.target)) {
      // We can only run task |t|; neither diversion nor replay sessions
      // support running multiple threads. So even if gdb tells us to continue
      // multiple threads, we don't do that.
      *signal_to_deliver = action.signal_to_deliver;
      return action.type == ACTION_STEP ? RUN_SINGLESTEP : RUN_CONTINUE;
    }
  }
  // gdb told us to run (or step) some thread that's not |t|, without resuming
  // |t|. It sometimes does this even though its target thread is entering a
  // blocking syscall and |t| must run before gdb's target thread can make
  // progress. So, allow |t| to run anyway.
  *signal_to_deliver = 0;
  return RUN_CONTINUE;
}

struct AllowedTasks {
  TaskUid task; // tid 0 means 'any member of debuggee_tguid'
  RunCommand command;
};
static RunCommand compute_run_command_for_reverse_exec(
    Session& session, const ThreadGroupUid& debuggee_tguid,
    const GdbRequest& req, vector<AllowedTasks>& allowed_tasks) {
  // Singlestep if any of the actions request singlestepping.
  RunCommand result = RUN_CONTINUE;
  for (auto& action : req.cont().actions) {
    if (action.target.pid > 0 && action.target.pid != debuggee_tguid.tid()) {
      continue;
    }
    AllowedTasks allowed;
    allowed.command = RUN_CONTINUE;
    if (action.type == ACTION_STEP) {
      allowed.command = result = RUN_SINGLESTEP;
    }
    if (action.target.tid > 0) {
      Task* t = session.find_task(action.target.tid);
      if (t) {
        allowed.task = t->tuid();
      }
    }
    allowed_tasks.push_back(allowed);
  }
  return result;
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
GdbRequest GdbServer::divert(ReplaySession& replay) {
  GdbRequest req;
  LOG(debug) << "Starting debugging diversion for " << &replay;

  if (timeline.is_running()) {
    // Ensure breakpoints and watchpoints are applied before we fork the
    // diversion, to ensure the diversion is consistent with the timeline
    // breakpoint/watchpoint state.
    timeline.apply_breakpoints_and_watchpoints();
  }
  DiversionSession::shr_ptr diversion_session = replay.clone_diversion();
  uint32_t diversion_refcount = 1;
  TaskUid saved_query_tuid = last_query_tuid;

  while (diverter_process_debugger_requests(*diversion_session,
                                            diversion_refcount, &req)) {
    DEBUG_ASSERT(req.is_resume_request());

    if (req.cont().run_direction == RUN_BACKWARD) {
      // We don't support reverse execution in a diversion. Just issue
      // an immediate stop.
      dbg->notify_stop(get_threadid(*diversion_session, last_continue_tuid), 0);
      memset(&stop_siginfo, 0, sizeof(stop_siginfo));
      last_query_tuid = last_continue_tuid;
      continue;
    }

    Task* t = diversion_session->find_task(last_continue_tuid);
    if (!t) {
      diversion_refcount = 0;
      req = GdbRequest(DREQ_NONE);
      break;
    }

    int signal_to_deliver;
    RunCommand command =
        compute_run_command_from_actions(t, req, &signal_to_deliver);
    auto result =
        diversion_session->diversion_step(t, command, signal_to_deliver);

    if (result.status == DiversionSession::DIVERSION_EXITED) {
      diversion_refcount = 0;
      req = GdbRequest(DREQ_NONE);
      break;
    }

    DEBUG_ASSERT(result.status == DiversionSession::DIVERSION_CONTINUE);

    maybe_notify_stop(req, result.break_status);
  }

  LOG(debug) << "... ending debugging diversion";
  DEBUG_ASSERT(diversion_refcount == 0);

  diversion_session->kill_all_tasks();

  last_query_tuid = saved_query_tuid;
  return req;
}

/**
 * Reply to debugger requests until the debugger asks us to resume
 * execution, detach, restart, or interrupt.
 */
GdbRequest GdbServer::process_debugger_requests(ReportState state) {
  while (true) {
    GdbRequest req = dbg->get_request();
    req.suppress_debugger_stop = false;
    try_lazy_reverse_singlesteps(req);

    if (req.type == DREQ_READ_SIGINFO) {
      vector<uint8_t> si_bytes;
      si_bytes.resize(req.mem().len);
      memset(si_bytes.data(), 0, si_bytes.size());
      memcpy(si_bytes.data(), &stop_siginfo,
             min(si_bytes.size(), sizeof(stop_siginfo)));
      dbg->reply_read_siginfo(si_bytes);

      // READ_SIGINFO is usually the start of a diversion. It can also be
      // triggered by "print $_siginfo" but that is rare so we just assume it's
      // a diversion start; if "print $_siginfo" happens we'll print the correct
      // siginfo and then incorrectly start a diversion and go haywire :-(.
      // Ideally we'd come up with a better way to detect diversions so that
      // "print $_siginfo" works.
      req = divert(timeline.current_session());
      if (req.type == DREQ_NONE) {
        continue;
      }
      // Carry on to process the request that was rejected by
      // the diversion session
    }

    if (req.is_resume_request()) {
      Task* t = current_session().find_task(last_continue_tuid);
      if (t) {
        maybe_singlestep_for_event(t, &req);
      }
      return req;
    }

    if (req.type == DREQ_INTERRUPT) {
      LOG(debug) << "  request to interrupt";
      return req;
    }

    if (req.type == DREQ_RESTART) {
      // Debugger client requested that we restart execution
      // from the beginning.  Restart our debug session.
      LOG(debug) << "  request to restart at event " << req.restart().param;
      return req;
    }
    if (req.type == DREQ_DETACH) {
      LOG(debug) << "  debugger detached";
      dbg->reply_detach();
      return req;
    }

    dispatch_debugger_request(current_session(), req, state);
  }
}

void GdbServer::try_lazy_reverse_singlesteps(GdbRequest& req) {
  if (!timeline.is_running()) {
    return;
  }

  ReplayTimeline::Mark now;
  bool need_seek = false;
  ReplayTask* t = timeline.current_session().current_task();
  while (t && req.type == DREQ_CONT &&
         req.cont().run_direction == RUN_BACKWARD &&
         req.cont().actions.size() == 1 &&
         req.cont().actions[0].type == ACTION_STEP &&
         req.cont().actions[0].signal_to_deliver == 0 &&
         matches_threadid(t, req.cont().actions[0].target) &&
         !req.suppress_debugger_stop) {
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
    maybe_notify_stop(req, break_status);

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

bool GdbServer::detach_or_restart(const GdbRequest& req, ContinueOrStop* s) {
  if (DREQ_RESTART == req.type) {
    restart_session(req);
    *s = CONTINUE_DEBUGGING;
    return true;
  }
  if (DREQ_DETACH == req.type) {
    *s = STOP_DEBUGGING;
    return true;
  }
  return false;
}

GdbServer::ContinueOrStop GdbServer::handle_exited_state(
    GdbRequest& last_resume_request) {
  // TODO return real exit code, if it's useful.
  dbg->notify_exit_code(0);
  final_event = timeline.current_session().trace_reader().time();
  GdbRequest req = process_debugger_requests(REPORT_THREADS_DEAD);
  ContinueOrStop s;
  if (detach_or_restart(req, &s)) {
    last_resume_request = GdbRequest();
    return s;
  }
  FATAL() << "Received continue/interrupt request after end-of-trace.";
  return STOP_DEBUGGING;
}

GdbServer::ContinueOrStop GdbServer::debug_one_step(
    GdbRequest& last_resume_request) {
  ReplayResult result;
  GdbRequest req;

  if (in_debuggee_end_state) {
    // Treat the state where the last thread is about to exit like
    // termination.
    req = process_debugger_requests();
    // If it's a forward execution request, fake the exited state.
    if (req.is_resume_request() && req.cont().run_direction == RUN_FORWARD) {
      if (interrupt_pending) {
        // Just process this. We're getting it after a restart.
      } else {
        return handle_exited_state(last_resume_request);
      }
    } else {
      if (req.type != DREQ_DETACH) {
        in_debuggee_end_state = false;
      }
    }
    // Otherwise (e.g. detach, restart, interrupt or reverse-exec) process
    // the request as normal.
  } else if (!interrupt_pending || last_resume_request.type == DREQ_NONE) {
    req = process_debugger_requests();
  } else {
    req = last_resume_request;
  }

  ContinueOrStop s;
  if (detach_or_restart(req, &s)) {
    last_resume_request = GdbRequest();
    return s;
  }

  if (req.is_resume_request()) {
    last_resume_request = req;
  } else {
    DEBUG_ASSERT(req.type == DREQ_INTERRUPT);
    interrupt_pending = true;
    req = last_resume_request;
    DEBUG_ASSERT(req.is_resume_request());
  }

  if (interrupt_pending) {
    Task* t = timeline.current_session().current_task();
    if (t->thread_group()->tguid() == debuggee_tguid) {
      interrupt_pending = false;
      dbg->notify_stop(get_threadid(t), in_debuggee_end_state ? SIGKILL : 0);
      memset(&stop_siginfo, 0, sizeof(stop_siginfo));
      return CONTINUE_DEBUGGING;
    }
  }

  if (req.cont().run_direction == RUN_FORWARD) {
    if (is_in_exec(timeline) &&
        timeline.current_session().current_task()->thread_group()->tguid() ==
            debuggee_tguid) {
      // Don't go any further forward. maybe_notify_stop will generate a
      // stop.
      result = ReplayResult();
    } else {
      int signal_to_deliver;
      RunCommand command = compute_run_command_from_actions(
          timeline.current_session().current_task(), req, &signal_to_deliver);
      // Ignore gdb's |signal_to_deliver|; we just have to follow the replay.
      result = timeline.replay_step_forward(command, target.event);
    }
    if (result.status == REPLAY_EXITED) {
      return handle_exited_state(last_resume_request);
    }
  } else {
    vector<AllowedTasks> allowed_tasks;
    // Convert the tids in GdbContActions into TaskUids to avoid issues
    // if tids get reused.
    RunCommand command = compute_run_command_for_reverse_exec(
        timeline.current_session(), debuggee_tguid, req, allowed_tasks);
    auto stop_filter = [&](Task* t) -> bool {
      if (t->thread_group()->tguid() != debuggee_tguid) {
        return false;
      }
      // If gdb's requested actions don't allow the task to run, we still
      // let it run (we can't do anything else, since we're replaying), but
      // we won't report stops in that task.
      for (auto& a : allowed_tasks) {
        if (a.task.tid() == 0 || a.task == t->tuid()) {
          return true;
        }
      }
      return false;
    };

    auto interrupt_check = [&]() { return dbg->sniff_packet(); };
    switch (command) {
      case RUN_CONTINUE:
        result = timeline.reverse_continue(stop_filter, interrupt_check);
        break;
      case RUN_SINGLESTEP: {
        Task* t = timeline.current_session().find_task(last_continue_tuid);
        DEBUG_ASSERT(t);
        result = timeline.reverse_singlestep(
            last_continue_tuid, t->tick_count(), stop_filter, interrupt_check);
        break;
      }
      default:
        DEBUG_ASSERT(0 && "Unknown RunCommand");
    }

    if (result.status == REPLAY_EXITED) {
      return handle_exited_state(last_resume_request);
    }
  }
  if (!req.suppress_debugger_stop) {
    maybe_notify_stop(req, result.break_status);
  }
  if (req.cont().run_direction == RUN_FORWARD &&
      is_last_thread_exit(result.break_status) &&
      result.break_status.task->thread_group()->tguid() == debuggee_tguid) {
    in_debuggee_end_state = true;
  }
  return CONTINUE_DEBUGGING;
}

bool GdbServer::at_target() {
  // Don't launch the debugger for the initial rr fork child.
  // No one ever wants that to happen.
  if (!timeline.current_session().done_initial_exec()) {
    return false;
  }
  Task* t = timeline.current_session().current_task();
  if (!t) {
    return false;
  }
  if (!timeline.can_add_checkpoint()) {
    return false;
  }
  if (stop_replaying_to_target) {
    return true;
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
  // NB: we'll happily attach to whichever task within the
  // group happens to be scheduled here.  We don't take
  // "attach to process" to mean "attach to thread-group
  // leader".
  return timeline.current_session().current_trace_frame().time() >
             target.event &&
         (!target.pid || t->tgid() == target.pid) &&
         (!target.require_exec || t->execed()) &&
         // Ensure we're at the start of processing an event. We don't
         // want to attach while we're finishing an exec() since that's a
         // slightly confusing state for ReplayTimeline's reverse execution.
         !timeline.current_session().current_step_key().in_execution();
}

/**
 * The trace has reached the event at which the user wanted to start debugging.
 * Set up the appropriate state.
 */
void GdbServer::activate_debugger() {
  TraceFrame next_frame = timeline.current_session().current_trace_frame();
  FrameTime event_now = next_frame.time();
  Task* t = timeline.current_session().current_task();
  if (target.event > 0 || target.pid) {
    if (stop_replaying_to_target) {
      fprintf(stderr, "\a\n"
                      "--------------------------------------------------\n"
                      " ---> Interrupted; attached to NON-TARGET process %d at event %llu.\n"
                      "--------------------------------------------------\n",
              t->tgid(), (long long)event_now);
    } else {
      fprintf(stderr, "\a\n"
                      "--------------------------------------------------\n"
                      " ---> Reached target process %d at event %llu.\n"
                      "--------------------------------------------------\n",
              t->tgid(), (long long)event_now);
    }
  }

  // Store the current tgid and event as the "execution target"
  // for the next replay session, if we end up restarting.  This
  // allows us to determine if a later session has reached this
  // target without necessarily replaying up to this point.
  target.pid = t->tgid();
  target.require_exec = false;
  target.event = event_now;

  last_query_tuid = last_continue_tuid = t->tuid();

  // Have the "checkpoint" be the original replay
  // session, and then switch over to using the cloned
  // session.  The cloned tasks will look like children
  // of the clonees, so this scheme prevents |pstree|
  // output from getting /too/ far out of whack.
  const char* where = "???";
  if (timeline.can_add_checkpoint()) {
    debugger_restart_checkpoint =
        Checkpoint(timeline, last_continue_tuid, Checkpoint::EXPLICIT, where);
  } else {
    debugger_restart_checkpoint = Checkpoint(timeline, last_continue_tuid,
                                             Checkpoint::NOT_EXPLICIT, where);
  }
}

void GdbServer::restart_session(const GdbRequest& req) {
  DEBUG_ASSERT(req.type == DREQ_RESTART);
  DEBUG_ASSERT(dbg);

  in_debuggee_end_state = false;
  timeline.remove_breakpoints_and_watchpoints();

  Checkpoint checkpoint_to_restore;
  if (req.restart().type == RESTART_FROM_CHECKPOINT) {
    auto it = checkpoints.find(req.restart().param);
    if (it == checkpoints.end()) {
      cout << "Checkpoint " << req.restart().param_str << " not found.\n";
      cout << "Valid checkpoints:";
      for (auto& c : checkpoints) {
        cout << " " << c.first;
      }
      cout << "\n";
      dbg->notify_restart_failed();
      return;
    }
    checkpoint_to_restore = it->second;
  } else if (req.restart().type == RESTART_FROM_PREVIOUS) {
    checkpoint_to_restore = debugger_restart_checkpoint;
  }

  interrupt_pending = true;

  if (checkpoint_to_restore.mark) {
    timeline.seek_to_mark(checkpoint_to_restore.mark);
    last_query_tuid = last_continue_tuid =
        checkpoint_to_restore.last_continue_tuid;
    if (debugger_restart_checkpoint.is_explicit == Checkpoint::EXPLICIT) {
      timeline.remove_explicit_checkpoint(debugger_restart_checkpoint.mark);
    }
    debugger_restart_checkpoint = checkpoint_to_restore;
    if (timeline.can_add_checkpoint()) {
      timeline.add_explicit_checkpoint();
    }
    return;
  }

  stop_replaying_to_target = false;

  DEBUG_ASSERT(req.restart().type == RESTART_FROM_EVENT);
  // Note that we don't reset the target pid; we intentionally keep targeting
  // the same process no matter what is running when we hit the event.
  target.event = req.restart().param;
  target.event = min(final_event - 1, target.event);
  timeline.seek_to_before_event(target.event);
  do {
    ReplayResult result =
        timeline.replay_step_forward(RUN_CONTINUE, target.event);
    // We should never reach the end of the trace without hitting the stop
    // condition below.
    DEBUG_ASSERT(result.status != REPLAY_EXITED);
    if (is_last_thread_exit(result.break_status) &&
        result.break_status.task->thread_group()->tgid == target.pid) {
      // Debuggee task is about to exit. Stop here.
      in_debuggee_end_state = true;
      break;
    }
  } while (!at_target());
  activate_debugger();
}

static uint32_t get_cpu_features(SupportedArch arch) {
  uint32_t cpu_features;
  switch (arch) {
    case x86:
      cpu_features = 0;
      break;
    case x86_64:
      cpu_features = GdbConnection::CPU_64BIT;
      break;
    default:
      FATAL() << "Unknown architecture";
      return 0;
  }

  unsigned int AVX_cpuid_flags = AVX_FEATURE_FLAG | OSXSAVE_FEATURE_FLAG;
  auto cpuid_data = cpuid(CPUID_GETFEATURES, 0);
  // We're assuming here that AVX support on the system making the recording
  // is the same as the AVX support during replay. But if that's not true,
  // rr is totally broken anyway.
  if ((cpuid_data.ecx & AVX_cpuid_flags) == AVX_cpuid_flags) {
    cpu_features |= GdbConnection::CPU_AVX;
  }

  return cpu_features;
}

struct DebuggerParams {
  char exe_image[PATH_MAX];
  char host[16]; // INET_ADDRSTRLEN, omitted for header churn
  short port;
};

static void push_default_gdb_options(vector<string>& vec) {
  // The gdb protocol uses the "vRun" packet to reload
  // remote targets.  The packet is specified to be like
  // "vCont", in which gdb waits infinitely long for a
  // stop reply packet.  But in practice, gdb client
  // expects the vRun to complete within the remote-reply
  // timeout, after which it issues vCont.  The timeout
  // causes gdb<-->rr communication to go haywire.
  //
  // rr can take a very long time indeed to send the
  // stop-reply to gdb after restarting replay; the time
  // to reach a specified execution target is
  // theoretically unbounded.  Timing out on vRun is
  // technically a gdb bug, but because the rr replay and
  // the gdb reload models don't quite match up, we'll
  // work around it on the rr side by disabling the
  // remote-reply timeout.
  vec.push_back("-l");
  vec.push_back("10000");
  // For now, avoid requesting binary files through vFile. That is slow and
  // hard to make work correctly, because gdb requests files based on the
  // names it sees in memory and in ELF, and those names may be symlinks to
  // the filenames in the trace, so it's hard to match those names to files in
  // the trace.
  vec.push_back("-ex");
  vec.push_back("set sysroot /");
}

static void push_target_remote_cmd(vector<string>& vec, const string& host,
                                   unsigned short port) {
  vec.push_back("-ex");
  stringstream ss;
  // If we omit the address, then gdb can try to resolve "localhost" which
  // in some broken environments may not actually resolve to the local host
  ss << "target extended-remote " << host << ":" << port;
  vec.push_back(ss.str());
}

/**
 * Wait for exactly one gdb host to connect to this remote target on
 * the specified IP address |host|, port |port|.  If |probe| is nonzero,
 * a unique port based on |start_port| will be searched for.  Otherwise,
 * if |port| is already bound, this function will fail.
 *
 * Pass the |tgid| of the task on which this debug-connection request
 * is being made.  The remaining debugging session will be limited to
 * traffic regarding |tgid|, but clients don't need to and shouldn't
 * need to assume that.
 *
 * If we're opening this connection on behalf of a known client, pass
 * an fd in |client_params_fd|; we'll write the allocated port and |exe_image|
 * through the fd before waiting for a connection. |exe_image| is the
 * process that will be debugged by client, or null ptr if there isn't
 * a client.
 *
 * This function is infallible: either it will return a valid
 * debugging context, or it won't return.
 */
static unique_ptr<GdbConnection> await_connection(
    Task* t, ScopedFd& listen_fd, const GdbConnection::Features& features) {
  auto dbg = unique_ptr<GdbConnection>(new GdbConnection(t->tgid(), features));
  dbg->set_cpu_features(get_cpu_features(t->arch()));
  dbg->await_debugger(listen_fd);
  return dbg;
}

static void print_debugger_launch_command(Task* t, const string& host,
                                          unsigned short port,
                                          const char* debugger_name,
                                          FILE* out) {
  vector<string> options;
  push_default_gdb_options(options);
  push_target_remote_cmd(options, host, port);
  fprintf(out, "%s ", debugger_name);
  for (auto& opt : options) {
    fprintf(out, "'%s' ", opt.c_str());
  }
  fprintf(out, "%s\n", t->vm()->exe_image().c_str());
}

void GdbServer::serve_replay(const ConnectionFlags& flags) {
  do {
    ReplayResult result =
        timeline.replay_step_forward(RUN_CONTINUE, target.event);
    if (result.status == REPLAY_EXITED) {
      LOG(info) << "Debugger was not launched before end of trace";
      return;
    }
  } while (!at_target());

  unsigned short port = flags.dbg_port > 0 ? flags.dbg_port : getpid();
  // Don't probe if the user specified a port.  Explicitly
  // selecting a port is usually done by scripts, which would
  // presumably break if a different port were to be selected by
  // rr (otherwise why would they specify a port in the first
  // place).  So fail with a clearer error message.
  auto probe = flags.dbg_port > 0 ? DONT_PROBE : PROBE_PORT;
  Task* t = timeline.current_session().current_task();
  ScopedFd listen_fd = open_socket(flags.dbg_host.c_str(), &port, probe);
  if (flags.debugger_params_write_pipe) {
    DebuggerParams params;
    memset(&params, 0, sizeof(params));
    strncpy(params.exe_image, t->vm()->exe_image().c_str(),
            sizeof(params.exe_image) - 1);
    strncpy(params.host, flags.dbg_host.c_str(), sizeof(params.host) - 1);
    params.port = port;

    ssize_t nwritten =
        write(*flags.debugger_params_write_pipe, &params, sizeof(params));
    DEBUG_ASSERT(nwritten == sizeof(params));
  } else {
    fputs("Launch gdb with\n  ", stderr);
    print_debugger_launch_command(t, flags.dbg_host, port,
                                  flags.debugger_name.c_str(), stderr);
  }

  if (flags.debugger_params_write_pipe) {
    flags.debugger_params_write_pipe->close();
  }
  debuggee_tguid = t->thread_group()->tguid();

  FrameTime first_run_event = t->vm()->first_run_event();
  if (first_run_event) {
    timeline.set_reverse_execution_barrier_event(first_run_event);
  }

  do {
    LOG(debug) << "initializing debugger connection";
    dbg = await_connection(t, listen_fd, GdbConnection::Features());
    activate_debugger();

    GdbRequest last_resume_request;
    while (debug_one_step(last_resume_request) == CONTINUE_DEBUGGING) {
    }

    timeline.remove_breakpoints_and_watchpoints();
  } while (flags.keep_listening);

  LOG(debug) << "debugger server exiting ...";
}

static string create_gdb_command_file(const string& macros) {
  TempFile file = create_temporary_file("rr-gdb-commands-XXXXXX");
  // This fd is just leaked. That's fine since we only call this once
  // per rr invocation at the moment.
  int fd = file.fd.extract();
  unlink(file.name.c_str());

  ssize_t len = macros.size();
  int written = write(fd, macros.c_str(), len);
  if (written != len) {
    FATAL() << "Failed to write gdb command file";
  }

  stringstream procfile;
  procfile << "/proc/" << getpid() << "/fd/" << fd;
  return procfile.str();
}

static string to_string(const vector<string>& args) {
  stringstream ss;
  for (auto& a : args) {
    ss << "'" << a << "' ";
  }
  return ss.str();
}

static bool needs_target(const string& option) {
  return !strncmp(option.c_str(), "continue", option.size());
}

/**
 * Exec gdb using the params that were written to
 * |params_pipe_fd|.  Optionally, pre-define in the gdb client the set
 * of macros defined in |macros| if nonnull.
 */
void GdbServer::launch_gdb(ScopedFd& params_pipe_fd,
                           const string& gdb_binary_file_path,
                           const vector<string>& gdb_options) {
  auto macros = gdb_rr_macros();
  string gdb_command_file = create_gdb_command_file(macros);

  DebuggerParams params;
  ssize_t nread;
  while (true) {
    nread = read(params_pipe_fd, &params, sizeof(params));
    if (nread == 0) {
      // pipe was closed. Probably rr failed/died.
      return;
    }
    if (nread != -1 || errno != EINTR) {
      break;
    }
  }
  DEBUG_ASSERT(nread == sizeof(params));

  vector<string> args;
  args.push_back(gdb_binary_file_path);
  push_default_gdb_options(args);
  args.push_back("-x");
  args.push_back(gdb_command_file);
  bool did_set_remote = false;
  for (size_t i = 0; i < gdb_options.size(); ++i) {
    if (!did_set_remote && gdb_options[i] == "-ex" &&
        i + 1 < gdb_options.size() && needs_target(gdb_options[i + 1])) {
      push_target_remote_cmd(args, string(params.host), params.port);
      did_set_remote = true;
    }
    args.push_back(gdb_options[i]);
  }
  if (!did_set_remote) {
    push_target_remote_cmd(args, string(params.host), params.port);
  }
  args.push_back(params.exe_image);

  vector<string> env = current_env();
  env.push_back("GDB_UNDER_RR=1");

  LOG(debug) << "launching " << to_string(args);

  StringVectorToCharArray c_args(args);
  StringVectorToCharArray c_env(env);
  execvpe(gdb_binary_file_path.c_str(), c_args.get(), c_env.get());
  FATAL() << "Failed to exec gdb.";
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
  unsigned short port = t->tid;
  ScopedFd listen_fd = open_socket(localhost_addr.c_str(), &port, PROBE_PORT);

  char* test_monitor_pid = getenv("RUNNING_UNDER_TEST_MONITOR");
  if (test_monitor_pid) {
    pid_t pid = atoi(test_monitor_pid);
    // Tell test-monitor to wake up and take a snapshot. It will also
    // connect the emergency debugger so let that happen.
    FILE* gdb_cmd = fopen("gdb_cmd", "w");
    if (gdb_cmd) {
      print_debugger_launch_command(t, localhost_addr, port, "gdb", gdb_cmd);
      fclose(gdb_cmd);
    }
    kill(pid, SIGURG);
  } else {
    dump_rr_stack();
    fputs("Launch gdb with\n  ", stderr);
    print_debugger_launch_command(t, localhost_addr, port, "gdb", stderr);
  }
  unique_ptr<GdbConnection> dbg = await_connection(t, listen_fd, features);

  GdbServer(dbg, t).process_debugger_requests();
}

string GdbServer::init_script() { return gdb_rr_macros(); }

static ScopedFd generate_fake_proc_maps(Task* t) {
  TempFile file = create_temporary_file("rr-fake-proc-maps-XXXXXX");
  unlink(file.name.c_str());

  int fd = dup(file.fd);
  if (fd < 0) {
    FATAL() << "Cannot dup";
  }
  FILE* f = fdopen(fd, "w");

  int addr_min_width = word_size(t->arch()) == 8 ? 10 : 8;
  for (auto& m : t->vm()->maps()) {
    int len =
        fprintf(f, "%0*llx-%0*llx %s%s%s%s %08llx %02x:%02x %lld",
                addr_min_width, (long long)m.recorded_map.start().as_int(),
                addr_min_width, (long long)m.recorded_map.end().as_int(),
                (m.recorded_map.prot() & PROT_READ) ? "r" : "-",
                (m.recorded_map.prot() & PROT_WRITE) ? "w" : "-",
                (m.recorded_map.prot() & PROT_EXEC) ? "x" : "-",
                (m.recorded_map.flags() & MAP_SHARED) ? "s" : "p",
                (long long)m.recorded_map.file_offset_bytes(),
                major(m.recorded_map.device()), minor(m.recorded_map.device()),
                (long long)m.recorded_map.inode());
    while (len < 72) {
      fputc(' ', f);
      ++len;
    }
    fputc(' ', f);

    string name;
    const string& fsname = m.recorded_map.fsname();
    for (size_t i = 0; i < fsname.size(); ++i) {
      if (fsname[i] == '\n') {
        name.append("\\012");
      } else {
        name.push_back(fsname[i]);
      }
    }
    fputs(name.c_str(), f);
    fputc('\n', f);
  }
  if (ferror(f) || fclose(f)) {
    FATAL() << "Can't write";
  }

  return move(file.fd);
}

int GdbServer::open_file(Session& session, const std::string& file_name) {
  // XXX should we require file_scope_pid == 0 here?
  ScopedFd contents;

  LOG(debug) << "Trying to open " << file_name;

  if (file_name.substr(0, 6) == "/proc/") {
    char* tid_end;
    long tid = strtol(file_name.c_str() + 6, &tid_end, 10);
    if (*tid_end != '/') {
      return -1;
    }
    if (!strncmp(tid_end, "/task/", 6)) {
      tid = strtol(tid_end + 6, &tid_end, 10);
      if (*tid_end != '/') {
        return -1;
      }
    }
    if (tid != (pid_t)tid) {
      return -1;
    }
    Task* t = session.find_task(tid);
    if (!t) {
      return -1;
    }
    if (!strcmp(tid_end, "/maps")) {
      contents = generate_fake_proc_maps(t);
    } else {
      return -1;
    }
  }

  int ret_fd = 0;
  while (files.find(ret_fd) != files.end()) {
    ++ret_fd;
  }
  files.insert(make_pair(ret_fd, move(contents)));
  return ret_fd;
}

} // namespace rr
