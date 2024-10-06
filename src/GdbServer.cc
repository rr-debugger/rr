/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "GdbServer.h"

#include <elf.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "BreakpointCondition.h"
#include "ElfReader.h"
#include "Event.h"
#include "DebuggerExtensionCommandHandler.h"
#include "GdbServerExpression.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "ScopedFd.h"
#include "StringVectorToCharArray.h"
#include "Task.h"
#include "ThreadGroup.h"
#include "core.h"
#include "kernel_metadata.h"
#include "launch_debugger.h"
#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

/**
 * The "outermost" saved register state is associated with the diversion.
 * "Restoring" it exits the diversion and restores all state of the tracee.
 */
const int DIVERSION_SAVED_REGISTER_STATE = 1;

GdbServer::ConnectionFlags::ConnectionFlags()
  : dbg_port(-1),
    keep_listening(false),
    serve_files(false),
    debugger_params_write_pipe(nullptr) {}

static ExtendedTaskId extended_task_id(Task* t) {
  return ExtendedTaskId(t->thread_group()->tguid(), t->tuid());
}

GdbServer::GdbServer(std::unique_ptr<GdbServerConnection>& connection,
                     Task* t, ReplayTimeline* timeline,
                     const Target& target)
    : dbg(std::move(connection)),
      debuggee_tguid(t->thread_group()->tguid()),
      target(target),
      last_continue_task(extended_task_id(t)),
      last_query_task(extended_task_id(t)),
      final_event(UINT32_MAX),
      in_debuggee_end_state(false),
      failed_restart(false),
      stop_replaying_to_target(nullptr),
      interrupt_pending(false),
      exit_sigkill_pending(false),
      timeline_(timeline),
      emergency_debug_session(timeline ? nullptr : &t->session()),
      file_scope_pid(0) {
  memset(&stop_siginfo, 0, sizeof(stop_siginfo));
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
                      uint8_t* buf, GdbServerRegister regname, bool* defined) {
  size_t num_bytes = regs.read_register(buf, regname, defined);
  if (!*defined) {
    num_bytes = extra_regs.read_register(buf, regname, defined);
  }
  return num_bytes;
}

static bool set_reg(Task* target, const GdbServerRegisterValue& reg) {
  if (!reg.defined) {
    return false;
  }

  Registers regs = target->regs();
  if (regs.write_register(reg.name, reg.value, reg.size)) {
    target->set_regs(regs);
    return true;
  }

  auto extra_regs_p = target->extra_regs_fallible();
  ASSERT(target, extra_regs_p) << "Task died";
  ExtraRegisters extra_regs = *extra_regs_p;
  if (extra_regs.write_register(reg.name, reg.value, reg.size)) {
    target->set_extra_regs(extra_regs);
    return true;
  }

  LOG(warn) << "Unhandled register name " << reg.name;
  return false;
}

/**
 * Return the register |which|, which may not have a defined value.
 */
GdbServerRegisterValue GdbServer::get_reg(const Registers& regs,
                                    const ExtraRegisters& extra_regs,
                                    GdbServerRegister which) {
  GdbServerRegisterValue reg;
  memset(&reg, 0, sizeof(reg));
  reg.name = which;
  reg.size = rr::get_reg(regs, extra_regs, &reg.value[0], which, &reg.defined);
  return reg;
}

static bool matches_threadid(const ExtendedTaskId& tid,
                             const GdbThreadId& target) {
  return (target.pid <= 0 || target.pid == tid.tguid.tid()) &&
         (target.tid <= 0 || target.tid == tid.tuid.tid());
}

static bool matches_threadid(Task* t, const GdbThreadId& target) {
  return matches_threadid(extended_task_id(t), target);
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
  ReplayTask* rt = t->as_replay();
  if (!rt) {
    return;
  }
  if (trace_instructions_up_to_event(
          rt->session().current_trace_frame().time())) {
    fputs("Stepping: ", stderr);
    t->regs().print_register_file_compact(stderr);
    fprintf(stderr, " ticks:%" PRId64 "\n", t->tick_count());
    *req = GdbRequest(DREQ_CONT);
    req->suppress_debugger_stop = true;
    req->cont().actions.push_back(
        GdbContAction(ACTION_STEP,
          extended_task_id(t).to_debugger_thread_id()));
  }
}

void GdbServer::dispatch_regs_request(const Registers& regs,
                                      const ExtraRegisters& extra_regs) {
  const GdbServerRegister end = arch_reg_end(regs.arch());
  vector<GdbServerRegisterValue> rs;
  rs.reserve(end);
  for (GdbServerRegister r = GdbServerRegister(0); r <= end; r = GdbServerRegister(r + 1)) {
    rs.push_back(get_reg(regs, extra_regs, r));
  }
  dbg->reply_get_regs(rs);
}

class GdbBreakpointCondition : public BreakpointCondition {
public:
  GdbBreakpointCondition(const vector<vector<uint8_t>>& bytecodes) {
    for (auto& b : bytecodes) {
      expressions.push_back(GdbServerExpression(b.data(), b.size()));
    }
  }
  virtual bool evaluate(ReplayTask* t) const override {
    for (auto& e : expressions) {
      GdbServerExpression::Value v;
      // Break if evaluation fails or the result is nonzero
      if (!e.evaluate(t, &v) || v.i != 0) {
        return true;
      }
    }
    return false;
  }

private:
  vector<GdbServerExpression> expressions;
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

static bool is_in_patch_stubs(Task* t, remote_code_ptr ip) {
  auto p = ip.to_data_ptr<void>();
  return t->vm()->has_mapping(p) &&
         (t->vm()->mapping_flags_of(p) & AddressSpace::Mapping::IS_PATCH_STUBS);
}

void GdbServer::maybe_intercept_mem_request(Task* target, const GdbRequest& req,
                                            vector<uint8_t>* result) {
  DEBUG_ASSERT(req.mem_.len >= result->size());
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
      target->regs().sp().as_int() + size <= req.mem_.addr + result->size() &&
      is_in_patch_stubs(target, target->ip())) {
    memset(result->data() + target->regs().sp().as_int() - req.mem_.addr, 0,
           size);
  }
}

static vector<GdbServerConnection::ThreadInfo> thread_info(const Session& session) {
  vector<GdbServerConnection::ThreadInfo> threads;
  for (auto& kv : session.tasks()) {
    threads.push_back({
      extended_task_id(kv.second),
      kv.second->regs().ip().register_value()
    });
  }
  return threads;
}

void GdbServer::notify_stop_internal(const Session& session,
                                     ExtendedTaskId which, int sig,
                                     const string& reason) {
  dbg->notify_stop(which, sig, thread_info(session), reason);
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
      dbg->reply_get_current_thread(last_continue_task);
      return;
    case DREQ_GET_OFFSETS:
      /* TODO */
      dbg->reply_get_offsets();
      return;
    case DREQ_GET_THREAD_LIST: {
      vector<ExtendedTaskId> tids;
      if (state != REPORT_THREADS_DEAD && !failed_restart) {
        for (auto& kv : session.tasks()) {
          tids.push_back(extended_task_id(kv.second));
        }
      }
      dbg->reply_get_thread_list(tids);
      return;
    }
    case DREQ_INTERRUPT:
      notify_stop_internal(session, last_continue_task, 0);
      memset(&stop_siginfo, 0, sizeof(stop_siginfo));
      last_query_task = last_continue_task;
      return;
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
        t = session.find_task(last_continue_task.tuid);
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
        Task* t = session.find_task(last_continue_task.tuid);
        int fd = open_file(session, t, req.file_open().file_name);
        dbg->reply_open(fd, fd >= 0 ? 0 : ENOENT);
      } else {
        dbg->reply_open(-1, EACCES);
      }
      return;
    case DREQ_FILE_PREAD: {
      GdbRequest::FilePread read_req = req.file_pread();
      {
        auto it = files.find(read_req.fd);
        if (it != files.end()) {
          size_t size = min<uint64_t>(read_req.size, 1024 * 1024);
          vector<uint8_t> data;
          data.resize(size);
          ssize_t bytes =
              read_to_end(it->second, read_req.offset, data.data(), size);
          dbg->reply_pread(data.data(), bytes, bytes >= 0 ? 0 : -errno);
          return;
        }
      }
      {
        auto it = memory_files.find(read_req.fd);
        if (it != memory_files.end() && timeline_) {
          // Search our mmap stream for a record that can satisfy this request
          TraceReader tmp_reader(timeline_->current_session().trace_reader());
          tmp_reader.rewind();
          while (true) {
            TraceReader::MappedData data;
            bool found;
            KernelMapping km = tmp_reader.read_mapped_region(
                &data, &found, TraceReader::DONT_VALIDATE, TraceReader::ANY_TIME);
            if (!found)
              break;
            if (it->second == FileId(km)) {
              if (data.source != TraceReader::SOURCE_FILE) {
                LOG(warn) << "Not serving file because it is not a file source";
                break;
              }
              ScopedFd fd(data.file_name.c_str(), O_RDONLY);
              vector<uint8_t> data;
              data.resize(read_req.size);
              LOG(debug) << "Reading " << read_req.size << " bytes at offset " <<
                read_req.offset;
              ssize_t bytes =
                  read_to_end(fd, read_req.offset, data.data(), read_req.size);
              if (bytes < (ssize_t)read_req.size) {
                LOG(warn) << "Requested " << read_req.size << " bytes but only got " << bytes;
              }
              dbg->reply_pread(data.data(), bytes, bytes >= 0 ? 0 : -errno);
              return;
            }
          }
          LOG(warn) << "No mapping found";
        }
      }
      LOG(warn) << "Unknown file descriptor requested";
      dbg->reply_pread(nullptr, 0, EIO);
      return;
    }
    case DREQ_FILE_CLOSE: {
      {
        auto it = files.find(req.file_close().fd);
        if (it != files.end()) {
          files.erase(it);
          dbg->reply_close(0);
          return;
        }
      } {
        auto it = memory_files.find(req.file_close().fd);
        if (it != memory_files.end()) {
          memory_files.erase(it);
          dbg->reply_close(0);
          return;
        }
      }
      LOG(warn) << "Unable to find file descriptor for close";
      dbg->reply_close(EBADF);
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
          : session.find_task(is_query ? last_query_task.tuid : last_continue_task.tuid);
  if (target) {
    if (is_query) {
      last_query_task = extended_task_id(target);
    } else {
      last_continue_task = extended_task_id(target);
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
    case DREQ_GET_MEM:
    case DREQ_GET_MEM_BINARY: {
      vector<uint8_t> mem;
      uintptr_t end = req.mem().addr + req.mem().len;
      if (end < req.mem().addr) {
        // Overflow
        dbg->reply_get_mem(mem);
        return;
      }
      mem.resize(req.mem().len);

      if (!session.is_diversion() &&
          read_debugger_mem(target->thread_group()->tguid(),
              MemoryRange(req.mem().addr, req.mem().len), mem.data())) {
      } else {
        ssize_t nread = target->read_bytes_fallible(req.mem().addr, req.mem().len,
                                                    mem.data());
        mem.resize(max(ssize_t(0), nread));
      }
      target->vm()->replace_breakpoints_with_original_values(
          mem.data(), mem.size(), req.mem().addr);
      maybe_intercept_mem_request(target, req, &mem);
      dbg->reply_get_mem(mem);
      return;
    }
    case DREQ_SET_MEM:
    case DREQ_SET_MEM_BINARY: {
      // gdb has been observed to send requests of length 0 at
      // odd times
      // (e.g. before sending the magic write to create a checkpoint)
      if (req.mem().len == 0) {
        dbg->reply_set_mem(true);
        return;
      }
      uintptr_t end = req.mem().addr + req.mem().len;
      if (end < req.mem().addr) {
        // Overflow
        dbg->reply_set_mem(false);
        return;
      }
      // If an address is recognised as belonging to a SystemTap semaphore it's
      // because it was detected by the audit library during recording and
      // pre-incremented.
      if (target->vm()->is_stap_semaphore(req.mem().addr)) {
        LOG(info) << "Suppressing write to SystemTap semaphore";
        dbg->reply_set_mem(true);
        return;
      }
      // We only allow the debugger to write memory if the
      // memory will be written to an diversion session.
      // Arbitrary writes to replay sessions cause
      // divergence.
      if (!session.is_diversion()) {
        if (write_debugger_mem(target->thread_group()->tguid(),
                MemoryRange(req.mem().addr, req.mem().len),
                req.mem().data.data())) {
          dbg->reply_set_mem(true);
          return;
        }

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
    case DREQ_SEARCH_MEM_BINARY: {
      remote_ptr<void> addr;
      bool found =
          search_memory(target, MemoryRange(req.mem().addr, req.mem().len),
                        req.mem().data, &addr);
      dbg->reply_search_mem_binary(found, addr);
      return;
    }
    case DREQ_MEM_INFO: {
      ASSERT(target, req.mem().len == 1);
      MemoryRange range;
      int prot;
      if (debugger_mem_region(target->thread_group()->tguid(), req.mem().addr,
          &prot, &range)) {
        dbg->reply_mem_info(range, prot, "");
        return;
      }
      if (target->vm()->has_mapping(req.mem().addr)) {
        AddressSpace::Mapping m = target->vm()->mapping_of(req.mem().addr);
        dbg->reply_mem_info(m.recorded_map, m.recorded_map.prot(),
                            m.recorded_map.fsname());
      } else {
        AddressSpace::Maps maps = target->vm()->maps();
        remote_ptr<void> last_end;
        remote_ptr<void> next_start;
        for (auto it : maps) {
          if (it.recorded_map.start() > req.mem().addr) {
            next_start = it.recorded_map.start();
            break;
          }
          last_end = it.recorded_map.end();
        }
        if (next_start.is_null()) {
          next_start = usable_address_space_end(target->arch());
        }
        dbg->reply_mem_info(MemoryRange(last_end, next_start), 0, string());
      }
      return;
    }
    case DREQ_MEM_ALLOC: {
      remote_ptr<void> addr = allocate_debugger_mem(target->thread_group()->tguid(),
          req.mem_alloc().size, req.mem_alloc().prot);
      if (!addr.is_null() && session.is_diversion()) {
        map_debugger_mem(*session.as_diversion(), target->thread_group()->tguid(),
            addr);
      }
      dbg->reply_mem_alloc(addr);
      return;
    }
    case DREQ_MEM_FREE: {
      size_t size = free_debugger_mem(target->thread_group()->tguid(), req.mem_free().address);
      if (size && session.is_diversion()) {
        unmap_debugger_mem(*session.as_diversion(), target->thread_group()->tguid(),
            req.mem_free().address, size);
      }
      dbg->reply_mem_free(size);
      return;
    }
    case DREQ_GET_REG: {
      GdbServerRegisterValue reg =
          get_reg(target->regs(), *target->extra_regs_fallible(), req.reg().name);
      dbg->reply_get_reg(reg);
      return;
    }
    case DREQ_GET_REGS: {
      dispatch_regs_request(target->regs(), *target->extra_regs_fallible());
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
      if (!set_reg(target, req.reg())) {
        LOG(warn) << "Attempt to set register " << req.reg().name << " failed";
      }
      dbg->reply_set_reg(true /*currently infallible*/);
      return;
    }
    case DREQ_GET_STOP_REASON: {
      dbg->reply_get_stop_reason(last_continue_task, stop_siginfo.si_signo,
                                 thread_info(session));
      return;
    }
    case DREQ_SET_SW_BREAK: {
      ASSERT(target, req.watch().kind == bkpt_instruction_length(target->arch()))
          << "Debugger setting bad breakpoint insn";
      // Mirror all breakpoint/watchpoint sets/unsets to the target process
      // if it's not part of the timeline (i.e. it's a diversion).
      if (!timeline_) {
        dbg->reply_watchpoint_request(false);
        return;
      }
      ReplayTask* replay_task =
          timeline_->current_session().find_task(target->tuid());
      bool ok = timeline_->add_breakpoint(replay_task, req.watch().addr,
                                        breakpoint_condition(req));
      if (ok && &session != &timeline_->current_session()) {
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
      if (!timeline_) {
        dbg->reply_watchpoint_request(false);
        return;
      }
      ReplayTask* replay_task =
          timeline_->current_session().find_task(target->tuid());
      bool ok = timeline_->add_watchpoint(
          replay_task, req.watch().addr, req.watch().kind,
          watchpoint_type(req.type), breakpoint_condition(req));
      if (ok && &session != &timeline_->current_session()) {
        bool diversion_ok = target->vm()->add_watchpoint(
            req.watch().addr, req.watch().kind, watchpoint_type(req.type));
        ASSERT(target, diversion_ok);
      }
      dbg->reply_watchpoint_request(ok);
      return;
    }
    case DREQ_REMOVE_SW_BREAK: {
      if (!timeline_) {
        dbg->reply_watchpoint_request(true);
        return;
      }
      ReplayTask* replay_task =
          timeline_->current_session().find_task(target->tuid());
      timeline_->remove_breakpoint(replay_task, req.watch().addr);
      if (&session != &timeline_->current_session()) {
        target->vm()->remove_breakpoint(req.watch().addr, BKPT_USER);
      }
      dbg->reply_watchpoint_request(true);
      return;
    }
    case DREQ_REMOVE_HW_BREAK:
    case DREQ_REMOVE_RD_WATCH:
    case DREQ_REMOVE_WR_WATCH:
    case DREQ_REMOVE_RDWR_WATCH: {
      if (!timeline_) {
        dbg->reply_watchpoint_request(true);
        return;
      }
      ReplayTask* replay_task =
          timeline_->current_session().find_task(target->tuid());
      timeline_->remove_watchpoint(replay_task, req.watch().addr,
                                   req.watch().kind, watchpoint_type(req.type));
      if (&session != &timeline_->current_session()) {
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
    case DREQ_SAVE_REGISTER_STATE: {
      int state_index = DIVERSION_SAVED_REGISTER_STATE + 1;
      while (saved_register_states.find(state_index) != saved_register_states.end()) {
        ++state_index;
      }
      SavedRegisters& regs = saved_register_states[state_index];
      regs.regs = target->regs();
      regs.extra_regs = *target->extra_regs_fallible();
      dbg->reply_save_register_state(true, state_index);
      return;
    }
    case DREQ_RESTORE_REGISTER_STATE: {
      if (!session.is_diversion()) {
        LOG(error) << "RESTORE_REGISTER_STATE request outside of diversion session";
        dbg->reply_restore_register_state(false);
        return;
      }
      int state_index = req.restore_register_state().state_index;
      auto it = saved_register_states.find(state_index);
      if (it == saved_register_states.end()) {
        LOG(error) << "Unknown register state";
        dbg->reply_restore_register_state(false);
        return;
      }
      target->set_regs(it->second.regs);
      target->set_extra_regs(it->second.extra_regs);
      saved_register_states.erase(it);
      dbg->reply_restore_register_state(true);
      return;
    }
    case DREQ_RR_CMD:
      dbg->reply_rr_cmd(
          DebuggerExtensionCommandHandler::process_command(*this, target, req.rr_cmd()));
      return;
#ifdef PROC_SERVICE_H
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
#endif
    default:
      FATAL() << "Unknown debugger request " << req.type;
  }
}

static bool any_action_targets_match(const ExtendedTaskId& thread,
                                     const vector<GdbContAction>& actions) {
  return any_of(actions.begin(), actions.end(), [&thread](GdbContAction action) {
    return matches_threadid(thread, action.target);
  });
}

static Task* find_first_task_matching_target(
    const Session& session, const vector<GdbContAction>& actions) {
  const Session::TaskMap& tasks = session.tasks();
  auto it = find_first_of(
      tasks.begin(), tasks.end(),
      actions.begin(), actions.end(),
      [](Session::TaskMap::value_type task_pair, GdbContAction action) {
        return matches_threadid(task_pair.second, action.target);
      });
  return it != tasks.end() ? it->second : nullptr;
}

bool GdbServer::diverter_process_debugger_requests(
    DiversionSession& diversion_session, uint32_t& diversion_refcount,
    GdbRequest* req) {
  while (true) {
    *req = dbg->get_request();

    if (req->is_resume_request()) {
      const vector<GdbContAction>& actions = req->cont().actions;
      DEBUG_ASSERT(actions.size() > 0);
      // GDB may ask us to resume more than one task, so we have to
      // choose one. We give priority to the task last resumed, as
      // this is likely to be the context in which GDB is executing
      // code; selecting any other task runs the risk of resuming
      // replay, denying the diverted code an opportunity to complete
      // and end the diversion session.
      if (!any_action_targets_match(last_continue_task, actions)) {
        // If none of the resumption targets match the task last
        // resumed, we simply choose any matching task. This ensures
        // that GDB (and the user) can choose an arbitrary thread to
        // serve as the context of the code being evaluated.
        // TODO: maybe it makes sense to try and select the matching
        // task that was most recently resumed, or possibly the
        // matching task with an event in the replay trace nearest to
        // 'now'.
        Task* task =
            find_first_task_matching_target(diversion_session, actions);
        DEBUG_ASSERT(task != nullptr);
        last_continue_task = extended_task_id(task);
      }
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

      case DREQ_RESTORE_REGISTER_STATE: {
        int state_index = req->restore_register_state().state_index;
        if (state_index == DIVERSION_SAVED_REGISTER_STATE) {
          diversion_refcount = 0;
          dbg->reply_restore_register_state(true);
          // This request does not need to be retried outside the diversion
          *req = GdbRequest(DREQ_NONE);
          return false;
        }
        break;
      }

      case DREQ_SET_QUERY_THREAD: {
        if (req->target.tid) {
          Task* next = diversion_session.find_task(req->target.tid);
          if (next) {
            last_query_task = extended_task_id(next);
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
        Task* task = diversion_session.find_task(last_continue_task.tuid);
        if (task) {
          std::string reply =
              DebuggerExtensionCommandHandler::process_command(*this, task, req->rr_cmd());
          // Certain commands cause the diversion to end immediately
          // while other commands must work within a diversion.
          if (reply == DebuggerExtensionCommandHandler::cmd_end_diversion()) {
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
  // The task set may be empty if the task has already exited.
  return break_status.task_exit &&
         break_status.task_context.thread_group->task_set().size() <= 1;
}

static Task* is_in_exec(ReplayTimeline* timeline) {
  if (!timeline) {
    return nullptr;
  }
  Task* t = timeline->current_session().current_task();
  if (!t) {
    return nullptr;
  }
  return timeline->current_session().next_step_is_successful_exec_syscall_exit()
             ? t
             : nullptr;
}

void GdbServer::maybe_notify_stop(const Session& session,
                                  const GdbRequest& req,
                                  const BreakStatus& break_status) {
  bool do_stop = false;
  stringstream reason;
  if (!break_status.watchpoints_hit.empty()) {
    do_stop = true;
    memset(&stop_siginfo, 0, sizeof(stop_siginfo));
    stop_siginfo.si_signo = SIGTRAP;
    remote_ptr<void> watch_addr = break_status.watchpoints_hit[0].addr;
    bool any_hw_break = false;
    for (const auto& w : break_status.watchpoints_hit) {
      if (w.type == WATCH_EXEC) {
        any_hw_break = true;
      }
    }
    if (dbg->hwbreak_supported() && any_hw_break) {
      reason << "hwbreak:;";
    } else if (watch_addr) {
      reason << "watch:" << std::hex << watch_addr.as_int() << ";";
    }
    LOG(debug) << "Stopping for watchpoint at " << watch_addr;
  }
  if (break_status.breakpoint_hit || break_status.singlestep_complete) {
    do_stop = true;
    memset(&stop_siginfo, 0, sizeof(stop_siginfo));
    stop_siginfo.si_signo = SIGTRAP;
    if (break_status.breakpoint_hit) {
      if (dbg->swbreak_supported()) {
        reason << "swbreak:;";
      }
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
  if (is_last_thread_exit(break_status)) {
    if (break_status.task_context.session->is_diversion()) {
      // If the last task of a diversion session has exited, we need
      // to make sure GDB knows it's unrecoverable. There's no good
      // way to do this: a stop is insufficient, but an inferior exit
      // typically signals the end of a debugging session. Using the
      // latter approach appears to work, but stepping through GDB's
      // processing of the event seems to indicate it isn't really
      // supposed to. FIXME.
      LOG(debug) << "Last task of diversion exiting. "
                 << "Notifying exit with synthetic SIGKILL";
      dbg->notify_exit_signal(SIGKILL);
      return;
    } else if (dbg->features().reverse_execution) {
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
        // Documented as "has reached the end (or the beginning when executing
        // backward) of the log"
        reason << "replaylog:begin;";
        LOG(debug) << "Stopping at start of execution while running backwards";
      }
    }
  }
  Task* t = break_status.task();
  Task* in_exec_task = is_in_exec(timeline_);
  if (in_exec_task) {
    do_stop = true;
    memset(&stop_siginfo, 0, sizeof(stop_siginfo));
    t = in_exec_task;
    LOG(debug) << "Stopping at exec";
  }
  if (do_stop && t->thread_group()->tguid() == debuggee_tguid) {
    /* Notify the debugger and process any new requests
     * that might have triggered before resuming. */
    notify_stop_internal(session, extended_task_id(t), stop_siginfo.si_signo,
                         reason.str());
    last_query_task = last_continue_task = extended_task_id(t);
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

  if (timeline_) {
    // Ensure breakpoints and watchpoints are applied before we fork the
    // diversion, to ensure the diversion is consistent with the timeline
    // breakpoint/watchpoint state.
    timeline_->apply_breakpoints_and_watchpoints();
  }
  DiversionSession::shr_ptr diversion_session = replay.clone_diversion();
  uint32_t diversion_refcount = 1;
  ExtendedTaskId saved_query_task = last_query_task;
  ExtendedTaskId saved_continue_task = last_continue_task;

  for (const auto& dbg_mem : debugger_mem) {
    for (const auto& region : dbg_mem.second.regions) {
      map_debugger_mem(*diversion_session, dbg_mem.first, region.first.start());
    }
  }

  while (true) {
    if (!diverter_process_debugger_requests(*diversion_session,
                                           diversion_refcount, &req)) {
      read_back_debugger_mem(*diversion_session);
      break;
    }

    DEBUG_ASSERT(req.is_resume_request());

    if (req.cont().run_direction == RUN_BACKWARD) {
      // We don't support reverse execution in a diversion. Just issue
      // an immediate stop.
      notify_stop_internal(*diversion_session, last_continue_task, 0);
      memset(&stop_siginfo, 0, sizeof(stop_siginfo));
      last_query_task = last_continue_task;
      continue;
    }

    Task* t = diversion_session->find_task(last_continue_task.tuid);
    DEBUG_ASSERT(t != nullptr);

    int signal_to_deliver;
    RunCommand command =
        compute_run_command_from_actions(t, req, &signal_to_deliver);
    auto result =
        diversion_session->diversion_step(t, command, signal_to_deliver);

    if (result.status == DiversionSession::DIVERSION_EXITED) {
      diversion_refcount = 0;
      maybe_notify_stop(*diversion_session, req, result.break_status);
      if (timeline_) {
        // gdb assumes that the process is gone and all its
        // breakpoints have gone with it. It will set new breakpoints.
        timeline_->remove_breakpoints_and_watchpoints();
      }
      req = GdbRequest(DREQ_NONE);
      // Deliberately not reading back debugger mem
      break;
    }

    DEBUG_ASSERT(result.status == DiversionSession::DIVERSION_CONTINUE);

    maybe_notify_stop(*diversion_session, req, result.break_status);
  }

  LOG(debug) << "... ending debugging diversion";
  DEBUG_ASSERT(diversion_refcount == 0);

  diversion_session->kill_all_tasks();

  last_query_task = saved_query_task;
  last_continue_task = saved_continue_task;
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

      if (!timeline_) {
        continue;
      }
      // READ_SIGINFO is usually the start of a diversion. It can also be
      // triggered by "print $_siginfo" but that is rare so we just assume it's
      // a diversion start; if "print $_siginfo" happens we'll print the correct
      // siginfo and then incorrectly start a diversion and go haywire :-(.
      // Ideally we'd come up with a better way to detect diversions so that
      // "print $_siginfo" works.
      req = divert(timeline_->current_session());
      if (req.type == DREQ_NONE) {
        continue;
      }
      // Carry on to process the request that was rejected by
      // the diversion session
    }

    if (req.type == DREQ_SAVE_REGISTER_STATE && timeline_) {
      dbg->reply_save_register_state(true, DIVERSION_SAVED_REGISTER_STATE);
      req = divert(timeline_->current_session());
      if (req.type == DREQ_NONE) {
        continue;
      }
      // Carry on to process the request that was rejected by
      // the diversion session
    }

    if (req.is_resume_request()) {
      Task* t = current_session().find_task(last_continue_task.tuid);
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
  if (!timeline_) {
    return;
  }

  ReplayTimeline::Mark now;
  bool need_seek = false;
  ReplayTask* t = timeline_->current_session().current_task();
  while (t && req.type == DREQ_CONT &&
         req.cont().run_direction == RUN_BACKWARD &&
         req.cont().actions.size() == 1 &&
         req.cont().actions[0].type == ACTION_STEP &&
         req.cont().actions[0].signal_to_deliver == 0 &&
         matches_threadid(t, req.cont().actions[0].target) &&
         !req.suppress_debugger_stop) {
    if (!now) {
      now = timeline_->mark();
    }
    ReplayTimeline::Mark previous = timeline_->lazy_reverse_singlestep(now, t);
    if (!previous) {
      break;
    }

    now = previous;
    need_seek = true;
    BreakStatus break_status;
    break_status.task_context = TaskContext(t);
    break_status.singlestep_complete = true;
    LOG(debug) << "  using lazy reverse-singlestep";
    maybe_notify_stop(timeline_->current_session(), req, break_status);

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
    timeline_->seek_to_mark(now);
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
  if (timeline_) {
    final_event = timeline_->current_session().trace_reader().time();
  }
  while (true) {
    GdbRequest req = process_debugger_requests(REPORT_THREADS_DEAD);
    ContinueOrStop s;
    if (detach_or_restart(req, &s)) {
      last_resume_request = GdbRequest();
      return s;
    }
    if (req.type == DREQ_INTERRUPT) {
      // Ignore this. Sometimes LLDB seems to send it automatically
      // after the task has exited, before we detach I guess.
      continue;
    }
    FATAL() << "Received continue/interrupt request after end-of-trace: "
            << req.type;
  }
}

ReplayTask* GdbServer::require_timeline_current_task() {
  if (!timeline_) {
    FATAL() << "Timeline required here";
  }
  ReplayTask* t = timeline_->current_session().current_task();
  if (!t) {
    FATAL() << "Expected current task but none found; expected task with tid "
      << timeline_->current_session().current_trace_frame().tid()
      << " at event " << timeline_->current_session().current_frame_time();
  }
  return t;
}

GdbServer::ContinueOrStop GdbServer::debug_one_step(
    GdbRequest& last_resume_request) {
  if (!timeline_) {
    FATAL() << "Timeline required here";
  }

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
    Task* t = require_timeline_current_task();
    if (t->thread_group()->tguid() == debuggee_tguid) {
      interrupt_pending = false;
      notify_stop_internal(timeline_->current_session(),
          extended_task_id(t), in_debuggee_end_state ? SIGKILL : 0);
      memset(&stop_siginfo, 0, sizeof(stop_siginfo));
      return CONTINUE_DEBUGGING;
    }
  }

  if (exit_sigkill_pending) {
    Task* t = require_timeline_current_task();
    if (t->thread_group()->tguid() == debuggee_tguid) {
      exit_sigkill_pending = false;
      if (req.cont().run_direction == RUN_FORWARD) {
        notify_stop_internal(timeline_->current_session(),
            extended_task_id(t), SIGKILL);
        memset(&stop_siginfo, 0, sizeof(stop_siginfo));
        return CONTINUE_DEBUGGING;
      }
    }
  }

  if (req.cont().run_direction == RUN_FORWARD) {
    if (is_in_exec(timeline_) &&
        require_timeline_current_task()->thread_group()->tguid() ==
            debuggee_tguid) {
      // Don't go any further forward. maybe_notify_stop will generate a
      // stop.
      result = ReplayResult();
    } else {
      int signal_to_deliver;
      RunCommand command = compute_run_command_from_actions(
          require_timeline_current_task(), req, &signal_to_deliver);
      // Ignore gdb's |signal_to_deliver|; we just have to follow the replay.
      result = timeline_->replay_step_forward(command);
    }
    if (result.status == REPLAY_EXITED) {
      return handle_exited_state(last_resume_request);
    }
  } else {
    vector<AllowedTasks> allowed_tasks;
    // Convert the tids in GdbContActions into TaskUids to avoid issues
    // if tids get reused.
    RunCommand command = compute_run_command_for_reverse_exec(
        timeline_->current_session(), debuggee_tguid, req, allowed_tasks);
    auto stop_filter = [&](ReplayTask* t, const BreakStatus &break_status) -> bool {
      if (t->thread_group()->tguid() != debuggee_tguid) {
        return false;
      }

      // don't stop for a signal that has been specified by QPassSignal
      if (break_status.signal && dbg->is_pass_signal(break_status.signal->si_signo)) {
        LOG(debug) << "Filtering out event for signal " << break_status.signal->si_signo;
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
        result = timeline_->reverse_continue(stop_filter, interrupt_check);
        break;
      case RUN_SINGLESTEP: {
        Task* t = timeline_->current_session().find_task(last_continue_task.tuid);
        DEBUG_ASSERT(t);
        result = timeline_->reverse_singlestep(
            last_continue_task.tuid, t->tick_count(), stop_filter, interrupt_check);
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
    maybe_notify_stop(timeline_->current_session(),
        req, result.break_status);
  }
  if (req.cont().run_direction == RUN_FORWARD &&
      is_last_thread_exit(result.break_status) &&
      result.break_status.task_context.thread_group->tguid() == debuggee_tguid) {
    in_debuggee_end_state = true;
  }
  return CONTINUE_DEBUGGING;
}

static bool target_event_reached(const ReplayTimeline& timeline,
                                 const GdbServer::Target& target,
                                 const ReplayResult& result) {
  if (target.event == -1) {
    return is_last_thread_exit(result.break_status) &&
      (target.pid <= 0 || result.break_status.task_context.thread_group->tgid == target.pid);
  } else {
    return timeline.current_session().current_trace_frame().time() > target.event;
  }
}

static bool at_target(ReplayTimeline& timeline,
                      const GdbServer::Target& target,
                      volatile bool* stop_replaying_to_target,
                      const ReplayResult& result) {
  // Don't launch the debugger for the initial rr fork child.
  // No one ever wants that to happen.
  if (!timeline.current_session().done_initial_exec()) {
    return false;
  }
  Task* t = timeline.current_session().current_task();
  if (!t) {
    return false;
  }
  bool target_is_exit = target.event == -1;
  if (!(timeline.can_add_checkpoint() || target_is_exit)) {
    return false;
  }
  if (stop_replaying_to_target && *stop_replaying_to_target) {
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
  return target_event_reached(timeline, target, result) &&
         (!target.pid || t->tgid() == target.pid) &&
         (!target.require_exec || t->execed()) &&
         // Ensure we're at the start of processing an event. We don't
         // want to attach while we're finishing an exec() since that's a
         // slightly confusing state for ReplayTimeline's reverse execution.
         (!timeline.current_session().current_step_key().in_execution() || target_is_exit);
}

/**
 * The trace has reached the event at which the user wanted to start debugging.
 * Set up the appropriate state.
 */
void GdbServer::activate_debugger() {
  if (!timeline_) {
    FATAL() << "Should only be called with a timeline";
  }
  TraceFrame next_frame = timeline_->current_session().current_trace_frame();
  FrameTime completed_event = next_frame.time() - 1;
  Task* t = require_timeline_current_task();
  if (target.event || target.pid) {
    if (stop_replaying_to_target && *stop_replaying_to_target) {
      fprintf(stderr, "\a\n"
                      "--------------------------------------------------\n"
                      " ---> Interrupted; attached to NON-TARGET process %d at event %llu.\n"
                      "--------------------------------------------------\n",
              t->tgid(), (long long)completed_event);
    } else if (target.event >= 0) {
      fprintf(stderr, "\a\n"
                      "--------------------------------------------------\n"
                      " ---> Reached target process %d at event %llu.\n"
                      "--------------------------------------------------\n",
              t->tgid(), (long long)completed_event);
    } else {
      ASSERT(t, target.event == -1);
      fprintf(stderr, "\a\n"
                      "--------------------------------------------------\n"
                      " ---> Reached exit of target process %d at event %llu.\n"
                      "--------------------------------------------------\n",
              t->tgid(), (long long)completed_event);
      exit_sigkill_pending = true;
    }
  }

  // Store the current tgid and event as the "execution target"
  // for the next replay session, if we end up restarting.  This
  // allows us to determine if a later session has reached this
  // target without necessarily replaying up to this point.
  target.pid = t->tgid();
  target.require_exec = false;
  target.event = completed_event;

  last_query_task = last_continue_task = extended_task_id(t);

  // Have the "checkpoint" be the original replay
  // session, and then switch over to using the cloned
  // session.  The cloned tasks will look like children
  // of the clonees, so this scheme prevents |pstree|
  // output from getting /too/ far out of whack.
  const char* where = "???";
  if (timeline_->can_add_checkpoint()) {
    debugger_restart_checkpoint =
        Checkpoint(*timeline_, last_continue_task, Checkpoint::EXPLICIT, where);
  } else {
    debugger_restart_checkpoint = Checkpoint(*timeline_, last_continue_task,
                                             Checkpoint::NOT_EXPLICIT, where);
  }
}

static FrameTime compute_time_from_ticks(ReplayTimeline& timeline, Ticks target) {
  ReplaySession &session = timeline.current_session();
  Task* task = session.current_task();
  FrameTime current_time = session.current_frame_time();
  TraceReader tmp_reader(session.trace_reader());
  FrameTime last_time = current_time;
  if (session.ticks_at_start_of_current_event() > target) {
    tmp_reader.rewind();
    FrameTime task_time;
    // EXEC and CLONE reset the ticks counter. Find the first event
    // where the tuid matches our current task.
    // We'll always hit at least one CLONE/EXEC event for a task
    // (we can't debug the time before the initial exec)
    // but set this to 0 anyway to silence compiler warnings.
    FrameTime ticks_start_time = 0;
    while (true) {
      TraceTaskEvent r = tmp_reader.read_task_event(&task_time);
      if (task_time >= current_time) {
        break;
      }
      if (r.type() == TraceTaskEvent::CLONE || r.type() == TraceTaskEvent::EXEC) {
        if (r.tid() == task->tuid().tid()) {
          ticks_start_time = task_time;
        }
      }
    }
    // Forward the frame reader to the current event
    last_time = ticks_start_time + 1;
    while (true) {
      TraceFrame frame = tmp_reader.read_frame();
      if (frame.time() >= ticks_start_time) {
        break;
      }
    }
  } else if (target < session.current_trace_frame().ticks()) {
    // The target tick is entirely within the current frame.
    // If not handled here, the below loop might otherwise skip over
    // it if the next frame is for another tid.
    return last_time;
  }
  
  while (true) {
    if (tmp_reader.at_end()) {
      return -1;
    }
    TraceFrame frame = tmp_reader.read_frame();
    if (frame.tid() == task->tuid().tid() && target < frame.ticks()) {
      break;
    }
    last_time = frame.time() + 1;
  }
  return last_time;
}

void GdbServer::restart_session(const GdbRequest& req) {
  DEBUG_ASSERT(req.type == DREQ_RESTART);
  DEBUG_ASSERT(dbg);

  failed_restart = false;
  in_debuggee_end_state = false;
  if (!timeline_) {
    failed_restart = true;
    dbg->notify_restart_failed();
    return;
  }

  timeline_->remove_breakpoints_and_watchpoints();

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
      failed_restart = true;
      dbg->notify_restart_failed();
      return;
    }
    checkpoint_to_restore = it->second;
  } else if (req.restart().type == RESTART_FROM_PREVIOUS) {
    checkpoint_to_restore = debugger_restart_checkpoint;
  } else if (req.restart().type == RESTART_FROM_TICKS) {
    Ticks ticks = req.restart().param;
    FrameTime time = compute_time_from_ticks(*timeline_, ticks);
    if (time == -1) {
      cout << "No event found matching specified ticks target.\n";
      failed_restart = true;
      dbg->notify_restart_failed();
      return;
    }
    timeline_->seek_to_ticks(time, ticks);
  }

  interrupt_pending = true;

  if (checkpoint_to_restore.mark) {
    timeline_->seek_to_mark(checkpoint_to_restore.mark);
    last_query_task = last_continue_task =
        checkpoint_to_restore.last_continue_task;
    if (debugger_restart_checkpoint.is_explicit == Checkpoint::EXPLICIT) {
      timeline_->remove_explicit_checkpoint(debugger_restart_checkpoint.mark);
    }
    debugger_restart_checkpoint = checkpoint_to_restore;
    if (timeline_->can_add_checkpoint()) {
      timeline_->add_explicit_checkpoint();
    }
    return;
  }

  if (req.restart().type == RESTART_FROM_EVENT) {
    // Note that we don't reset the target pid; we intentionally keep targeting
    // the same process no matter what is running when we hit the event.
    target.event = req.restart().param;
    target.event = min(final_event - 1, target.event);
    timeline_->seek_to_before_event(target.event);
    ReplayResult result;
    do {
      result = timeline_->replay_step_forward(RUN_CONTINUE);
      // We should never reach the end of the trace without hitting the stop
      // condition below.
      DEBUG_ASSERT(result.status != REPLAY_EXITED);
      if (is_last_thread_exit(result.break_status) &&
          result.break_status.task_context.thread_group->tgid == target.pid) {
        // Debuggee task is about to exit. Stop here.
        in_debuggee_end_state = true;
        break;
      }
    } while (!at_target(*timeline_, target, stop_replaying_to_target, result));
  }
  activate_debugger();
}

void GdbServer::serve_replay(std::shared_ptr<ReplaySession> session,
                             const Target& target,
                             volatile bool* stop_replaying_to_target,
                             const ConnectionFlags& flags) {
  ReplayTimeline timeline(std::move(session));

  ReplayResult result;
  do {
    result = timeline.replay_step_forward(RUN_CONTINUE);
    if (result.status == REPLAY_EXITED) {
      LOG(info) << "Debugger was not launched before end of trace";
      return;
    }
  } while (!at_target(timeline, target, stop_replaying_to_target, result));

  unsigned short port = flags.dbg_port > 0 ? flags.dbg_port : getpid();
  // Don't probe if the user specified a port.  Explicitly
  // selecting a port is usually done by scripts, which would
  // presumably break if a different port were to be selected by
  // rr (otherwise why would they specify a port in the first
  // place).  So fail with a clearer error message.
  auto probe = flags.dbg_port > 0 ? DONT_PROBE : PROBE_PORT;
  Task* t = timeline.current_session().current_task();
  OpenedSocket listen_socket = open_socket(flags.dbg_host, port, probe);
  if (flags.debugger_params_write_pipe) {
    DebuggerParams params;
    memset(&params, 0, sizeof(params));
    strncpy(params.exe_image, t->vm()->exe_image().c_str(),
            sizeof(params.exe_image) - 1);
    params.socket_domain = listen_socket.domain;
    strncpy(params.host, listen_socket.host.c_str(), sizeof(params.host) - 1);
    params.port = listen_socket.port;

    ssize_t nwritten =
        write(*flags.debugger_params_write_pipe, &params, sizeof(params));
    DEBUG_ASSERT(nwritten == sizeof(params));
  } else {
    vector<string> cmd = debugger_launch_command(t, listen_socket.domain,
        listen_socket.host, listen_socket.port,
        flags.serve_files, flags.debugger_name);
    fprintf(stderr, "Launch debugger with\n  %s\n", to_shell_string(cmd).c_str());
  }

  if (flags.debugger_params_write_pipe) {
    flags.debugger_params_write_pipe->close();
  }

  FrameTime first_run_event = std::max(t->vm()->first_run_event(),
    t->thread_group()->first_run_event());
  if (first_run_event) {
    timeline.set_reverse_execution_barrier_event(first_run_event);
  }

  do {
    LOG(debug) << "initializing debugger connection";
    auto connection = GdbServerConnection::await_connection(t, listen_socket.fd);

    GdbServer server(connection, timeline.current_session().current_task(),
                     &timeline, target);
    server.activate_debugger();

    GdbRequest last_resume_request;
    while (server.debug_one_step(last_resume_request) == CONTINUE_DEBUGGING) {
    }

    timeline.remove_breakpoints_and_watchpoints();
  } while (flags.keep_listening);

  LOG(debug) << "debugger server exiting ...";
}

static ScopedFd generate_fake_proc_maps(Task* t) {
  TempFile file = create_temporary_file("rr-fake-proc-maps-XXXXXX");
  unlink(file.name.c_str());

  int fd = dup(file.fd);
  if (fd < 0) {
    FATAL() << "Cannot dup";
  }
  FILE* f = fdopen(fd, "w");


  int addr_min_width = word_size(t->arch()) == 8 ? 10 : 8;
  for (AddressSpace::Maps::iterator it = t->vm()->maps().begin();
       it != t->vm()->maps().end(); ++it) {
    // If this is the mapping just before the rr page and it's still librrpage,
    // merge this mapping with the subsequent one. We'd like gdb to treat
    // librrpage as the vdso, but it'll only do so if the entire vdso is one
    // mapping.
    auto m = *it;
    uintptr_t map_end = (long long)m.recorded_map.end().as_int();
    if (m.recorded_map.end() == t->vm()->rr_page_start()) {
      auto it2 = it;
      if (++it2 != t->vm()->maps().end()) {
        auto m2 = *it2;
        if (m2.flags & AddressSpace::Mapping::IS_RR_PAGE) {
          // Extend this mapping
          map_end += PRELOAD_LIBRARY_PAGE_SIZE;
          // Skip the rr page
          ++it;
        }
      }
    }

    int len =
        fprintf(f, "%0*llx-%0*llx %s%s%s%s %08llx %02x:%02x %lld",
                addr_min_width, (long long)m.recorded_map.start().as_int(),
                addr_min_width, (long long)map_end,
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

  return std::move(file.fd);
}

static bool is_ld_mapping(string map_name) {
  char ld_start[] = "ld-";
  size_t matchpos = map_name.find_last_of('/');
  string fname = map_name.substr(matchpos == string::npos ? 0 : matchpos + 1);
  return memcmp(fname.c_str(), ld_start,
                sizeof(ld_start)-1) == 0;
}

static bool is_likely_interp(string fsname) {
#ifdef __aarch64__
  return fsname == "/lib/ld-linux-aarch64.so.1";
#else
  return fsname == "/lib64/ld-linux-x86-64.so.2" || fsname == "/lib/ld-linux.so.2";
#endif
}

#ifndef __BIONIC__
static remote_ptr<void> base_addr_from_rendezvous(Task* t, string fname)
{
  remote_ptr<void> interpreter_base = t->vm()->saved_interpreter_base();
  if (!interpreter_base || !t->vm()->has_mapping(interpreter_base)) {
    return nullptr;
  }
  string ld_path = t->vm()->saved_ld_path();
  if (ld_path.length() == 0) {
    FATAL() << "Failed to retrieve interpreter name with interpreter_base=" << interpreter_base;
  }
  ScopedFd ld(ld_path.c_str(), O_RDONLY);
  if (ld < 0) {
    FATAL() << "Open failed: " << ld_path;
  }
  ElfFileReader reader(ld);
  auto syms = reader.read_symbols(".dynsym", ".dynstr");
  static const char r_debug[] = "_r_debug";
  bool found = false;
  uintptr_t r_debug_offset = 0;
  for (size_t i = 0; i < syms.size(); ++i) {
    if (!syms.is_name(i, r_debug)) {
      continue;
    }
    r_debug_offset = syms.addr(i);
    found = true;
  }
  if (!found) {
    return nullptr;
  }
  bool ok = true;
  remote_ptr<NativeArch::r_debug> r_debug_remote = interpreter_base.as_int()+r_debug_offset;
  remote_ptr<NativeArch::link_map> link_map = t->read_mem(REMOTE_PTR_FIELD(r_debug_remote, r_map), &ok);
  while (ok && link_map != nullptr) {
    if (fname == t->read_c_str(t->read_mem(REMOTE_PTR_FIELD(link_map, l_name), &ok), &ok)) {
      remote_ptr<void> result = t->read_mem(REMOTE_PTR_FIELD(link_map, l_addr), &ok);
      return ok ? result : nullptr;
    }
    link_map = t->read_mem(REMOTE_PTR_FIELD(link_map, l_next), &ok);
  }
  return nullptr;
}
#endif

int GdbServer::open_file(Session& session, Task* continue_task, const std::string& file_name) {
  // XXX should we require file_scope_pid == 0 here?
  ScopedFd contents;

  if (file_name.empty()) {
    return -1;
  }

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
  } else if (file_name == continue_task->vm()->interp_name()) {
    remote_ptr<void> interp_base = continue_task->vm()->interp_base();
    auto m = continue_task->vm()->mapping_of(interp_base);
    LOG(debug) << "Found dynamic linker as memory mapping " << m.recorded_map;
    int ret_fd = 0;
    while (files.find(ret_fd) != files.end() ||
           memory_files.find(ret_fd) != memory_files.end()) {
      ++ret_fd;
    }
    memory_files.insert(make_pair(ret_fd, FileId(m.recorded_map)));
    return ret_fd;
  } else {
    // See if we can find the file by serving one of our mappings
    std::string normalized_file_name = file_name;
    normalize_file_name(normalized_file_name);
    for (const auto& m : continue_task->vm()->maps()) {
      // The dynamic linker is generally a symlink that is resolved by the
      // kernel when the process image gets loaded. We add a special case to
      // substitute the correct mapping, so gdb can find the dynamic linker
      // rendezvous structures.
      // Use our old hack for ld from before we read PT_INTERP for backwards
      // compat with older traces.
      if (m.recorded_map.fsname().compare(0, normalized_file_name.length(), normalized_file_name) == 0
          || m.map.fsname().compare(0, normalized_file_name.length(), normalized_file_name) == 0
          || (is_ld_mapping(m.recorded_map.fsname()) &&
              is_likely_interp(normalized_file_name)))
      {
        int ret_fd = 0;
        while (files.find(ret_fd) != files.end() ||
               memory_files.find(ret_fd) != memory_files.end()) {
          ++ret_fd;
        }
        LOG(debug) << "Found as memory mapping " << m.recorded_map;
        memory_files.insert(make_pair(ret_fd, FileId(m.recorded_map)));
        return ret_fd;
      }
    }
    // Last ditch attempt: Dig through the tracee's libc rendezvous struct to
    // see if we can find this file by a different name (e.g. if it was opened
    // via symlink)
#ifndef __BIONIC__
    remote_ptr<void> base = base_addr_from_rendezvous(continue_task, file_name);
    if (base != nullptr && continue_task->vm()->has_mapping(base)) {
      int ret_fd = 0;
      while (files.find(ret_fd) != files.end() ||
              memory_files.find(ret_fd) != memory_files.end()) {
        ++ret_fd;
      }
      memory_files.insert(make_pair(ret_fd, FileId(continue_task->vm()->mapping_of(base).recorded_map)));
      return ret_fd;
    }
#endif
    LOG(debug) << "... not found";
    return -1;
   }

  int ret_fd = 0;
  while (files.find(ret_fd) != files.end()) {
    ++ret_fd;
  }
  files.insert(make_pair(ret_fd, std::move(contents)));
  return ret_fd;
}

static void remove_trailing_guard_pages(ReplaySession::MemoryRanges& ranges) {
  remote_ptr<void> ptr;
  while (true) {
    auto it = ranges.lower_bound(MemoryRange(ptr, 1));
    if (it == ranges.end()) {
      return;
    }
    MemoryRange r = *it;
    ranges.erase(it);
    remote_ptr<void> end = floor_page_size(r.end() - 1);
    if (end > r.start()) {
      ranges.insert(MemoryRange(r.start(), end));
    }
    ptr = end;
  }
}

remote_ptr<void> GdbServer::allocate_debugger_mem(ThreadGroupUid tguid, size_t size,
    int prot) {
  if (!timeline_) {
    return nullptr;
  }

  auto it = debugger_mem.find(tguid);
  if (it == debugger_mem.end()) {
    it = debugger_mem.insert(make_pair(tguid, DebuggerMem())).first;
    it->second.free_memory = timeline_->current_session().
        always_free_address_space(ReplaySession::FAST);
    remove_trailing_guard_pages(it->second.free_memory);
    it->second.did_get_accurate_free_memory = false;
  }
  DebuggerMem& dbg_mem = it->second;

  if (size >= (1 << 30)) {
    return nullptr;
  }
  size = ceil_page_size(size);
  while (true) {
    for (auto it = dbg_mem.free_memory.begin();
         it != dbg_mem.free_memory.end(); ++it) {
      if (it->size() >= size + page_size()) {
        MemoryRange r = *it;
        dbg_mem.free_memory.erase(it);
        // Skip guard page
        remote_ptr<void> result = r.start() + page_size();
        if (r.end() > result + size) {
          dbg_mem.free_memory.insert(MemoryRange(result + size, r.end()));
        }
        DebuggerMemRegion& region =
            dbg_mem.regions[MemoryRange(result, size)];
        region.values.resize(size, 0);
        region.prot = prot;
        return result;
      }
    }

    if (dbg_mem.did_get_accurate_free_memory) {
      LOG(warn) << "Can't allocate free memory for debugger";
      return nullptr;
    }
    dbg_mem.did_get_accurate_free_memory = true;
    dbg_mem.free_memory = timeline_->current_session().
        always_free_address_space(ReplaySession::ACCURATE);
    for (const auto& kv : dbg_mem.regions) {
      ReplaySession::delete_range(dbg_mem.free_memory,
          MemoryRange(kv.first.start() - page_size(),
                      kv.second.values.size() + page_size()));
    }
  }
}

static void coalesce_free_memory(ReplaySession::MemoryRanges& ranges,
                                 remote_ptr<void> addr) {
  if (addr.is_null()) {
    return;
  }
  auto before = ranges.find(MemoryRange(addr - 1, 1));
  if (before == ranges.end() || before->end() != addr) {
    return;
  }
  MemoryRange before_range = *before;
  ranges.erase(before);

  auto after = ranges.find(MemoryRange(addr, 1));
  if (after == ranges.end()) {
    return;
  }
  MemoryRange after_range = *after;
  ranges.erase(after);

  ranges.insert(MemoryRange(before_range.start(), after_range.end()));
}

size_t GdbServer::free_debugger_mem(ThreadGroupUid tguid, remote_ptr<void> addr) {
  auto it = debugger_mem.find(tguid);
  if (it == debugger_mem.end()) {
    return 0;
  }
  DebuggerMem& dbg_mem = it->second;
  auto region_it = dbg_mem.regions.find(MemoryRange(addr, 1));
  if (region_it == dbg_mem.regions.end() || region_it->first.start() != addr) {
    return 0;
  }

  size_t ret = region_it->first.size();
  MemoryRange freed(addr - page_size(), region_it->first.end());
  dbg_mem.free_memory.insert(freed);
  coalesce_free_memory(dbg_mem.free_memory, freed.start());
  coalesce_free_memory(dbg_mem.free_memory, freed.end());

  dbg_mem.regions.erase(region_it);
  return ret;
}

bool GdbServer::read_debugger_mem(ThreadGroupUid tguid, MemoryRange range,
    uint8_t* values) {
  auto it = debugger_mem.find(tguid);
  if (it == debugger_mem.end()) {
    return false;
  }
  DebuggerMem& dbg_mem = it->second;
  auto region_it = dbg_mem.regions.lower_bound(range);
  if (region_it == dbg_mem.regions.end() || range.end() <= region_it->first.start()) {
    return false;
  }
  if (!region_it->first.contains(range)) {
    FATAL() << "Debugger read beyond bounds of region, no idea what's going on";
  }
  size_t offset = range.start() - region_it->first.start();
  memcpy(values, region_it->second.values.data() + offset, range.size());
  return true;
}

bool GdbServer::write_debugger_mem(ThreadGroupUid tguid, MemoryRange range,
    const uint8_t* values) {
  auto it = debugger_mem.find(tguid);
  if (it == debugger_mem.end()) {
    return false;
  }
  DebuggerMem& dbg_mem = it->second;
  auto region_it = dbg_mem.regions.lower_bound(range);
  if (region_it == dbg_mem.regions.end() || range.end() <= region_it->first.start()) {
    return false;
  }
  if (!region_it->first.contains(range)) {
    FATAL() << "Debugger write beyond bounds of region, no idea what's going on";
  }
  size_t offset = range.start() - region_it->first.start();
  memcpy(region_it->second.values.data() + offset, values, range.size());
  return true;
}

void GdbServer::map_debugger_mem(DiversionSession& session,
                                 ThreadGroupUid tguid, remote_ptr<void> addr) {
  for (const auto& dbg_mem : debugger_mem) {
    if (!addr.is_null() && tguid != dbg_mem.first) {
      continue;
    }
    ThreadGroup* tg = session.find_thread_group(dbg_mem.first);
    if (!tg || tg->task_set().empty()) {
      // Threadgroup doesn't exist or is somehow empty at this point in time
      continue;
    }

    Task* t = *tg->task_set().begin();
    AddressSpace::shr_ptr vm = (*tg->task_set().begin())->vm();
    AutoRemoteSyscalls remote(t);
    for (const auto& region : dbg_mem.second.regions) {
      remote_ptr<void> start = region.first.start();
      if (!addr.is_null() && addr != start) {
        continue;
      }
      size_t size = region.second.values.size();
      // Mask debugger-provided prot bits here just in case someone
      // tries to do something silly/dangerous/malicious.
      int prot = region.second.prot & (PROT_READ | PROT_WRITE | PROT_EXEC);
      int flags = MAP_PRIVATE | MAP_ANONYMOUS;
      remote.infallible_mmap_syscall_if_alive(start, size, prot, flags, -1, 0);
      vm->map(t, start, size, prot, flags, 0, "");
      t->write_bytes_helper(start, size, region.second.values.data());
    }
  }
}

void GdbServer::unmap_debugger_mem(DiversionSession& session,
                                   ThreadGroupUid tguid, remote_ptr<void> addr,
                                   size_t size) {
  ThreadGroup* tg = session.find_thread_group(tguid);
  if (!tg || tg->task_set().empty()) {
    // Threadgroup doesn't exist or is somehow empty at this point in time
    return;
  }

  Task* t = *tg->task_set().begin();
  AddressSpace::shr_ptr vm = (*tg->task_set().begin())->vm();
  AutoRemoteSyscalls remote(t);
  remote.infallible_munmap_syscall_if_alive(addr, size);
  vm->unmap(t, addr, size);
}

void GdbServer::read_back_debugger_mem(DiversionSession& session) {
  for (auto& dbg_mem : debugger_mem) {
    ThreadGroup* tg = session.find_thread_group(dbg_mem.first);
    if (!tg || tg->task_set().empty()) {
      // Threadgroup doesn't exist or is somehow empty at this point in time
      continue;
    }

    Task* t = *tg->task_set().begin();
    AddressSpace::shr_ptr vm = (*tg->task_set().begin())->vm();
    for (auto& region : dbg_mem.second.regions) {
      remote_ptr<void> start = region.first.start();
      size_t size = region.second.values.size();
      t->read_bytes_helper(start, size, region.second.values.data());
    }
  }
}

GdbServerRegister GdbServer::arch_reg_end(SupportedArch arch) noexcept {
  if(target_regs_end != GdbServerRegister(0)) {
    return target_regs_end;
  }

  // Send values for all the registers we sent XML register descriptions for.
  // Those descriptions are controlled by GdbServerConnection::cpu_features().
  bool have_PKU = dbg->cpu_features() & GdbServerConnection::CPU_PKU;
  bool have_AVX = dbg->cpu_features() & GdbServerConnection::CPU_AVX;
  bool have_AVX512 = dbg->cpu_features() & GdbServerConnection::CPU_AVX512;
  switch (arch) {
    case x86:
      if(have_PKU) {
        target_regs_end = DREG_PKRU;
      } else if(have_AVX512) {
        target_regs_end = DREG_K7;
      } else if(have_AVX) {
        target_regs_end = DREG_YMM7H;
      } else {
        target_regs_end = DREG_ORIG_EAX;
      }
      break;
    case x86_64:
      if(have_PKU) {
        target_regs_end = DREG_64_PKRU;
      } else if(have_AVX512) {
        target_regs_end = DREG_64_K7;
      } else if(have_AVX) {
        target_regs_end = DREG_64_YMM15H;
      } else {
        target_regs_end = DREG_GS_BASE;
      }
      break;
    case aarch64:
      target_regs_end = DREG_FPCR;
      break;
    default:
      FATAL() << "Unknown architecture";
      return target_regs_end;
  }
  return target_regs_end;
}

bool GdbServer::debugger_mem_region(ThreadGroupUid tguid, remote_ptr<void> addr,
    int* prot, MemoryRange* mem_range) {
  auto it = debugger_mem.find(tguid);
  if (it == debugger_mem.end()) {
    return false;
  }
  DebuggerMem& dbg_mem = it->second;
  auto region_it = dbg_mem.regions.find(MemoryRange(addr, 1));
  if (region_it == dbg_mem.regions.end()) {
    return false;
  }
  *prot = region_it->second.prot;
  *mem_range = region_it->first;
  return true;
}

} // namespace rr
