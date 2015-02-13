/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "Session"

#include "Session.h"

#include <syscall.h>
#include <sys/prctl.h>

#include <algorithm>

#include "kernel_metadata.h"
#include "log.h"
#include "task.h"
#include "util.h"

using namespace rr;
using namespace std;

Session::Session()
    : next_task_serial_(1),
      tracees_consistent(false),
      visible_execution_(true) {
  LOG(debug) << "Session " << this << " created";
}

Session::~Session() {
  kill_all_tasks();
  LOG(debug) << "Session " << this << " destroyed";

  for (auto tg : task_group_map) {
    tg.second->forget_session();
  }
}

void Session::on_create(TaskGroup* tg) { task_group_map[tg->tguid()] = tg; }
void Session::on_destroy(TaskGroup* tg) { task_group_map.erase(tg->tguid()); }

void Session::post_exec() {
  if (tracees_consistent) {
    return;
  }
  tracees_consistent = true;
  // Reset ticks for all Tasks (there should only be one).
  for (auto task = tasks().begin(); task != tasks().end(); ++task) {
    task->second->flush_inconsistent_state();
  }
}

AddressSpace::shr_ptr Session::create_vm(Task* t, const std::string& exe,
                                         uint32_t exec_count) {
  AddressSpace::shr_ptr as(new AddressSpace(t, exe, exec_count));
  as->insert_task(t);
  vm_map[as->uid()] = as.get();
  return as;
}

AddressSpace::shr_ptr Session::clone(Task* t, AddressSpace::shr_ptr vm) {
  // If vm already belongs to our session this is a fork, otherwise it's
  // a session-clone
  AddressSpace::shr_ptr as(new AddressSpace(
      t, *vm, this == vm->session() ? 0 : vm->uid().exec_count()));
  as->session_ = this;
  vm_map[as->uid()] = as.get();
  return as;
}

vector<AddressSpace*> Session::vms() const {
  vector<AddressSpace*> result;
  for (auto& vm : vm_map) {
    result.push_back(vm.second);
  }
  return result;
}

Task* Session::clone(Task* p, int flags, remote_ptr<void> stack,
                     remote_ptr<void> tls, remote_ptr<int> cleartid_addr,
                     pid_t new_tid, pid_t new_rec_tid) {
  Task* c = p->clone(flags, stack, tls, cleartid_addr, new_tid, new_rec_tid,
                     next_task_serial());
  on_create(c);
  return c;
}

Task* Session::find_task(pid_t rec_tid) const {
  auto it = tasks().find(rec_tid);
  return tasks().end() != it ? it->second : nullptr;
}

Task* Session::find_task(const TaskUid& tuid) const {
  Task* t = find_task(tuid.tid());
  return t && t->tuid() == tuid ? t : nullptr;
}

TaskGroup* Session::find_task_group(const TaskGroupUid& tguid) const {
  auto it = task_group_map.find(tguid);
  if (task_group_map.end() == it) {
    return nullptr;
  }
  return it->second;
}

AddressSpace* Session::find_address_space(const AddressSpaceUid& vmuid) const {
  auto it = vm_map.find(vmuid);
  if (vm_map.end() == it) {
    return nullptr;
  }
  return it->second;
}

void Session::kill_all_tasks() {
  for (auto& v : task_map) {
    v.second->prepare_kill();
  }

  while (!task_map.empty()) {
    Task* t = task_map.rbegin()->second;
    t->kill();
    delete t;
  }
}

void Session::on_destroy(AddressSpace* vm) {
  assert(vm->task_set().size() == 0);
  vm_map.erase(vm->uid());
}

void Session::on_destroy(Task* t) { task_map.erase(t->rec_tid); }

void Session::on_create(Task* t) { task_map[t->rec_tid] = t; }

BreakStatus Session::diagnose_debugger_trap(Task* t, int stop_sig) {
  BreakStatus break_status;
  break_status.task = t;
  break_status.watch_address = nullptr;

  TrapType pending_bp = t->vm()->get_breakpoint_type_at_addr(t->ip());
  TrapType retired_bp = t->vm()->get_breakpoint_type_for_retired_insn(t->ip());

  // NBB: very little effort has been made to handle
  // corner cases where multiple
  // breakpoints/watchpoints/singlesteps are fired
  // simultaneously.  These cases will be addressed as
  // they arise in practice.
  if (SIGTRAP != stop_sig) {
    if (TRAP_BKPT_USER == pending_bp) {
      // A signal was raised /just/ before a trap
      // instruction for a SW breakpoint.  This is
      // observed when debuggers write trap
      // instructions into no-exec memory, for
      // example the stack.
      //
      // We report the breakpoint before any signal
      // that might have been raised in order to let
      // the debugger do something at the breakpoint
      // insn; possibly clearing the breakpoint and
      // changing the $ip.  Otherwise, we expect the
      // debugger to clear the breakpoint and resume
      // execution, which should raise the original
      // signal again.
      LOG(debug) << "hit debugger breakpoint BEFORE ip " << t->ip() << " for "
                 << signal_name(stop_sig);
#ifdef DEBUGTAG
      siginfo_t si = t->get_siginfo();
      psiginfo(&si, "  siginfo for signal-stop:\n    ");
#endif
      break_status.reason = BREAK_BREAKPOINT;
    } else if (stop_sig == PerfCounters::TIME_SLICE_SIGNAL || stop_sig == 0) {
      break_status.reason = BREAK_TICKS_TARGET;
    } else {
      break_status.reason = BREAK_SIGNAL;
      break_status.signal = stop_sig;
    }
  } else if (TRAP_BKPT_USER == retired_bp) {
    LOG(debug) << "hit debugger breakpoint at ip " << t->ip();
    // SW breakpoint: $ip is just past the
    // breakpoint instruction.  Move $ip back
    // right before it.
    t->move_ip_before_breakpoint();
    break_status.reason = BREAK_BREAKPOINT;
  } else if (DS_SINGLESTEP & t->debug_status()) {
    LOG(debug) << "  finished debugger stepi";
    /* Successful stepi.  Nothing else to do. */
    break_status.reason = BREAK_SINGLESTEP;
  } else {
    break_status.reason = BREAK_NONE;
  }
  if (DS_WATCHPOINT_ANY & t->debug_status()) {
    LOG(debug) << "  " << t->tid << "(rec:" << t->rec_tid
               << "): hit debugger watchpoint.";
    // XXX it's possible for multiple watchpoints
    // to be triggered simultaneously.  No attempt
    // to prioritize them is made here; we just
    // choose the first one that fired.
    size_t dr = DS_WATCHPOINT0 & t->debug_status()
                    ? 0
                    : DS_WATCHPOINT1 & t->debug_status()
                          ? 1
                          : DS_WATCHPOINT2 & t->debug_status()
                                ? 2
                                : DS_WATCHPOINT3 & t->debug_status() ? 3 : -1;
    if (break_status.reason == BREAK_NONE) {
      break_status.reason = BREAK_WATCHPOINT;
    }
    break_status.watch_address = t->watchpoint_addr(dr);
  }

  return break_status;
}
