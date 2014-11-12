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

Session::Session() : tracees_consistent(false) {
  LOG(debug) << "Session " << this << " created";
}

Session::~Session() {
  kill_all_tasks();
  LOG(debug) << "Session " << this << " destroyed";
}

void Session::after_exec() {
  if (tracees_consistent) {
    return;
  }
  tracees_consistent = true;
  // Reset ticks for all Tasks (there should only be one).
  for (auto task = tasks().begin(); task != tasks().end(); ++task) {
    task->second->flush_inconsistent_state();
  }
}

AddressSpace::shr_ptr Session::create_vm(Task* t, const std::string& exe) {
  AddressSpace::shr_ptr as(new AddressSpace(t, exe, *this));
  as->insert_task(t);
  sas.insert(as.get());
  return as;
}

AddressSpace::shr_ptr Session::clone(AddressSpace::shr_ptr vm) {
  AddressSpace::shr_ptr as(new AddressSpace(*vm));
  as->session = this;
  sas.insert(as.get());
  return as;
}

Task* Session::clone(Task* p, int flags, remote_ptr<void> stack,
                     remote_ptr<void> tls, remote_ptr<int> cleartid_addr,
                     pid_t new_tid, pid_t new_rec_tid) {
  Task* c = p->clone(flags, stack, tls, cleartid_addr, new_tid, new_rec_tid);
  on_create(c);
  return c;
}

Task* Session::find_task(pid_t rec_tid) const {
  auto it = tasks().find(rec_tid);
  return tasks().end() != it ? it->second : nullptr;
}

void Session::kill_all_tasks() {
  while (!task_map.empty()) {
    Task* t = task_map.rbegin()->second;
    LOG(debug) << "Killing " << t->tid << "(" << t << ")";
    t->kill();
    delete t;
  }
}

void Session::on_destroy(AddressSpace* vm) {
  assert(vm->task_set().size() == 0);
  assert(sas.end() != sas.find(vm));
  sas.erase(vm);
}

void Session::on_destroy(Task* t) { task_map.erase(t->rec_tid); }

void Session::on_create(Task* t) { task_map[t->rec_tid] = t; }

Session::BreakStatus Session::diagnose_debugger_trap(Task* t, int stop_sig) {
  BreakStatus break_status;
  break_status.task = t;

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
                 << signalname(stop_sig);
#ifdef DEBUGTAG
      siginfo_t si = t->get_siginfo();
      psiginfo(&si, "  siginfo for signal-stop:\n    ");
#endif
      break_status.reason = BREAK_BREAKPOINT;
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
  } else if (DS_WATCHPOINT_ANY & t->debug_status()) {
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
    break_status.reason = BREAK_WATCHPOINT;
    break_status.watch_address = t->watchpoint_addr(dr);
  }

  return break_status;
}
