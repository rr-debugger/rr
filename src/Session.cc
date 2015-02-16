/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "Session"

#include "Session.h"

#include <syscall.h>
#include <sys/prctl.h>

#include <algorithm>

#include "AutoRemoteSyscalls.h"
#include "EmuFs.h"
#include "kernel_metadata.h"
#include "log.h"
#include "task.h"
#include "util.h"

using namespace rr;
using namespace std;

struct Session::CloneCompletion {
  struct TaskGroup {
    Task* clone_leader;
    Task::CapturedState clone_leader_state;
    vector<Task::CapturedState> member_states;
  };
  vector<TaskGroup> task_groups;
};

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

Session::Session(const Session& other) {
  statistics_ = other.statistics_;
  next_task_serial_ = other.next_task_serial_;
  tracees_consistent = other.tracees_consistent;
  visible_execution_ = other.visible_execution_;
}

void Session::on_create(TaskGroup* tg) { task_group_map[tg->tguid()] = tg; }
void Session::on_destroy(TaskGroup* tg) { task_group_map.erase(tg->tguid()); }

void Session::post_exec() {
  assert_fully_initialized();
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
  assert_fully_initialized();
  AddressSpace::shr_ptr as(new AddressSpace(t, exe, exec_count));
  as->insert_task(t);
  vm_map[as->uid()] = as.get();
  return as;
}

AddressSpace::shr_ptr Session::clone(Task* t, AddressSpace::shr_ptr vm) {
  assert_fully_initialized();
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
  assert_fully_initialized();
  Task* c = p->clone(flags, stack, tls, cleartid_addr, new_tid, new_rec_tid,
                     next_task_serial());
  on_create(c);
  return c;
}

Task* Session::find_task(pid_t rec_tid) const {
  assert_fully_initialized();
  auto it = tasks().find(rec_tid);
  return tasks().end() != it ? it->second : nullptr;
}

Task* Session::find_task(const TaskUid& tuid) const {
  Task* t = find_task(tuid.tid());
  return t && t->tuid() == tuid ? t : nullptr;
}

TaskGroup* Session::find_task_group(const TaskGroupUid& tguid) const {
  assert_fully_initialized();
  auto it = task_group_map.find(tguid);
  if (task_group_map.end() == it) {
    return nullptr;
  }
  return it->second;
}

AddressSpace* Session::find_address_space(const AddressSpaceUid& vmuid) const {
  assert_fully_initialized();
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
  assert(vm_map.count(vm->uid()) == 1);
  vm_map.erase(vm->uid());
}

void Session::on_destroy(Task* t) {
  assert(task_map.count(t->rec_tid) == 1);
  task_map.erase(t->rec_tid);
}

void Session::on_create(Task* t) { task_map[t->rec_tid] = t; }

BreakStatus Session::diagnose_debugger_trap(Task* t, int stop_sig) {
  assert_fully_initialized();
  BreakStatus break_status;
  break_status.task = t;
  break_status.signal = 0;
  break_status.watch_address = nullptr;

  TrapType pending_bp = t->vm()->get_breakpoint_type_at_addr(t->ip());
  TrapType retired_bp = t->vm()->get_breakpoint_type_for_retired_insn(t->ip());

  uintptr_t debug_status = t->consume_debug_status();

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
  } else if (DS_SINGLESTEP & debug_status) {
    LOG(debug) << "  finished debugger stepi";
    /* Successful stepi.  Nothing else to do. */
    break_status.reason = BREAK_SINGLESTEP;
  } else {
    break_status.reason = BREAK_NONE;
  }
  if (DS_WATCHPOINT_ANY & debug_status) {
    LOG(debug) << "  " << t->tid << "(rec:" << t->rec_tid
               << "): hit debugger watchpoint.";
    t->vm()->notify_watchpoint_fired(debug_status);
  }
  check_for_watchpoint_changes(t, break_status);

  return break_status;
}

void Session::check_for_watchpoint_changes(Task* t, BreakStatus& break_status) {
  assert_fully_initialized();
  if (t->vm()->consume_watchpoint_change(&break_status.watch_address) &&
      break_status.reason == BREAK_NONE) {
    break_status.reason = BREAK_WATCHPOINT;
  }
}

void Session::assert_fully_initialized() const {
  assert(!clone_completion && "Session not fully initialized");
}

void Session::finish_initializing() {
  if (!clone_completion) {
    return;
  }

  for (auto& tgleader : clone_completion->task_groups) {
    AutoRemoteSyscalls remote(tgleader.clone_leader);
    for (auto& tgmember : tgleader.member_states) {
      Task* t_clone =
          Task::os_clone_into(tgmember, tgleader.clone_leader, remote);
      on_create(t_clone);
      t_clone->copy_state(tgmember);
    }
    tgleader.clone_leader->copy_state(tgleader.clone_leader_state);
  }

  clone_completion = nullptr;
}

static void remap_shared_mmap(AutoRemoteSyscalls& remote, EmuFs& dest_emu_fs,
                              const Mapping& m, const MappableResource& r) {
  LOG(debug) << "    remapping shared region at " << m.start << "-" << m.end;
  remote.syscall(syscall_number_for_munmap(remote.arch()), m.start,
                 m.num_bytes());
  // NB: we don't have to unmap then re-map |t->vm()|'s idea of
  // the emulated file mapping.  Though we'll be remapping the
  // *real* OS mapping in |t| to a different file, that new
  // mapping still refers to the same *emulated* file, with the
  // same emulated metadata.

  auto emufile = dest_emu_fs.at(r.id);
  // TODO: this duplicates some code in replay_syscall.cc, but
  // it's somewhat nontrivial to factor that code out.
  int remote_fd;
  {
    string path = emufile->proc_path();
    AutoRestoreMem child_path(remote, path.c_str());
    int oflags =
        (MAP_SHARED & m.flags) && (PROT_WRITE & m.prot) ? O_RDWR : O_RDONLY;
    remote_fd = remote.syscall(syscall_number_for_open(remote.arch()),
                               child_path.get().as_int(), oflags);
    if (0 > remote_fd) {
      FATAL() << "Couldn't open " << path << " in tracee";
    }
  }
  // XXX this condition is x86/x64-specific, I imagine.
  remote_ptr<void> addr = remote.mmap_syscall(m.start, m.num_bytes(), m.prot,
                                              // The remapped segment *must* be
                                              // remapped at the same address,
                                              // or else many things will go
                                              // haywire.
                                              m.flags | MAP_FIXED, remote_fd,
                                              m.offset / page_size());
  ASSERT(remote.task(), addr == m.start);

  remote.syscall(syscall_number_for_close(remote.arch()), remote_fd);
}

void Session::copy_state_to(Session& dest, EmuFs& dest_emu_fs) {
  assert_fully_initialized();
  assert(!dest.clone_completion);

  auto completion = unique_ptr<CloneCompletion>(new CloneCompletion());

  for (auto vm : vm_map) {
    Task* some_task = *vm.second->task_set().begin();
    pid_t tgid = some_task->tgid();
    Task* group_leader = find_task(tgid);
    LOG(debug) << "  forking tg " << tgid
               << " (real: " << group_leader->real_tgid() << ")";

    if (group_leader->is_probably_replaying_syscall()) {
      group_leader->finish_emulated_syscall();
    }

    completion->task_groups.push_back(CloneCompletion::TaskGroup());
    auto& group = completion->task_groups.back();

    group.clone_leader = group_leader->os_fork_into(&dest);
    dest.on_create(group.clone_leader);
    LOG(debug) << "  forked new group leader " << group.clone_leader->tid;

    {
      AutoRemoteSyscalls remote(group.clone_leader);
      for (auto& kv : group.clone_leader->vm()->memmap()) {
        const Mapping& m = kv.first;
        const MappableResource& r = kv.second;
        if (!r.is_shared_mmap_file()) {
          continue;
        }
        remap_shared_mmap(remote, dest_emu_fs, m, r);
      }

      for (auto t : group_leader->task_group()->task_set()) {
        if (group_leader == t) {
          continue;
        }
        LOG(debug) << "    cloning " << t->rec_tid;

        if (t->is_probably_replaying_syscall()) {
          t->finish_emulated_syscall();
        }

        group.member_states.push_back(t->capture_state());
      }
    }

    group.clone_leader_state = group_leader->capture_state();
  }
  dest.clone_completion = move(completion);

  assert(dest.vms().size() > 0);
}
