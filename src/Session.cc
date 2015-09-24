/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "Session"

#include "Session.h"

#include <syscall.h>
#include <sys/prctl.h>

#include <algorithm>

#include "rr/rr.h"

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
  assert(tasks().size() == 1);
  tasks().begin()->second->flush_inconsistent_state();
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
  AddressSpace::shr_ptr as;
  if (this == vm->session()) {
    as = AddressSpace::shr_ptr(
        new AddressSpace(this, *vm, t->rec_tid, t->tuid().serial(), 0));
  } else {
    as = AddressSpace::shr_ptr(new AddressSpace(this, *vm, vm->uid().tid(),
                                                vm->uid().serial(),
                                                vm->uid().exec_count()));
  }
  vm_map[as->uid()] = as.get();
  return as;
}

TaskGroup::shr_ptr Session::create_tg(Task* t) {
  TaskGroup::shr_ptr tg(
      new TaskGroup(this, nullptr, t->rec_tid, t->tid, t->tuid().serial()));
  tg->insert_task(t);
  return tg;
}

TaskGroup::shr_ptr Session::clone(Task* t, TaskGroup::shr_ptr tg) {
  assert_fully_initialized();
  // If tg already belongs to our session this is a fork to create a new
  // taskgroup, otherwise it's a session-clone of an existing taskgroup
  if (this == tg->session()) {
    return TaskGroup::shr_ptr(
        new TaskGroup(this, tg.get(), t->rec_tid, t->tid, t->tuid().serial()));
  }
  TaskGroup* parent =
      tg->parent() ? find_task_group(tg->parent()->tguid()) : nullptr;
  return TaskGroup::shr_ptr(
      new TaskGroup(this, parent, tg->tgid, t->tid, tg->tguid().serial()));
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
  finish_initializing();
  auto it = tasks().find(rec_tid);
  return tasks().end() != it ? it->second : nullptr;
}

Task* Session::find_task(const TaskUid& tuid) const {
  Task* t = find_task(tuid.tid());
  return t && t->tuid() == tuid ? t : nullptr;
}

TaskGroup* Session::find_task_group(const TaskGroupUid& tguid) const {
  finish_initializing();
  auto it = task_group_map.find(tguid);
  if (task_group_map.end() == it) {
    return nullptr;
  }
  return it->second;
}

AddressSpace* Session::find_address_space(const AddressSpaceUid& vmuid) const {
  finish_initializing();
  auto it = vm_map.find(vmuid);
  if (vm_map.end() == it) {
    return nullptr;
  }
  return it->second;
}

void Session::kill_all_tasks() {
  for (auto& v : task_map) {
    Task* t = v.second;

    if (!t->is_stopped) {
      // During recording we might be aborting the recording, in which case
      // one or more tasks might not be stopped. We haven't got any really
      // good options here so we'll just skip detaching and try killing
      // it with SIGKILL below. rr will usually exit immediatley after this
      // so the likelihood that we'll leak a zombie task isn't too bad.
      continue;
    }

    if (!t->stable_exit) {
      /*
       * Prepare to forcibly kill this task by detaching it first. To ensure
       * the task doesn't continue executing, we first set its ip() to an
       * invalid value. We need to do this for all tasks in the Session before
       * kill() is guaranteed to work properly. SIGKILL on ptrace-attached tasks
       * seems to not work very well, and after sending SIGKILL we can't seem to
       * reliably detach.
       */
      LOG(debug) << "safely detaching from " << t->tid << " ...";
      // Detaching from the process lets it continue. We don't want a replaying
      // process to perform syscalls or do anything else observable before we
      // get around to SIGKILLing it. So we move its ip() to an invalid
      // address. If it does continue, it will probably get a fatal signal.
      // We don't install real signal handlers in replayed processes so there's
      // no way it could handle the signal and continue.
      Registers r = t->regs();
      r.set_ip(intptr_t(-1));
      t->set_regs(r);
      long result;
      do {
        // We have observed this failing with an ESRCH when the thread clearly
        // still exists and is ptraced. Retrying the PTRACE_DETACH seems to
        // work around it.
        result = t->fallible_ptrace(PTRACE_DETACH, nullptr, nullptr);
        ASSERT(t, result >= 0 || errno == ESRCH);
      } while (result < 0);
    }
  }

  while (!task_map.empty()) {
    Task* t = task_map.rbegin()->second;
    if (!t->stable_exit && !t->unstable) {
      /**
       * Destroy the OS task backing this by sending it SIGKILL and
       * ensuring it was delivered.  After |kill()|, the only
       * meaningful thing that can be done with this task is to
       * delete it.
       */
      LOG(debug) << "sending SIGKILL to " << t->tid << " ...";
      // If we haven't already done a stable exit via syscall,
      // kill the task and note that the entire task group is unstable.
      t->tgkill(SIGKILL);
      t->task_group()->destabilize();
    }

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

BreakStatus Session::diagnose_debugger_trap(Task* t) {
  assert_fully_initialized();
  BreakStatus break_status;
  break_status.task = t;

  TrapType pending_bp = t->vm()->get_breakpoint_type_at_addr(t->ip());
  TrapType retired_bp = t->vm()->get_breakpoint_type_for_retired_insn(t->ip());

  uintptr_t debug_status = t->consume_debug_status();

  // NBB: very little effort has been made to handle
  // corner cases where multiple
  // breakpoints/watchpoints/singlesteps are fired
  // simultaneously.  These cases will be addressed as
  // they arise in practice.
  int stop_sig = t->pending_sig();
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
      break_status.breakpoint_hit = true;
    } else if (stop_sig && stop_sig != PerfCounters::TIME_SLICE_SIGNAL) {
      break_status.signal = stop_sig;
    }
  } else if (TRAP_BKPT_USER == retired_bp) {
    LOG(debug) << "hit debugger breakpoint at ip " << t->ip();
    // SW breakpoint: $ip is just past the
    // breakpoint instruction.  Move $ip back
    // right before it.
    t->move_ip_before_breakpoint();
    break_status.breakpoint_hit = true;
  } else if (DS_SINGLESTEP & debug_status) {
    LOG(debug) << "  finished debugger stepi";
    break_status.singlestep_complete = true;
  }
  // In VMWare Player 6.0.4 build-2249910, 32-bit Ubuntu x86 guest,
  // single-stepping does not trigger watchpoints :-(. We work around
  // that here by calling notify_watchpoint_fired if there's a singlestep
  // but no watchpoints reported; write-watchpoints will detect that their
  // value has changed and trigger. Read/exec watchpoints can't be detected
  // this way so they're still broken :-(.
  if ((DS_WATCHPOINT_ANY | DS_SINGLESTEP) & debug_status) {
    LOG(debug) << "  " << t->tid << "(rec:" << t->rec_tid
               << "): hit debugger watchpoint.";
    t->vm()->notify_watchpoint_fired(debug_status);
  }
  check_for_watchpoint_changes(t, break_status);

  return break_status;
}

void Session::check_for_watchpoint_changes(Task* t, BreakStatus& break_status) {
  assert_fully_initialized();
  break_status.watchpoints_hit = t->vm()->consume_watchpoint_changes();
}

void Session::assert_fully_initialized() const {
  assert(!clone_completion && "Session not fully initialized");
}

void Session::finish_initializing() const {
  if (!clone_completion) {
    return;
  }

  Session* self = const_cast<Session*>(this);
  for (auto& tgleader : clone_completion->task_groups) {
    AutoRemoteSyscalls remote(tgleader.clone_leader);
    for (auto& tgmember : tgleader.member_states) {
      Task* t_clone =
          Task::os_clone_into(tgmember, tgleader.clone_leader, remote);
      self->on_create(t_clone);
      t_clone->copy_state(tgmember);
    }
    tgleader.clone_leader->copy_state(tgleader.clone_leader_state);
  }

  self->clone_completion = nullptr;
}

static void remap_shared_mmap(AutoRemoteSyscalls& remote, EmuFs& dest_emu_fs,
                              const AddressSpace::Mapping& m_in_mem) {
  AddressSpace::Mapping m = m_in_mem;

  LOG(debug) << "    remapping shared region at " << m.map.start() << "-"
             << m.map.end();
  remote.infallible_syscall(syscall_number_for_munmap(remote.arch()),
                            m.map.start(), m.map.size());

  auto emufile = dest_emu_fs.at(m.recorded_map);
  // TODO: this duplicates some code in replay_syscall.cc, but
  // it's somewhat nontrivial to factor that code out.
  int remote_fd;
  {
    string path = emufile->proc_path();
    AutoRestoreMem child_path(remote, path.c_str());
    // Always open the emufs file O_RDWR, even if the current mapping prot
    // is read-only. We might mprotect it to read-write later.
    // skip leading '/' since we want the path to be relative to the root fd
    remote_fd = remote.infallible_syscall(
        syscall_number_for_openat(remote.arch()), RR_RESERVED_ROOT_DIR_FD,
        child_path.get() + 1, O_RDWR);
    if (0 > remote_fd) {
      FATAL() << "Couldn't open " << path << " in tracee";
    }
  }
  struct stat real_file = remote.task()->stat_fd(remote_fd);
  string real_file_name = remote.task()->file_name_of_fd(remote_fd);
  // XXX this condition is x86/x64-specific, I imagine.
  remote.infallible_mmap_syscall(m.map.start(), m.map.size(), m.map.prot(),
                                 // The remapped segment *must* be
                                 // remapped at the same address,
                                 // or else many things will go
                                 // haywire.
                                 (m.map.flags() & ~MAP_ANONYMOUS) | MAP_FIXED,
                                 remote_fd,
                                 m.map.file_offset_bytes() / page_size());

  // We update the AddressSpace mapping too, since that tracks the real file
  // name and we need to update that.
  remote.task()->vm()->map(m.map.start(), m.map.size(), m.map.prot(),
                           m.map.flags(), m.map.file_offset_bytes(),
                           real_file_name, real_file.st_dev, real_file.st_ino,
                           &m.recorded_map);

  remote.infallible_syscall(syscall_number_for_close(remote.arch()), remote_fd);
}

void Session::copy_state_to(Session& dest, EmuFs& dest_emu_fs) {
  assert_fully_initialized();
  assert(!dest.clone_completion);

  auto completion = unique_ptr<CloneCompletion>(new CloneCompletion());

  for (auto vm : vm_map) {
    // Pick an arbitrary task to be group leader. The actual group leader
    // might have died already.
    Task* group_leader = *vm.second->task_set().begin();
    LOG(debug) << "  forking tg " << group_leader->tgid()
               << " (real: " << group_leader->real_tgid() << ")";

    completion->task_groups.push_back(CloneCompletion::TaskGroup());
    auto& group = completion->task_groups.back();

    group.clone_leader = group_leader->os_fork_into(&dest);
    dest.on_create(group.clone_leader);
    LOG(debug) << "  forked new group leader " << group.clone_leader->tid;

    {
      AutoRemoteSyscalls remote(group.clone_leader);
      for (auto m : group.clone_leader->vm()->maps()) {
        if (dest_emu_fs.has_file_for(m.recorded_map)) {
          remap_shared_mmap(remote, dest_emu_fs, m);
        }
      }

      for (auto t : group_leader->task_group()->task_set()) {
        if (group_leader == t) {
          continue;
        }
        LOG(debug) << "    cloning " << t->rec_tid;

        group.member_states.push_back(t->capture_state());
      }
    }

    group.clone_leader_state = group_leader->capture_state();
    // Close perfcounters for now. They will be automatically reopened
    // when we next run this task (if ever). This reduces the numer of
    // file descriptors we need to have open.
    group.clone_leader->hpc.stop();
  }
  dest.clone_completion = move(completion);

  assert(dest.vms().size() > 0);
}
