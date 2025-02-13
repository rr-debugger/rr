/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Session.h"

#include <linux/limits.h>
#include <linux/unistd.h>
#include <syscall.h>
#include <sys/wait.h>

#include <algorithm>
#include <limits>

#include "rr/rr.h"

#include "AutoRemoteSyscalls.h"
#include "EmuFs.h"
#include "Flags.h"
#include "PerfCounters.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "Task.h"
#include "ThreadGroup.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"
#include "preload/preload_interface.h"

using namespace std;

namespace rr {

Session::Session()
    : tracee_socket(make_shared<ScopedFd>()),
      tracee_socket_receiver(make_shared<ScopedFd>()),
      tracee_socket_fd_number(0),
      next_task_serial_(1),
      rrcall_base_(RR_CALL_BASE),
      syscallbuf_fds_disabled_size_(SYSCALLBUF_FDS_DISABLED_SIZE),
      syscallbuf_hdr_size_(sizeof(syscallbuf_hdr)),
      syscall_seccomp_ordering_(PTRACE_SYSCALL_BEFORE_SECCOMP_UNKNOWN),
      ticks_semantics_(PerfCounters::default_ticks_semantics()),
      done_initial_exec_(false),
      visible_execution_(true),
      intel_pt_(false) {
  LOG(debug) << "Session " << this << " created";
}

Session::~Session() {
  kill_all_tasks();
  LOG(debug) << "Session " << this << " destroyed";

  for (auto tg : thread_group_map_) {
    tg.second->forget_session();
  }
}

Session::Session(const Session& other)
    : statistics_(other.statistics_),
      tracee_socket(other.tracee_socket),
      tracee_socket_receiver(other.tracee_socket_receiver),
      tracee_socket_fd_number(other.tracee_socket_fd_number),
      next_task_serial_(other.next_task_serial_),
      rrcall_base_(other.rrcall_base_),
      syscallbuf_fds_disabled_size_(other.syscallbuf_fds_disabled_size_),
      syscallbuf_hdr_size_(other.syscallbuf_hdr_size_),
      syscall_seccomp_ordering_(other.syscall_seccomp_ordering_),
      ticks_semantics_(other.ticks_semantics_),
      original_affinity_(other.original_affinity_),
      done_initial_exec_(other.done_initial_exec_),
      visible_execution_(other.visible_execution_),
      intel_pt_(other.intel_pt_) {}

void Session::on_create(ThreadGroup* tg) { thread_group_map_[tg->tguid()] = tg; }
void Session::on_destroy(ThreadGroup* tg) {
  thread_group_map_.erase(tg->tguid());
}

void Session::post_exec() {
  /* We just saw a successful exec(), so from now on we know
   * that the address space layout for the replay tasks will
   * (should!) be the same as for the recorded tasks.  So we can
   * start validating registers at events. */
  assert_fully_initialized();
  if (done_initial_exec_) {
    return;
  }
  done_initial_exec_ = true;
  DEBUG_ASSERT(tasks().size() == 1);
  Task* t = tasks().begin()->second;
  t->flush_inconsistent_state();
  spawned_task_error_fd_.close();
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

ThreadGroup::shr_ptr Session::create_initial_tg(Task* t) {
  ThreadGroup::shr_ptr tg(
      new ThreadGroup(this, nullptr, t->rec_tid, t->rec_tid,
                      t->tuid().serial()));
  tg->insert_task(t);
  return tg;
}

ThreadGroup::shr_ptr Session::clone(Task* t, ThreadGroup::shr_ptr tg) {
  assert_fully_initialized();
  // If tg already belongs to our session this is a fork to create a new
  // taskgroup, otherwise it's a session-clone of an existing taskgroup
  if (this == tg->session()) {
    return ThreadGroup::shr_ptr(
       new ThreadGroup(this, tg.get(), t->rec_tid,
                       t->own_namespace_tid(), t->tuid().serial()));
  }
  ThreadGroup* parent =
      tg->parent() ? find_thread_group(tg->parent()->tguid()) : nullptr;
  return ThreadGroup::shr_ptr(
      new ThreadGroup(this, parent, tg->tgid,
                      t->own_namespace_tid(), tg->tguid().serial()));
}

Task* Session::new_task(pid_t tid, pid_t rec_tid, uint32_t serial,
                        SupportedArch a, const std::string&) {
  return new Task(*this, tid, rec_tid, serial, a);
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
  Task* c = p->clone(Task::TRACEE_CLONE, flags, stack, tls, cleartid_addr,
                     new_tid, new_rec_tid, next_task_serial());
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

ThreadGroup* Session::find_thread_group(const ThreadGroupUid& tguid) const {
  finish_initializing();
  auto it = thread_group_map_.find(tguid);
  if (thread_group_map_.end() == it) {
    return nullptr;
  }
  return it->second;
}

ThreadGroup* Session::find_thread_group(pid_t pid) const {
  finish_initializing();
  for (auto& tg : thread_group_map_) {
    if (tg.first.tid() == pid) {
      return tg.second;
    }
  }
  return nullptr;
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
  LOG(debug) << "Killing all tasks ...";
  for (int pass = 0; pass <= 1; ++pass) {
    /* We delete tasks in two passes. First, we kill
     * every non-thread-group-leader, then we kill every group leader.
     * Linux expects threads group leaders to survive until the last
     * member of the thread group has exited, so we accommodate that.
     */
    for (auto& v : task_map) {
      Task* t = v.second;
      bool is_group_leader = t->tid == t->real_tgid();
      if (pass == 0 ? is_group_leader : !is_group_leader) {
        continue;
      }
      t->kill();
    }
  }
  while (!task_map.empty()) {
    Task* t = task_map.rbegin()->second;
    delete t;
  }
  assert(task_map.empty());
}

void Session::on_destroy(AddressSpace* vm) {
  DEBUG_ASSERT(vm->task_set().size() == 0);
  DEBUG_ASSERT(vm_map.count(vm->uid()) == 1);
  vm_map.erase(vm->uid());
}

void Session::on_destroy(Task* t) {
  DEBUG_ASSERT(task_map.count(t->rec_tid) == 1);
  task_map.erase(t->rec_tid);
}

void Session::on_create(Task* t) { task_map[t->rec_tid] = t; }

ScopedFd Session::create_spawn_task_error_pipe() {
  int fds[2];
  if (0 != pipe2(fds, O_CLOEXEC)) {
    FATAL();
  }
  spawned_task_error_fd_ = ScopedFd(fds[0]);
  return ScopedFd(fds[1]);
}

string Session::read_spawned_task_error() const {
  char buf[1024] = "";
  ssize_t len = read(spawned_task_error_fd_, buf, sizeof(buf));
  if (len <= 0) {
    return string();
  }
  buf[len] = 0;
  return string(buf, len);
}

BreakStatus Session::diagnose_debugger_trap(Task* t, RunCommand run_command) {
  assert_fully_initialized();
  BreakStatus break_status;
  break_status.task_context = TaskContext(t);

  int stop_sig = t->stop_sig();
  if (!stop_sig) {
    // This can happen if we were INCOMPLETE because we're close to
    // the ticks_target.
    return break_status;
  }

  if (SIGTRAP != stop_sig) {
    BreakpointType pending_bp = t->vm()->get_breakpoint_type_at_addr(t->ip());
    if (BKPT_USER == pending_bp) {
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
                 << t->get_siginfo();
      break_status.breakpoint_hit = true;
    } else if (stop_sig && stop_sig != PerfCounters::TIME_SLICE_SIGNAL) {
      break_status.signal =
          unique_ptr<siginfo_t>(new siginfo_t(t->get_siginfo()));
      LOG(debug) << "Got signal " << *break_status.signal << " (expected sig "
                 << stop_sig << ")";
      break_status.signal->si_signo = stop_sig;
    }
  } else {
    TrapReasons trap_reasons = t->compute_trap_reasons();

    // Conceal any internal singlestepping
    if (trap_reasons.singlestep && is_singlestep(run_command)) {
      LOG(debug) << "  finished debugger stepi";
      break_status.singlestep_complete = true;
    }

    if (trap_reasons.watchpoint) {
      check_for_watchpoint_changes(t, break_status);
    }

    if (trap_reasons.breakpoint) {
      BreakpointType retired_bp =
          t->vm()->get_breakpoint_type_for_retired_insn(t->ip());
      if (BKPT_USER == retired_bp) {
        // SW breakpoint: $ip is just past the
        // breakpoint instruction.  Move $ip back
        // right before it.
        t->move_ip_before_breakpoint();
        break_status.breakpoint_hit = true;
        LOG(debug) << "hit debugger breakpoint at ip " << t->ip();
      }
    }
  }

  return break_status;
}

void Session::check_for_watchpoint_changes(Task* t, BreakStatus& break_status) {
  assert_fully_initialized();
  break_status.watchpoints_hit = t->vm()->consume_watchpoint_changes();
}

void Session::assert_fully_initialized() const {
  DEBUG_ASSERT(!clone_completion && "Session not fully initialized");
}

void Session::finish_initializing() const {
  if (!clone_completion) {
    return;
  }

  Session* self = const_cast<Session*>(this);
  for (auto& asleader : clone_completion->address_spaces) {
    {
      AutoRemoteSyscalls remote(asleader.clone_leader);
      for (const auto& m : asleader.clone_leader->vm()->maps()) {
        // Creating this mapping was delayed in capture_state for performance
        if (m.flags & AddressSpace::Mapping::IS_SYSCALLBUF) {
          self->recreate_shared_mmap(remote, m);
        }
      }
      for (auto& mem : asleader.captured_memory) {
        asleader.clone_leader->write_bytes_helper(mem.first, mem.second.size(),
                                                  mem.second.data());
      }
      for (auto& asmember : asleader.member_states) {
        auto it = thread_group_map_.find(asmember.tguid);
        ThreadGroup::shr_ptr tg(it == thread_group_map_.end() ? nullptr :
          it->second->shared_from_this());
        if (!tg) {
          tg = std::make_shared<ThreadGroup>
            (self, nullptr, asmember.tguid.tid(), asmember.tguid.tid(), asmember.tguid.serial());
        }
        Task* t_clone = Task::os_clone_into(
            asmember, remote, clone_completion->cloned_fd_tables, tg);
        self->on_create(t_clone);
        t_clone->copy_state(asmember);
      }
    }
    asleader.clone_leader->copy_state(asleader.clone_leader_state);
  }

  self->clone_completion = nullptr;
}

static void remap_shared_mmap(AutoRemoteSyscalls& remote, EmuFs& emu_fs,
                              EmuFs& dest_emu_fs,
                              const AddressSpace::Mapping& m_in_mem) {
  AddressSpace::Mapping m = m_in_mem;

  LOG(debug) << "    remapping shared region at " << m.map.start() << "-"
             << m.map.end();
  remote.infallible_syscall(syscall_number_for_munmap(remote.arch()),
                            m.map.start(), m.map.size());

  EmuFile::shr_ptr emu_file;
  if (dest_emu_fs.has_file_for(m.recorded_map)) {
    emu_file = dest_emu_fs.at(m.recorded_map);
  } else {
    emu_file = dest_emu_fs.clone_file(emu_fs.at(m.recorded_map));
  }

  // TODO: this duplicates some code in replay_syscall.cc, but
  // it's somewhat nontrivial to factor that code out.
  int remote_fd = remote.infallible_send_fd_if_alive(emu_file->fd());
  if (remote_fd < 0) {
    if (remote.task()->vm()->task_set().size() > remote.task()->thread_group()->task_set().size()) {
      // XXX not sure how to handle the case where the tracee died after
      // we unmapped the area
      FATAL() << "Unexpected task death leaving this address space in a bad state";
    }
    return;
  }
  struct stat real_file = remote.task()->stat_fd(remote_fd);
  string real_file_name = remote.task()->file_name_of_fd(remote_fd);
  // XXX this condition is x86/x64-specific, I imagine.
  // The remapped segment *must* be remapped at the same address,
  // or else many things will go haywire.
  auto ret = remote.infallible_mmap_syscall_if_alive(m.map.start(), m.map.size(), m.map.prot(),
                                                     (m.map.flags() & ~MAP_ANONYMOUS) | MAP_FIXED,
                                                     remote_fd,
                                                     m.map.file_offset_bytes());
  if (!ret) {
    if (remote.task()->vm()->task_set().size() > remote.task()->thread_group()->task_set().size()) {
      // XXX not sure how to handle the case where the tracee died after
      // we unmapped the area
      FATAL() << "Unexpected task death leaving this address space in a bad state";
    }
    return;
  }

  // We update the AddressSpace mapping too, since that tracks the real file
  // name and we need to update that.
  remote.task()->vm()->map(
      remote.task(), m.map.start(), m.map.size(), m.map.prot(), m.map.flags(),
      m.map.file_offset_bytes(), real_file_name, real_file.st_dev,
      real_file.st_ino, nullptr, &m.recorded_map, emu_file);

  remote.infallible_close_syscall_if_alive(remote_fd);
}

/*static*/ const char* Session::rr_mapping_prefix() { return "/rr-shared-"; }

KernelMapping Session::create_shared_mmap(
    AutoRemoteSyscalls& remote, size_t size, remote_ptr<void> required_child_addr,
    const char* name, int tracee_prot, int tracee_flags,
    MonitoredSharedMemory::shr_ptr monitored) {
  Task* t = remote.task();
  static int nonce = 0;
  // Create the segment we'll share with the tracee.
  char path[PATH_MAX];
  snprintf(path, sizeof(path) - 1, "%s%s%s-%d-%d", tmp_dir(),
           rr_mapping_prefix(), name, t->real_tgid(), nonce++);

  ScopedFd shmem_fd(path, O_CREAT | O_EXCL | O_RDWR);
  ASSERT(t, shmem_fd.is_open());
  /* Remove the fs name so that we don't have to worry about
   * cleaning up this segment in error conditions. */
  unlink(path);

  void* map_addr = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, shmem_fd, 0);
  if (map_addr == MAP_FAILED) {
    FATAL() << "Failed to mmap shmem region";
  }
  resize_shmem_segment(shmem_fd, size);

  remote_ptr<void> child_map_addr = required_child_addr;
  if (child_map_addr.is_null()) {
    if (t->session().is_recording() &&
        static_cast<RecordTask*>(t)->enable_chaos_memory_allocations()) {
      child_map_addr = t->vm()->chaos_mode_find_free_memory(static_cast<RecordTask*>(t),
          size, nullptr);
    } else {
      child_map_addr = t->vm()->find_free_memory(t, size, RR_PAGE_ADDR,
          AddressSpace::FindFreeMemoryPolicy::USE_LAST_FREE_HINT);
      if (!child_map_addr) {
        FATAL() << "Can't find free memory for shared mmap";
      }
    }
  }

  struct stat st;
  ASSERT(t, 0 == ::fstat(shmem_fd, &st));
  int flags = MAP_SHARED;
  if (!required_child_addr.is_null()) {
    flags |= MAP_FIXED;
  }

  int child_shmem_fd = remote.infallible_send_fd_if_alive(shmem_fd);
  if (child_shmem_fd < 0) {
    return KernelMapping();
  }
  LOG(debug) << "created shmem segment " << path;

  // Map the segment in ours and the tracee's address spaces.
  remote_ptr<void> addr = remote.infallible_mmap_syscall_if_alive(
      child_map_addr, size, tracee_prot, flags | MAP_FIXED, child_shmem_fd, 0);
  if (!addr) {
    // tracee unexpectedly died.
    // We leak the fd; cleaning it up is probably impossible/unnecessary.
    return KernelMapping();
  }

  // Note the mapping after we successfully created it in the child.
  // If the child mapping fails for some reason (e.g. SIGKILL) we still
  // want our cache to be correct (and not contain the mapping).
  KernelMapping km = t->vm()->map(
      t, child_map_addr, size, tracee_prot, flags | tracee_flags, 0,
      path, st.st_dev, st.st_ino, nullptr, nullptr, nullptr, map_addr,
      std::move(monitored));

  remote.infallible_close_syscall_if_alive(child_shmem_fd);
  return km;
}

const AddressSpace::Mapping Session::recreate_shared_mmap(
    AutoRemoteSyscalls& remote, const AddressSpace::Mapping& m,
    PreserveContents preserve, MonitoredSharedMemory::shr_ptr monitored) {
  char name[PATH_MAX];
  strncpy(name, m.map.fsname().c_str(), sizeof(name) - 1);
  name[sizeof(name) - 1] = 0;
  uint32_t flags = m.flags;
  size_t size = m.map.size();
  void* preserved_data = preserve == PRESERVE_CONTENTS ? m.local_addr : nullptr;
  void* remote_task_local_mapping = nullptr;

  {
    // Note that Mapping `m` may correspond to a Mapping from a different Task
    // than the `maybe_detach_mapping`. See replay_syscall.cc prepare_clone()
    // for an example.
    auto remote_task_mapping = remote.task()->vm()->mapping_of(m.map.start());

    // Sanity check
    ASSERT(remote.task(), size == remote_task_mapping.map.size());
    ASSERT(remote.task(), m.map.start() == remote_task_mapping.map.start());

    remote_task_local_mapping =
        remote.task()->vm()->detach_local_mapping(m.map.start());
  }

  remote_ptr<void> new_addr =
      create_shared_mmap(remote, m.map.size(), m.map.start(),
                         extract_name(name, sizeof(name)), m.map.prot(), 0,
                         std::move(monitored))
          .start();
  AddressSpace::Mapping new_map;
  if (new_addr) {
    // m may be invalid now
    remote.task()->vm()->mapping_flags_of(new_addr) = flags;
    new_map = remote.task()->vm()->mapping_of(new_addr);
    if (preserved_data) {
      memcpy(new_map.local_addr, preserved_data, size);
    }
  }
  if (remote_task_local_mapping) {
    munmap(remote_task_local_mapping, size);
  }
  return new_map;
}

AddressSpace::Mapping Session::steal_mapping(
    AutoRemoteSyscalls& remote, const AddressSpace::Mapping& m,
    MonitoredSharedMemory::shr_ptr monitored) {
  // We will include the name of the full path of the original mapping in the
  // name of the shared mapping, replacing slashes by dashes.
  char name[PATH_MAX - 40];
  strncpy(name, m.map.fsname().c_str(), sizeof(name)-1);
  name[sizeof(name) - 1] = '\0';
  for (char* ptr = name; *ptr != '\0'; ++ptr) {
    if (*ptr == '/') {
      *ptr = '-';
    }
  }

  // Now create the new mapping in its place
  remote_ptr<void> start = m.map.start();
  size_t sz = m.map.size();
  const AddressSpace::Mapping& new_m = remote.task()->vm()->mapping_of(
      create_shared_mmap(remote, sz, start, name, m.map.prot(),
                         m.map.flags() & (MAP_GROWSDOWN | MAP_STACK),
                         std::move(monitored))
          .start());
  return new_m;
}

// Replace a MAP_PRIVATE segment by one that is shared between rr and the
// tracee.
void Session::make_private_shared(AutoRemoteSyscalls& remote,
                                  const AddressSpace::Mapping m) {
  if (!(m.map.flags() & MAP_PRIVATE)) {
    return;
  }
  // Find a place to map the current segment to temporarily
  remote_ptr<void> start = m.map.start();
  size_t sz = m.map.size();
  remote_ptr<void> free_mem = remote.task()->vm()->find_free_memory(remote.task(), sz);
  remote.infallible_syscall(syscall_number_for_mremap(remote.arch()), start, sz,
                            sz, MREMAP_MAYMOVE | MREMAP_FIXED, free_mem);
  remote.task()->vm()->remap(remote.task(), start, sz, free_mem, sz,
                             MREMAP_MAYMOVE | MREMAP_FIXED);

  // AutoRemoteSyscalls may have gotten unlucky and picked the old stack
  // segment as it's scratch space, reevaluate that choice
  AutoRemoteSyscalls remote2(remote.task());

  AddressSpace::Mapping new_m = steal_mapping(remote2, m);

  if (!new_m.local_addr) {
    return;
  }
  // And copy over the contents. Since we can't just call memcpy in the
  // inferior, just copy directly from the remote private into the local
  // reference of the shared mapping. We use the fallible read method to
  // handle the case where the mapping is larger than the backing file, which
  // would otherwise cause a short read.
  remote2.task()->read_bytes_fallible(free_mem, sz, new_m.local_addr);

  // Finally unmap the original segment
  remote2.infallible_syscall(syscall_number_for_munmap(remote.arch()), free_mem,
                             sz);
  remote.task()->vm()->unmap(remote.task(), free_mem, sz);
}

static vector<uint8_t> capture_syscallbuf(const AddressSpace::Mapping& m,
                                          Task* clone_leader) {
  remote_ptr<uint8_t> start = m.map.start().cast<uint8_t>();
  auto syscallbuf_hdr = start.cast<struct syscallbuf_hdr>();
  size_t data_size;
  if (clone_leader->read_mem(REMOTE_PTR_FIELD(syscallbuf_hdr, locked))) {
    // There may be an incomplete syscall record after num_rec_bytes that
    // we need to capture here. We don't know how big that record is,
    // so just record the entire buffer. This should not be common.
    data_size = m.map.size();
  } else {
    data_size = clone_leader->read_mem(REMOTE_PTR_FIELD(syscallbuf_hdr, num_rec_bytes)) +
        clone_leader->session().syscallbuf_hdr_size();
  }
  return clone_leader->read_mem(start, data_size);
}

static FdTable::shr_ptr& get_or_clone_fd_table(
    Task::ClonedFdTables& existing_clones, Task* task_to_clone) {
  auto original_fd_table = task_to_clone->fd_table();
  FdTable::shr_ptr& existing_clone =
      existing_clones[uintptr_t(original_fd_table.get())];
  if (!existing_clone) {
    existing_clone = original_fd_table->clone();
  }
  return existing_clone;
}

void Session::copy_state_to(Session& dest, EmuFs& emu_fs, EmuFs& dest_emu_fs) {
  assert_fully_initialized();
  DEBUG_ASSERT(!dest.clone_completion);

  auto completion = unique_ptr<CloneCompletion>(new CloneCompletion());
  auto& cloned_fd_tables = completion->cloned_fd_tables;

  for (auto vm : vm_map) {
    // Pick an arbitrary task to be group leader. The actual group leader
    // might have died already.
    Task* group_leader = *vm.second->task_set().begin();
    LOG(debug) << "  forking tg " << group_leader->tgid()
               << " (real: " << group_leader->real_tgid() << ")";

    completion->address_spaces.push_back(CloneCompletion::AddressSpaceClone());
    auto& group = completion->address_spaces.back();

    group.clone_leader = group_leader->os_fork_into(
        &dest, get_or_clone_fd_table(cloned_fd_tables, group_leader));
    dest.on_create(group.clone_leader);
    LOG(debug) << "  forked new group leader " << group.clone_leader->tid;

    {
      AutoRemoteSyscalls remote(group.clone_leader);
      vector<AddressSpace::Mapping> shared_maps_to_clone;
      for (const auto& m : group.clone_leader->vm()->maps()) {
        // Special case the syscallbuf as a performance optimization. The amount
        // of data we need to capture is usually significantly smaller than the
        // size of the mapping, so allocating the whole mapping here would be
        // wasteful.
        if (m.flags & AddressSpace::Mapping::IS_SYSCALLBUF) {
          group.captured_memory.push_back(make_pair(
              m.map.start(), capture_syscallbuf(m, group.clone_leader)));
        } else if (m.local_addr != nullptr) {
          ASSERT(group.clone_leader,
                 m.map.start() == AddressSpace::preload_thread_locals_start());
        } else if ((m.recorded_map.flags() & MAP_SHARED) &&
                   emu_fs.has_file_for(m.recorded_map)) {
          shared_maps_to_clone.push_back(m);
        }
      }
      // Do this in a separate loop to avoid iteration invalidation issues
      for (const auto& m : shared_maps_to_clone) {
        remap_shared_mmap(remote, emu_fs, dest_emu_fs, m);
      }

      for (auto t : vm.second->task_set()) {
        if (group_leader == t) {
          continue;
        }
        LOG(debug) << "    cloning " << t->rec_tid;

        get_or_clone_fd_table(cloned_fd_tables, t);
        group.member_states.push_back(t->capture_state());
      }
    }

    group.clone_leader_state = group_leader->capture_state();
  }
  dest.clone_completion = std::move(completion);

  DEBUG_ASSERT(dest.vms().size() > 0);
}

bool Session::has_cpuid_faulting() {
  return !Flags::get().disable_cpuid_faulting && cpuid_faulting_works();
}

int Session::cpu_binding() const {
  return const_cast<Session*>(this)->trace_stream()->bound_to_cpu();
}

// Returns true if we succeeded, false if we failed because the
// requested CPU does not exist/is not available.
static bool set_cpu_affinity(int cpu) {
  DEBUG_ASSERT(cpu >= 0);

  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(cpu, &mask);
  if (0 > sched_setaffinity(0, sizeof(mask), &mask)) {
    if (errno == EINVAL) {
      return false;
    }
    FATAL() << "Couldn't bind to CPU " << cpu;
  }
  return true;
}

void Session::do_bind_cpu() {
  if (intel_pt_) {
    PerfCounters::start_pt_copy_thread();
  }

  sched_getaffinity(0, sizeof(original_affinity_), &original_affinity_);

  int cpu_index = this->cpu_binding();
  if (cpu_index >= 0) {
    // Set CPU affinity now, after we've created any helper threads
    // (so they aren't affected), but before we create any
    // tracees (so they are all affected).
    // Note that we're binding rr itself to the same CPU as the
    // tracees, since this seems to help performance.
    if (!set_cpu_affinity(cpu_index)) {
      if (has_cpuid_faulting() && !is_recording()) {
        cpu_index = choose_cpu(BIND_CPU, cpu_lock);
        if (!set_cpu_affinity(cpu_index)) {
          FATAL() << "Can't bind to requested CPU " << cpu_index
                  << " even after we re-selected it";
        }
        LOG(warn) << "Bound to CPU " << cpu_index
                  << "instead of selected " << trace_stream()->bound_to_cpu()
                  << "because the latter is not available;\n"
                  << "Hoping tracee doesn't use LSL instruction!";
        trace_stream()->set_bound_cpu(cpu_index);
      } else {
        FATAL() << "Can't bind to requested CPU " << cpu_index
                << ", and CPUID faulting not available";
      }
    } else if (!is_recording()) {
      // Make sure to mark this CPU as in use in the cpu_lock.
      (void)choose_cpu((BindCPU)cpu_index, cpu_lock);
    }
  }
}

bool Session::mark_stdio() const {
  return visible_execution_ && Flags::get().mark_stdio;
}

} // namespace rr
