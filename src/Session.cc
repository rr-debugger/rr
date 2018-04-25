/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Session.h"

#include <asm/ptrace.h>
#include <linux/limits.h>
#include <linux/unistd.h>
#include <sys/prctl.h>
#include <syscall.h>

#include <algorithm>
#include <limits>

#include "rr/rr.h"

#include "AutoRemoteSyscalls.h"
#include "EmuFs.h"
#include "Flags.h"
#include "Task.h"
#include "ThreadGroup.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

struct Session::CloneCompletion {
  struct AddressSpaceClone {
    Task* clone_leader;
    Task::CapturedState clone_leader_state;
    vector<Task::CapturedState> member_states;
    vector<pair<remote_ptr<void>, vector<uint8_t>>> captured_memory;
  };
  vector<AddressSpaceClone> address_spaces;
};

Session::Session()
    : tracee_socket(shared_ptr<ScopedFd>(new ScopedFd())),
      tracee_socket_fd_number(0),
      next_task_serial_(1),
      syscall_seccomp_ordering_(PTRACE_SYSCALL_BEFORE_SECCOMP_UNKNOWN),
      done_initial_exec_(false),
      visible_execution_(true),
      has_cpuid_faulting_(!Flags::get().disable_cpuid_faulting &&
                          cpuid_faulting_works()) {
  LOG(debug) << "Session " << this << " created";
}

Session::~Session() {
  kill_all_tasks();
  LOG(debug) << "Session " << this << " destroyed";

  for (auto tg : thread_group_map) {
    tg.second->forget_session();
  }
}

Session::Session(const Session& other) {
  statistics_ = other.statistics_;
  next_task_serial_ = other.next_task_serial_;
  done_initial_exec_ = other.done_initial_exec_;
  visible_execution_ = other.visible_execution_;
  has_cpuid_faulting_ = other.has_cpuid_faulting_;
  tracee_socket = other.tracee_socket;
  tracee_socket_fd_number = other.tracee_socket_fd_number;
}

void Session::on_create(ThreadGroup* tg) { thread_group_map[tg->tguid()] = tg; }
void Session::on_destroy(ThreadGroup* tg) {
  thread_group_map.erase(tg->tguid());
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
      new ThreadGroup(this, nullptr, t->rec_tid, t->tid,
                      t->tid, t->tuid().serial()));
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
                       t->tid, t->own_namespace_tid(), t->tuid().serial()));
  }
  ThreadGroup* parent =
      tg->parent() ? find_thread_group(tg->parent()->tguid()) : nullptr;
  return ThreadGroup::shr_ptr(
      new ThreadGroup(this, parent, tg->tgid, t->tid,
                      t->own_namespace_tid(), tg->tguid().serial()));
}

Task* Session::new_task(pid_t tid, pid_t rec_tid, uint32_t serial,
                        SupportedArch a) {
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
  auto it = thread_group_map.find(tguid);
  if (thread_group_map.end() == it) {
    return nullptr;
  }
  return it->second;
}

ThreadGroup* Session::find_thread_group(pid_t pid) const {
  finish_initializing();
  for (auto& tg : thread_group_map) {
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
  for (auto& v : task_map) {
    Task* t = v.second;

    if (!t->is_stopped) {
      // During recording we might be aborting the recording, in which case
      // one or more tasks might not be stopped. We haven't got any really
      // good options here so we'll just skip detaching and try killing
      // it with SIGKILL below. rr will usually exit immediately after this
      // so the likelihood that we'll leak a zombie task isn't too bad.
      continue;
    }

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
    // get around to SIGKILLing it. So we move its ip() to an address
    // which will cause it to do an exit() syscall if it runs at all.
    // We used to set this to an invalid address, but that causes a SIGSEGV
    // to be raised which can cause core dumps after we detach from ptrace.
    // Making the process undumpable with PR_SET_DUMPABLE turned out not to
    // be practical because that has a side effect of triggering various
    // security measures blocking inspection of the process (PTRACE_ATTACH,
    // access to /proc/<pid>/fd).
    // Disabling dumps via setrlimit(RLIMIT_CORE, 0) doesn't stop dumps
    // if /proc/sys/kernel/core_pattern is set to pipe the core to a process
    // (e.g. to systemd-coredump).
    // We also tried setting ip() to an address that does an infinite loop,
    // but that leaves a runaway process if something happens to kill rr
    // after detaching but before we get a chance to SIGKILL the tracee.
    Registers r = t->regs();
    r.set_ip(t->vm()->privileged_traced_syscall_ip());
    r.set_syscallno(syscall_number_for_exit(r.arch()));
    r.set_arg1(0);
    t->set_regs(r);
    t->flush_regs();
    long result;
    do {
      // We have observed this failing with an ESRCH when the thread clearly
      // still exists and is ptraced. Retrying the PTRACE_DETACH seems to
      // work around it.
      result = t->fallible_ptrace(PTRACE_DETACH, nullptr, nullptr);
      ASSERT(t, result >= 0 || errno == ESRCH);
      // But we it might get ESRCH because it really doesn't exist.
      if (errno == ESRCH && is_zombie_process(t->tid)) {
        break;
      }
    } while (result < 0);
  }

  while (!task_map.empty()) {
    Task* t = task_map.rbegin()->second;
    if (!t->unstable) {
      /**
       * Destroy the OS task backing this by sending it SIGKILL and
       * ensuring it was delivered.  After |kill()|, the only
       * meaningful thing that can be done with this task is to
       * delete it.
       */
      LOG(debug) << "sending SIGKILL to " << t->tid << " ...";
      // If we haven't already done a stable exit via syscall,
      // kill the task and note that the entire thread group is unstable.
      // The task may already have exited due to the preparation above,
      // so we might accidentally shoot down the wrong task :-(, but we
      // have to do this because the task might be in a state where it's not
      // going to run and exit by itself.
      // Linux doesn't seem to give us a reliable way to detach and kill
      // the tracee without races.
      syscall(SYS_tgkill, t->real_tgid(), t->tid, SIGKILL);
      t->thread_group()->destabilize();
    }

    t->destroy();
  }
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
  spawned_task_error_fd_ = fds[0];
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
  break_status.task = t;

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
        LOG(debug) << "hit debugger breakpoint at ip " << t->ip();
        // SW breakpoint: $ip is just past the
        // breakpoint instruction.  Move $ip back
        // right before it.
        t->move_ip_before_breakpoint();
        break_status.breakpoint_hit = true;
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
  for (auto& tgleader : clone_completion->address_spaces) {
    {
      AutoRemoteSyscalls remote(tgleader.clone_leader);
      for (const auto& m : tgleader.clone_leader->vm()->maps()) {
        // Creating this mapping was delayed in capture_state for performance
        if (m.flags & AddressSpace::Mapping::IS_SYSCALLBUF) {
          self->recreate_shared_mmap(remote, m);
        }
      }
      for (auto& mem : tgleader.captured_memory) {
        tgleader.clone_leader->write_bytes_helper(mem.first, mem.second.size(),
                                                  mem.second.data());
      }
      for (auto& tgmember : tgleader.member_states) {
        Task* t_clone = Task::os_clone_into(tgmember, remote);
        self->on_create(t_clone);
        t_clone->copy_state(tgmember);
      }
    }
    tgleader.clone_leader->copy_state(tgleader.clone_leader_state);
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
  int remote_fd;
  {
    string path = emu_file->proc_path();
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
  remote.task()->vm()->map(
      remote.task(), m.map.start(), m.map.size(), m.map.prot(), m.map.flags(),
      m.map.file_offset_bytes(), real_file_name, real_file.st_dev,
      real_file.st_ino, nullptr, &m.recorded_map, emu_file);

  remote.infallible_syscall(syscall_number_for_close(remote.arch()), remote_fd);
}

/*static*/ const char* Session::rr_mapping_prefix() { return "/rr-shared-"; }

KernelMapping Session::create_shared_mmap(
    AutoRemoteSyscalls& remote, size_t size, remote_ptr<void> map_hint,
    const char* name, int tracee_prot, int tracee_flags,
    MonitoredSharedMemory::shr_ptr&& monitored) {
  static int nonce = 0;
  // Create the segment we'll share with the tracee.
  char path[PATH_MAX];
  snprintf(path, sizeof(path) - 1, "%s%s%s-%d-%d", tmp_dir(),
           rr_mapping_prefix(), name, remote.task()->real_tgid(), nonce++);

  // Let the child create the shmem block and then send the fd back to us.
  // This lets us avoid having to make the file world-writeable so that
  // the child can read it when it's in a different user namespace (which
  // would be a security hole, letting other users abuse rr users).
  int child_shmem_fd;
  {
    AutoRestoreMem child_path(remote, path);
    // skip leading '/' since we want the path to be relative to the root fd
    child_shmem_fd = remote.infallible_syscall(
        syscall_number_for_openat(remote.arch()), RR_RESERVED_ROOT_DIR_FD,
        child_path.get() + 1, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  }

  /* Remove the fs name so that we don't have to worry about
   * cleaning up this segment in error conditions. */
  unlink(path);

  ScopedFd shmem_fd = remote.retrieve_fd(child_shmem_fd);
  resize_shmem_segment(shmem_fd, size);
  LOG(debug) << "created shmem segment " << path;

  // Map the segment in ours and the tracee's address spaces.
  void* map_addr;
  int flags = MAP_SHARED;
  if ((void*)-1 == (map_addr = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                                    flags, shmem_fd, 0))) {
    FATAL() << "Failed to mmap shmem region";
  }
  if (!map_hint.is_null()) {
    flags |= MAP_FIXED;
  }
  remote_ptr<void> child_map_addr = remote.infallible_mmap_syscall(
      map_hint, size, tracee_prot, flags, child_shmem_fd, 0);

  struct stat st;
  ASSERT(remote.task(), 0 == ::fstat(shmem_fd, &st));
  KernelMapping km = remote.task()->vm()->map(
      remote.task(), child_map_addr, size, tracee_prot, flags | tracee_flags, 0,
      path, st.st_dev, st.st_ino, nullptr, nullptr, nullptr, map_addr,
      std::move(monitored));

  shmem_fd.close();
  remote.infallible_syscall(syscall_number_for_close(remote.arch()),
                            child_shmem_fd);
  return km;
}

static char* extract_name(char* name_buffer, size_t buffer_size) {
  // Recover the name that was originally chosen by finding the part of the
  // name between rr_mapping_prefix and the -%d-%d at the end.
  char* path_start = strstr(name_buffer, Session::rr_mapping_prefix());
  DEBUG_ASSERT(path_start &&
               "Passed something to create_shared_mmap that"
               " wasn't a mapping shared between rr and the tracee?");
  size_t prefix_len = path_start - name_buffer;
  buffer_size -= prefix_len;
  name_buffer += prefix_len;

  char* name_end = name_buffer + strnlen(name_buffer, buffer_size);
  char* name_start = name_buffer + strlen(Session::rr_mapping_prefix());
  int hyphens_seen = 0;
  while (name_end > name_start) {
    --name_end;
    if (*name_end == '-') {
      ++hyphens_seen;
    } else if (*name_end == '/') {
      DEBUG_ASSERT(false &&
                   "Passed something to create_shared_mmap that"
                   " wasn't a mapping shared between rr and the tracee?");
    }
    if (hyphens_seen == 2) {
      break;
    }
  }
  DEBUG_ASSERT(hyphens_seen == 2);
  *name_end = '\0';
  return name_start;
}

const AddressSpace::Mapping& Session::recreate_shared_mmap(
    AutoRemoteSyscalls& remote, const AddressSpace::Mapping& m,
    PreserveContents preserve, MonitoredSharedMemory::shr_ptr&& monitored) {
  char name[PATH_MAX];
  strncpy(name, m.map.fsname().c_str(), sizeof(name));
  uint32_t flags = m.flags;
  size_t size = m.map.size();
  void* preserved_data = preserve == PRESERVE_CONTENTS ? m.local_addr : nullptr;
  if (preserved_data) {
    remote.task()->vm()->detach_local_mapping(m.map.start());
  }
  remote_ptr<void> new_addr =
      create_shared_mmap(remote, m.map.size(), m.map.start(),
                         extract_name(name, sizeof(name)), m.map.prot(), 0,
                         std::move(monitored))
          .start();
  // m may be invalid now
  remote.task()->vm()->mapping_flags_of(new_addr) = flags;
  auto& new_map = remote.task()->vm()->mapping_of(new_addr);
  if (preserved_data) {
    memcpy(new_map.local_addr, preserved_data, size);
    munmap(preserved_data, size);
  }
  return new_map;
}

const AddressSpace::Mapping& Session::steal_mapping(
    AutoRemoteSyscalls& remote, const AddressSpace::Mapping& m,
    MonitoredSharedMemory::shr_ptr&& monitored) {
  // We will include the name of the full path of the original mapping in the
  // name of the shared mapping, replacing slashes by dashes.
  char name[PATH_MAX - 40];
  strncpy(name, m.map.fsname().c_str(), sizeof(name));
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
// tracee. Returns true on success
bool Session::make_private_shared(AutoRemoteSyscalls& remote,
                                  const AddressSpace::Mapping m) {
  if (!(m.map.flags() & MAP_PRIVATE)) {
    return false;
  }
  // Find a place to map the current segment to temporarily
  remote_ptr<void> start = m.map.start();
  size_t sz = m.map.size();
  remote_ptr<void> free_mem = remote.task()->vm()->find_free_memory(sz);
  remote.infallible_syscall(syscall_number_for_mremap(remote.arch()), start, sz,
                            sz, MREMAP_MAYMOVE | MREMAP_FIXED, free_mem);
  remote.task()->vm()->remap(remote.task(), start, sz, free_mem, sz);

  // AutoRemoteSyscalls may have gotten unlucky and picked the old stack
  // segment as it's scratch space, reevaluate that choice
  AutoRemoteSyscalls remote2(remote.task());

  const AddressSpace::Mapping& new_m = steal_mapping(remote2, m);

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
  return true;
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
    data_size = clone_leader->read_mem(
                    REMOTE_PTR_FIELD(syscallbuf_hdr, num_rec_bytes)) +
                sizeof(struct syscallbuf_hdr);
  }
  return clone_leader->read_mem(start, data_size);
}

void Session::copy_state_to(Session& dest, EmuFs& emu_fs, EmuFs& dest_emu_fs) {
  assert_fully_initialized();
  DEBUG_ASSERT(!dest.clone_completion);

  auto completion = unique_ptr<CloneCompletion>(new CloneCompletion());

  for (auto vm : vm_map) {
    // Pick an arbitrary task to be group leader. The actual group leader
    // might have died already.
    Task* group_leader = *vm.second->task_set().begin();
    LOG(debug) << "  forking tg " << group_leader->tgid()
               << " (real: " << group_leader->real_tgid() << ")";

    completion->address_spaces.push_back(CloneCompletion::AddressSpaceClone());
    auto& group = completion->address_spaces.back();

    group.clone_leader = group_leader->os_fork_into(&dest);
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

        group.member_states.push_back(t->capture_state());
      }
    }

    group.clone_leader_state = group_leader->capture_state();
  }
  dest.clone_completion = move(completion);

  DEBUG_ASSERT(dest.vms().size() > 0);
}

} // namespace rr
