/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/perf_event.h>
#include <linux/shm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <syscall.h>

#include <array>
#include <initializer_list>
#include <map>
#include <memory>
#include <sstream>
#include <string>

#include "replay_syscall.h"

#include "preload/preload_interface.h"

#include "rr/rr.h"

#include "AutoRemoteSyscalls.h"
#include "EmuFs.h"
#include "MmappedFileMonitor.h"
#include "ProcFdDirMonitor.h"
#include "ProcMemMonitor.h"
#include "ProcStatMonitor.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "SeccompFilterRewriter.h"
#include "StdioMonitor.h"
#include "SysCpuMonitor.h"
#include "ThreadGroup.h"
#include "TraceStream.h"
#include "VirtualPerfCounterMonitor.h"
#include "core.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "kernel_supplement.h"
#include "log.h"
#include "util.h"

/* Uncomment this to check syscall names and numbers defined in syscalls.py
   against the definitions in unistd.h. This may cause the build to fail
   if unistd.h is slightly out of date, so it's not turned on by default. */
//#define CHECK_SYSCALL_NUMBERS

using namespace std;

namespace rr {

// XXX: x86-only currently.
#ifdef CHECK_SYSCALL_NUMBERS

// Hack because our 'break' syscall is called '_break'
#define SYS__break SYS_break

#include "CheckSyscallNumbers.generated"

#endif // CHECK_SYSCALL_NUMBERS

static void init_scratch_memory(ReplayTask* t, const KernelMapping& km,
                                const TraceReader::MappedData& data) {
  ASSERT(t, data.source == TraceReader::SOURCE_ZERO);

  t->scratch_ptr = km.start();
  t->scratch_size = km.size();
  size_t sz = t->scratch_size;
  // Make the scratch buffer read/write during replay so that
  // preload's sys_read can use it to buffer cloned data.
  ASSERT(t, (km.prot() & (PROT_READ | PROT_WRITE)) == (PROT_READ | PROT_WRITE));
  ASSERT(t,
         (km.flags() & (MAP_PRIVATE | MAP_ANONYMOUS)) ==
             (MAP_PRIVATE | MAP_ANONYMOUS));

  {
    AutoRemoteSyscalls remote(t);
    remote.infallible_mmap_syscall(t->scratch_ptr, sz, km.prot(),
                                   km.flags() | MAP_FIXED, -1, 0);
    t->vm()->map(t, t->scratch_ptr, sz, km.prot(), km.flags(), 0, string(),
                 KernelMapping::NO_DEVICE, KernelMapping::NO_INODE, nullptr,
                 &km);
  }
  t->setup_preload_thread_locals();
}

/**
 * If scratch data was incidentally recorded for the current desched'd
 * but write-only syscall, then do a no-op restore of that saved data
 * to keep the trace in sync.
 *
 * Syscalls like |write()| that may-block and are wrapped in the
 * preload library can be desched'd.  When this happens, we save the
 * syscall record's "extra data" as if it were normal scratch space,
 * since it's used that way in effect.  But syscalls like |write()|
 * that don't actually use scratch space don't ever try to restore
 * saved scratch memory during replay.  So, this helper can be used
 * for that class of syscalls.
 */
static void maybe_noop_restore_syscallbuf_scratch(ReplayTask* t) {
  if (t->is_in_untraced_syscall()) {
    // Untraced syscalls always have t's arch
    LOG(debug) << "  noop-restoring scratch for write-only desched'd "
               << syscall_name(t->regs().original_syscallno(), t->arch());
    t->set_data_from_trace();
  }
}

static TraceTaskEvent read_task_trace_event(ReplayTask* t,
                                            TraceTaskEvent::Type type) {
  TraceTaskEvent tte;
  FrameTime time;
  do {
    tte = t->trace_reader().read_task_event(&time);
    ASSERT(t, tte.type() != TraceTaskEvent::NONE)
        << "Unable to find TraceTaskEvent; "
           "trace is corrupt (did you kill -9 "
           "rr?)";
  } while (tte.type() != type || time < t->current_frame_time());
  ASSERT(t, time == t->current_frame_time());
  return tte;
}


template <typename Arch>
static bool syscall_shares_vm(Registers r)
{
  switch (r.original_syscallno()) {
    case Arch::clone:
      return (CLONE_VM & r.arg1());
    case Arch::vfork:
      return true;
    case Arch::fork:
      return false;
    default:
      FATAL() << "Unknown clone syscall";
      __builtin_unreachable();
  }
}

template <typename Arch> static void prepare_clone(ReplayTask* t) {
  const TraceFrame& trace_frame = t->current_trace_frame();

  // We're being called with the syscall entry event, so we can't inspect the result
  // of the syscall exit to see whether the clone succeeded (that event can happen
  // much later, even after the spawned task has run).
  if (trace_frame.event().Syscall().failed_during_preparation) {
    /* creation failed, nothing special to do */
    return;
  }

  Registers r = t->regs();
  int sys = r.original_syscallno();
  int flags = 0;
  if (Arch::clone == sys) {
    // BLOCKED clone flags:
    // If we allow CLONE_UNTRACED then the child would escape from rr control
    // and we can't allow that.
    // Block CLONE_CHILD_CLEARTID because we'll emulate that ourselves.
    // Block CLONE_VFORK for the reasons below.
    // Block CLONE_NEW* from replay, any effects it had were dealt with during
    // recording.
    // Block CLONE_THREAD/CLONE_FILES - during replay each task is its own
    // thread group/has its own fd table. We track what the membership was during
    // record, but it's hard (and unnecessary) to replicate this kernel state during
    // replay.
    // Block CLONE_PIDFD/CLONE_CHILD_SETTID/CLONE_PARENT_SETTID because we record these.
    //
    // ALLOWED clone flags:
    // We allow CLONE_VM because address space sharing must not be broken.
    // We allow CLONE_SETTLS because we must set %fs correctly if requested.
    //
    // IRRELEVANT clone flags:
    // CLONE_SIGHAND/CLONE_SYSVSEM/CLONE_FS/CLONE_IO are irrelevant because we don't set signal handlers
    // or use SYSV-semaphore objects during replay, or let it use the filesystem, or do I/O.
    //
    // CLONE_PARENT/CLONE_PTRACE ... they probably need work to work under rr.
    uintptr_t disallowed_clone_flags =
        CLONE_UNTRACED |
        CLONE_CHILD_CLEARTID |
        CLONE_VFORK |
        CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER |
        CLONE_NEWUTS | CLONE_NEWCGROUP |
        CLONE_THREAD | CLONE_FILES |
        CLONE_PIDFD | CLONE_CHILD_SETTID | CLONE_PARENT_SETTID;
    flags = r.arg1();
    r.set_arg1(flags & ~disallowed_clone_flags);
  } else if (Arch::vfork == sys) {
    // We can't perform a real vfork, because the kernel won't let the vfork
    // parent return from the syscall until the vfork child has execed or
    // exited, and it is an invariant of replay that tasks are not in the kernel
    // except when we need them to execute a specific syscall on rr's behalf.
    // So instead we do a regular fork but use the CLONE_VM flag to share
    // address spaces between the parent and child. That's just like a vfork
    // except the parent is immediately runnable. This is no problem for replay
    // since we follow the recorded schedule in which the vfork parent did not
    // run until the vfork child exited.
    sys = Arch::clone;
    flags = CLONE_VM;
    r.set_arg1(flags);
    r.set_arg2(0);
  }
  r.set_syscallno(sys);
  r.set_ip(r.ip().decrement_by_syscall_insn_length(r.arch()));
  t->set_regs(r);
  Registers entry_regs = r;

  // Run; we will be interrupted by PTRACE_EVENT_CLONE/FORK/VFORK.
  t->resume_execution(RESUME_CONT, RESUME_WAIT, RESUME_NO_TICKS);

  pid_t new_tid;
  while (!t->clone_syscall_is_complete(&new_tid, Arch::arch())) {
    // clone() calls sometimes fail with -EAGAIN due to load issues or
    // whatever. We need to retry the system call until it succeeds. Reset
    // state to try the syscall again.
    ASSERT(t, t->regs().syscall_result_signed() == -EAGAIN);
    t->set_regs(entry_regs);
    t->resume_execution(RESUME_CONT, RESUME_WAIT, RESUME_NO_TICKS);
  }

  // Get out of the syscall
  t->exit_syscall();

  ASSERT(t, !t->ptrace_event())
      << "Unexpected ptrace event while waiting for syscall exit; got "
      << ptrace_event_name(t->ptrace_event());

  r = t->regs();
  // Restore the saved flags, to hide the fact that we may have
  // masked out CLONE_UNTRACED/CLONE_CHILD_CLEARTID or changed from vfork to
  // clone.
  r.set_arg1(trace_frame.regs().arg1());
  r.set_arg2(trace_frame.regs().arg2());
  // Pretend we're still in the system call
  r.set_syscall_result(-ENOSYS);
  r.set_original_syscallno(trace_frame.regs().original_syscallno());
  t->set_regs(r);
  t->canonicalize_regs(trace_frame.event().Syscall().arch());

  // Dig the recorded tid out out of the trace. The tid value returned in
  // the recorded registers could be in a different pid namespace from rr's,
  // so we can't use it directly.
  TraceTaskEvent tte = read_task_trace_event(t, TraceTaskEvent::CLONE);
  ASSERT(t, tte.parent_tid() == t->rec_tid)
      << "Expected tid " << t->rec_tid << ", got " << tte.parent_tid();
  long rec_tid = tte.tid();

  CloneParameters params;
  if (Arch::clone == t->regs().original_syscallno()) {
    params = extract_clone_parameters(t);
  }
  ReplayTask* new_task = static_cast<ReplayTask*>(
      t->session().clone(t, clone_flags_to_task_flags(flags), params.stack,
                         params.tls, params.ctid, new_tid, rec_tid));

  if (Arch::clone == t->regs().original_syscallno()) {
    /* FIXME: what if registers are non-null and contain an
     * invalid address? */
    t->set_data_from_trace();

    if (Arch::clone_tls_type == Arch::UserDescPointer) {
      t->set_data_from_trace();
      new_task->set_data_from_trace();
    } else {
      DEBUG_ASSERT(Arch::clone_tls_type == Arch::PthreadStructurePointer);
    }
    new_task->set_data_from_trace();
    new_task->set_data_from_trace();
  }

  // Fix registers in new task
  Registers new_r = new_task->regs();
  new_r.set_original_syscallno(trace_frame.regs().original_syscallno());
  new_r.set_orig_arg1(trace_frame.regs().arg1());
  new_r.set_arg2(trace_frame.regs().arg2());
  new_task->set_regs(new_r);
  new_task->canonicalize_regs(new_task->arch());

  if (!syscall_shares_vm<Arch>(r)) {
    // It's hard to imagine a scenario in which it would
    // be useful to inherit breakpoints (along with their
    // refcounts) across a non-VM-sharing clone, but for
    // now we never want to do this.
    new_task->vm()->remove_all_breakpoints();
    new_task->vm()->remove_all_watchpoints();

    AutoRemoteSyscalls remote(new_task);
    for (const auto& m : t->vm()->maps()) {
      // Recreate any tracee-shared mappings
      if (m.local_addr &&
          !(m.flags & (AddressSpace::Mapping::IS_THREAD_LOCALS |
                       AddressSpace::Mapping::IS_SYSCALLBUF))) {
        Session::recreate_shared_mmap(remote, m, Session::PRESERVE_CONTENTS);
      }
    }
  }

  TraceReader::MappedData data;
  KernelMapping km = t->trace_reader().read_mapped_region(&data);
  init_scratch_memory(new_task, km, data);

  new_task->vm()->after_clone();
}

static void restore_mapped_region(ReplayTask* t, AutoRemoteSyscalls& remote,
                                  const KernelMapping& km,
                                  const TraceReader::MappedData& data) {
  ASSERT(t, !(km.flags() & MAP_SHARED))
      << "Shared mappings after exec not supported";

  string real_file_name;
  dev_t device = KernelMapping::NO_DEVICE;
  ino_t inode = KernelMapping::NO_INODE;
  int flags = km.flags();
  uint64_t offset_bytes = 0;
  switch (data.source) {
    case TraceReader::SOURCE_FILE: {
      struct stat real_file;
      offset_bytes = km.file_offset_bytes();
      // Private mapping, so O_RDONLY is always OK.
      remote.finish_direct_mmap(km.start(), km.size(), km.prot(),
                         km.flags(), data.file_name, O_RDONLY,
                         data.data_offset_bytes / page_size(), real_file,
                         real_file_name);
      device = real_file.st_dev;
      inode = real_file.st_ino;
      break;
    }
    case TraceReader::SOURCE_TRACE:
    case TraceReader::SOURCE_ZERO:
      flags |= MAP_ANONYMOUS;
      remote.infallible_mmap_syscall(km.start(), km.size(), km.prot(),
                                     (flags & ~MAP_GROWSDOWN) | MAP_FIXED, -1,
                                     0);
      // The data, if any, will be written back by
      // ReplayTask::apply_all_data_records_from_trace
      break;
    default:
      ASSERT(t, false) << "Unknown data source";
      break;
  }

  t->vm()->map(t, km.start(), km.size(), km.prot(), flags, offset_bytes,
               real_file_name, device, inode, nullptr, &km);
}

static void process_execve(ReplayTask* t, const TraceFrame& trace_frame,
                           ReplayTraceStep* step) {
  step->action = TSTEP_RETIRE;

  /* First, exec a stub program */
  pid_t new_tid = t->real_tgid();
  pid_t old_tid = t->tid;
  t->os_exec_stub(trace_frame.regs().arch());
  if (new_tid != old_tid) {
    t->set_real_tid_and_update_serial(new_tid);
  }

  vector<KernelMapping> kms;
  vector<TraceReader::MappedData> datas;

  TraceTaskEvent tte = read_task_trace_event(t, TraceTaskEvent::EXEC);

  // Find the text mapping of the main executable. This is complicated by the
  // fact that the kernel also loads the dynamic linker (if the main
  // executable specifies an interpreter).
  ssize_t exe_km_option1 = -1, exe_km_option2 = -1, rip_km = -1;
  while (true) {
    TraceReader::MappedData data;
    bool found;
    KernelMapping km = t->trace_reader().read_mapped_region(&data, &found);
    if (!found) {
      break;
    }
    if (km.start() == AddressSpace::rr_page_start() ||
        km.start() == AddressSpace::preload_thread_locals_start()) {
      // Skip rr-page mapping record, that gets mapped automatically
      continue;
    }

    if (tte.exe_base()) {
      // We recorded the executable's start address so we can just use that
      if (tte.exe_base() == km.start()) {
        exe_km_option1 = kms.size();
      }
    } else {
      // To disambiguate, we use the following criterion: The dynamic linker
      // (if it exists) is a different file (identified via fsname) that has
      // an executable segment that contains the ip. To compute this, we find
      // (up to) two kms that have different fsnames but do each have an
      // executable segment, as well as the km that contains the ip. This is
      // slightly complicated, but should handle the case where either file has
      // more than one exectuable segment.
      const string& file_name = km.fsname();
      if ((km.prot() & PROT_EXEC) && file_name.size() > 0 &&
          // Make sure to exclude [vdso] (and similar) and executable stacks.
          file_name[0] != '[') {
        if (exe_km_option1 == -1) {
          exe_km_option1 = kms.size();
        } else if (exe_km_option2 == -1 &&
                   kms[exe_km_option1].fsname() != file_name) {
          exe_km_option2 = kms.size();
        } else {
          ASSERT(t,
                 kms[exe_km_option1].fsname() == file_name ||
                     kms[exe_km_option2].fsname() == file_name);
        }
      }
      if (km.contains(trace_frame.regs().ip().to_data_ptr<void>())) {
        rip_km = kms.size();
      }
    }
    kms.push_back(km);
    datas.push_back(data);
  }

  ASSERT(t, exe_km_option1 >= 0) << "No executable mapping?";

  ssize_t exe_km = exe_km_option1;
  if (exe_km_option2 >= 0) {
    // Ok, we have two options. We choose the one that doesn't have the ip.
    if (kms[exe_km_option2].fsname() != kms[rip_km].fsname()) {
      ASSERT(t, kms[exe_km_option1].fsname() == kms[rip_km].fsname());
      exe_km = exe_km_option2;
    }
  }

  ASSERT(t, kms[0].is_stack()) << "Can't find stack";

  // The exe name we pass in here will be passed to gdb. Pass the backing file
  // name if there is one, otherwise pass the original file name (which means
  // we declined to copy it to the trace file during recording for whatever
  // reason).
  const string& exe_name = datas[exe_km].file_name.empty()
                               ? kms[exe_km].fsname()
                               : datas[exe_km].file_name;
  t->post_exec_syscall(exe_name);

  t->fd_table()->close_after_exec(
      t, t->current_trace_frame().event().Syscall().exec_fds_to_close);

  {
    // Tell AutoRemoteSyscalls that we don't need memory parameters. This will
    // stop it from having trouble if our current stack pointer (the value
    // from the replay) isn't in the [stack] mapping created for our stub.
    AutoRemoteSyscalls remote(t, AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS);

    // Now fix up the address space. First unmap all the mappings other than
    // our rr page.
    t->vm()->unmap_all_but_rr_page(remote);
    // We will have unmapped the stack memory that |remote| would have used for
    // memory parameters. Fortunately process_mapped_region below doesn't
    // need any memory parameters for its remote syscalls.

    // Process the [stack] mapping.
    restore_mapped_region(t, remote, kms[0], datas[0]);
  }

  const string& recorded_exe_name = kms[exe_km].fsname();

  {
    // Now that [stack] is mapped, reinitialize AutoRemoteSyscalls with
    // memory parameters enabled.
    AutoRemoteSyscalls remote(t);

    // Now map in all the mappings that we recorded from the real exec.
    for (ssize_t i = 1; i < ssize_t(kms.size()) - 1; ++i) {
      restore_mapped_region(t, remote, kms[i], datas[i]);
    }

    size_t index = recorded_exe_name.rfind('/');
    string name =
        string("rr:") +
        recorded_exe_name.substr(index == string::npos ? 0 : index + 1);
    AutoRestoreMem mem(remote, name.c_str());
    remote.infallible_syscall(syscall_number_for_prctl(t->arch()), PR_SET_NAME,
                              mem.get());
  }

  init_scratch_memory(t, kms.back(), datas.back());

  // Apply final data records --- fixing up the last page in each data segment
  // for zeroing applied by the kernel, and applying monkeypatches.
  t->apply_all_data_records_from_trace();

  // Now it's safe to save the auxv data
  t->vm()->save_auxv(t);

  // Notify outer rr if there is one. We're assuming here that our
  // rr is the same version as the outer rr, or at least is using
  // the same syscall numbers. The inner rr could be replaying
  // a trace with different rr syscall numbers.
  syscall(SYS_rrcall_reload_auxv, t->tid);
}

static void process_brk(ReplayTask* t) {
  TraceReader::MappedData data;
  KernelMapping km = t->trace_reader().read_mapped_region(&data);
  // Zero flags means it's an an unmap, or no change.
  if (km.flags()) {
    AutoRemoteSyscalls remote(t);
    ASSERT(t, data.source == TraceReader::SOURCE_ZERO);
    remote.infallible_mmap_syscall(km.start(), km.size(), km.prot(),
                                   MAP_ANONYMOUS | MAP_FIXED | km.flags(), -1,
                                   0);
    t->vm()->map(t, km.start(), km.size(), km.prot(),
                 MAP_ANONYMOUS | km.flags(), 0, "[heap]",
                 KernelMapping::NO_DEVICE, KernelMapping::NO_INODE, nullptr,
                 &km);
  } else if (km.size() > 0) {
    AutoRemoteSyscalls remote(t);
    remote.infallible_syscall(syscall_number_for_munmap(t->arch()), km.start(),
                              km.size());
    t->vm()->unmap(t, km.start(), km.size());
  }
}

static void finish_anonymous_mmap(ReplayTask* t, AutoRemoteSyscalls& remote,
                                  remote_ptr<void> rec_addr, size_t length,
                                  int prot, int flags) {
  string file_name;
  dev_t device = KernelMapping::NO_DEVICE;
  ino_t inode = KernelMapping::NO_INODE;
  TraceReader::MappedData data;
  KernelMapping recorded_km = t->trace_reader().read_mapped_region(&data);
  EmuFile::shr_ptr emu_file;
  if (!(flags & MAP_SHARED)) {
    remote.infallible_mmap_syscall(rec_addr, length, prot,
                                   // Tell the kernel to take |rec_addr|
                                   // seriously.
                                   (flags & ~MAP_GROWSDOWN) | MAP_FIXED, -1, 0);
  } else {
    ASSERT(remote.task(), data.source == TraceReader::SOURCE_ZERO);
    emu_file = t->session().emufs().get_or_create(recorded_km);
    struct stat real_file;
    // Emufs file, so open it read-write in case we need to write to it
    // through the task's memfd.
    remote.finish_direct_mmap(rec_addr, length, prot,
                       flags & ~MAP_ANONYMOUS, emu_file->proc_path(), O_RDWR, 0,
                       real_file, file_name);
    device = real_file.st_dev;
    inode = real_file.st_ino;
  }

  remote.task()->vm()->map(t, rec_addr, length, prot, flags, 0, file_name,
                           device, inode, nullptr, &recorded_km, emu_file);
}

static void write_mapped_data(ReplayTask* t,
                              remote_ptr<void> rec_addr,
                              size_t size,
                              TraceReader::MappedData& data) {
  switch (data.source) {
  case TraceReader::SOURCE_TRACE:
    t->set_data_from_trace();
    break;
  case TraceReader::SOURCE_FILE: {
    ScopedFd file(data.file_name.c_str(), O_RDONLY);
    ASSERT(t, file.is_open()) << "Can't open " << data.file_name;
    off_t offset = lseek(file, data.data_offset_bytes, SEEK_SET);
    ASSERT(t, offset == (off_t)data.data_offset_bytes)
      << "Couldn't seek to " << data.data_offset_bytes << ", got " << offset;
    vector<uint8_t> buf;
    buf.resize(page_size()*16);
    while (size > 0) {
      ssize_t ret = read(file, buf.data(), min(size, buf.size()));
      if (ret < 0) {
        FATAL() << "Can't read from trace file " << data.file_name;
      }
      if (ret == 0) {
        break;
      }
      t->write_bytes_helper(rec_addr, ret, buf.data());
      rec_addr += ret;
      size -= ret;
    }
    break;
  }
  case TraceReader::SOURCE_ZERO:
    break;
  default:
    FATAL() << "Unknown data source";
    break;
  }
}

static void finish_private_mmap(ReplayTask* t, AutoRemoteSyscalls& remote,
                                remote_ptr<void> rec_addr, size_t length,
                                int prot, int flags, off64_t offset_pages,
                                const KernelMapping& km,
                                TraceReader::MappedData& data) {
  LOG(debug) << "  finishing private mmap of " << km.fsname();

  remote.infallible_mmap_syscall(
      rec_addr, length, prot,
      // Tell the kernel to take |rec_addr| seriously.
      (flags & ~MAP_GROWSDOWN) | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

  // Update AddressSpace before loading data from the trace. This ensures our
  // kernel-bug-workarounds when writing to tracee memory see the up-to-date
  // virtual map.
  t->vm()->map(t, rec_addr, length, prot, flags | MAP_ANONYMOUS,
               page_size() * offset_pages, string(), KernelMapping::NO_DEVICE,
               KernelMapping::NO_INODE, nullptr, &km);

  /* Restore the map region we copied. */
  write_mapped_data(t, rec_addr, km.size(), data);
}

static void finish_shared_mmap(ReplayTask* t, AutoRemoteSyscalls& remote,
                               remote_ptr<void> rec_addr, size_t length,
                               int prot, int flags, const vector<TraceRemoteFd>& fds,
                               off64_t offset_pages,
                               const KernelMapping& km,
                               TraceReader::MappedData& data) {
  // Ensure there's a virtual file for the file that was mapped
  // during recording.
  auto emufile = t->session().emufs().get_or_create(km);
  // Re-use the direct_map() machinery to map the virtual file.
  //
  // NB: the tracee will map the procfs link to our fd; there's
  // no "real" name for the file anywhere, to ensure that when
  // we exit/crash the kernel will clean up for us.
  struct stat real_file;
  string real_file_name;
  // Emufs file, so open it read-write in case we want to write to it through
  // the task's mem fd.
  remote.finish_direct_mmap(rec_addr, km.size(), prot, flags,
                     emufile->proc_path(), O_RDWR, offset_pages, real_file,
                     real_file_name);
  // Write back the snapshot of the segment that we recorded.
  //
  // TODO: this is a poor man's shared segment synchronization.
  // For full generality, we also need to emulate direct file
  // modifications through write/splice/etc.
  //
  // Update AddressSpace before loading data from the trace. This ensures our
  // kernel-bug-workarounds when writing to tracee memory see the up-to-date
  // virtual map.
  uint64_t offset_bytes = page_size() * offset_pages;
  t->vm()->map(t, rec_addr, km.size(), prot, flags, offset_bytes,
               real_file_name, real_file.st_dev, real_file.st_ino, nullptr, &km,
               emufile);

  write_mapped_data(t, rec_addr, km.size(), data);

  LOG(debug) << "  restored " << length << " bytes at "
             << HEX(offset_bytes) << " to " << emufile->real_path() << " for "
             << emufile->emu_path();
  for (auto fd : fds) {
    auto rt = t->session().find_task(fd.tid);
    ASSERT(t, rt) << "Can't find task " << fd.tid;
    if (rt->fd_table()->is_monitoring(fd.fd)) {
      ASSERT(rt,
             rt->fd_table()->get_monitor(fd.fd)->type() ==
                 FileMonitor::Type::Mmapped);
      ((MmappedFileMonitor*)rt->fd_table()->get_monitor(fd.fd))->revive();
    } else {
      rt->fd_table()->add_monitor(rt, fd.fd, new MmappedFileMonitor(rt, emufile));
    }
  }
}

static void process_mmap(ReplayTask* t, const TraceFrame& trace_frame,
                         size_t length, int prot, int flags, int fd,
                         off64_t offset_pages, ReplayTraceStep* step) {
  step->action = TSTEP_RETIRE;

  {
    remote_ptr<void> addr = trace_frame.regs().syscall_result();
    // Hand off actual execution of the mapping to the appropriate helper.
    AutoRemoteSyscalls remote(t,
                              !(flags & MAP_SHARED) && (flags & MAP_ANONYMOUS)
                                  ? AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS
                                  : AutoRemoteSyscalls::ENABLE_MEMORY_PARAMS);
    if (flags & MAP_ANONYMOUS) {
      finish_anonymous_mmap(t, remote, trace_frame.regs().syscall_result(),
                            length, prot, flags);
    } else {
      TraceReader::MappedData data;
      vector<TraceRemoteFd> extra_fds;
      bool skip_monitoring_mapped_fd;
      KernelMapping km = t->trace_reader().read_mapped_region(&data, nullptr,
        TraceReader::VALIDATE, TraceReader::CURRENT_TIME_ONLY, &extra_fds,
        &skip_monitoring_mapped_fd);

      if (data.source == TraceReader::SOURCE_FILE &&
          data.file_size_bytes > data.data_offset_bytes) {
        struct stat real_file;
        string real_file_name;
        uint64_t map_bytes = min(ceil_page_size(data.file_size_bytes) - data.data_offset_bytes, length);
        remote.finish_direct_mmap(addr, map_bytes, prot, flags,
                           data.file_name, O_RDONLY,
                           data.data_offset_bytes / page_size(), real_file,
                           real_file_name);
        KernelMapping km_sub = km.subrange(km.start(), km.start() + ceil_page_size(map_bytes));
        t->vm()->map(t, km.start(), map_bytes, prot, flags,
                     page_size() * offset_pages, real_file_name,
                     real_file.st_dev, real_file.st_ino, nullptr, &km_sub);
        addr += map_bytes;
        length -= map_bytes;
        offset_pages += ceil_page_size(map_bytes) / page_size();
        data.source = TraceReader::SOURCE_ZERO;
        km = km.subrange(km_sub.end(), km.end());
      }
      if (length > 0) {
        if (MAP_SHARED & flags) {
          if (!skip_monitoring_mapped_fd) {
            extra_fds.push_back({ t->rec_tid, fd });
          }
          finish_shared_mmap(t, remote, addr, length, prot, flags, extra_fds,
                              offset_pages, km, data);
        } else {
          ASSERT(t, extra_fds.empty());
          finish_private_mmap(t, remote, addr, length, prot, flags,
                              offset_pages, km, data);
        }
      }
    }

    // This code is used to test the sharing functionality. It is in
    // general a bad idea to indiscriminately share mappings between the
    // tracer and the tracee. Instead, only mappings that have
    // sufficiently many memory access from the tracer to require
    // acceleration should be shared.
    if (!(MAP_SHARED & flags) && t->session().flags().share_private_mappings) {
      Session::make_private_shared(remote, t->vm()->mapping_of(addr));
    }

    // Finally, we finish by emulating the return value.
    remote.regs().set_syscall_result(trace_frame.regs().syscall_result());
  }
  // Monkeypatcher can emit data records that need to be applied now
  t->apply_all_data_records_from_trace();
  t->validate_regs();
}

static void process_mremap(ReplayTask* t, const TraceFrame& trace_frame,
                           ReplayTraceStep* step) {
  step->action = TSTEP_RETIRE;

  auto& trace_regs = trace_frame.regs();
  remote_ptr<void> old_addr = trace_frame.regs().orig_arg1();
  size_t old_size = ceil_page_size(trace_regs.arg2());
  remote_ptr<void> new_addr = trace_frame.regs().syscall_result();
  size_t new_size = ceil_page_size(trace_regs.arg3());

  // The recorded mremap call succeeded, so we know the original mapping can be
  // treated as a single mapping.
  t->vm()->ensure_replay_matches_single_recorded_mapping(t, MemoryRange(old_addr, old_size));

  TraceReader::MappedData data;
  t->trace_reader().read_mapped_region(&data);
  ASSERT(t, data.source == TraceReader::SOURCE_ZERO);
  // We don't need to do anything; this is the mapping record for the moved
  // data.

  // Try reading a mapping record for new data.
  bool found;
  t->trace_reader().read_mapped_region(&data, &found);

  {
    // We must emulate mremap because the kernel's choice for the remap
    // destination can vary (in particular, when we emulate exec it makes
    // different decisions).
    AutoRemoteSyscalls remote(t);
    if (new_addr == old_addr) {
      // Non-moving mremap. Don't pass MREMAP_FIXED or MREMAP_MAYMOVE
      // since that triggers EINVAL when the new map overlaps the old map.
      remote.infallible_syscall_ptr(trace_regs.original_syscallno(), new_addr,
                                    old_size, new_size, 0);
    } else {
      // Force the mremap to use the destination address from recording.
      // XXX could the new mapping overlap the old, with different start
      // addresses? Hopefully the kernel doesn't do that to us!!!
      remote.infallible_syscall_ptr(trace_regs.original_syscallno(), old_addr,
                                    old_size, new_size,
                                    MREMAP_MAYMOVE | MREMAP_FIXED, new_addr);
    }

    remote.regs().set_syscall_result(new_addr);
  }

  t->vm()->remap(t, old_addr, old_size, new_addr, new_size);

  AddressSpace::Mapping mapping = t->vm()->mapping_of(new_addr);
  auto f = mapping.emu_file;
  if (f) {
    f->ensure_size(mapping.map.file_offset_bytes() + new_size);
  } else if (new_size > old_size && mapping.map.fsname().size() > 0) {
    struct stat st;
    int ret = stat(mapping.map.fsname().c_str(), &st);
    if (ret != 0) {
      FATAL() << "Can't stat " << mapping.map.fsname();
    }
    if (ceil_page_size(st.st_size) <
        mapping.map.file_offset_bytes() + new_size) {
      // Replace mapping with anonymous mapping to cover full mapped region.
      // Don't just read the file data, since this could be a private mapping
      // with some data changed.
      vector<uint8_t> buf;
      buf.resize(old_size);
      t->read_bytes_helper(new_addr, buf.size(), buf.data());
      AutoRemoteSyscalls remote(t);
      // Shared non-EmuFs mappings must be of immutable files so it's OK to
      // just copy the file data into a private mapping here.
      int map_flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED;
      remote.infallible_mmap_syscall(new_addr, new_size, mapping.map.prot(),
                                     map_flags, -1, 0);
      t->vm()->unmap(t, new_addr, new_size);
      t->vm()->map(t, new_addr, new_size, mapping.map.prot(), map_flags,
                   mapping.map.file_offset_bytes(), string(),
                   KernelMapping::NO_DEVICE,
                   KernelMapping::NO_INODE, nullptr, &mapping.recorded_map);
      t->write_bytes_helper(new_addr, buf.size(), buf.data());
      mapping = t->vm()->mapping_of(new_addr);
    }
  }

  // SOURCE_FILE for mapped files should be handled automatically by the mremap
  // above.
  // (If we started storing partial files, we'd have to careful to ensure this
  // is still the case.)
  if (found &&
      (data.source != TraceReader::SOURCE_FILE || f ||
       mapping.map.fsname().empty())) {
    write_mapped_data(t, new_addr + old_size, new_size - old_size, data);
  }

  t->validate_regs();
}

void process_grow_map(ReplayTask* t) {
  AutoRemoteSyscalls remote(t);
  TraceReader::MappedData data;
  KernelMapping km = t->trace_reader().read_mapped_region(&data);
  ASSERT(t, km.size());
  restore_mapped_region(t, remote, km, data);
}

static void process_shmat(ReplayTask* t, const TraceFrame& trace_frame,
                          int shm_flags, ReplayTraceStep* step) {
  step->action = TSTEP_RETIRE;

  {
    AutoRemoteSyscalls remote(t);
    TraceReader::MappedData data;
    KernelMapping km = t->trace_reader().read_mapped_region(&data);
    int prot = shm_flags_to_mmap_prot(shm_flags);
    int flags = MAP_SHARED;
    finish_shared_mmap(t, remote, km.start(), km.size(), prot, flags,
                       vector<TraceRemoteFd>(), 0, km, data);
    t->vm()->set_shm_size(km.start(), km.size());

    // Finally, we finish by emulating the return value.
    // On x86-32 this is not the shm address...
    remote.regs().set_syscall_result(trace_frame.regs().syscall_result());
  }
  // on x86-32 we have an extra data record that we need to apply ---
  // the ipc syscall's klugy out-parameter.
  t->apply_all_data_records_from_trace();
  t->validate_regs();
}

static void process_shmdt(ReplayTask* t, const TraceFrame& trace_frame,
                          remote_ptr<void> addr, ReplayTraceStep* step) {
  step->action = TSTEP_RETIRE;

  {
    AutoRemoteSyscalls remote(t);
    size_t size = t->vm()->get_shm_size(addr);
    remote.infallible_syscall(syscall_number_for_munmap(t->arch()), addr, size);
    remote.regs().set_syscall_result(trace_frame.regs().syscall_result());
  }
  t->validate_regs();
}

static void process_init_buffers(ReplayTask* t, ReplayTraceStep* step) {
  step->action = TSTEP_RETIRE;

  /* Proceed to syscall exit so we can run our own syscalls. */
  remote_ptr<void> rec_child_map_addr =
      t->current_trace_frame().regs().syscall_result();

  /* We don't want the desched event fd during replay, because
   * we already know where they were.  (The perf_event fd is
   * emulated anyway.) */
  t->init_buffers(rec_child_map_addr);

  ASSERT(t, t->syscallbuf_child.cast<void>() == rec_child_map_addr)
      << "Should have mapped syscallbuf at " << rec_child_map_addr
      << ", but it's at " << t->syscallbuf_child;
  t->validate_regs();
}

static int non_negative_syscall(int sys) { return sys < 0 ? INT32_MAX : sys; }

template <typename Arch>
static void rep_after_enter_syscall_arch(ReplayTask* t) {
  switch (non_negative_syscall(t->regs().original_syscallno())) {
    case Arch::write:
    case Arch::writev: {
      int fd = (int)t->regs().arg1_signed();
      t->fd_table()->will_write(t, fd);
      break;
    }
    case Arch::clone:
    case Arch::vfork:
    case Arch::fork:
      // Create the new task now. It needs to exist before clone/fork/vfork
      // returns so that a ptracer can touch it during PTRACE_EVENT handling.
      prepare_clone<Arch>(t);
      break;

    case Arch::ptrace: {
      ReplayTask* target =
          t->session().find_task((pid_t)t->regs().arg2_signed());
      if (!target) {
        break;
      }
      switch ((int)t->regs().arg1_signed()) {
        case Arch::PTRACE_POKETEXT:
        case Arch::PTRACE_POKEDATA:
          target->apply_all_data_records_from_trace();
          break;
        case PTRACE_SYSCALL:
        case PTRACE_SINGLESTEP:
        case Arch::PTRACE_SYSEMU:
        case Arch::PTRACE_SYSEMU_SINGLESTEP:
        case PTRACE_CONT:
        case PTRACE_DETACH: {
          int command = (int)t->regs().arg1_signed();
          target->set_syscallbuf_locked(command != PTRACE_CONT &&
                                        command != PTRACE_DETACH);
          break;
        }
        case Arch::PTRACE_SET_THREAD_AREA: {
          bool ok = true;
          X86Arch::user_desc desc = t->read_mem(
              remote_ptr<X86Arch::user_desc>(t->regs().arg4()), &ok);
          if (ok) {
            target->emulate_set_thread_area((int)t->regs().arg3(), desc);
          }
          break;
        }
      }
      break;
    }

    case Arch::exit:
      /* Destroy buffers now to match when we destroyed them during recording.
         It's possible for another mapping to be created overlapping our
         buffers before this task truly exits, and we don't want to trash
         that mapping by destroying our buffers then. */
      t->destroy_buffers();
      break;
    case Arch::exit_group:
      if (t->thread_group()->task_set().size() == 1) {
        /* See above. */
        t->destroy_buffers();
      }
      break;
  }
  t->apply_all_data_records_from_trace();
}

void rep_after_enter_syscall(ReplayTask* t) {
  RR_ARCH_FUNCTION(rep_after_enter_syscall_arch, t->arch(), t)
}

void rep_prepare_run_to_syscall(ReplayTask* t, ReplayTraceStep* step) {
  const SyscallEvent& sys_ev = t->current_trace_frame().event().Syscall();
  int sys = sys_ev.number;

  LOG(debug) << "processing " << sys_ev.syscall_name() << " (entry)";

  if (is_restart_syscall_syscall(sys, sys_ev.arch())) {
    ASSERT(t, t->tick_count() == t->current_trace_frame().ticks());
    t->set_regs(t->current_trace_frame().regs());
    t->apply_all_data_records_from_trace();
    step->action = TSTEP_RETIRE;
    return;
  }

  step->syscall.number = sys;
  step->action = TSTEP_ENTER_SYSCALL;

  if (sys == t->session().syscall_number_for_rrcall_notify_syscall_hook_exit()) {
    ASSERT(t, t->syscallbuf_child != nullptr);
    t->write_mem(
        REMOTE_PTR_FIELD(t->syscallbuf_child, notify_on_syscall_hook_exit),
        (uint8_t)1);
  }
}

static void handle_opened_files(ReplayTask* t, int flags) {
  const auto& opened = t->current_trace_frame().event().Syscall().opened;
  for (const auto& o : opened) {
    // This must be kept in sync with record_syscall's handle_opened_file.
    EmuFile::shr_ptr emu_file = t->session().emufs().find(o.device, o.inode);
    FileMonitor* file_monitor = nullptr;
    if (emu_file) {
      file_monitor = new MmappedFileMonitor(t, emu_file);
    } else if (o.path == "terminal") {
      file_monitor = new StdioMonitor(STDERR_FILENO);
    } else if (is_proc_mem_file(o.path.c_str())) {
      file_monitor = new ProcMemMonitor(t, o.path);
    } else if (is_proc_fd_dir(o.path.c_str())) {
      file_monitor = new ProcFdDirMonitor(t, o.path);
    } else if (is_sys_cpu_online_file(o.path.c_str())) {
      file_monitor = new SysCpuMonitor(t, o.path);
    } else if (is_proc_stat_file(o.path.c_str())) {
      file_monitor = new ProcStatMonitor(t, o.path);
    } else if (flags & O_DIRECT) {
      file_monitor = new FileMonitor();
    } else {
      ASSERT(t, false) << "Why did we write filename " << o.path;
    }
    t->fd_table()->add_monitor(t, o.fd, file_monitor);
  }
}

template <typename Arch>
static void rep_process_syscall_arch(ReplayTask* t, ReplayTraceStep* step,
                                     const Registers& trace_regs) {
  int sys = t->current_trace_frame().event().Syscall().number;
  const TraceFrame& trace_frame = t->session().current_trace_frame();

  LOG(debug) << "processing " << syscall_name(sys, Arch::arch()) << " (exit)";

  // sigreturns are never restartable, and the value of the
  // syscall-result register after a sigreturn is not actually the
  // syscall result.
  if (trace_regs.syscall_may_restart() && !is_sigreturn(sys, Arch::arch())) {
    // During recording, when a sys exits with a
    // restart "error", the kernel sometimes restarts the
    // tracee by resetting its $ip to the syscall entry
    // point, but other times restarts the syscall without
    // changing the $ip.
    t->apply_all_data_records_from_trace();
    t->set_return_value_from_trace();
    step->action = TSTEP_RETIRE;
    LOG(debug) << "  " << syscall_name(sys, Arch::arch()) << " interrupted by "
               << trace_regs.syscall_result() << " at " << trace_regs.ip()
               << ", may restart";
    return;
  }

  if (sys == Arch::restart_syscall) {
    sys = t->regs().original_syscallno();
  }

  step->syscall.number = sys;
  step->action = TSTEP_EXIT_SYSCALL;

  if (trace_regs.original_syscallno() ==
      SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO) {
    // rr vetoed this syscall. Don't do any post-processing. Do set registers
    // to match any registers rr modified to fool the signal handler.
    t->set_regs(trace_regs);
    return;
  }

  if (trace_regs.syscall_failed()) {
    switch (non_negative_syscall(sys)) {
      case Arch::madvise:
      case Arch::mprotect:
      case Arch::sigreturn:
      case Arch::rt_sigreturn:
        break;
      default:
        return;
    }
  }

  /* Manual implementations of irregular syscalls that need to do more during
   * replay than just modify register and memory state.
   * Don't let a negative incoming syscall number be treated as a real
   * system call that we assigned a negative number because it doesn't
   * exist in this architecture.
   * All invalid/unsupported syscalls get the default emulation treatment.
   */
  /* Don't let a negative incoming syscall number be treated as a real
   * system call that we assigned a negative number because it doesn't
   * exist in this architecture.
   */
  switch (non_negative_syscall(sys)) {
    case Arch::execve:
      return process_execve(t, trace_frame, step);

    case Arch::brk:
      return process_brk(t);

    case Arch::mmap: {
      switch (Arch::mmap_semantics) {
        case Arch::StructArguments: {
          auto args = t->read_mem(
              remote_ptr<typename Arch::mmap_args>(trace_regs.orig_arg1()));
          return process_mmap(t, trace_frame, args.len, args.prot, args.flags,
                              args.fd, args.offset / page_size(), step);
        }
        case Arch::RegisterArguments:
          return process_mmap(t, trace_frame, trace_regs.arg2(),
                              trace_regs.arg3(), trace_regs.arg4(),
                              trace_regs.arg5(),
                              trace_regs.arg6() / page_size(), step);
      }
      break;
    }
    case Arch::mmap2:
      return process_mmap(t, trace_frame, trace_regs.arg2(), trace_regs.arg3(),
                          trace_regs.arg4(), trace_regs.arg5(),
                          trace_regs.arg6(), step);

    case Arch::shmat:
      return process_shmat(t, trace_frame, trace_regs.arg3(), step);

    case Arch::shmdt:
      return process_shmdt(t, trace_frame, trace_regs.orig_arg1(), step);

    case Arch::mremap:
      return process_mremap(t, trace_frame, step);

    case Arch::madvise:
      switch ((int)t->regs().arg3()) {
        case MADV_DONTNEED:
        case MADV_REMOVE:
          break;
        default:
          return;
      }
      RR_FALLTHROUGH;
    case Arch::arch_prctl: {
      auto arg1 = t->regs().arg1();
      if (sys == Arch::arch_prctl &&
          (arg1 == ARCH_GET_CPUID || arg1 == ARCH_SET_CPUID)) {
        return;
      }
    }
      RR_FALLTHROUGH;
    case Arch::prctl: {
      auto arg1 = t->regs().arg1();
      if (sys == Arch::prctl && (Arch::arch() != aarch64 ||
          arg1 != PR_SET_SPECULATION_CTRL)) {
        // On aarch64 PR_SET_SPECULATION_CTRL affects the pstate
        // register during the system call, so we need to replay
        // it, otherwise we'll get a mismatch there.
        return;
      }
    }
      RR_FALLTHROUGH;
    case Arch::munmap:
    case Arch::mprotect:
    case Arch::modify_ldt:
    case Arch::set_thread_area: {
      // Using AutoRemoteSyscalls here fails for arch_prctl, not sure why.
      Registers r = t->regs();
      r.set_syscallno(sys);
      r.set_ip(r.ip().decrement_by_syscall_insn_length(r.arch()));
      t->set_regs(r);
      if (sys == Arch::mprotect) {
        t->vm()->fixup_mprotect_growsdown_parameters(t);
      }
      t->enter_syscall();
      t->exit_syscall();
      ASSERT(t, t->regs().syscall_result() == trace_regs.syscall_result());
      if (sys == Arch::mprotect) {
        Registers r2 = t->regs();
        r2.set_arg1(r.arg1());
        r2.set_arg2(r.arg2());
        r2.set_arg3(r.arg3());
        t->set_regs(r2);
      }
      // The syscall modified registers. Re-emulate the syscall entry.
      t->canonicalize_regs(step->syscall.arch);
      return;
    }

    case Arch::ipc:
      switch ((int)trace_regs.orig_arg1_signed()) {
        case SHMAT:
          return process_shmat(t, trace_frame, trace_regs.arg3(), step);
        case SHMDT:
          return process_shmdt(t, trace_frame, trace_regs.arg5(), step);
        default:
          break;
      }
      break;

    case Arch::sigreturn:
    case Arch::rt_sigreturn:
      if (Arch::arch() == aarch64) {
        // The aarch64 kernel has a bug where it refuses to apply updates
        // to x7 during any syscall stops. Make sure to move to a signal
        // stop if we reached here using sysemu.
        t->move_to_signal_stop();
      }
      t->set_regs(trace_regs);
      t->set_extra_regs(trace_frame.extra_regs());
      step->action = TSTEP_RETIRE;
      return;

    case Arch::perf_event_open: {
      Task* target = t->session().find_task((pid_t)trace_regs.arg2_signed());
      int cpu = trace_regs.arg3_signed();
      unsigned long flags = trace_regs.arg5();
      int fd = trace_regs.syscall_result_signed();
      int allowed_perf_flags = PERF_FLAG_FD_CLOEXEC;
      if (target && cpu == -1 && !(flags & ~allowed_perf_flags)) {
        auto attr =
            t->read_mem(remote_ptr<struct perf_event_attr>(trace_regs.orig_arg1()));
        if (VirtualPerfCounterMonitor::should_virtualize(attr)) {
          t->fd_table()->add_monitor(t,
              fd, new VirtualPerfCounterMonitor(t, target, attr));
        }
      }
    }
      RR_FALLTHROUGH;

    case Arch::recvmsg:
    case Arch::recvmmsg:
    case Arch::recvmmsg_time64:
    case Arch::socketcall:
      handle_opened_files(t, 0);
      break;

    case Arch::openat:
      handle_opened_files(t, t->regs().arg3());
      break;
    case Arch::open:
      handle_opened_files(t, t->regs().arg2());
      break;

    case Arch::write:
    case Arch::writev:
      /* write*() can be desched'd, but don't use scratch,
       * so we might have saved 0 bytes of scratch after a
       * desched. */
      maybe_noop_restore_syscallbuf_scratch(t);
      return;

    case Arch::process_vm_writev: {
      // Recorded data records may be for another process.
      ReplayTask* dest = t->session().find_task(t->regs().arg1());
      if (dest) {
        uint32_t iov_cnt = t->regs().arg5();
        for (uint32_t i = 0; i < iov_cnt; ++i) {
          dest->set_data_from_trace();
        }
      }
      return;
    }

    case Arch::read: {
      if (t->cloned_file_data_fd_child >= 0) {
        int fd = (int)t->regs().arg1();
        string file_name = t->file_name_of_fd(fd);
        if (!file_name.empty() &&
            file_name == t->file_name_of_fd(t->cloned_file_data_fd_child)) {
          // This is a read of the cloned-data file. Replay logic depends on
          // this file's offset actually advancing.
          AutoRemoteSyscalls remote(t);
          remote.infallible_lseek_syscall(fd, trace_regs.syscall_result(),
                                          SEEK_CUR);
        }
      }
      return;
    }
  }

  if (sys == t->session().syscall_number_for_rrcall_notify_control_msg()) {
    handle_opened_files(t, 0);
  } else if (sys == t->session().syscall_number_for_rrcall_init_buffers()) {
    process_init_buffers(t, step);
  } else if (sys == t->session().syscall_number_for_rrcall_init_preload()) {
    t->at_preload_init();
  } else if (sys == t->session().syscall_number_for_rrcall_reload_auxv()) {
    // Inner rr has finished emulating execve for a tracee. Reload auxv
    // vectors now so that if gdb gets attached to the inner tracee, it will
    // get useful symbols.
    Task* target = t->session().find_task((pid_t)t->regs().arg1());
    ASSERT(t, target) << "SYS_rrcall_reload_auxv misused";
    target->vm()->save_auxv(target);
  } else if (sys == t->session().syscall_number_for_rrcall_notify_stap_semaphore_added()) {
    remote_ptr<uint16_t> range_start(t->regs().arg1()),
                         range_end(t->regs().arg2());
    MemoryRange semaphore_range(range_start, range_end);
    t->vm()->add_stap_semaphore_range(t, semaphore_range);
  } else if (sys == t->session().syscall_number_for_rrcall_notify_stap_semaphore_removed()) {
    remote_ptr<uint16_t> range_start(t->regs().arg1()),
                         range_end(t->regs().arg2());
    MemoryRange semaphore_range(range_start, range_end);
    t->vm()->remove_stap_semaphore_range(t, semaphore_range);
  }
}

void rep_process_syscall(ReplayTask* t, ReplayTraceStep* step) {
  const TraceFrame& trace_frame = t->current_trace_frame();
  step->syscall.arch = trace_frame.event().Syscall().arch();
  const Registers& trace_regs = trace_frame.regs();
  with_converted_registers<void>(
      trace_regs, step->syscall.arch, [&](const Registers& trace_regs) {
        RR_ARCH_FUNCTION(rep_process_syscall_arch, step->syscall.arch, t, step,
                         trace_regs)
      });
}

} // namespace rr
