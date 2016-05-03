/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "replay_syscall.h"

#include <asm/prctl.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/perf_event.h>
#include <linux/shm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include <array>
#include <initializer_list>
#include <map>
#include <memory>
#include <sstream>
#include <string>

#include "preload/preload_interface.h"

#include "AutoRemoteSyscalls.h"
#include "EmuFs.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"
#include "ProcMemMonitor.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "StdioMonitor.h"
#include "TraceStream.h"
#include "util.h"
#include "VirtualPerfCounterMonitor.h"

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

static string maybe_dump_written_string(ReplayTask* t) {
  if (!is_write_syscall(t->regs().original_syscallno(), t->arch())) {
    return "";
  }
  size_t len = min<size_t>(1000, t->regs().arg3());
  vector<char> buf;
  buf.resize(len + 1);
  buf.resize(t->read_bytes_fallible(t->regs().arg2(), len, buf.data()) + 1);
  buf[buf.size() - 1] = 0;
  return " \"" + string(buf.data()) + "\"";
}

/**
 * Proceeds until the next system call, which is being executed.
 */
static void __ptrace_cont(ReplayTask* t, ResumeRequest resume_how,
                          int expect_syscallno, int expect_syscallno2 = -1) {
  do {
    t->resume_execution(resume_how, RESUME_WAIT, RESUME_NO_TICKS);
  } while (ReplaySession::is_ignored_signal(t->status().stop_sig()));

  ASSERT(t, !t->stop_sig()) << "Expected no pending signal, but got "
                            << t->stop_sig();

  /* check if we are synchronized with the trace -- should never fail */
  int current_syscall = t->regs().original_syscallno();
  ASSERT(t, current_syscall == expect_syscallno ||
                current_syscall == expect_syscallno2)
      << "Should be at " << t->syscall_name(expect_syscallno)
      << ", but instead at " << t->syscall_name(current_syscall)
      << maybe_dump_written_string(t);
}

static void init_scratch_memory(ReplayTask* t, const KernelMapping& km,
                                const TraceReader::MappedData& data) {
  ASSERT(t, data.source == TraceReader::SOURCE_ZERO);

  t->scratch_ptr = km.start();
  t->scratch_size = km.size();
  size_t sz = t->scratch_size;
  // Make the scratch buffer read/write during replay so that
  // preload's sys_read can use it to buffer cloned data.
  ASSERT(t, (km.prot() & (PROT_READ | PROT_WRITE)) == (PROT_READ | PROT_WRITE));
  ASSERT(t, (km.flags() & (MAP_PRIVATE | MAP_ANONYMOUS)) ==
                (MAP_PRIVATE | MAP_ANONYMOUS));

  AutoRemoteSyscalls remote(t);
  remote.infallible_mmap_syscall(t->scratch_ptr, sz, km.prot(),
                                 km.flags() | MAP_FIXED, -1, 0);
  t->vm()->map(t->scratch_ptr, sz, km.prot(), km.flags(), 0, string(),
               KernelMapping::NO_DEVICE, KernelMapping::NO_INODE, &km);
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
    LOG(debug) << "  noop-restoring scratch for write-only desched'd "
               << t->syscall_name(t->regs().original_syscallno());
    t->set_data_from_trace();
  }
}

static TraceTaskEvent read_task_trace_event(ReplayTask* t,
                                            TraceTaskEvent::Type type) {
  TraceTaskEvent tte;
  while (true) {
    ASSERT(t, t->trace_reader().good()) << "Unable to find TraceTaskEvent; "
                                           "trace is corrupt (did you kill -9 "
                                           "rr?)";
    tte = t->trace_reader().read_task_event();
    if (tte.type() == type) {
      break;
    }
  }
  return tte;
}

template <typename Arch> static void prepare_clone(ReplayTask* t) {
  const TraceFrame& trace_frame = t->current_trace_frame();

  if (trace_frame.event().Syscall().failed_during_preparation) {
    /* creation failed, nothing special to do */
    return;
  }

  Registers r = t->regs();
  int sys = r.original_syscallno();
  int flags = 0;
  if (Arch::clone == sys) {
    // If we allow CLONE_UNTRACED then the child would escape from rr control
    // and we can't allow that.
    // Block CLONE_CHILD_CLEARTID because we'll emulate that ourselves.
    // Filter CLONE_VFORK too.
    flags = r.arg1();
    r.set_arg1(flags & ~(CLONE_UNTRACED | CLONE_CHILD_CLEARTID | CLONE_VFORK));
  } else if (Arch::vfork == sys) {
    sys = Arch::fork;
  }
  r.set_syscallno(sys);
  r.set_ip(r.ip().decrement_by_syscall_insn_length(r.arch()));
  t->set_regs(r);
  Registers entry_regs = r;

  // Run; we will be interrupted by PTRACE_EVENT_CLONE/FORK.
  __ptrace_cont(t, RESUME_CONT, sys);

  while (!t->clone_syscall_is_complete()) {
    // clone() calls sometimes fail with -EAGAIN due to load issues or
    // whatever. We need to retry the system call until it succeeds. Reset
    // state to try the syscall again.
    ASSERT(t, t->regs().syscall_result_signed() == -EAGAIN);
    t->set_regs(entry_regs);
    __ptrace_cont(t, RESUME_CONT, sys);
  }

  // Get out of the syscall
  __ptrace_cont(t, RESUME_SYSCALL, sys);

  ASSERT(t, !t->ptrace_event())
      << "Unexpected ptrace event while waiting for syscall exit; got "
      << ptrace_event_name(t->ptrace_event());

  r = t->regs();
  // Restore original_syscallno if vfork set it to fork
  r.set_original_syscallno(trace_frame.regs().original_syscallno());
  // Restore the saved flags, to hide the fact that we may have
  // masked out CLONE_UNTRACED/CLONE_CHILD_CLEARTID.
  r.set_arg1(trace_frame.regs().arg1());
  // Pretend we're still in the system call
  r.set_syscall_result(-ENOSYS);
  t->set_regs(r);
  // Get out of the kernel
  t->finish_emulated_syscall();

  // Dig the recorded tid out out of the trace. The tid value returned in
  // the recorded registers could be in a different pid namespace from rr's,
  // so we can't use it directly.
  TraceTaskEvent tte = read_task_trace_event(
      t, Arch::clone == sys ? TraceTaskEvent::CLONE : TraceTaskEvent::FORK);
  ASSERT(t, tte.parent_tid() == t->rec_tid);
  long rec_tid = tte.tid();
  pid_t new_tid = t->get_ptrace_eventmsg<pid_t>();

  CloneParameters params;
  if (Arch::clone == t->regs().original_syscallno()) {
    params = extract_clone_parameters(t);
  }
  ReplayTask* new_task = static_cast<ReplayTask*>(
      t->session().clone(t, clone_flags_to_task_flags(flags), params.stack,
                         params.tls, params.ctid, new_tid, rec_tid));

  if (Arch::clone == sys) {
    /* FIXME: what if registers are non-null and contain an
     * invalid address? */
    t->set_data_from_trace();

    if (Arch::clone_tls_type == Arch::UserDescPointer) {
      t->set_data_from_trace();
      new_task->set_data_from_trace();
    } else {
      assert(Arch::clone_tls_type == Arch::PthreadStructurePointer);
    }
    new_task->set_data_from_trace();
    new_task->set_data_from_trace();
  }

  // Fix registers in new task
  Registers new_r = new_task->regs();
  new_r.set_original_syscallno(trace_frame.regs().original_syscallno());
  new_r.set_arg1(trace_frame.regs().arg1());
  new_task->emulate_syscall_entry(new_r);

  if (!(CLONE_VM & r.arg1())) {
    // It's hard to imagine a scenario in which it would
    // be useful to inherit breakpoints (along with their
    // refcounts) across a non-VM-sharing clone, but for
    // now we never want to do this.
    new_task->vm()->remove_all_breakpoints();
    new_task->vm()->remove_all_watchpoints();
  }

  TraceReader::MappedData data;
  KernelMapping km = t->trace_reader().read_mapped_region(&data);
  init_scratch_memory(new_task, km, data);

  new_task->vm()->after_clone();
}

static string find_exec_stub(SupportedArch arch) {
  string exe_path = exe_directory();
  if (arch == x86 && NativeArch::arch() == x86_64) {
    exe_path += "exec_stub_32";
  } else {
    exe_path += "exec_stub";
  }
  return exe_path;
}

static void finish_direct_mmap(ReplayTask* t, AutoRemoteSyscalls& remote,
                               remote_ptr<void> rec_addr, size_t length,
                               int prot, int flags,
                               const string& backing_file_name,
                               off64_t backing_offset_pages,
                               struct stat& real_file, string& real_file_name) {
  int fd;

  LOG(debug) << "directly mmap'ing " << length << " bytes of "
             << backing_file_name << " at page offset "
             << HEX(backing_offset_pages);

  ASSERT(t, !(flags & MAP_GROWSDOWN));

  /* Open in the tracee the file that was mapped during
   * recording. */
  {
    AutoRestoreMem child_str(remote, backing_file_name.c_str());
    /* We only need RDWR for shared writeable mappings.
     * Private mappings will happily COW from the mapped
     * RDONLY file.
     *
     * TODO: should never map any files writable */
    int oflags =
        (MAP_SHARED & flags) && (PROT_WRITE & prot) ? O_RDWR : O_RDONLY;
    /* TODO: unclear if O_NOATIME is relevant for mmaps */
    fd = remote.infallible_syscall(syscall_number_for_open(remote.arch()),
                                   child_str.get().as_int(), oflags);
  }
  /* And mmap that file. */
  remote.infallible_mmap_syscall(rec_addr, length,
                                 /* (We let SHARED|WRITEABLE
                                  * mappings go through while
                                  * they're not handled properly,
                                  * but we shouldn't do that.) */
                                 prot, flags | MAP_FIXED, fd,
                                 backing_offset_pages);

  // While it's open, grab the link reference.
  real_file = t->stat_fd(fd);
  real_file_name = t->file_name_of_fd(fd);

  /* Don't leak the tmp fd.  The mmap doesn't need the fd to
   * stay open. */
  remote.infallible_syscall(syscall_number_for_close(remote.arch()), fd);
}

static void restore_mapped_region(ReplayTask* t, AutoRemoteSyscalls& remote,
                                  const KernelMapping& km,
                                  const TraceReader::MappedData& data) {
  ASSERT(t, km.flags() & MAP_PRIVATE)
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
      finish_direct_mmap(t, remote, km.start(), km.size(), km.prot(),
                         km.flags(), data.file_name,
                         data.file_data_offset_bytes / page_size(), real_file,
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

  t->vm()->map(km.start(), km.size(), km.prot(), flags, offset_bytes,
               real_file_name, device, inode, &km);
}

static void process_execve(ReplayTask* t, const TraceFrame& trace_frame,
                           ReplayTraceStep* step) {
  if (trace_frame.regs().syscall_failed()) {
    return;
  }

  step->action = TSTEP_RETIRE;

  /* First, exec a stub program */
  string stub_filename = find_exec_stub(trace_frame.regs().arch());

  // Setup memory and registers for the execve call. We don't need to save
  // the old values since they're going to be wiped out by execve.
  Registers regs = t->regs();
  regs.set_ip(t->vm()->traced_syscall_ip());
  remote_ptr<void> remote_mem = floor_page_size(regs.sp());
  // We write a zero word in the host size, not t's size, but that's OK,
  // since the host size must be bigger than t's size.
  // We pass no argv or envp, so exec params 2 and 3 just point to the NULL
  // word.
  t->write_mem(remote_mem.cast<size_t>(), size_t(0));
  regs.set_arg2(remote_mem);
  regs.set_arg3(remote_mem);
  remote_mem += sizeof(size_t);
  t->write_bytes_helper(remote_mem, stub_filename.size() + 1,
                        stub_filename.c_str());
  regs.set_arg1(remote_mem);
  /* The original_syscallno is execve in the old architecture. The kernel does
   * not update the original_syscallno when the architecture changes across
   * an exec.
   */
  int expect_syscallno = syscall_number_for_execve(t->arch());
  regs.set_syscallno(expect_syscallno);
  t->set_regs(regs);

  /* Enter our execve syscall. */
  __ptrace_cont(t, RESUME_SYSCALL, expect_syscallno);
  ASSERT(t, !t->stop_sig()) << "Stub exec failed on entry";
  /* Complete the syscall */
  __ptrace_cont(t, RESUME_SYSCALL, expect_syscallno,
                syscall_number_for_execve(trace_frame.regs().arch()));
  if (t->regs().syscall_result()) {
    errno = -t->regs().syscall_result();
    if (access(stub_filename.c_str(), 0) == -1 && errno == ENOENT &&
        trace_frame.regs().arch() == x86) {
      FATAL() << "Cannot find exec stub " << stub_filename
              << " to replay this 32-bit process; you probably built rr with "
                 "disable32bit";
    }
    ASSERT(t, false) << "Exec of stub " << stub_filename << " failed";
  }

  vector<KernelMapping> kms;
  vector<TraceReader::MappedData> datas;
  ssize_t exe_km = -1;
  while (true) {
    TraceReader::MappedData data;
    bool found;
    KernelMapping km = t->trace_reader().read_mapped_region(&data, &found);
    if (!found) {
      break;
    }
    const string& file_name = km.fsname();
    if ((km.prot() & PROT_EXEC) && file_name.size() > 0 &&
        file_name[0] == '/' && file_name.rfind(".so") != file_name.size() - 3) {
      exe_km = kms.size();
    }
    kms.push_back(km);
    datas.push_back(data);
  }

  ASSERT(t, exe_km >= 0) << "Can't find exe mapping";
  ASSERT(t, kms[0].is_stack()) << "Can't find stack";

  TraceTaskEvent tte = read_task_trace_event(t, TraceTaskEvent::EXEC);
  // The exe name we pass in here will be passed to gdb. Pass the backing file
  // name if there is one, otherwise pass the original file name (which means
  // we declined to copy it to the trace file during recording for whatever
  // reason).
  const string& exe_name = datas[exe_km].file_name.empty()
                               ? kms[exe_km].fsname()
                               : datas[exe_km].file_name;
  t->post_exec_syscall(exe_name, tte);

  {
    // Tell AutoRemoteSyscalls that we don't need memory parameters. This will
    // stop it from having trouble if our current stack pointer (the value
    // from the replay) isn't in the [stack] mapping created for our stub.
    AutoRemoteSyscalls remote(t, AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS);

    // Now fix up the address space. First unmap all the mappings other than
    // our rr page.
    vector<MemoryRange> unmaps;
    for (auto m : t->vm()->maps()) {
      // Do not attempt to unmap [vsyscall] --- it doesn't work.
      if (m.map.start() != AddressSpace::rr_page_start() &&
          !m.map.is_vsyscall()) {
        unmaps.push_back(m.map);
      }
    }
    for (auto& m : unmaps) {
      remote.infallible_syscall(syscall_number_for_munmap(t->arch()), m.start(),
                                m.size());
      t->vm()->unmap(m.start(), m.size());
    }
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

  // Notify outer rr if there is one
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
    t->vm()->map(km.start(), km.size(), km.prot(), MAP_ANONYMOUS | km.flags(),
                 0, "[heap]", KernelMapping::NO_DEVICE, KernelMapping::NO_INODE,
                 &km);
  } else if (km.size() > 0) {
    AutoRemoteSyscalls remote(t);
    remote.infallible_syscall(syscall_number_for_munmap(t->arch()), km.start(),
                              km.size());
    t->vm()->unmap(km.start(), km.size());
  }
}

/**
 * Pass NOTE_TASK_MAP to update cached mmap data.  If the data
 * need to be manually updated, pass |DONT_NOTE_TASK_MAP| and update
 * it manually.
 */
enum NoteTaskMap { DONT_NOTE_TASK_MAP = 0, NOTE_TASK_MAP };

static remote_ptr<void> finish_anonymous_mmap(
    ReplayTask* t, AutoRemoteSyscalls& remote, const TraceFrame& trace_frame,
    size_t length, int prot, int flags, NoteTaskMap note_task_map) {
  const Registers& rec_regs = trace_frame.regs();
  /* *Must* map the segment at the recorded address, regardless
     of what the recorded tracee passed as the |addr| hint. */
  remote_ptr<void> rec_addr = rec_regs.syscall_result();

  string file_name;
  dev_t device = KernelMapping::NO_DEVICE;
  ino_t inode = KernelMapping::NO_INODE;
  KernelMapping recorded_km;
  EmuFile::shr_ptr emu_file;
  if (flags & MAP_PRIVATE) {
    remote.infallible_mmap_syscall(rec_addr, length, prot,
                                   // Tell the kernel to take |rec_addr|
                                   // seriously.
                                   (flags & ~MAP_GROWSDOWN) | MAP_FIXED, -1, 0);
    recorded_km = KernelMapping(rec_addr, rec_addr + ceil_page_size(length),
                                string(), KernelMapping::NO_DEVICE,
                                KernelMapping::NO_INODE, prot, flags, 0);
  } else {
    TraceReader::MappedData data;
    recorded_km = remote.task()->trace_reader().read_mapped_region(&data);
    ASSERT(remote.task(), data.source == TraceReader::SOURCE_ZERO);
    emu_file = t->session().emufs().get_or_create(recorded_km, length);
    struct stat real_file;
    finish_direct_mmap(t, remote, rec_addr, length, prot,
                       flags & ~MAP_ANONYMOUS, emu_file->proc_path(), 0,
                       real_file, file_name);
    device = real_file.st_dev;
    inode = real_file.st_ino;
  }

  if (note_task_map) {
    remote.task()->vm()->map(rec_addr, length, prot, flags, 0, file_name,
                             device, inode, &recorded_km, emu_file);
  }
  return rec_addr;
}

/* Ensure that accesses to the memory region given by start/length
   cause a SIGBUS, as for accesses beyond the end of an mmaped file. */
static void create_sigbus_region(AutoRemoteSyscalls& remote, int prot,
                                 remote_ptr<void> start, size_t length,
                                 const KernelMapping& km) {
  if (length == 0) {
    return;
  }

  /* Open an empty file in the tracee */
  char filename[] = PREFIX_FOR_EMPTY_MMAPED_REGIONS "XXXXXX";

  {
    /* Close our side immediately */
    ScopedFd fd(mkstemp(filename));
  }

  int child_fd;
  {
    AutoRestoreMem child_str(remote, filename);
    child_fd = remote.infallible_syscall(syscall_number_for_open(remote.arch()),
                                         child_str.get(), O_RDONLY);
  }

  /* Unlink it now that the child has opened it */
  unlink(filename);

  struct stat fstat = remote.task()->stat_fd(child_fd);
  string file_name = remote.task()->file_name_of_fd(child_fd);

  /* mmap it in the tracee. We need to set the correct 'prot' flags
     so that the correct signal is generated on a memory access
     (SEGV if 'prot' doesn't allow the access, BUS if 'prot' does allow
     the access). */
  remote.infallible_mmap_syscall(start, length, prot, MAP_FIXED | MAP_PRIVATE,
                                 child_fd, 0);
  /* Don't leak the tmp fd.  The mmap doesn't need the fd to
   * stay open. */
  remote.infallible_syscall(syscall_number_for_close(remote.arch()), child_fd);

  KernelMapping km_slice = km.subrange(start, start + length);
  remote.task()->vm()->map(start, length, prot, MAP_FIXED | MAP_PRIVATE, 0,
                           file_name, fstat.st_dev, fstat.st_ino, &km_slice);
}

static void finish_private_mmap(ReplayTask* t, AutoRemoteSyscalls& remote,
                                const TraceFrame& trace_frame, size_t length,
                                int prot, int flags, off64_t offset_pages,
                                const KernelMapping& km) {
  LOG(debug) << "  finishing private mmap of " << km.fsname();

  size_t num_bytes = length;
  remote_ptr<void> mapped_addr =
      finish_anonymous_mmap(t, remote, trace_frame, length, prot,
                            /* The restored region won't be backed
                             * by file. */
                            flags | MAP_ANONYMOUS, DONT_NOTE_TASK_MAP);
  /* Restore the map region we copied. */
  ssize_t data_size = t->set_data_from_trace();

  /* Ensure pages past the end of the file fault on access */
  size_t data_pages = ceil_page_size(data_size);
  size_t mapped_pages = ceil_page_size(num_bytes);

  t->vm()->map(mapped_addr, num_bytes, prot, flags | MAP_ANONYMOUS,
               page_size() * offset_pages, string(), KernelMapping::NO_DEVICE,
               KernelMapping::NO_INODE, &km);

  create_sigbus_region(remote, prot, mapped_addr + data_pages,
                       mapped_pages - data_pages, km);
}

static void finish_shared_mmap(ReplayTask* t, AutoRemoteSyscalls& remote,
                               int prot, int flags, off64_t offset_pages,
                               size_t file_size, const KernelMapping& km) {
  auto buf = t->trace_reader().read_raw_data();
  size_t rec_num_bytes = ceil_page_size(buf.data.size());

  // Ensure there's a virtual file for the file that was mapped
  // during recording.
  auto emufile = t->session().emufs().get_or_create(km, file_size);
  // Re-use the direct_map() machinery to map the virtual file.
  //
  // NB: the tracee will map the procfs link to our fd; there's
  // no "real" name for the file anywhere, to ensure that when
  // we exit/crash the kernel will clean up for us.
  struct stat real_file;
  string real_file_name;
  finish_direct_mmap(t, remote, buf.addr, rec_num_bytes, prot, flags,
                     emufile->proc_path(), offset_pages, real_file,
                     real_file_name);
  // Write back the snapshot of the segment that we recorded.
  // We have to write directly to the underlying file, because
  // the tracee may have mapped its segment read-only.
  //
  // TODO: this is a poor man's shared segment synchronization.
  // For full generality, we also need to emulate direct file
  // modifications through write/splice/etc.
  off64_t offset_bytes = page_size() * offset_pages;
  if (ssize_t(buf.data.size()) !=
      pwrite64(emufile->fd(), buf.data.data(), buf.data.size(), offset_bytes)) {
    FATAL() << "Failed to write " << buf.data.size() << " bytes at "
            << HEX(offset_bytes) << " to " << emufile->real_path() << " for "
            << emufile->emu_path();
  }
  LOG(debug) << "  restored " << buf.data.size() << " bytes at "
             << HEX(offset_bytes) << " to " << emufile->real_path() << " for "
             << emufile->emu_path();

  t->vm()->map(buf.addr, buf.data.size(), prot, flags, offset_bytes,
               real_file_name, real_file.st_dev, real_file.st_ino, &km,
               emufile);
}

static void process_mmap(ReplayTask* t, const TraceFrame& trace_frame,
                         size_t length, int prot, int flags,
                         off64_t offset_pages, ReplayTraceStep* step) {
  if (trace_frame.regs().syscall_failed()) {
    return;
  }

  step->action = TSTEP_RETIRE;

  /* Successful mmap calls are much more interesting to process. */
  {
    // Next we hand off actual execution of the mapping to the
    // appropriate helper.
    AutoRemoteSyscalls remote(t,
                              (flags & MAP_PRIVATE) && (flags & MAP_ANONYMOUS)
                                  ? AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS
                                  : AutoRemoteSyscalls::ENABLE_MEMORY_PARAMS);
    if (flags & MAP_ANONYMOUS) {
      finish_anonymous_mmap(t, remote, trace_frame, length, prot, flags,
                            NOTE_TASK_MAP);
    } else {
      TraceReader::MappedData data;
      KernelMapping km = t->trace_reader().read_mapped_region(&data);

      if (data.source == TraceReader::SOURCE_FILE) {
        struct stat real_file;
        string real_file_name;
        finish_direct_mmap(t, remote, trace_frame.regs().syscall_result(),
                           length, prot, flags, data.file_name,
                           data.file_data_offset_bytes / page_size(), real_file,
                           real_file_name);
        t->vm()->map(km.start(), length, prot, flags,
                     page_size() * offset_pages, real_file_name,
                     real_file.st_dev, real_file.st_ino, &km);
      } else {
        ASSERT(t, data.source == TraceReader::SOURCE_TRACE);
        if (MAP_PRIVATE & flags) {
          finish_private_mmap(t, remote, trace_frame, length, prot, flags,
                              offset_pages, km);
        } else {
          finish_shared_mmap(t, remote, prot, flags, offset_pages,
                             data.file_size_bytes, km);
        }
      }
    }
    // Finally, we finish by emulating the return value.
    remote.regs().set_syscall_result(trace_frame.regs().syscall_result());
  }
  // Monkeypatcher can emit data records that need to be applied now
  t->apply_all_data_records_from_trace();
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
  if (trace_frame.regs().syscall_failed()) {
    return;
  }

  step->action = TSTEP_RETIRE;

  {
    AutoRemoteSyscalls remote(t);
    TraceReader::MappedData data;
    KernelMapping km = t->trace_reader().read_mapped_region(&data);
    int prot = shm_flags_to_mmap_prot(shm_flags);
    int flags = MAP_SHARED;
    finish_shared_mmap(t, remote, prot, flags, 0, data.file_size_bytes, km);

    // Finally, we finish by emulating the return value.
    remote.regs().set_syscall_result(trace_frame.regs().syscall_result());
  }
  // on x86-32 we have an extra data record that we need to apply ---
  // the ipc syscall's klugy out-parameter.
  t->apply_all_data_records_from_trace();
  t->validate_regs();
}

static void process_shmdt(ReplayTask* t, const TraceFrame& trace_frame,
                          remote_ptr<void> addr, ReplayTraceStep* step) {
  if (trace_frame.regs().syscall_failed()) {
    return;
  }

  step->action = TSTEP_RETIRE;

  {
    AutoRemoteSyscalls remote(t);
    auto mapping = t->vm()->mapping_of(addr);
    ASSERT(t, mapping.map.start() == addr);
    remote.infallible_syscall(syscall_number_for_munmap(t->arch()), addr,
                              mapping.map.end() - addr);
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
    case Arch::exit:
    case Arch::exit_group:
      // We don't really need to destroy buffers in exit_group since they'll
      // go away anyway, but it makes memory consistent with recording
      // for checksumming.
      t->destroy_buffers();
      break;

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

    case Arch::ptrace:
      switch ((int)t->regs().arg1_signed()) {
        case PTRACE_POKETEXT:
        case PTRACE_POKEDATA:
          ReplayTask* target =
              t->session().find_task((pid_t)t->regs().arg2_signed());
          if (target) {
            target->apply_all_data_records_from_trace();
          }
          break;
      }
      break;
  }
  t->apply_all_data_records_from_trace();
}

void rep_after_enter_syscall(ReplayTask* t) {
  RR_ARCH_FUNCTION(rep_after_enter_syscall_arch, t->arch(), t)
}

void rep_prepare_run_to_syscall(ReplayTask* t, ReplayTraceStep* step) {
  int sys = t->current_trace_frame().event().Syscall().number;

  LOG(debug) << "processing " << t->syscall_name(sys) << " (entry)";

  if (is_restart_syscall_syscall(sys, t->arch())) {
    ASSERT(t, t->tick_count() == t->current_trace_frame().ticks());
    t->set_regs(t->current_trace_frame().regs());
    step->action = TSTEP_RETIRE;
    return;
  }

  step->syscall.number = sys;
  step->action = TSTEP_ENTER_SYSCALL;

  /* Don't let a negative incoming syscall number be treated as a real
   * system call that we assigned a negative number because it doesn't
   * exist in this architecture.
   */
  if (is_rrcall_notify_syscall_hook_exit_syscall(sys, t->arch())) {
    ASSERT(t, t->syscallbuf_hdr);
    t->syscallbuf_hdr->notify_on_syscall_hook_exit = true;
  }
}

static void handle_opened_files(ReplayTask* t) {
  vector<uint8_t> buf;
  while (
      t->trace_reader().read_generic_for_frame(t->current_trace_frame(), buf)) {
    int fd = *reinterpret_cast<int*>(buf.data());
    t->trace_reader().read_generic(buf);
    string pathname(reinterpret_cast<const char*>(buf.data()), buf.size());
    // This must be kept in sync with replay_syscall's handle_opened_file.
    if (is_dev_tty(pathname.c_str())) {
      // This will let rr event annotations echo to /dev/tty. It will also
      // ensure writes to this fd are not syscall-buffered.
      // XXX the tracee's /dev/tty could refer to a tty other than
      // the recording tty, in which case output should not be
      // redirected. That's not too bad, replay will still work, just
      // with some spurious echoes.
      t->fd_table()->add_monitor(fd, new StdioMonitor(STDERR_FILENO));
    } else if (is_proc_mem_file(pathname.c_str())) {
      t->fd_table()->add_monitor(fd, new ProcMemMonitor(t, pathname));
    } else {
      ASSERT(t, false) << "Why did we write filename " << pathname;
    }
  }
}

template <typename Arch>
static void rep_process_syscall_arch(ReplayTask* t, ReplayTraceStep* step) {
  int sys = t->current_trace_frame().event().Syscall().number;
  const TraceFrame& trace_frame = t->session().current_trace_frame();
  const Registers& trace_regs = trace_frame.regs();

  LOG(debug) << "processing " << t->syscall_name(sys) << " (exit)";

  // sigreturns are never restartable, and the value of the
  // syscall-result register after a sigreturn is not actually the
  // syscall result.
  if (trace_regs.syscall_may_restart() && !is_sigreturn(sys, t->arch())) {
    // During recording, when a sys exits with a
    // restart "error", the kernel sometimes restarts the
    // tracee by resetting its $ip to the syscall entry
    // point, but other times restarts the syscall without
    // changing the $ip.
    t->apply_all_data_records_from_trace();
    t->set_return_value_from_trace();
    step->action = TSTEP_RETIRE;
    LOG(debug) << "  " << t->syscall_name(sys) << " interrupted by "
               << trace_regs.syscall_result() << " at " << trace_regs.ip()
               << ", may restart";
    return;
  }

  if (sys == Arch::restart_syscall) {
    sys = t->regs().original_syscallno();
  }

  step->syscall.number = sys;
  step->action = TSTEP_EXIT_SYSCALL;

  /* Manual implementations of irregular syscalls that need to do more during
   * replay than just modify register and memory state.
   * Don't let a negative incoming syscall number be treated as a real
   * system call that we assigned a negative number because it doesn't
   * exist in this architecture.
   * All invalid/unsupported syscalls get the default emulation treatment.
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
              remote_ptr<typename Arch::mmap_args>(trace_regs.arg1()));
          return process_mmap(t, trace_frame, args.len, args.prot, args.flags,
                              args.offset / page_size(), step);
        }
        case Arch::RegisterArguments:
          return process_mmap(t, trace_frame, trace_regs.arg2(),
                              trace_regs.arg3(), trace_regs.arg4(),
                              trace_regs.arg6() / page_size(), step);
      }
      break;
    }
    case Arch::mmap2:
      return process_mmap(t, trace_frame, trace_regs.arg2(), trace_regs.arg3(),
                          trace_regs.arg4(), trace_regs.arg6(), step);

    case Arch::shmat:
      return process_shmat(t, trace_frame, trace_regs.arg3(), step);

    case Arch::shmdt:
      return process_shmdt(t, trace_frame, trace_regs.arg1(), step);

    case Arch::mremap: {
      // We must emulate mremap because the kernel's choice for the remap
      // destination can vary (in particular, when we emulate exec it makes
      // different decisions).
      AutoRemoteSyscalls remote(t);
      if (trace_regs.syscall_result() == trace_regs.arg1()) {
        // Non-moving mremap. Don't pass MREMAP_FIXED or MREMAP_MAYMOVE
        // since that triggers EINVAL when the new map overlaps the old map.
        remote.infallible_syscall_ptr(sys, trace_regs.arg1(), trace_regs.arg2(),
                                      trace_regs.arg3(), 0);
      } else {
        // Force the mremap to use the destination address from recording.
        // XXX could the new mapping overlap the old, with different start
        // addresses? Hopefully the kernel doesn't do that to us!!!
        remote.infallible_syscall_ptr(
            sys, trace_regs.arg1(), trace_regs.arg2(), trace_regs.arg3(),
            MREMAP_MAYMOVE | MREMAP_FIXED, trace_regs.syscall_result());
      }
      // ReplayTask::on_syscall_exit takes care of updating AddressSpace.
      return;
    }

    case Arch::madvise:
      switch ((int)t->regs().arg3()) {
        case MADV_DONTNEED:
        case MADV_REMOVE:
          break;
        default:
          return;
      }
    /* fall through */
    case Arch::munmap:
    case Arch::mprotect:
    case Arch::arch_prctl:
    case Arch::set_thread_area: {
      // Using AutoRemoteSyscalls here fails for arch_prctl, not sure why.
      Registers r = t->regs();
      r.set_syscallno(t->regs().original_syscallno());
      r.set_ip(r.ip().decrement_by_syscall_insn_length(r.arch()));
      t->set_regs(r);
      if (sys == Arch::mprotect) {
        t->vm()->fixup_mprotect_growsdown_parameters(t);
      }
      __ptrace_cont(t, RESUME_SYSCALL, sys);
      __ptrace_cont(t, RESUME_SYSCALL, sys);
      ASSERT(t, t->regs().syscall_result() == trace_regs.syscall_result());
      if (sys == Arch::mprotect) {
        Registers r2 = t->regs();
        r2.set_arg1(r.arg1());
        r2.set_arg2(r.arg2());
        r2.set_arg3(r.arg3());
        t->set_regs(r2);
      }
      return;
    }

    case Arch::ipc:
      switch ((int)trace_regs.arg1_signed()) {
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
      t->set_regs(trace_regs);
      t->set_extra_regs(trace_frame.extra_regs());
      step->action = TSTEP_RETIRE;
      return;

    case Arch::perf_event_open: {
      Task* target = t->session().find_task((pid_t)trace_regs.arg2_signed());
      int cpu = trace_regs.arg3_signed();
      int group_fd = trace_regs.arg4_signed();
      unsigned long flags = trace_regs.arg5();
      int fd = trace_regs.syscall_result_signed();
      if (target && cpu == -1 && group_fd == -1 && !flags) {
        auto attr =
            t->read_mem(remote_ptr<struct perf_event_attr>(trace_regs.arg1()));
        if (VirtualPerfCounterMonitor::should_virtualize(attr)) {
          t->fd_table()->add_monitor(
              fd, new VirtualPerfCounterMonitor(t, target, attr));
        }
      }
    }

    case Arch::recvmsg:
    case Arch::recvmmsg:
    case Arch::openat:
    case Arch::open:
    case Arch::socketcall:
    case Arch::rrcall_notify_control_msg:
      handle_opened_files(t);
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
      int fd = (int)t->regs().arg1();
      if (!trace_regs.syscall_failed() && t->cloned_file_data_fd_child >= 0) {
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

    case SYS_rrcall_init_buffers:
      return process_init_buffers(t, step);

    case SYS_rrcall_init_preload:
      t->at_preload_init();
      return;

    case SYS_rrcall_reload_auxv: {
      // Inner rr has finished emulating execve for a tracee. Reload auxv
      // vectors now so that if gdb gets attached to the inner tracee, it will
      // get useful symbols.
      Task* target = t->session().find_task((pid_t)t->regs().arg1());
      ASSERT(t, target) << "SYS_rrcall_reload_auxv misused";
      target->vm()->save_auxv(target);
      return;
    }

    default:
      return;
  }
}

void rep_process_syscall(ReplayTask* t, ReplayTraceStep* step) {
  // Use the event's arch, not the task's, because the task's arch may
  // be out of date immediately after an exec.
  RR_ARCH_FUNCTION(rep_process_syscall_arch,
                   t->current_trace_frame().event().arch(), t, step)
}

} // namespace rr
