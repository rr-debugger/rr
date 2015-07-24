/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "ProcessSyscallRep"

#include "replay_syscall.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
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
#include "ReplaySession.h"
#include "task.h"
#include "TraceStream.h"
#include "util.h"

/* Uncomment this to check syscall names and numbers defined in syscalls.py
   against the definitions in unistd.h. This may cause the build to fail
   if unistd.h is slightly out of date, so it's not turned on by default. */
//#define CHECK_SYSCALL_NUMBERS

using namespace std;
using namespace rr;

enum SyscallDefType {
  rep_UNDEFINED = 0, /* NB: this symbol must have the value 0 */
  rep_EMU,
  rep_EXEC
};
struct syscall_def {
  /* See syscalls.py for documentation on these values. */
  SyscallDefType type;
};

typedef pair<size_t, syscall_def> SyscallInit;

template <size_t N> struct SyscallTable : array<syscall_def, N> {
  SyscallTable(initializer_list<SyscallInit> init) {
    for (auto& i : init) {
      (*this)[i.first] = i.second;
    }
  }
};

template <typename Arch> struct syscall_defs {
  // Reserve a final element which is guaranteed to be an undefined syscall.
  // Negative and out-of-range syscall numbers are mapped to this element.
  typedef SyscallTable<Arch::SYSCALL_COUNT + 1> Table;
  static Table table;
};

#include "SyscallDefsTable.generated"

// XXX: x86-only currently.
#ifdef CHECK_SYSCALL_NUMBERS

// Hack because our 'break' syscall is called '_break'
#define SYS__break SYS_break

#include "CheckSyscallNumbers.generated"

#endif // CHECK_SYSCALL_NUMBERS

enum SyscallEntryOrExit { SYSCALL_ENTRY, SYSCALL_EXIT };

/**
 * Return the symbolic name of |state|, or "???state" if unknown.
 */
static const char* state_name(SyscallEntryOrExit state) {
  switch (state) {
#define CASE(_id)                                                              \
  case _id:                                                                    \
    return #_id
    CASE(SYSCALL_ENTRY);
    CASE(SYSCALL_EXIT);
#undef CASE
    default:
      return "???state";
  }
}

/**
 * Proceeds until the next system call, which is not executed.
 */
static void goto_next_syscall_emu(Task* t) {
  t->cont_sysemu();

  int sig = t->pending_sig();
  if (ReplaySession::is_ignored_signal(sig)) {
    goto_next_syscall_emu(t);
    return;
  }
  if (SIGTRAP == sig) {
    FATAL() << "SIGTRAP while entering syscall ... were you using a debugger? "
               "If so, the current syscall needs to be made interruptible";
  } else if (sig) {
    FATAL() << "Replay got unrecorded signal " << sig;
  }

  /* check if we are synchronized with the trace -- should never
   * fail */
  const int rec_syscall = t->current_trace_frame().regs().original_syscallno();
  const int current_syscall = t->regs().original_syscallno();

  if (current_syscall != rec_syscall) {
    /* this signal is ignored and most likey delivered
     * later, or was already delivered earlier */
    /* TODO: this code is now obselete */
    if (ReplaySession::is_ignored_signal(t->stop_sig())) {
      LOG(debug) << "do we come here?\n";
      /*t->replay_sig = SIGCHLD; // remove that if
       * spec does not work anymore */
      goto_next_syscall_emu(t);
      return;
    }

    ASSERT(t, current_syscall == rec_syscall)
        << "Should be at `" << t->syscall_name(rec_syscall) << "', instead at `"
        << t->syscall_name(current_syscall) << "'";
  }
  t->child_sig = 0;
}

static string maybe_dump_written_string(Task* t) {
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
static void __ptrace_cont(Task* t, int expect_syscallno) {
  do {
    t->cont_syscall();
  } while (ReplaySession::is_ignored_signal(t->stop_sig()));

  ASSERT(t, !t->pending_sig()) << "Expected no pending signal, but got "
                               << t->pending_sig();
  t->child_sig = 0;

  /* check if we are synchronized with the trace -- should never fail */
  int current_syscall = t->regs().original_syscallno();
  ASSERT(t, current_syscall == expect_syscallno)
      << "Should be at " << t->syscall_name(expect_syscallno)
      << ", but instead at " << t->syscall_name(current_syscall)
      << maybe_dump_written_string(t);
}

static void init_scratch_memory(Task* t) {
  /* Initialize the scratchpad as the recorder did, but make it
   * PROT_NONE. The idea is just to reserve the address space so
   * the replayed process address map looks like the recorded
   * process, if it were to be probed by madvise or some other
   * means. But we make it PROT_NONE so that rogue reads/writes
   * to the scratch memory are caught. */
  TraceReader::MappedData data;
  auto mapped_region = t->trace_reader().read_mapped_region(&data);
  ASSERT(t, data.source == TraceReader::SOURCE_ZERO);

  t->scratch_ptr = mapped_region.start();
  t->scratch_size = mapped_region.size();
  size_t sz = t->scratch_size;
  int prot = PROT_NONE;
  int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
  remote_ptr<void> map_addr;
  {
    AutoRemoteSyscalls remote(t);
    map_addr = remote.mmap_syscall(t->scratch_ptr, sz, prot, flags, -1, 0);
  }
  ASSERT(t, t->scratch_ptr == map_addr)
      << "scratch mapped " << mapped_region.start() << " during recording, but "
      << map_addr << " in replay";

  t->vm()->map(map_addr, sz, prot, flags, 0,
               MappableResource::scratch(t->rec_tid));
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
static void maybe_noop_restore_syscallbuf_scratch(Task* t) {
  if (t->is_in_untraced_syscall()) {
    LOG(debug) << "  noop-restoring scratch for write-only desched'd "
               << t->syscall_name(t->regs().original_syscallno());
    t->set_data_from_trace();
  }
}

/**
 * Return true iff the syscall represented by |frame| (either entry to
 * or exit from) failed.
 */
static bool is_failed_syscall(Task* t, const TraceFrame& frame) {
  TraceFrame next_frame;
  if (ENTERING_SYSCALL == frame.event().Syscall().state) {
    next_frame = t->trace_reader().peek_to(t->rec_tid, frame.event().type(),
                                           EXITING_SYSCALL);
    return next_frame.regs().syscall_failed();
  }
  return frame.regs().syscall_failed();
}

static ReplayTraceStepType syscall_action(SyscallEntryOrExit state) {
  return state == SYSCALL_ENTRY ? TSTEP_ENTER_SYSCALL : TSTEP_EXIT_SYSCALL;
}

static TraceTaskEvent read_task_trace_event(Task* t,
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

template <typename Arch>
static void process_clone(Task* t, const TraceFrame& trace_frame,
                          SyscallEntryOrExit state, ReplayTraceStep* step,
                          unsigned long flags, int expect_syscallno) {
  if (is_failed_syscall(t, trace_frame)) {
    /* creation failed, emulate it */
    step->syscall.emu = EMULATE;
    step->action = syscall_action(state);
    return;
  }
  if (state == SYSCALL_ENTRY) {
    step->action = TSTEP_ENTER_SYSCALL;
    return;
  }

  if (flags & CLONE_UNTRACED) {
    ASSERT(t, trace_frame.regs().original_syscallno() == Arch::clone);
    Registers r = t->regs();
    r.set_arg1(flags & ~CLONE_UNTRACED);
    t->set_regs(r);
  }

  // TODO: can debugger signals interrupt us here?

  // The syscall may be interrupted. Keep trying it until we get the
  // ptrace event we're expecting.
  __ptrace_cont(t, expect_syscallno);

  while (!t->clone_syscall_is_complete()) {
    if (t->regs().syscall_result_signed() == -EAGAIN) {
      // clone() calls sometimes fail with -EAGAIN due to load issues or
      // whatever. We need to retry the system call until it succeeds. Reset
      // state to try the syscall again.
      Registers r = t->regs();
      r.set_syscallno(trace_frame.regs().original_syscallno());
      r.set_ip(trace_frame.regs().ip() - syscall_instruction_length(t->arch()));
      t->set_regs(r);
      // reenter syscall
      __ptrace_cont(t, expect_syscallno);
      // continue to exit
      __ptrace_cont(t, expect_syscallno);
    } else {
      __ptrace_cont(t, expect_syscallno);
    }
  }

  // Now continue again to get the syscall exit event.
  __ptrace_cont(t, expect_syscallno);
  ASSERT(t, !t->ptrace_event())
      << "Unexpected ptrace event while waiting for syscall exit; got "
      << ptrace_event_name(t->ptrace_event());

  Registers r = t->regs();
  // Restore original_syscallno if vfork set it to fork
  r.set_original_syscallno(trace_frame.regs().original_syscallno());
  // Restore the saved flags, to hide the fact that we may have
  // masked out CLONE_UNTRACED.
  r.set_arg1(trace_frame.regs().arg1());
  t->set_regs(r);

  // Dig the recorded tid out out of the trace. The tid value returned in
  // the recorded registers could be in a different pid namespace from rr's,
  // so we can't use it directly.
  TraceTaskEvent tte = read_task_trace_event(
      t, Arch::clone == t->regs().original_syscallno() ? TraceTaskEvent::CLONE
                                                       : TraceTaskEvent::FORK);
  ASSERT(t, tte.parent_tid() == t->rec_tid);
  long rec_tid = tte.tid();
  pid_t new_tid = t->get_ptrace_eventmsg_pid();

  remote_ptr<void> stack;
  remote_ptr<void> tls;
  remote_ptr<int> ctid;
  if (Arch::clone == t->regs().original_syscallno()) {
    remote_ptr<int>* ptid_not_needed = nullptr;
    extract_clone_parameters(t, &stack, ptid_not_needed, &tls, &ctid);
  }
  Task* new_task = t->session().clone(t, clone_flags_to_task_flags(flags),
                                      stack, tls, ctid, new_tid, rec_tid);

  if (Arch::clone == t->regs().original_syscallno()) {
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

  if (!(CLONE_VM & flags)) {
    // It's hard to imagine a scenario in which it would
    // be useful to inherit breakpoints (along with their
    // refcounts) across a non-VM-sharing clone, but for
    // now we never want to do this.
    new_task->vm()->remove_all_breakpoints();
    new_task->vm()->remove_all_watchpoints();
  }

  t->set_return_value_from_trace();
  t->validate_regs();

  init_scratch_memory(new_task);

  new_task->vm()->after_clone();

  step->action = TSTEP_RETIRE;
}

static void process_execve(Task* t, const TraceFrame& trace_frame,
                           SyscallEntryOrExit state, ReplayTraceStep* step) {
  if (is_failed_syscall(t, trace_frame)) {
    /* exec failed, emulate it */
    step->syscall.emu = EMULATE;
    step->action = syscall_action(state);
    return;
  }

  if (SYSCALL_ENTRY == state) {
    // Executed, not emulated.
    step->action = TSTEP_ENTER_SYSCALL;
    return;
  }

  step->action = TSTEP_RETIRE;

  /* The original_syscallno is execve in the old architecture. The kernel does
   * not update the original_syscallno when the architecture changes across
   * an exec.
   */
  int expect_syscallno = syscall_number_for_execve(t->arch());
  /* Wait for the PTRACE_EVENT_EXREC */
  __ptrace_cont(t, expect_syscallno);
  ASSERT(t, t->ptrace_event() == PTRACE_EVENT_EXEC)
      << "Expected PTRACE_EVENT_EXEC";

  /* Wait for the execve exit. */
  __ptrace_cont(t, expect_syscallno);

  t->post_exec(&trace_frame.regs(), &trace_frame.extra_regs());

  TraceTaskEvent tte = read_task_trace_event(t, TraceTaskEvent::EXEC);
  t->post_exec_syscall(tte);

  bool check = t->regs().arg1();
  /* if the execve comes from a vfork system call the ebx
   * register is not zero. in this case, no recorded data needs
   * to be injected */
  if (check == 0) {
    t->set_data_from_trace();
  }

  init_scratch_memory(t);

  t->vm()->save_auxv(t);
  t->set_return_value_from_trace();
  t->validate_regs();
}

/**
 * Return true if a FUTEX_LOCK_PI operation on |futex| done by |t|
 * will transition the futex into the contended state.  (This results
 * in the kernel atomically setting the FUTEX_WAITERS bit on the futex
 * value.)  The new value of the futex after the kernel updates it is
 * returned in |next_val|.
 */
static bool is_now_contended_pi_futex(Task* t, remote_ptr<int> futex,
                                      int* next_val) {
  int val = t->read_mem(futex);
  pid_t owner_tid = (val & FUTEX_TID_MASK);
  bool now_contended =
      (owner_tid != 0 && owner_tid != t->rec_tid && !(val & FUTEX_WAITERS));
  if (now_contended) {
    LOG(debug) << t->tid << ": futex " << futex << " is " << val
               << ", so WAITERS bit will be set";
    *next_val = (owner_tid & FUTEX_TID_MASK) | FUTEX_WAITERS;
  }
  return now_contended;
}

static void process_futex(Task* t, const TraceFrame& trace_frame,
                          SyscallEntryOrExit state, ReplayTraceStep* step) {
  step->syscall.emu = EMULATE;

  if (state == SYSCALL_ENTRY) {
    const Registers& regs = trace_frame.regs();
    int op = (int)regs.arg2_signed() & FUTEX_CMD_MASK;
    if (FUTEX_LOCK_PI == op) {
      remote_ptr<int> futex = regs.arg1();
      int next_val;
      if (is_now_contended_pi_futex(t, futex, &next_val)) {
        // During recording, we waited for the
        // kernel to update the futex, but
        // since we emulate SYS_futex in
        // replay, we need to set it ourselves
        // here.
        t->write_mem(futex, next_val);
      }
    }
    step->action = TSTEP_ENTER_SYSCALL;
    return;
  }

  step->action = TSTEP_EXIT_SYSCALL;
}

/**
 * Pass NOTE_TASK_MAP to update |t|'s cached mmap data.  If the data
 * need to be manually updated, pass |DONT_NOTE_TASK_MAP| and update
 * it manually.
 */
enum NoteTaskMap { DONT_NOTE_TASK_MAP = 0, NOTE_TASK_MAP };

static void finish_direct_mmap(
    AutoRemoteSyscalls& remote, const TraceFrame& trace_frame,
    remote_ptr<void> rec_addr, size_t length, int prot, int flags,
    const TraceMappedRegion& file, off64_t mmap_offset_pages,
    const string& backing_file_name, off64_t backing_offset_pages,
    NoteTaskMap note_task_map = NOTE_TASK_MAP) {
  Task* t = remote.task();
  int fd;

  LOG(debug) << "directly mmap'ing " << length << " bytes of "
             << backing_file_name << " at page offset "
             << HEX(backing_offset_pages);

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
    fd = remote.syscall(syscall_number_for_open(remote.arch()),
                        child_str.get().as_int(), oflags);
    if (0 > fd) {
      FATAL() << "Couldn't open " << backing_file_name << " to mmap in tracee";
    }
  }
  /* And mmap that file. */
  remote_ptr<void> mapped_addr =
      remote.mmap_syscall(rec_addr, length,
                          /* (We let SHARED|WRITEABLE
                           * mappings go through while
                           * they're not handled properly,
                           * but we shouldn't do that.) */
                          prot, flags | MAP_FIXED, fd, backing_offset_pages);
  ASSERT(t, mapped_addr == rec_addr);
  /* Don't leak the tmp fd.  The mmap doesn't need the fd to
   * stay open. */
  remote.syscall(syscall_number_for_close(remote.arch()), fd);

  if (note_task_map) {
    t->vm()->map(
        mapped_addr, length, prot, flags, page_size() * mmap_offset_pages,
        MappableResource(FileId(file.stat()), file.file_name().c_str()));
  }
}

static remote_ptr<void> finish_anonymous_mmap(
    AutoRemoteSyscalls& remote, const TraceFrame& trace_frame, size_t length,
    int prot, int flags, int fd, NoteTaskMap note_task_map = NOTE_TASK_MAP) {
  const Registers& rec_regs = trace_frame.regs();
  /* *Must* map the segment at the recorded address, regardless
     of what the recorded tracee passed as the |addr| hint. */
  remote_ptr<void> rec_addr = rec_regs.syscall_result();

  MappableResource r;
  if (flags & MAP_PRIVATE) {
    r = MappableResource::anonymous();
    auto result = remote.mmap_syscall(rec_addr, length, prot,
                                      // Tell the kernel to take |rec_addr|
                                      // seriously.
                                      flags | MAP_FIXED, fd, 0);
    ASSERT(remote.task(), rec_addr == result);
  } else {
    r = MappableResource::shared_mmap_anonymous(trace_frame.time());
    auto emufile =
        remote.task()->replay_session().emufs().create_anonymous(r.id, length);
    TraceMappedRegion vfile(TraceMappedRegion::MMAP, emufile->proc_path(),
                            emufile->stat(), rec_addr,
                            rec_addr + ceil_page_size(length));
    finish_direct_mmap(remote, trace_frame, rec_addr, length, prot,
                       flags & ~MAP_ANONYMOUS, vfile, 0, vfile.file_name(), 0,
                       DONT_NOTE_TASK_MAP);
  }

  if (note_task_map) {
    remote.task()->vm()->map(rec_addr, length, prot, flags, 0, r);
  }
  return rec_addr;
}

/* Ensure that accesses to the memory region given by start/length
   cause a SIGBUS, as for accesses beyond the end of an mmaped file. */
static void create_sigbus_region(AutoRemoteSyscalls& remote, int prot,
                                 remote_ptr<void> start, size_t length) {
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
    child_fd = remote.syscall(syscall_number_for_open(remote.arch()),
                              child_str.get(), O_RDONLY);
    if (0 > child_fd) {
      FATAL() << "Couldn't open " << filename << " to mmap in tracee";
    }
  }

  /* Unlink it now that the child has opened it */
  unlink(filename);

  /* mmap it in the tracee. We need to set the correct 'prot' flags
     so that the correct signal is generated on a memory access
     (SEGV if 'prot' doesn't allow the access, BUS if 'prot' does allow
     the access). */
  remote.mmap_syscall(start, length, prot, MAP_FIXED | MAP_PRIVATE, child_fd,
                      0);
  /* Don't leak the tmp fd.  The mmap doesn't need the fd to
   * stay open. */
  remote.syscall(syscall_number_for_close(remote.arch()), child_fd);
}

static void finish_private_mmap(AutoRemoteSyscalls& remote,
                                const TraceFrame& trace_frame, size_t length,
                                int prot, int flags, int fd,
                                off64_t offset_pages,
                                const TraceMappedRegion& file) {
  LOG(debug) << "  finishing private mmap of " << file.file_name();

  Task* t = remote.task();
  size_t num_bytes = length;
  remote_ptr<void> mapped_addr =
      finish_anonymous_mmap(remote, trace_frame, length, prot,
                            /* The restored region won't be backed
                             * by file. */
                            flags | MAP_ANONYMOUS, fd, DONT_NOTE_TASK_MAP);
  /* Restore the map region we copied. */
  ssize_t data_size = t->set_data_from_trace();

  /* Ensure pages past the end of the file fault on access */
  size_t data_pages = ceil_page_size(data_size);
  size_t mapped_pages = ceil_page_size(num_bytes);
  create_sigbus_region(remote, prot, mapped_addr + data_pages,
                       mapped_pages - data_pages);

  /* Mark the resource as ANONYMOUS since it's backed by an anonymous
   * mapping at the kernel level.
   */
  t->vm()->map(mapped_addr, num_bytes, prot, flags, page_size() * offset_pages,
               MappableResource(FileId(file.stat(), PSEUDODEVICE_ANONYMOUS),
                                file.file_name().c_str()));
}

static void finish_shared_mmap(AutoRemoteSyscalls& remote,
                               const TraceFrame& trace_frame, int prot,
                               int flags, off64_t offset_pages,
                               const TraceMappedRegion& file) {
  Task* t = remote.task();
  auto buf = t->trace_reader().read_raw_data();
  size_t rec_num_bytes = ceil_page_size(buf.data.size());

  // Ensure there's a virtual file for the file that was mapped
  // during recording.
  auto emufile = t->replay_session().emufs().get_or_create(file);
  // Re-use the direct_map() machinery to map the virtual file.
  //
  // NB: the tracee will map the procfs link to our fd; there's
  // no "real" name for the file anywhere, to ensure that when
  // we exit/crash the kernel will clean up for us.
  TraceMappedRegion vfile(TraceMappedRegion::MMAP, emufile->proc_path(),
                          file.stat(), file.start(), file.end());
  finish_direct_mmap(remote, trace_frame, buf.addr, rec_num_bytes, prot, flags,
                     vfile, offset_pages, vfile.file_name(), offset_pages,
                     DONT_NOTE_TASK_MAP);
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
            << HEX(offset_bytes) << " to " << vfile.file_name();
  }
  LOG(debug) << "  restored " << buf.data.size() << " bytes at "
             << HEX(offset_bytes) << " to " << vfile.file_name();

  t->vm()->map(buf.addr, buf.data.size(), prot, flags, offset_bytes,
               MappableResource::shared_mmap_file(file));
}

static void process_mmap(Task* t, const TraceFrame& trace_frame,
                         SyscallEntryOrExit state, size_t length, int prot,
                         int flags, int fd, off64_t offset_pages,
                         ReplayTraceStep* step) {
  if (SYSCALL_ENTRY == state) {
    /* We emulate entry for all types of mmap calls,
     * successful and not. */
    step->action = TSTEP_ENTER_SYSCALL;
    step->syscall.emu = EMULATE;
    return;
  }

  if (trace_frame.regs().syscall_failed()) {
    /* Failed maps are fully emulated too; nothing
     * interesting to do. */
    step->action = TSTEP_EXIT_SYSCALL;
    step->syscall.emu = EMULATE;
    return;
  }

  /* Successful mmap calls are much more interesting to process. */
  {
    // Next we hand off actual execution of the mapping to the
    // appropriate helper.
    AutoRemoteSyscalls remote(t);
    if (flags & MAP_ANONYMOUS) {
      finish_anonymous_mmap(remote, trace_frame, length, prot, flags, fd);
    } else {
      TraceReader::MappedData data;
      auto file = t->trace_reader().read_mapped_region(&data);

      if (data.source == TraceReader::SOURCE_FILE) {
        finish_direct_mmap(remote, trace_frame,
                           trace_frame.regs().syscall_result(), length, prot,
                           flags, file, offset_pages, data.file_name,
                           data.file_data_offset_pages);
      } else {
        ASSERT(t, data.source == TraceReader::SOURCE_TRACE);
        if (!(MAP_SHARED & flags)) {
          finish_private_mmap(remote, trace_frame, length, prot, flags, fd,
                              offset_pages, file);
        } else {
          finish_shared_mmap(remote, trace_frame, prot, flags, offset_pages,
                             file);
        }
      }
    }
    // Finally, we finish by emulating the return value.
    remote.regs().set_syscall_result(trace_frame.regs().syscall_result());
  }
  t->validate_regs();

  step->action = TSTEP_RETIRE;
}

static void process_shmat(Task* t, const TraceFrame& trace_frame,
                          SyscallEntryOrExit state, int shmid, int shm_flags,
                          ReplayTraceStep* step) {
  if (SYSCALL_ENTRY == state) {
    step->action = TSTEP_ENTER_SYSCALL;
    step->syscall.emu = EMULATE;
    return;
  }

  if (trace_frame.regs().syscall_failed()) {
    step->action = TSTEP_EXIT_SYSCALL;
    step->syscall.emu = EMULATE;
    return;
  }

  {
    AutoRemoteSyscalls remote(t);
    TraceReader::MappedData data;
    auto file = t->trace_reader().read_mapped_region(&data);
    int prot = shm_flags_to_mmap_prot(shm_flags);
    int flags = MAP_SHARED;
    finish_shared_mmap(remote, trace_frame, prot, flags, 0, file);

    // Finally, we finish by emulating the return value.
    remote.regs().set_syscall_result(trace_frame.regs().syscall_result());
  }
  // on x86-32 we have an extra data record that we need to apply ---
  // the ipc syscall's klugy out-parameter.
  t->apply_all_data_records_from_trace();
  t->validate_regs();

  step->action = TSTEP_RETIRE;
}

static void process_shmdt(Task* t, const TraceFrame& trace_frame,
                          SyscallEntryOrExit state, remote_ptr<void> addr,
                          ReplayTraceStep* step) {
  if (SYSCALL_ENTRY == state) {
    step->action = TSTEP_ENTER_SYSCALL;
    step->syscall.emu = EMULATE;
    return;
  }

  if (trace_frame.regs().syscall_failed()) {
    step->action = TSTEP_EXIT_SYSCALL;
    step->syscall.emu = EMULATE;
    return;
  }

  {
    AutoRemoteSyscalls remote(t);
    auto mapping = t->vm()->mapping_of(addr);
    ASSERT(t, mapping.first.start == addr);
    int result = remote.syscall(syscall_number_for_munmap(t->arch()), addr,
                                mapping.first.end - addr);
    ASSERT(t, result == 0);
    remote.regs().set_syscall_result(trace_frame.regs().syscall_result());
  }
  t->validate_regs();

  step->action = TSTEP_RETIRE;
}

static void process_init_buffers(Task* t, SyscallEntryOrExit state,
                                 ReplayTraceStep* step) {
  /* This was a phony syscall to begin with. */
  step->syscall.emu = EMULATE;

  if (SYSCALL_ENTRY == state) {
    step->action = TSTEP_ENTER_SYSCALL;
    return;
  }

  step->action = TSTEP_RETIRE;

  /* Proceed to syscall exit so we can run our own syscalls. */
  remote_ptr<void> rec_child_map_addr =
      t->current_trace_frame().regs().syscall_result();

  /* We don't want the desched event fd during replay, because
   * we already know where they were.  (The perf_event fd is
   * emulated anyway.) */
  t->init_buffers(rec_child_map_addr, DONT_SHARE_DESCHED_EVENT_FD);

  ASSERT(t, t->syscallbuf_child.cast<void>() == rec_child_map_addr)
      << "Should have mapped syscallbuf at " << rec_child_map_addr
      << ", but it's at " << t->syscallbuf_child;
  t->validate_regs();
}

template <typename Arch>
static void rep_after_enter_syscall_arch(Task* t, int syscallno) {
  switch (syscallno) {
    case Arch::exit:
      t->destroy_buffers();
      break;

    case Arch::write:
    case Arch::writev: {
      int fd = (int)t->regs().arg1_signed();
      t->fd_table()->will_write(t, fd);
      break;
    }
  }
}

void rep_after_enter_syscall(Task* t, int syscallno) {
  RR_ARCH_FUNCTION(rep_after_enter_syscall_arch, t->arch(), t, syscallno)
}

template <typename Arch>
static void rep_process_syscall_arch(Task* t, ReplayTraceStep* step) {
  /* FIXME: don't shadow syscall() */
  int syscall = t->current_trace_frame().event().Syscall().number;
  const TraceFrame& trace_frame = t->replay_session().current_trace_frame();
  const Registers& trace_regs = trace_frame.regs();
  EmuFs::AutoGc maybe_gc(t->replay_session(), t->arch(), syscall,
                         trace_frame.event().Syscall().state);

  SyscallEntryOrExit state;
  switch (trace_frame.event().Syscall().state) {
    case ENTERING_SYSCALL:
      state = SYSCALL_ENTRY;
      break;
    case EXITING_SYSCALL:
      state = SYSCALL_EXIT;
      break;
    default:
      ASSERT(t, "Not entering or exiting?");
      return;
  }

  LOG(debug) << "processing " << t->syscall_name(syscall) << " ("
             << state_name(state) << ")";

  // sigreturns are never restartable, and the value of the
  // syscall-result register after a sigreturn is not actually the
  // syscall result --- and may be anything, including one of the values
  // below.
  if (SYSCALL_EXIT == state && trace_regs.syscall_may_restart() &&
      !is_sigreturn(syscall, t->arch())) {
    bool interrupted_restart = (EV_SYSCALL_INTERRUPTION == t->ev().type());
    // The tracee was interrupted while attempting to
    // restart a syscall.  We have to look at the previous
    // event to see which syscall we're trying to restart.
    if (interrupted_restart) {
      syscall = t->ev().Syscall().number;
      LOG(debug) << "  interrupted " << t->syscall_name(syscall)
                 << " interrupted again";
    }
    // During recording, when a syscall exits with a
    // restart "error", the kernel sometimes restarts the
    // tracee by resetting its $ip to the syscall entry
    // point, but other times restarts the syscall without
    // changing the $ip.  In the latter case, we have to
    // leave the syscall return "hanging".  If it's
    // restarted without changing the $ip, we'll skip
    // advancing to the restart entry below and just
    // emulate exit by setting the kernel outparams.
    //
    // It's probably possible to predict which case is
    // going to happen (seems to be for
    // -ERESTART_RESTARTBLOCK and
    // ptrace-declined-signal-delivery restarts), but it's
    // simpler and probably more reliable to just check
    // the tracee $ip at syscall restart to determine
    // whether syscall re-entry needs to occur.
    t->apply_all_data_records_from_trace();
    t->set_return_value_from_trace();
    // Use this record to recognize the syscall if it
    // indeed restarts.  If the syscall isn't restarted,
    // we'll pop this event eventually, at the point when
    // the recorder determined that the syscall wasn't
    // going to be restarted.
    if (!interrupted_restart) {
      // For interrupted SYS_restart_syscall's,
      // reuse the restart record, both because
      // that's semantically correct, and because
      // we'll only know how to pop one interruption
      // event later.
      t->push_event(Event(interrupted, SyscallEvent(syscall, t->arch())));
      t->ev().Syscall().regs = t->regs();
    }
    step->action = TSTEP_RETIRE;
    LOG(debug) << "  " << t->syscall_name(syscall) << " interrupted by "
               << trace_regs.syscall_result() << " at " << trace_regs.ip()
               << ", may restart";
    return;
  }

  if (Arch::restart_syscall == syscall) {
    ASSERT(t, EV_SYSCALL_INTERRUPTION == t->ev().type())
        << "Must have interrupted syscall to restart";

    syscall = t->ev().Syscall().number;
    if (SYSCALL_ENTRY == state) {
      remote_code_ptr intr_ip = t->ev().Syscall().regs.ip();
      auto cur_ip = t->ip();

      LOG(debug) << "'restarting' " << t->syscall_name(syscall)
                 << " interrupted by "
                 << t->ev().Syscall().regs.syscall_result() << " at " << intr_ip
                 << "; now at " << cur_ip;
      if (cur_ip == intr_ip) {
        // See long comment above; this
        // "emulates" the restart by just
        // continuing on from the interrupted
        // syscall.
        step->action = TSTEP_RETIRE;
        return;
      }
    } else {
      t->pop_syscall_interruption();
      LOG(debug) << "exiting restarted " << t->syscall_name(syscall);
    }
  }

  auto& table = syscall_defs<Arch>::table;
  if (syscall < 0 || syscall >= int(array_length(table))) {
    // map to an invalid syscall.
    syscall = array_length(table) - 1;
    // we ensure this when we construct the table
    assert(table[syscall].type == rep_UNDEFINED);
  }

  const struct syscall_def* def = &table[syscall];
  step->syscall.number = syscall;

  if (def->type == rep_UNDEFINED) {
    ASSERT(t, trace_regs.syscall_result_signed() == -ENOSYS)
        << "Valid but unhandled syscallno " << syscall;
    step->action = syscall_action(state);
    step->syscall.emu = EMULATE;
    return;
  }

  /* Manual implementations of irregular syscalls that need to do more during
   * replay than just modify register and memory state.
   */

  switch (syscall) {
    case Arch::clone:
      return process_clone<Arch>(t, trace_frame, state, step,
                                 trace_frame.regs().arg1(), syscall);

    case Arch::vfork:
      if (state == SYSCALL_EXIT) {
        Registers r = t->regs();
        r.set_original_syscallno(Arch::fork);
        t->set_regs(r);
      }
      return process_clone<Arch>(t, trace_frame, state, step, 0, Arch::fork);

    case Arch::fork:
      return process_clone<Arch>(t, trace_frame, state, step, 0, syscall);

    case Arch::execve:
      return process_execve(t, trace_frame, state, step);

    case Arch::futex:
      return process_futex(t, trace_frame, state, step);

    case Arch::mmap: {
      // process_mmap checks 'state' too, but we need to check it now to
      // avoid reading 'args' prematurely. When state == SYSCALL_ENTRY,
      // there could be a lot of code to execute before we reach the syscall.
      if (SYSCALL_ENTRY == state) {
        step->action = TSTEP_ENTER_SYSCALL;
        step->syscall.emu = EMULATE;
        return;
      }
      switch (Arch::mmap_semantics) {
        case Arch::StructArguments: {
          auto args = t->read_mem(
              remote_ptr<typename Arch::mmap_args>(trace_regs.arg1()));
          return process_mmap(t, trace_frame, state, args.len, args.prot,
                              args.flags, args.fd, args.offset / page_size(),
                              step);
        }
        case Arch::RegisterArguments:
          return process_mmap(t, trace_frame, state, trace_regs.arg2(),
                              trace_regs.arg3(), trace_regs.arg4(),
                              trace_regs.arg5(),
                              trace_regs.arg6() / page_size(), step);
      }
    }
    case Arch::mmap2:
      return process_mmap(t, trace_frame, state, trace_regs.arg2(),
                          trace_regs.arg3(), trace_regs.arg4(),
                          trace_regs.arg5(), trace_regs.arg6(), step);

    case Arch::shmat:
      return process_shmat(t, trace_frame, state, trace_regs.arg1(),
                           trace_regs.arg3(), step);

    case Arch::shmdt:
      return process_shmdt(t, trace_frame, state, trace_regs.arg1(), step);

    case Arch::ipc:
      switch ((int)trace_regs.arg1_signed()) {
        case SHMAT:
          return process_shmat(t, trace_frame, state, trace_regs.arg2(),
                               trace_regs.arg3(), step);
        case SHMDT:
          return process_shmdt(t, trace_frame, state, trace_regs.arg5(), step);
        default:
          break;
      }
      step->action = syscall_action(state);
      step->syscall.emu = EMULATE;
      break;

    case Arch::prctl: {
      step->action = syscall_action(state);
      step->syscall.emu = EMULATE;
      if (TSTEP_EXIT_SYSCALL == step->action) {
        switch ((int)trace_regs.arg1_signed()) {
          case PR_SET_NAME: {
            remote_ptr<void> arg2 = trace_regs.arg2();
            t->update_prname(arg2);
            AutoRemoteSyscalls remote(t);
            remote.syscall(syscall_number_for_prctl(t->arch()), PR_SET_NAME,
                           arg2);
            return;
          }
        }
      }
      return;
    }

    case Arch::sigreturn:
    case Arch::rt_sigreturn:
      if (state == SYSCALL_ENTRY) {
        step->syscall.emu = EMULATE;
        step->action = TSTEP_ENTER_SYSCALL;
        return;
      }
      t->set_regs(trace_regs);
      t->set_extra_regs(trace_frame.extra_regs());
      step->action = TSTEP_RETIRE;
      return;

    case Arch::write:
    case Arch::writev:
      step->syscall.emu = EMULATE;
      step->action = syscall_action(state);
      if (state == SYSCALL_EXIT) {
        /* write*() can be desched'd, but don't use scratch,
         * so we might have saved 0 bytes of scratch after a
         * desched. */
        maybe_noop_restore_syscallbuf_scratch(t);
      }
      return;

    case SYS_rrcall_init_buffers:
      return process_init_buffers(t, state, step);

    case SYS_rrcall_init_preload:
      step->syscall.emu = EMULATE;
      if (SYSCALL_ENTRY == state) {
        step->action = TSTEP_ENTER_SYSCALL;
        return;
      }
      /* Proceed to syscall exit so we can run our own syscalls. */
      t->set_return_value_from_trace();
      t->validate_regs();
      t->at_preload_init();
      step->action = TSTEP_RETIRE;
      return;

    case SYS_rrcall_notify_syscall_hook_exit:
      step->action = syscall_action(state);
      step->syscall.emu = EMULATE;
      if (SYSCALL_ENTRY == state) {
        ASSERT(t, t->syscallbuf_hdr);
        t->syscallbuf_hdr->notify_on_syscall_hook_exit = true;
      }
      return;

    default:
      step->action = syscall_action(state);
      step->syscall.emu = rep_EXEC == def->type ? EXEC : EMULATE;
      return;
  }
}

void rep_process_syscall(Task* t, ReplayTraceStep* step) {
  // Use the event's arch, not the task's, because the task's arch may
  // be out of date immediately after an exec.
  RR_ARCH_FUNCTION(rep_process_syscall_arch,
                   t->current_trace_frame().event().arch(), t, step)
}
