/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "ProcessSyscallRep"

#include "replay_syscall.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/if.h>
#include <linux/net.h>
#include <linux/mman.h>
#include <linux/prctl.h>
#include <linux/shm.h>
#include <linux/sem.h>
#include <linux/sockios.h>
#include <linux/soundcard.h>
#include <linux/wireless.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/quota.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <map>
#include <memory>
#include <sstream>
#include <string>

#include <rr/rr.h>

#include "preload/syscall_buffer.h"

#include "emufs.h"
#include "kernel_abi.h"
#include "log.h"
#include "remote_syscalls.h"
#include "replayer.h"
#include "session.h"
#include "syscalls.h"
#include "task.h"
#include "trace.h"
#include "util.h"

/* Uncomment this to check syscall names and numbers defined in syscall_defs.h
   against the definitions in unistd.h. This may cause the build to fail
   if unistd.h is slightly out of date, so it's not turned on by default. */
//#define CHECK_SYSCALL_NUMBERS

using namespace std;
using namespace rr;

enum SyscallDefType {
  rep_UNDEFINED = 0, /* NB: this symbol must have the value 0 */
  rep_EMU,
  rep_EXEC,
  rep_EXEC_RET_EMU,
  rep_IRREGULAR
};
struct syscall_def {
  int no;
  /* See syscall_defs.h for documentation on these values. */
  SyscallDefType type;
  /* Not meaningful for rep_IRREGULAR. */
  ssize_t num_emu_args;
};

#define SYSCALL_NUM(_name) X86Arch::_name

#define SYSCALLNO_X86(num)
#define SYSCALLNO_X86_64(num)
#define SYSCALL_UNDEFINED_X86_64()
#define SYSCALL_DEF0(_name, _type)                                             \
  { SYSCALL_NUM(_name), rep_##_type, 0 }                                       \
  ,
#define SYSCALL_DEF1(_name, _type, _, _1)                                      \
  { SYSCALL_NUM(_name), rep_##_type, 1 }                                       \
  ,
#define SYSCALL_DEF1_DYNSIZE(_name, _type, _, _1)                              \
  { SYSCALL_NUM(_name), rep_##_type, 1 }                                       \
  ,
#define SYSCALL_DEF1_STR(_name, _type, _)                                      \
  { SYSCALL_NUM(_name), rep_##_type, 1 }                                       \
  ,
#define SYSCALL_DEF2(_name, _type, _, _1, _2, _3)                              \
  { SYSCALL_NUM(_name), rep_##_type, 2 }                                       \
  ,
#define SYSCALL_DEF3(_name, _type, _, _1, _2, _3, _4, _5)                      \
  { SYSCALL_NUM(_name), rep_##_type, 3 }                                       \
  ,
#define SYSCALL_DEF4(_name, _type, _, _1, _2, _3, _4, _5, _6, _7)              \
  { SYSCALL_NUM(_name), rep_##_type, 4 }                                       \
  ,
#define SYSCALL_DEF_IRREG(_name, _type)                                        \
  { SYSCALL_NUM(_name), rep_IRREGULAR, -1 }                                    \
  ,
#define SYSCALL_DEF_UNSUPPORTED(_name)

static struct syscall_def syscall_defs[] = {
/* Not-yet-defined syscalls will end up being type
 * rep_UNDEFINED. */
#include "syscall_defs.h"
};

// Reserve a final element which is guaranteed to be an undefined syscall.
// Negative and out-of-range syscall numbers are mapped to this element.
static struct syscall_def syscall_table[X86Arch::SYSCALL_COUNT + 1];

__attribute__((constructor)) static void init_syscall_table() {
  static_assert(ALEN(syscall_defs) <= ALEN(syscall_table), "");
  for (size_t i = 0; i < ALEN(syscall_defs); ++i) {
    const struct syscall_def& def = syscall_defs[i];
    assert(def.no < (int)ALEN(syscall_table));
    assert(def.no == 0 || def.type != rep_UNDEFINED);
    syscall_table[def.no] = def;
  }

#ifdef CHECK_SYSCALL_NUMBERS

// Hack because our 'break' syscall is called '_break'
#define SYS__break SYS_break

#define SYSCALLNO_X86(num)
#define SYSCALLNO_X86_64(num)
#define SYSCALL_UNDEFINED_X86_64()
#define CHECK_SYSCALL_NUM(_name)                                               \
  static_assert(SYSCALL_NUM(_name) == SYS_##_name,                             \
                "Incorrect syscall number for " #_name);
#define SYSCALL_DEF0(_name, _type) CHECK_SYSCALL_NUM(_name)
#define SYSCALL_DEF1(_name, _type, _, _1) CHECK_SYSCALL_NUM(_name)
#define SYSCALL_DEF1_DYNSIZE(_name, _type, _, _1) CHECK_SYSCALL_NUM(_name)
#define SYSCALL_DEF1_STR(_name, _type, _) CHECK_SYSCALL_NUM(_name)
#define SYSCALL_DEF2(_name, _type, _, _1, _2, _3) CHECK_SYSCALL_NUM(_name)
#define SYSCALL_DEF3(_name, _type, _, _1, _2, _3, _4, _5)                      \
  CHECK_SYSCALL_NUM(_name)
#define SYSCALL_DEF4(_name, _type, _, _1, _2, _3, _4, _5, _6, _7)              \
  CHECK_SYSCALL_NUM(_name)
#define SYSCALL_DEF_IRREG(_name, _type) CHECK_SYSCALL_NUM(_name)
#define SYSCALL_DEF_UNSUPPORTED(_name) CHECK_SYSCALL_NUM(_name)

#include "syscall_defs.h"

#undef CHECK_SYSCALL_NUM

#endif // CHECK_SYSCALL_NUMBERS
}

#undef SYSCALL_NUM

/**
 * Compares the register file as it appeared in the recording phase
 * with the current register file.
 */
static void validate_args(int syscall, int state, Task* t) {
  /* don't validate anything before execve is done as the actual
   * process did not start prior to this point */
  if (!t->session().can_validate()) {
    return;
  }
  assert_child_regs_are(t, &t->current_trace_frame().recorded_regs);
}

/**
 * Proceeds until the next system call, which is not executed.
 */
static void goto_next_syscall_emu(Task* t) {
  t->cont_sysemu();

  int sig = t->pending_sig();
  if (is_ignored_replay_signal(sig)) {
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
  const int rec_syscall =
      t->current_trace_frame().recorded_regs.original_syscallno();
  const int current_syscall = t->regs().original_syscallno();

  if (current_syscall != rec_syscall) {
    /* this signal is ignored and most likey delivered
     * later, or was already delivered earlier */
    /* TODO: this code is now obselete */
    if (is_ignored_replay_signal(t->stop_sig())) {
      LOG(debug) << "do we come here?\n";
      /*t->replay_sig = SIGCHLD; // remove that if
       * spec does not work anymore */
      goto_next_syscall_emu(t);
      return;
    }

    ASSERT(t, current_syscall == rec_syscall)
        << "Should be at `" << t->syscallname(rec_syscall) << "', instead at `"
        << t->syscallname(current_syscall) << "'";
  }
  t->child_sig = 0;
}

/**
 * Proceeds until the next system call, which is being executed.
 */
static void __ptrace_cont(Task* t) {
  do {
    t->cont_syscall();
  } while (is_ignored_replay_signal(t->stop_sig()));

  ASSERT(t, !t->pending_sig()) << "Expected no pending signal, but got "
                               << t->pending_sig();
  t->child_sig = 0;

  /* check if we are synchronized with the trace -- should never fail */
  int rec_syscall = t->current_trace_frame().recorded_regs.original_syscallno();
  int current_syscall = t->regs().original_syscallno();
  ASSERT(t, current_syscall == rec_syscall)
      << "Should be at " << t->syscallname(rec_syscall) << ", but instead at "
      << t->syscallname(current_syscall);
}

template <typename Arch>
static void rep_maybe_replay_stdio_write_arch(Task* t) {
  if (!rr_flags()->redirect) {
    return;
  }

  assert(Arch::write == t->regs().original_syscallno() ||
         Arch::writev == t->regs().original_syscallno());

  int fd = t->regs().arg1_signed();
  if (fd == STDOUT_FILENO || fd == STDERR_FILENO) {
    size_t len = t->regs().arg3();
    void* addr = (void*)t->regs().arg2();
    uint8_t buf[len];
    // NB: |buf| may not be null-terminated.
    t->read_bytes_helper(addr, sizeof(buf), buf);
    maybe_mark_stdio_write(t, fd);
    if (len != (size_t)write(fd, buf, len)) {
      FATAL() << "Couldn't write stdio";
    }
  }
}

void rep_maybe_replay_stdio_write(Task* t)
    RR_ARCH_FUNCTION(rep_maybe_replay_stdio_write_arch, t->arch(),
                     t) static void exit_syscall_emu_ret(Task* t, int syscall) {
  t->set_return_value_from_trace();
  validate_args(syscall, STATE_SYSCALL_EXIT, t);
  t->finish_emulated_syscall();
}

static void exit_syscall_emu(Task* t, int syscall, int num_emu_args) {
  int i;

  for (i = 0; i < num_emu_args; ++i) {
    t->set_data_from_trace();
  }
  exit_syscall_emu_ret(t, syscall);
}

template <typename Arch> static void init_scratch_memory(Task* t) {
  /* Initialize the scratchpad as the recorder did, but make it
   * PROT_NONE. The idea is just to reserve the address space so
   * the replayed process address map looks like the recorded
   * process, if it were to be probed by madvise or some other
   * means. But we make it PROT_NONE so that rogue reads/writes
   * to the scratch memory are caught. */
  struct mmapped_file file;
  void* map_addr;

  t->ifstream() >> file;

  t->scratch_ptr = file.start;
  t->scratch_size = (uint8_t*)file.end - (uint8_t*)file.start;
  size_t sz = t->scratch_size;
  int prot = PROT_NONE;
  int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
  int fd = -1;
  off_t offset = 0;
  {
    AutoRemoteSyscalls remote(t);
    map_addr = (void*)remote.syscall(Arch::mmap2, t->scratch_ptr, sz, prot,
                                     flags, fd, offset);
  }
  ASSERT(t, t->scratch_ptr == map_addr) << "scratch mapped " << file.start
                                        << " during recording, but " << map_addr
                                        << " in replay";

  t->vm()->map(map_addr, sz, prot, flags, offset,
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
  if (t->is_untraced_syscall()) {
    LOG(debug) << "  noop-restoring scratch for write-only desched'd "
               << t->syscallname(t->regs().original_syscallno());
    t->set_data_from_trace();
  }
}

/**
 * Return true iff the syscall represented by |frame| (either entry to
 * or exit from) failed.
 */
static bool is_failed_syscall(Task* t, const struct trace_frame* frame) {
  struct trace_frame next_frame;
  if (STATE_SYSCALL_ENTRY == frame->ev.state) {
    next_frame = t->ifstream().peek_to(t->rec_tid, EventType(frame->ev.type),
                                       STATE_SYSCALL_EXIT);
    frame = &next_frame;
  }
  return SYSCALL_FAILED(frame->recorded_regs.syscall_result_signed());
}

template <typename Arch>
static void process_clone(Task* t, struct trace_frame* trace, int state,
                          struct rep_trace_step* step) {
  int syscallno = Arch::clone;
  if (is_failed_syscall(t, trace)) {
    /* creation failed, emulate it */
    step->syscall.emu = 1;
    step->syscall.emu_ret = 1;
    step->action = (state == STATE_SYSCALL_ENTRY) ? TSTEP_ENTER_SYSCALL
                                                  : TSTEP_EXIT_SYSCALL;
    return;
  }
  if (state == STATE_SYSCALL_ENTRY) {
    step->action = TSTEP_ENTER_SYSCALL;
    return;
  }

  Registers rec_regs = trace->recorded_regs;
  unsigned long flags = rec_regs.arg1();

  if (flags & CLONE_UNTRACED) {
    // See related comment in rec_process_event.c.
    rec_regs.set_arg1(flags & ~CLONE_UNTRACED);
    t->set_regs(rec_regs);
  }

  // TODO: can debugger signals interrupt us here?

  // The syscall may be interrupted. Keep trying it until we get the
  // ptrace event we're expecting.
  __ptrace_cont(t);
  while (!t->clone_syscall_is_complete()) {
    __ptrace_cont(t);
  }

  // Now continue again to get the syscall exit event.
  __ptrace_cont(t);
  ASSERT(t, !t->ptrace_event())
      << "Unexpected ptrace event while waiting for syscall exit; got "
      << ptrace_event_name(t->ptrace_event());

  long rec_tid = rec_regs.syscall_result_signed();
  pid_t new_tid = t->get_ptrace_eventmsg_pid();

  void* stack = (void*)t->regs().arg2();
  void* tls = (void*)t->regs().arg4();
  void* ctid = (void*)t->regs().arg5();
  unsigned long flags_arg =
      (Arch::clone == t->regs().original_syscallno()) ? t->regs().arg1() : 0;

  Task* new_task = t->session().clone(t, clone_flags_to_task_flags(flags_arg),
                                      stack, tls, ctid, new_tid, rec_tid);

  /* FIXME: what if registers are non-null and contain an
   * invalid address? */
  t->set_data_from_trace();
  t->set_data_from_trace();

  new_task->set_data_from_trace();
  new_task->set_data_from_trace();
  new_task->set_data_from_trace();
  if (!(CLONE_VM & flags)) {
    // It's hard to imagine a scenario in which it would
    // be useful to inherit breakpoints (along with their
    // refcounts) across a non-VM-sharing clone, but for
    // now we never want to do this.
    new_task->vm()->destroy_all_breakpoints();
    new_task->vm()->destroy_all_watchpoints();
  }

  Registers r = t->regs();
  /* set the ebp register to the recorded value -- it should not
   * point to data on that is used afterwards */
  r.set_fp(rec_regs.fp());
  // Restore the saved flags, to hide the fact that we may have
  // masked out CLONE_UNTRACED.
  r.set_arg1(flags);
  t->set_regs(r);
  t->set_return_value_from_trace();
  validate_args(syscallno, state, t);

  init_scratch_memory<Arch>(new_task);

  new_task->vm()->after_clone();

  step->action = TSTEP_RETIRE;
}

template <typename Arch>
static void process_execve(Task* t, struct trace_frame* trace, int state,
                           const Registers* rec_regs,
                           struct rep_trace_step* step) {
  const int syscallno = Arch::execve;

  if (is_failed_syscall(t, trace)) {
    /* exec failed, emulate it */
    step->syscall.emu = 1;
    step->syscall.emu_ret = 1;
    step->action = (state == STATE_SYSCALL_ENTRY) ? TSTEP_ENTER_SYSCALL
                                                  : TSTEP_EXIT_SYSCALL;
    return;
  }

  if (STATE_SYSCALL_ENTRY == state) {
    Event next_ev(t->ifstream().peek_frame().ev);
    if (EV_SYSCALL == next_ev.type() && Arch::execve == next_ev.Syscall().no &&
        EXITING_SYSCALL == next_ev.Syscall().state) {
      // The first entering-exec event, when the
      // tracee is /about to/ enter execve(),
      // records the PTRACE_EVENT_EXEC delivery.
      // (TODO: we don't need to record that.)  The
      // second entering-exec event is when the
      // tracee is in the exec call.  At that point,
      // the /next/ event will be the exiting-exec
      // event, which we're checking for here.
      t->pre_exec();
    }
    // Executed, not emulated.
    step->action = TSTEP_ENTER_SYSCALL;
    return;
  }

  step->action = TSTEP_RETIRE;

  /* Wait for the syscall exit */
  __ptrace_cont(t);
  ASSERT(t, !t->ptrace_event()) << "Expected no ptrace event, but got "
                                << ptrace_event_name(t->ptrace_event());

  /* We just saw a successful exec(), so from now on we know
   * that the address space layout for the replay tasks will
   * (should!) be the same as for the recorded tasks.  So we can
   * start validating registers at events. */
  t->session().after_exec();

  bool check = t->regs().arg1();
  /* if the execve comes from a vfork system call the ebx
   * register is not zero. in this case, no recorded data needs
   * to be injected */
  if (check == 0) {
    t->set_data_from_trace();
  }

  init_scratch_memory<Arch>(t);

  t->post_exec();

  t->set_return_value_from_trace();
  validate_args(syscallno, state, t);
}

static void process_futex(Task* t, int state, struct rep_trace_step* step,
                          const Registers* regs) {
  int op = (int)regs->arg2_signed() & FUTEX_CMD_MASK;
  void* futex = (void*)regs->arg1();

  step->syscall.emu = 1;
  step->syscall.emu_ret = 1;

  if (state == STATE_SYSCALL_ENTRY) {
    if (FUTEX_LOCK_PI == op) {
      uint32_t next_val;
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
  switch (op) {
    case FUTEX_LOCK_PI:
    case FUTEX_WAKE:
    case FUTEX_WAIT_BITSET:
    case FUTEX_WAIT:
    case FUTEX_UNLOCK_PI:
      step->syscall.num_emu_args = 1;
      return;
    case FUTEX_CMP_REQUEUE:
    case FUTEX_WAKE_OP:
    case FUTEX_CMP_REQUEUE_PI:
    case FUTEX_WAIT_REQUEUE_PI:
      step->syscall.num_emu_args = 2;
      return;
    default:
      FATAL() << "Unknown futex op " << op;
  }
}

static void process_ioctl(Task* t, int state, struct rep_trace_step* step) {
  step->syscall.emu = 1;
  step->syscall.emu_ret = 1;

  if (state == STATE_SYSCALL_ENTRY) {
    step->action = TSTEP_ENTER_SYSCALL;
    return;
  }

  step->action = TSTEP_EXIT_SYSCALL;
  int request = t->regs().arg2_signed();
  int dir = _IOC_DIR(request);

  LOG(debug) << "Processing ioctl " << HEX(request) << ": dir " << HEX(dir);

  /* Process special-cased ioctls first. */
  switch (request) {
    case SIOCGIFCONF:
      step->syscall.num_emu_args = 3;
      return;

    case SIOCETHTOOL:
    case SIOCGIFADDR:
    case SIOCGIFFLAGS:
    case SIOCGIFINDEX:
    case SIOCGIFMTU:
    case SIOCGIFNAME:
    case SIOCGIWRATE:
      step->syscall.num_emu_args = 2;
      return;

    case TCGETS:
    case TIOCINQ:
    case TIOCGWINSZ:
      step->syscall.num_emu_args = 1;
      return;
  }
  /* Now on to the "regular" ioctls. */

  if (!(_IOC_WRITE & dir)) {
    /* Deterministic ioctl(), no data to restore to the
     * tracee. */
    return;
  }

  switch (request) {
    default:
      FATAL() << "Unknown ioctl " << HEX(request);
  }
}

void process_ipc(Task* t, struct trace_frame* trace, int state,
                 struct rep_trace_step* step) {
  step->syscall.emu = 1;
  step->syscall.emu_ret = 1;
  if (STATE_SYSCALL_ENTRY == state) {
    step->action = TSTEP_ENTER_SYSCALL;
    return;
  }

  step->action = TSTEP_EXIT_SYSCALL;
  unsigned int call = trace->recorded_regs.arg1();
  LOG(debug) << "ipc call: " << call;
  switch (call) {
    case MSGCTL:
    case MSGRCV:
      step->syscall.num_emu_args = 1;
      return;
    default:
      step->syscall.num_emu_args = 0;
      return;
  }
}

/**
 * Pass NOTE_TASK_MAP to update |t|'s cached mmap data.  If the data
 * need to be manually updated, pass |DONT_NOTE_TASK_MAP| and update
 * it manually.
 */
enum {
  DONT_NOTE_TASK_MAP = 0,
  NOTE_TASK_MAP
};

template <typename Arch>
static void* finish_anonymous_mmap(AutoRemoteSyscalls& remote,
                                   struct trace_frame* trace, int prot,
                                   int flags, off64_t offset_pages,
                                   int note_task_map = NOTE_TASK_MAP) {
  const Registers* rec_regs = &trace->recorded_regs;
  /* *Must* map the segment at the recorded address, regardless
     of what the recorded tracee passed as the |addr| hint. */
  void* rec_addr = (void*)rec_regs->syscall_result();
  size_t length = rec_regs->arg2();
  /* These are supposed to be (-1, 0) respectively, but use
   * whatever the tracee passed to avoid stirring up trouble. */
  int fd = rec_regs->arg5_signed();

  if (note_task_map) {
    remote.task()->vm()->map(rec_addr, length, prot, flags,
                             page_size() * offset_pages,
                             MappableResource::anonymous());
  }
  return (void*)remote.syscall(Arch::mmap2, rec_addr, length, prot,
                               // Tell the kernel to take
                               // |rec_addr| seriously.
                               flags | MAP_FIXED, fd, offset_pages);
}

/* Ensure that accesses to the memory region given by start/length
   cause a SIGBUS, as for accesses beyond the end of an mmaped file. */
template <typename Arch>
static void create_sigbus_region(AutoRemoteSyscalls& remote, int prot,
                                 void* start, size_t length) {
  if (length == 0) {
    return;
  }

  /* Open an empty file in the tracee */
  char filename[] = PREFIX_FOR_EMPTY_MMAPED_REGIONS "XXXXXX";
  int fd = mkstemp(filename);
  /* Close our side immediately */
  close(fd);

  int child_fd;
  {
    AutoRestoreMem child_str(remote, filename);
    child_fd =
        remote.syscall(Arch::open, static_cast<void*>(child_str), O_RDONLY);
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
  remote.syscall(Arch::mmap2, start, length, prot, MAP_FIXED | MAP_PRIVATE,
                 child_fd, 0);
  /* Don't leak the tmp fd.  The mmap doesn't need the fd to
   * stay open. */
  remote.syscall(Arch::close, fd);
}

template <typename Arch>
static void* finish_private_mmap(AutoRemoteSyscalls& remote,
                                 struct trace_frame* trace, int prot, int flags,
                                 off64_t offset_pages,
                                 const struct mmapped_file* file) {
  LOG(debug) << "  finishing private mmap of " << file->filename;

  Task* t = remote.task();
  const Registers& rec_regs = trace->recorded_regs;
  size_t num_bytes = rec_regs.arg2();
  void* mapped_addr =
      finish_anonymous_mmap<Arch>(remote, trace, prot,
                                  /* The restored region
                                   * won't be backed by
                                   * file. */
                                  flags | MAP_ANONYMOUS, DONT_NOTE_TASK_MAP);
  /* Restore the map region we copied. */
  ssize_t data_size = t->set_data_from_trace();

  /* Ensure pages past the end of the file fault on access */
  size_t data_pages = ceil_page_size(data_size);
  size_t mapped_pages = ceil_page_size(num_bytes);
  create_sigbus_region<Arch>(remote, prot, (char*)mapped_addr + data_pages,
                             mapped_pages - data_pages);

  t->vm()->map(mapped_addr, num_bytes, prot, flags, page_size() * offset_pages,
               // Intentionally drop the stat() information
               // saved to trace so as to match /proc/maps's
               // device/inode info for this anonymous mapping.
               // Preserve the mapping name though, so
               // AddressSpace::dump() shows something useful.
               MappableResource(FileId(), file->filename));

  return mapped_addr;
}

static void verify_backing_file(const struct mmapped_file* file, int prot,
                                int flags) {
  struct stat metadata;
  if (stat(file->filename, &metadata)) {
    FATAL() << "Failed to stat " << file->filename << ": replay is impossible";
  }
  if (metadata.st_ino != file->stat.st_ino ||
      metadata.st_mode != file->stat.st_mode ||
      metadata.st_uid != file->stat.st_uid ||
      metadata.st_gid != file->stat.st_gid ||
      metadata.st_size != file->stat.st_size ||
      metadata.st_mtime != file->stat.st_mtime ||
      metadata.st_ctime != file->stat.st_ctime) {
    LOG(error)
        << "Metadata of " << file->filename
        << " changed: replay divergence likely, but continuing anyway ...";
  }
  if (should_copy_mmap_region(file->filename, &metadata, prot, flags,
                              WARN_DEFAULT)) {
    LOG(error) << file->filename
               << " wasn't copied during recording, but now it should be?";
  }
}

enum {
  DONT_VERIFY = 0,
  VERIFY_BACKING_FILE
};

template <typename Arch>
static void* finish_direct_mmap(AutoRemoteSyscalls& remote,
                                struct trace_frame* trace, int prot, int flags,
                                off64_t offset_pages,
                                const struct mmapped_file* file,
                                int verify = VERIFY_BACKING_FILE,
                                int note_task_map = NOTE_TASK_MAP) {
  Task* t = remote.task();
  Registers* rec_regs = &trace->recorded_regs;
  void* rec_addr = (void*)rec_regs->syscall_result();
  size_t length = rec_regs->arg2();
  int fd;
  void* mapped_addr;

  LOG(debug) << "directly mmap'ing " << length << " bytes of " << file->filename
             << " at page offset " << HEX(offset_pages);

  if (verify) {
    verify_backing_file(file, prot, flags);
  }

  /* Open in the tracee the file that was mapped during
   * recording. */
  {
    AutoRestoreMem child_str(remote, file->filename);
    /* We only need RDWR for shared writeable mappings.
     * Private mappings will happily COW from the mapped
     * RDONLY file.
     *
     * TODO: should never map any files writable */
    int oflags =
        (MAP_SHARED & flags) && (PROT_WRITE & prot) ? O_RDWR : O_RDONLY;
    /* TODO: unclear if O_NOATIME is relevant for mmaps */
    fd = remote.syscall(Arch::open, static_cast<void*>(child_str), oflags);
    if (0 > fd) {
      FATAL() << "Couldn't open " << file->filename << " to mmap in tracee";
    }
  }
  /* And mmap that file. */
  mapped_addr = (void*)remote.syscall(Arch::mmap2, rec_addr, length,
                                      /* (We let SHARED|WRITEABLE
                                       * mappings go through while
                                       * they're not handled properly,
                                       * but we shouldn't do that.) */
                                      prot, flags, fd, offset_pages);
  /* Don't leak the tmp fd.  The mmap doesn't need the fd to
   * stay open. */
  remote.syscall(Arch::close, fd);

  if (note_task_map) {
    t->vm()->map(mapped_addr, length, prot, flags, page_size() * offset_pages,
                 MappableResource(FileId(file->stat), file->filename));
  }

  return mapped_addr;
}

template <typename Arch>
static void* finish_shared_mmap(AutoRemoteSyscalls& remote,
                                struct trace_frame* trace, int prot, int flags,
                                off64_t offset_pages,
                                const struct mmapped_file* file) {
  Task* t = remote.task();
  const Registers& rec_regs = trace->recorded_regs;
  size_t rec_num_bytes = ceil_page_size(rec_regs.arg2());

  // Ensure there's a virtual file for the file that was mapped
  // during recording.
  auto emufile = t->replay_session().emufs().get_or_create(*file);
  // Re-use the direct_map() machinery to map the virtual file.
  //
  // NB: the tracee will map the procfs link to our fd; there's
  // no "real" name for the file anywhere, to ensure that when
  // we exit/crash the kernel will clean up for us.
  struct mmapped_file vfile = *file;
  strncpy(vfile.filename, emufile->proc_path().c_str(), sizeof(vfile.filename));
  void* mapped_addr =
      finish_direct_mmap<Arch>(remote, trace, prot, flags, offset_pages, &vfile,
                               DONT_VERIFY, DONT_NOTE_TASK_MAP);
  // Write back the snapshot of the segment that we recorded.
  // We have to write directly to the underlying file, because
  // the tracee may have mapped its segment read-only.
  //
  // TODO: this is a poor man's shared segment synchronization.
  // For full generality, we also need to emulate direct file
  // modifications through write/splice/etc.
  struct raw_data buf;
  t->ifstream() >> buf;
  assert(mapped_addr == buf.addr &&
         rec_num_bytes == ceil_page_size(buf.data.size()));

  off64_t offset_bytes = page_size() * offset_pages;
  if (ssize_t(buf.data.size()) !=
      pwrite64(emufile->fd(), buf.data.data(), buf.data.size(), offset_bytes)) {
    FATAL() << "Failed to write " << buf.data.size() << " bytes at "
            << HEX(offset_bytes) << " to " << vfile.filename;
  }
  LOG(debug) << "  restored " << buf.data.size() << " bytes at "
             << HEX(offset_bytes) << " to " << vfile.filename;

  t->vm()->map(mapped_addr, buf.data.size(), prot, flags, offset_bytes,
               MappableResource::shared_mmap_file(*file));

  return mapped_addr;
}

template <typename Arch>
static void process_mmap(Task* t, struct trace_frame* trace, int exec_state,
                         int prot, int flags, off64_t offset_pages,
                         struct rep_trace_step* step) {
  void* mapped_addr;

  if (SYSCALL_FAILED(trace->recorded_regs.syscall_result_signed())) {
    /* Failed maps are fully emulated too; nothing
     * interesting to do. */
    step->action = TSTEP_EXIT_SYSCALL;
    step->syscall.emu = 1;
    step->syscall.emu_ret = 1;
    return;
  }
  /* Successful mmap calls are much more interesting to process.
   * First we advance to the emulated syscall exit. */
  t->finish_emulated_syscall();
  {
    // Next we hand off actual execution of the mapping to the
    // appropriate helper.
    AutoRemoteSyscalls remote(t);
    if (flags & MAP_ANONYMOUS) {
      mapped_addr =
          finish_anonymous_mmap<Arch>(remote, trace, prot, flags, offset_pages);
    } else {
      struct mmapped_file file;
      t->ifstream() >> file;

      ASSERT(t, file.time == trace->global_time) << "mmap time " << file.time
                                                 << " should equal "
                                                 << trace->global_time;
      if (!file.copied) {
        mapped_addr = finish_direct_mmap<Arch>(remote, trace, prot, flags,
                                               offset_pages, &file);
      } else if (!(MAP_SHARED & flags)) {
        mapped_addr = finish_private_mmap<Arch>(remote, trace, prot, flags,
                                                offset_pages, &file);
      } else {
        mapped_addr = finish_shared_mmap<Arch>(remote, trace, prot, flags,
                                               offset_pages, &file);
      }
    }
    // Finally, we finish by emulating the return value.
    remote.regs().set_syscall_result((uintptr_t)mapped_addr);
  }
  validate_args(Arch::mmap2, exec_state, t);

  step->action = TSTEP_RETIRE;
}

/**
 * Restore the recorded msghdr pointed at in |t|'s address space by
 * |child_msghdr|.
 */
template <typename Arch>
void restore_struct_msghdr(Task* t, typename Arch::msghdr* child_msghdr) {
  typename Arch::msghdr msg;
  t->read_mem(child_msghdr, &msg);

  // Restore msg itself.
  t->set_data_from_trace();
  // Restore msg.msg_name.
  t->set_data_from_trace();
  // For each iovec arg, restore its recorded data.
  for (size_t i = 0; i < msg.msg_iovlen; ++i) {
    // Restore iov_base buffer.
    t->set_data_from_trace();
  }
  // Restore msg_control buffer.
  t->set_data_from_trace();
}

/** Like restore_struct_msghdr(), but for mmsghdr. */
template <typename Arch>
void restore_struct_mmsghdr(Task* t, typename Arch::mmsghdr* child_mmsghdr) {
  restore_struct_msghdr<Arch>(t, (typename Arch::msghdr*)child_mmsghdr);
  t->set_data_from_trace();
}

/**
 * Restore saved struct mmsghdr* msgvec
 */
template <typename Arch>
static void restore_msgvec(Task* t, int nmmsgs,
                           typename Arch::mmsghdr* pmsgvec) {
  for (int i = 0; i < nmmsgs; ++i, ++pmsgvec) {
    restore_struct_mmsghdr<Arch>(t, pmsgvec);
  }
}

/**
 * Restore saved msglen for each struct mmsghdr* of msgvec
 */
static void restore_msglen_for_msgvec(Task* t, int nmmsgs) {
  for (int i = 0; i < nmmsgs; ++i) {
    t->set_data_from_trace();
  }
}

/**
 * Return nonzero if this socketcall was "regular" and |step| was
 * updated appropriately, or zero if this was an irregular socketcall
 * that needs to be processed specially.
 */
template <typename Arch>
static void process_socketcall(Task* t, int state,
                               struct rep_trace_step* step) {
  unsigned int call;

  step->syscall.emu = 1;
  step->syscall.emu_ret = 1;

  if (state == STATE_SYSCALL_ENTRY) {
    step->action = TSTEP_ENTER_SYSCALL;
    return;
  }

  step->action = TSTEP_EXIT_SYSCALL;
  switch ((call = t->regs().arg1())) {
    /* FIXME: define a SSOT for socketcall record and
     * replay data, a la syscall_defs.h */
    case SYS_SOCKET:
    case SYS_CONNECT:
    case SYS_BIND:
    case SYS_LISTEN:
    case SYS_SENDMSG:
    case SYS_SEND:
    case SYS_SENDTO:
    case SYS_SETSOCKOPT:
    case SYS_SHUTDOWN:
      step->syscall.num_emu_args = 0;
      return;
    case SYS_GETPEERNAME:
    case SYS_GETSOCKNAME:
      step->syscall.num_emu_args = 2;
      return;
    case SYS_RECV:
      step->syscall.num_emu_args = 1;
      return;

    /* int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
     * int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int
     *flags);
     *
     * Note: The returned address is truncated if the buffer
     * provided is too small; in this case, addrlen will return a
     * value greater than was supplied to the call.
     *
     * For now we record the size of bytes that is returned by the
     * system call. We check in the replayer, if the buffer was
     * actually too small and throw an error there.
     */
    case SYS_ACCEPT:
    case SYS_ACCEPT4:
      /* FIXME: not quite sure about socket_addr */
      step->syscall.num_emu_args = 2;
      return;

    case SYS_SOCKETPAIR:
      step->syscall.num_emu_args = 1;
      return;

    case SYS_GETSOCKOPT:
      step->syscall.num_emu_args = 2;
      return;

    case SYS_RECVFROM:
      step->syscall.num_emu_args = 3;
      return;

    case SYS_RECVMSG: {
      // We manually restore the msg buffer.
      step->syscall.num_emu_args = 0;

      void* base_addr = (void*)t->current_trace_frame().recorded_regs.arg2();
      typename Arch::recvmsg_args args;
      t->read_mem(base_addr, &args);

      restore_struct_msghdr<Arch>(t, args.msg);
      return;
    }

    case SYS_RECVMMSG: {
      step->syscall.num_emu_args = 0;

      void* base_addr = (void*)t->current_trace_frame().recorded_regs.arg2();
      typename Arch::recvmmsg_args args;
      t->read_mem(base_addr, &args);

      restore_msgvec<Arch>(
          t, t->current_trace_frame().recorded_regs.syscall_result_signed(),
          args.msgvec);
      return;
    }

    case SYS_SENDMMSG: {
      restore_msglen_for_msgvec(
          t, t->current_trace_frame().recorded_regs.syscall_result_signed());
      return;
    }

    default:
      FATAL() << "Unhandled socketcall " << call;
  }
}

static void process_init_buffers(Task* t, int exec_state,
                                 struct rep_trace_step* step) {
  void* rec_child_map_addr;
  void* child_map_addr;

  /* This was a phony syscall to begin with. */
  step->syscall.emu = 1;
  step->syscall.emu_ret = 1;

  if (STATE_SYSCALL_ENTRY == exec_state) {
    step->action = TSTEP_ENTER_SYSCALL;
    return;
  }

  step->action = TSTEP_RETIRE;

  /* Proceed to syscall exit so we can run our own syscalls. */
  t->finish_emulated_syscall();
  rec_child_map_addr =
      (void*)t->current_trace_frame().recorded_regs.syscall_result();

  /* We don't want the desched event fd during replay, because
   * we already know where they were.  (The perf_event fd is
   * emulated anyway.) */
  child_map_addr =
      t->init_buffers(rec_child_map_addr, DONT_SHARE_DESCHED_EVENT_FD);

  ASSERT(t, child_map_addr == rec_child_map_addr)
      << "Should have mapped syscallbuf at " << rec_child_map_addr
      << ", but it's at " << child_map_addr;
  validate_args(SYS_rrcall_init_buffers, STATE_SYSCALL_EXIT, t);
}

template <typename Arch>
static void process_restart_syscall(Task* t, int syscallno) {
  switch (syscallno) {
    case Arch::nanosleep:
      /* Write the remaining-time outparam that we were
       * forced to during recording. */
      t->set_data_from_trace();

    default:
      return;
  }
}

static void dump_path_data(Task* t, int global_time, const char* tag,
                           char* filename, size_t filename_size,
                           const void* buf, size_t buf_len, void* addr) {
  format_dump_filename(t, global_time, tag, filename, filename_size);
  dump_binary_data(filename, tag, (const uint32_t*)buf, buf_len / 4, addr);
}

static void notify_save_data_error(Task* t, void* addr, const void* rec_buf,
                                   size_t rec_buf_len, const void* rep_buf,
                                   size_t rep_buf_len) {
  char rec_dump[PATH_MAX];
  char rep_dump[PATH_MAX];
  int global_time = t->current_trace_frame().global_time;

  dump_path_data(t, global_time, "rec_save_data", rec_dump, sizeof(rec_dump),
                 rec_buf, rec_buf_len, addr);
  dump_path_data(t, global_time, "rep_save_data", rep_dump, sizeof(rep_dump),
                 rep_buf, rep_buf_len, addr);

  ASSERT(t,
         (rec_buf_len == rep_buf_len && !memcmp(rec_buf, rep_buf, rec_buf_len)))
      << "Divergence in contents of 'tracee-save buffer'.  Recording executed\n"
         "\n"
         "  write(" << RR_MAGIC_SAVE_DATA_FD << ", " << addr << ", "
      << rec_buf_len << ")\n"
                        "\n"
                        "and replay executed\n"
                        "\n"
                        "  write(" << RR_MAGIC_SAVE_DATA_FD << ", " << addr
      << ", " << rep_buf_len
      << ")\n"
         "\n"
         "The contents of the tracee-save buffers have been dumped to disk.\n"
         "Compare them by using the following command\n"
         "\n"
         "$ diff -u " << rec_dump << " " << rep_dump
      << " >save-data-diverge.diff\n";
}

/**
 * If the tracee saved data in this syscall to the magic save-data fd,
 * read and check the replay buffer against the one saved during
 * recording.
 */
static void maybe_verify_tracee_saved_data(Task* t, const Registers* rec_regs) {
  int fd = rec_regs->arg1_signed();
  void* rep_addr = (void*)rec_regs->arg2();
  size_t rep_len = rec_regs->arg3();

  if (RR_MAGIC_SAVE_DATA_FD != fd) {
    return;
  }

  struct raw_data rec;
  t->ifstream() >> rec;

  // If the data address changed, something disastrous happened
  // and the buffers aren't comparable.  Just bail.
  ASSERT(t, rec.addr == rep_addr) << "Recorded write(" << rec.addr
                                  << ") being replayed as write(" << rep_addr
                                  << ")";

  uint8_t rep_buf[rep_len];
  t->read_bytes_helper(rep_addr, sizeof(rep_buf), rep_buf);
  if (rec.data.size() != rep_len || memcmp(rec.data.data(), rep_buf, rep_len)) {
    notify_save_data_error(t, rec.addr, rec.data.data(), rec.data.size(),
                           rep_buf, rep_len);
  }
}

template <typename Arch>
static void rep_after_enter_syscall_arch(Task* t, int syscallno) {
  switch (syscallno) {
    case Arch::exit:
      destroy_buffers(t);
      return;

    case Arch::write:
      maybe_verify_tracee_saved_data(t,
                                     &t->current_trace_frame().recorded_regs);
      return;

    default:
      return;
  }
}

void rep_after_enter_syscall(Task* t, int syscallno)
    RR_ARCH_FUNCTION(rep_after_enter_syscall_arch, t->arch(), t, syscallno)

    /**
     * Call this hook just before exiting a syscall.  Often Task
     * attributes need to be updated based on the finishing syscall.
     */
    template <typename Arch>
static void before_syscall_exit(Task* t, int syscallno) {
  switch (syscallno) {
    case Arch::set_robust_list:
      t->set_robust_list((void*)t->regs().arg1(), t->regs().arg2());
      return;

    case Arch::set_thread_area:
      t->set_thread_area((void*)t->regs().arg1());
      return;

    case Arch::set_tid_address:
      t->set_tid_addr((void*)t->regs().arg1());
      return;

    case Arch::sigaction:
    case Arch::rt_sigaction:
      // Use registers saved in the current trace frame since the
      // syscall result hasn't been updated to the
      // post-syscall-exit state yet.
      t->update_sigaction(t->current_trace_frame().recorded_regs);
      return;

    case Arch::sigprocmask:
    case Arch::rt_sigprocmask:
      // Use registers saved in the current trace frame since the
      // syscall result hasn't been updated to the
      // post-syscall-exit state yet.
      t->update_sigmask(t->current_trace_frame().recorded_regs);
      return;

    default:
      return;
  }
}

template <typename Arch>
static void rep_process_syscall_arch(Task* t, struct rep_trace_step* step) {
  int syscall =
      t->current_trace_frame().ev.data; /* FIXME: don't shadow syscall() */
  const struct syscall_def* def;
  struct trace_frame* trace = &t->replay_session().current_trace_frame();
  int state = trace->ev.state;
  const Registers* rec_regs = &trace->recorded_regs;
  AutoGc maybe_gc(t->replay_session(), syscall, state);

  LOG(debug) << "processing " << t->syscallname(syscall) << " ("
             << statename(state) << ")";

  if (STATE_SYSCALL_EXIT == state &&
      SYSCALL_MAY_RESTART(rec_regs->syscall_result_signed())) {
    bool interrupted_restart = (EV_SYSCALL_INTERRUPTION == t->ev().type());
    // The tracee was interrupted while attempting to
    // restart a syscall.  We have to look at the previous
    // event to see which syscall we're trying to restart.
    if (interrupted_restart) {
      syscall = t->ev().Syscall().no;
      LOG(debug) << "  interrupted " << t->syscallname(syscall)
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
    t->set_return_value_from_trace();
    process_restart_syscall<Arch>(t, syscall);
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
      t->push_event(Event(interrupted, SyscallEvent(syscall)));
      t->ev().Syscall().regs = t->regs();
    }
    step->action = TSTEP_RETIRE;
    LOG(debug) << "  " << t->syscallname(syscall) << " interrupted by "
               << rec_regs->syscall_result() << " at " << (void*)rec_regs->ip()
               << ", may restart";
    return;
  }

  if (Arch::restart_syscall == syscall) {
    ASSERT(t, EV_SYSCALL_INTERRUPTION == t->ev().type())
        << "Must have interrupted syscall to restart";

    syscall = t->ev().Syscall().no;
    if (STATE_SYSCALL_ENTRY == state) {
      void* intr_ip = (void*)t->ev().Syscall().regs.ip();
      void* cur_ip = (void*)t->ip();

      LOG(debug) << "'restarting' " << t->syscallname(syscall)
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
      LOG(debug) << "exiting restarted " << t->syscallname(syscall);
    }
  }

  if (syscall < 0 || syscall >= int(ALEN(syscall_table))) {
    // map to an invalid syscall.
    syscall = ALEN(syscall_table) - 1;
    // we ensure this when we construct the table
    assert(syscall_table[syscall].type == rep_UNDEFINED);
  }

  def = &syscall_table[syscall];
  ASSERT(t, rep_UNDEFINED != def->type) << "Valid but unhandled syscallno "
                                        << syscall;

  step->syscall.no = syscall;

  t->maybe_update_vm(syscall, state);

  if (rep_IRREGULAR != def->type) {
    step->syscall.num_emu_args = def->num_emu_args;
    step->action =
        STATE_SYSCALL_ENTRY == state ? TSTEP_ENTER_SYSCALL : TSTEP_EXIT_SYSCALL;
    step->syscall.emu = rep_EMU == def->type;
    step->syscall.emu_ret =
        rep_EMU == def->type || rep_EXEC_RET_EMU == def->type;
    // TODO: there are several syscalls below that aren't
    // /actually/ irregular, they just want to update some
    // state on syscall exit.  Convert them to use
    // before_syscall_exit().
    if (TSTEP_EXIT_SYSCALL == step->action) {
      before_syscall_exit<Arch>(t, syscall);
    }
    return;
  }

  assert(rep_IRREGULAR == def->type);

  /* Manual implementations of irregular syscalls. */

  switch (syscall) {
    case Arch::clone:
      return process_clone<Arch>(t, trace, state, step);

    case Arch::epoll_wait:
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      step->syscall.num_emu_args = 1;
      step->action = (STATE_SYSCALL_ENTRY == state) ? TSTEP_ENTER_SYSCALL
                                                    : TSTEP_EXIT_SYSCALL;
      return;

    case Arch::execve:
      return process_execve<Arch>(t, trace, state, rec_regs, step);

    case Arch::exit:
    case Arch::exit_group:
      step->syscall.emu = 0;
      assert(state == STATE_SYSCALL_ENTRY);
      step->action = TSTEP_ENTER_SYSCALL;
      return;

    case Arch::fcntl64:
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      if (STATE_SYSCALL_ENTRY == state) {
        step->action = TSTEP_ENTER_SYSCALL;
      } else {
        int cmd = t->regs().arg2_signed();

        step->action = TSTEP_EXIT_SYSCALL;
        switch (cmd) {
          case F_DUPFD:
          case F_GETFD:
          case F_GETFL:
          case F_SETFL:
          case F_SETFD:
          case F_SETLK:
#if F_SETLK64 != F_SETLK
          case F_SETLK64:
#endif
          case F_SETLKW:
#if F_SETLKW64 != F_SETLKW
          case F_SETLKW64:
#endif
          case F_SETOWN:
          case F_SETOWN_EX:
          case F_SETSIG:
            step->syscall.num_emu_args = 0;
            break;
          case F_GETLK:
#if F_GETLK64 != F_GETLK
          case F_GETLK64:
#endif
          case F_GETOWN_EX:
            step->syscall.num_emu_args = 1;
            break;
          default:
            FATAL() << "Unknown fcntl64 command: " << cmd;
        }
      }
      return;

    case Arch::futex:
      return process_futex(t, state, step, rec_regs);

    case Arch::getxattr:
    case Arch::lgetxattr:
    case Arch::fgetxattr:
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      step->syscall.num_emu_args = 1;
      step->action = (STATE_SYSCALL_ENTRY == state) ? TSTEP_ENTER_SYSCALL
                                                    : TSTEP_EXIT_SYSCALL;
      return;

    case Arch::ioctl:
      return process_ioctl(t, state, step);

    case Arch::ipc:
      return process_ipc(t, trace, state, step);

    case Arch::mmap: {
      if (STATE_SYSCALL_ENTRY == state) {
        step->action = TSTEP_ENTER_SYSCALL;
        step->syscall.emu = 1;
        return;
      }
      typename Arch::mmap_args args;
      t->read_mem((void*)t->regs().arg1(), &args);
      return process_mmap<Arch>(t, trace, state, args.prot, args.flags,
                                args.offset / 4096, step);
    }
    case Arch::mmap2:
      if (STATE_SYSCALL_ENTRY == state) {
        /* We emulate entry for all types of mmap calls,
         * successful and not. */
        step->action = TSTEP_ENTER_SYSCALL;
        step->syscall.emu = 1;
        return;
      }
      return process_mmap<Arch>(t, trace, state, trace->recorded_regs.arg3(),
                                trace->recorded_regs.arg4(),
                                trace->recorded_regs.arg6(), step);

    case Arch::nanosleep:
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      if (STATE_SYSCALL_ENTRY == state) {
        step->action = TSTEP_ENTER_SYSCALL;
      } else {
        step->action = TSTEP_EXIT_SYSCALL;
        step->syscall.num_emu_args = (trace->recorded_regs.arg2() != 0) ? 1 : 0;
      }
      return;

    case Arch::open:
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      step->action = (STATE_SYSCALL_ENTRY == state) ? TSTEP_ENTER_SYSCALL
                                                    : TSTEP_EXIT_SYSCALL;
      return;

    case Arch::poll:
    case Arch::ppoll:
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      step->syscall.num_emu_args = 1;
      step->action = (STATE_SYSCALL_ENTRY == state) ? TSTEP_ENTER_SYSCALL
                                                    : TSTEP_EXIT_SYSCALL;
      return;

    case Arch::prctl: {
      int option = trace->recorded_regs.arg1_signed();
      void* arg2 = (void*)trace->recorded_regs.arg2();
      if (PR_SET_NAME == option || PR_GET_NAME == option) {
        step->syscall.num_emu_args = 1;
        // We actually execute these.
        step->action = (STATE_SYSCALL_ENTRY == state) ? TSTEP_ENTER_SYSCALL
                                                      : TSTEP_EXIT_SYSCALL;
        if (TSTEP_EXIT_SYSCALL == step->action && PR_SET_NAME == option) {
          t->update_prname(arg2);
        }
        return;
      }
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      step->syscall.num_emu_args = 1;
      if (STATE_SYSCALL_ENTRY == state) {
        step->action = TSTEP_ENTER_SYSCALL;
        return;
      }
      step->action = TSTEP_EXIT_SYSCALL;
      step->syscall.num_emu_args = 1;
      return;
    }
    case Arch::ptrace:
      step->syscall.emu = 1;
      if (STATE_SYSCALL_ENTRY == state) {
        step->action = TSTEP_ENTER_SYSCALL;
        return;
      }
      // ptrace isn't supported yet, but we bend over
      // backwards to make traces that contain ptrace aborts
      // as pleasantly debuggable as possible.  This is
      // because several crash-monitoring systems use ptrace
      // to generate crash reports, and those are exactly
      // the kinds of events users will want to debug.
      ASSERT(t, false) << "Should have reached trace termination.";
      return; // not reached

    case Arch::quotactl:
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      if (state == STATE_SYSCALL_ENTRY) {
        step->action = TSTEP_ENTER_SYSCALL;
      } else {
        int cmd = t->regs().arg1_signed();

        step->action = TSTEP_EXIT_SYSCALL;
        switch (cmd & SUBCMDMASK) {
          case Q_GETQUOTA:
          case Q_GETINFO:
          case Q_GETFMT:
            step->syscall.num_emu_args = 1;
            break;
          default:
            step->syscall.num_emu_args = 0;
        }
      }
      return;

    case Arch::read:
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      if (STATE_SYSCALL_ENTRY == state) {
        step->action = TSTEP_ENTER_SYSCALL;
      } else {
        step->action = TSTEP_EXIT_SYSCALL;
        step->syscall.num_emu_args = 1;
      }
      return;

    case Arch::recvmmsg: {
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      if (STATE_SYSCALL_ENTRY == state) {
        step->action = TSTEP_ENTER_SYSCALL;
        return;
      }
      restore_msgvec<Arch>(t, rec_regs->syscall_result_signed(),
                           (typename Arch::mmsghdr*)rec_regs->arg2());
      step->action = TSTEP_EXIT_SYSCALL;
      return;
    }
    case Arch::rt_sigtimedwait:
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      step->syscall.num_emu_args = 1;
      step->action = (STATE_SYSCALL_ENTRY == state) ? TSTEP_ENTER_SYSCALL
                                                    : TSTEP_EXIT_SYSCALL;
      return;

    case Arch::sendfile64:
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      step->syscall.num_emu_args = 1;
      step->action = (STATE_SYSCALL_ENTRY == state) ? TSTEP_ENTER_SYSCALL
                                                    : TSTEP_EXIT_SYSCALL;
      return;

    case Arch::sendmmsg: {
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      if (STATE_SYSCALL_ENTRY == state) {
        step->action = TSTEP_ENTER_SYSCALL;
        return;
      }
      restore_msglen_for_msgvec(t, rec_regs->syscall_result_signed());
      step->action = TSTEP_EXIT_SYSCALL;
      return;
    }
    case Arch::sigreturn:
    case Arch::rt_sigreturn:
      if (state == STATE_SYSCALL_ENTRY) {
        step->syscall.emu = 1;
        step->action = TSTEP_ENTER_SYSCALL;
        return;
      }
      t->finish_emulated_syscall();
      t->set_regs(trace->recorded_regs);
      t->set_extra_regs(trace->recorded_extra_regs);
      step->action = TSTEP_RETIRE;
      return;

    case Arch::socketcall:
      return process_socketcall<Arch>(t, state, step);

    case Arch::splice:
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      step->syscall.num_emu_args = 2;
      step->action = (STATE_SYSCALL_ENTRY == state) ? TSTEP_ENTER_SYSCALL
                                                    : TSTEP_EXIT_SYSCALL;
      return;

    case Arch::_sysctl:
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      step->syscall.num_emu_args = 2;
      step->action = (STATE_SYSCALL_ENTRY == state) ? TSTEP_ENTER_SYSCALL
                                                    : TSTEP_EXIT_SYSCALL;
      return;

    case Arch::waitid:
    case Arch::waitpid:
    case Arch::wait4:
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      step->syscall.num_emu_args = Arch::wait4 == syscall ? 2 : 1;
      step->action = (STATE_SYSCALL_ENTRY == state) ? TSTEP_ENTER_SYSCALL
                                                    : TSTEP_EXIT_SYSCALL;
      return;

    case Arch::write:
    case Arch::writev:
      step->syscall.num_emu_args = 0;
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      if (state == STATE_SYSCALL_ENTRY) {
        step->action = TSTEP_ENTER_SYSCALL;
        return;
      }

      step->action = TSTEP_EXIT_SYSCALL;
      /* XXX technically this will print the output before
       * we reach the interrupt.  That could maybe cause
       * issues in the future. */
      rep_maybe_replay_stdio_write_arch<Arch>(t);
      /* write*() can be desched'd, but don't use scratch,
       * so we might have saved 0 bytes of scratch after a
       * desched. */
      maybe_noop_restore_syscallbuf_scratch(t);
      return;

    case Arch::sched_setaffinity:
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      step->syscall.num_emu_args = 0;
      step->action = (STATE_SYSCALL_ENTRY == state) ? TSTEP_ENTER_SYSCALL
                                                    : TSTEP_EXIT_SYSCALL;
      return;

    case SYS_rrcall_init_buffers:
      return process_init_buffers(t, state, step);

    case SYS_rrcall_monkeypatch_vdso:
      step->syscall.num_emu_args = 0;
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      if (STATE_SYSCALL_ENTRY == state) {
        step->action = TSTEP_ENTER_SYSCALL;
        return;
      }
      /* Proceed to syscall exit so we can run our own syscalls. */
      exit_syscall_emu(t, SYS_rrcall_monkeypatch_vdso, 0);
      monkeypatch_vdso(t);
      step->action = TSTEP_RETIRE;
      return;

    default:
      // Emulate, assuming it was an invalid syscall.
      if (STATE_SYSCALL_EXIT == state) {
        ASSERT(t, rec_regs->syscall_result_signed() == -ENOSYS)
            << "Unknown syscall should have returned -ENOSYS";
      }
      step->syscall.num_emu_args = 0;
      step->action = STATE_SYSCALL_ENTRY == state ? TSTEP_ENTER_SYSCALL
                                                  : TSTEP_EXIT_SYSCALL;
      step->syscall.emu = 1;
      step->syscall.emu_ret = 1;
      return;
  }
}

void rep_process_syscall(Task* t, struct rep_trace_step* step)
    RR_ARCH_FUNCTION(rep_process_syscall_arch, t->arch(), t, step)
