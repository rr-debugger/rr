/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RecordSession.h"

#include <limits.h>

#include <algorithm>
#include <sstream>

#include "AutoRemoteSyscalls.h"
#include "Flags.h"
#include "ftrace.h"
#include "kernel_metadata.h"
#include "log.h"
#include "record_signal.h"
#include "record_syscall.h"
#include "RecordTask.h"
#include "seccomp-bpf.h"

namespace rr {

// Undef si_addr_lsb since it's an alias for a field name that doesn't exist,
// and we need to use the actual field name.
#ifdef si_addr_lsb
#undef si_addr_lsb
#endif

using namespace rr;
using namespace std;

/**
 * Create a pulseaudio client config file with shm disabled.  That may
 * be the cause of a mysterious divergence.  Return an envpair to set
 * in the tracee environment.
 */
static string create_pulseaudio_config() {
  // TODO let PULSE_CLIENTCONFIG env var take precedence.
  static const char pulseaudio_config_path[] = "/etc/pulse/client.conf";
  if (access(pulseaudio_config_path, R_OK)) {
    // Assume pulseaudio isn't installed
    return "";
  }
  char tmp[] = "/tmp/rr-pulseaudio-client-conf-XXXXXX";
  int fd = mkstemp(tmp);
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  unlink(tmp);
  // The fd is deliberately leaked so that the /proc/fd link below works
  // indefinitely. But we stop it leaking into tracee processes.

  stringstream procfile;
  procfile << "/proc/" << getpid() << "/fd/" << fd;

  // Running cp passing the procfile path under Docker fails for some
  // odd filesystem-related reason, so just read/write the contents.
  int pulse_config_fd = open(pulseaudio_config_path, O_RDONLY, 0);
  if (pulse_config_fd < 0) {
    FATAL() << "Failed to open pulseaudio config file: '"
            << pulseaudio_config_path << "'";
  }

  char buf[BUFSIZ];
  while (true) {
    ssize_t size = read(pulse_config_fd, buf, BUFSIZ);
    if (size == 0) {
      break;
    } else if (size < 0) {
      FATAL() << "Failed to read pulseaudio config file";
    }
    if (write(fd, buf, size) != size) {
      FATAL() << "Failed to write temp pulseaudio config file to "
              << procfile.str();
    }
  }
  close(pulse_config_fd);

  char disable_shm[] = "disable-shm = true\n";
  ssize_t nwritten = write(fd, disable_shm, sizeof(disable_shm) - 1);
  if (nwritten != sizeof(disable_shm) - 1) {
    FATAL() << "Failed to append '" << disable_shm << "' to " << procfile.str();
  }
  stringstream envpair;
  envpair << "PULSE_CLIENTCONFIG=" << procfile.str();
  return envpair.str();
}

static int get_num_cpus() {
  int cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
  return cpus > 0 ? cpus : 1;
}

/**
 * Pick a CPU at random to bind to, unless --cpu-unbound has been given,
 * in which case we return -1.
 */
static int choose_cpu(RecordSession::BindCPU bind_cpu) {
  if (bind_cpu == RecordSession::UNBOUND_CPU) {
    return -1;
  }

  // Pin tracee tasks to logical CPU 0, both in
  // recording and replay.  Tracees can see which HW
  // thread they're running on by asking CPUID, and we
  // don't have a way to emulate it yet.  So if a tracee
  // happens to be scheduled on a different core in
  // recording than replay, it can diverge.  (And
  // indeed, has been observed to diverge in practice,
  // in glibc.)
  //
  // Note that we will pin both the tracee processes *and*
  // the tracer process.  This ends up being a tidy
  // performance win in certain circumstances,
  // presumably due to cheaper context switching and/or
  // better interaction with CPU frequency scaling.
  return random() % get_num_cpus();
}

template <typename T> static remote_ptr<T> mask_low_bit(remote_ptr<T> p) {
  return p.as_int() & ~uintptr_t(1);
}

template <typename Arch>
static void record_robust_futex_change(
    RecordTask* t, const typename Arch::robust_list_head& head,
    remote_ptr<void> base) {
  if (base.is_null()) {
    return;
  }
  remote_ptr<void> futex_void_ptr = base + head.futex_offset;
  auto futex_ptr = futex_void_ptr.cast<uint32_t>();
  // We can't just record the current futex value because at this point
  // in task exit the robust futex handling has not happened yet. So we have
  // to emulate what the kernel will do!
  bool ok = true;
  uint32_t val = t->read_mem(futex_ptr, &ok);
  if (!ok) {
    return;
  }
  if (pid_t(val & FUTEX_TID_MASK) != t->own_namespace_rec_tid) {
    return;
  }
  val = (val & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
  // Update memory now so that the kernel doesn't decide to do it later, at
  // a time that might race with other tracee execution.
  t->write_mem(futex_ptr, val);
  t->record_local(futex_ptr, &val);
}

/**
 * Any user-space writes performed by robust futex handling are captured here.
 * They must be emulated during replay; the kernel will not do it for us
 * during replay because the TID value in each futex is the recorded
 * TID, not the actual TID of the dying task.
 */
template <typename Arch>
static void record_robust_futex_changes_arch(RecordTask* t) {
  auto head_ptr = t->robust_list().cast<typename Arch::robust_list_head>();
  if (head_ptr.is_null()) {
    return;
  }
  ASSERT(t, t->robust_list_len() == sizeof(typename Arch::robust_list_head));
  bool ok = true;
  auto head = t->read_mem(head_ptr, &ok);
  if (!ok) {
    return;
  }
  record_robust_futex_change<Arch>(t, head,
                                   mask_low_bit(head.list_op_pending.rptr()));
  for (auto current = mask_low_bit(head.list.next.rptr());
       current.as_int() != head_ptr.as_int();) {
    record_robust_futex_change<Arch>(t, head, current);
    auto next = t->read_mem(current, &ok);
    if (!ok) {
      return;
    }
    current = mask_low_bit(next.next.rptr());
  }
}

static void record_robust_futex_changes(RecordTask* t) {
  RR_ARCH_FUNCTION(record_robust_futex_changes_arch, t->arch(), t);
}

/**
 * Return true if we handle a ptrace exit event for task t. When this returns
 * true, t has been deleted and cannot be referenced again.
 */
static bool handle_ptrace_exit_event(RecordTask* t) {
  if (t->ptrace_event() != PTRACE_EVENT_EXIT) {
    return false;
  }

  if (t->stable_exit) {
    LOG(debug) << "stable exit";
  } else {
    LOG(warn)
        << "unstable exit; may misrecord CLONE_CHILD_CLEARTID memory race";
    t->task_group()->destabilize();
  }

  record_robust_futex_changes(t);

  t->session().trace_writer().write_task_event(
      TraceTaskEvent::for_exit(t->tid, t->get_ptrace_eventmsg<int>()));

  // Delete t. t's destructor writes the final EV_(UNSTABLE_)EXIT.
  t->destroy();
  return true;
}

static void note_entering_syscall(RecordTask* t) {
  ASSERT(t, EV_SYSCALL == t->ev().type());
  t->ev().Syscall().state = ENTERING_SYSCALL;
  if (!t->ev().Syscall().is_restart) {
    /* Save a copy of the arg registers so that we
     * can use them to detect later restarted
     * syscalls, if this syscall ends up being
     * restarted.  We have to save the registers
     * in this rather awkward place because we
     * need the original registers; the restart
     * (if it's not a SYS_restart_syscall restart)
     * will use the original registers. */
    t->ev().Syscall().regs = t->regs();
  }
}

static void handle_seccomp_traced_syscall(
    RecordTask* t, RecordSession::StepState* step_state) {
  int syscallno = t->regs().original_syscallno();
  if (syscallno < 0) {
    // negative syscall numbers after a SECCOMP event
    // are treated as "skip this syscall". There will be one syscall event
    // reported instead of two. So fake an enter-syscall event now.
    t->emulate_syscall_entry(t->regs());
    t->push_event(SyscallEvent(syscallno, t->arch()));
    note_entering_syscall(t);
    // Don't continue yet. At the next iteration of record_step, we'll
    // enter syscall_state_changed and that will trigger a continue to
    // the syscall exit.
    step_state->continue_type = RecordSession::DONT_CONTINUE;
  } else {
    // The next continue needs to be a PTRACE_SYSCALL to observe
    // the enter-syscall event.
    step_state->continue_type = RecordSession::CONTINUE_SYSCALL;
  }
}

static void handle_seccomp_trap(RecordTask* t,
                                RecordSession::StepState* step_state,
                                uint16_t seccomp_data) {
  int syscallno = t->regs().original_syscallno();

  t->emulate_syscall_entry(t->regs());

  if (!t->is_in_untraced_syscall()) {
    t->push_event(SyscallEvent(syscallno, t->arch()));
    note_entering_syscall(t);
  }

  Registers r = t->regs();

  // Use NativeArch here because different versions of system headers
  // have inconsistent field naming.
  union {
    NativeArch::siginfo_t native_api;
    siginfo_t linux_api;
  } si;
  memset(&si, 0, sizeof(si));
  si.native_api.si_signo = SIGSYS;
  si.native_api.si_errno = seccomp_data;
  si.native_api.si_code = SYS_SECCOMP;
  switch (r.arch()) {
    case x86:
      si.native_api._sifields._sigsys._arch = AUDIT_ARCH_I386;
      break;
    case x86_64:
      si.native_api._sifields._sigsys._arch = AUDIT_ARCH_X86_64;
      break;
    default:
      assert(0 && "Unknown architecture");
      break;
  }
  si.native_api._sifields._sigsys._syscall = syscallno;
  // We don't set call_addr here, because the current ip() might not be the
  // ip() at which we deliver the signal, and they must match. In particular
  // this event might be triggered during syscallbuf processing but delivery
  // delayed until we exit the syscallbuf code.
  t->stash_synthetic_sig(si.linux_api, DETERMINISTIC_SIG);

  // Tests show that the current registers are preserved (on x86, eax/rax
  // retains the syscall number).
  r.set_syscallno(syscallno);
  // Cause kernel processing to skip the syscall
  r.set_original_syscallno(-1);
  t->set_regs(r);
  // Don't continue yet. At the next iteration of record_step, if we
  // recorded the syscall-entry we'll enter syscall_state_changed and
  // that will trigger a continue to the syscall exit.
  step_state->continue_type = RecordSession::DONT_CONTINUE;
}

static void handle_seccomp_errno(RecordTask* t,
                                 RecordSession::StepState* step_state,
                                 uint16_t seccomp_data) {
  int syscallno = t->regs().original_syscallno();

  t->emulate_syscall_entry(t->regs());

  if (!t->is_in_untraced_syscall()) {
    t->push_event(SyscallEvent(syscallno, t->arch()));
    note_entering_syscall(t);
  }

  Registers r = t->regs();
  // Cause kernel processing to skip the syscall
  r.set_original_syscallno(-1);
  r.set_syscall_result(-seccomp_data);
  t->set_regs(r);
  // Don't continue yet. At the next iteration of record_step, if we
  // recorded the syscall-entry we'll enter syscall_state_changed and
  // that will trigger a continue to the syscall exit.
  step_state->continue_type = RecordSession::DONT_CONTINUE;
}

bool RecordSession::handle_ptrace_event(RecordTask* t, StepState* step_state) {
  if (t->status().group_stop()) {
    last_task_switchable = ALLOW_SWITCH;
    step_state->continue_type = DONT_CONTINUE;
    return true;
  }

  int event = t->ptrace_event();
  if (!event) {
    return false;
  }

  LOG(debug) << "  " << t->tid << ": handle_ptrace_event "
             << ptrace_event_name(event) << ": event " << t->ev();

  switch (event) {
    case PTRACE_EVENT_SECCOMP_OBSOLETE:
    case PTRACE_EVENT_SECCOMP: {
      t->seccomp_bpf_enabled = true;
      uint16_t seccomp_data = t->get_ptrace_eventmsg_seccomp_data();
      if (seccomp_data == SECCOMP_RET_DATA) {
        handle_seccomp_traced_syscall(t, step_state);
      } else {
        uint32_t real_result =
            seccomp_filter_rewriter().map_filter_data_to_real_result(
                seccomp_data);
        uint16_t real_result_data = real_result & SECCOMP_RET_DATA;
        switch (real_result & SECCOMP_RET_ACTION) {
          case SECCOMP_RET_TRAP:
            handle_seccomp_trap(t, step_state, real_result_data);
            break;
          case SECCOMP_RET_ERRNO:
            handle_seccomp_errno(t, step_state, real_result_data);
            break;
          default:
            ASSERT(t, false) << "Seccomp result not handled";
            break;
        }
      }
      break;
    }

    case PTRACE_EVENT_EXEC:
      t->post_exec();

      // Skip past the ptrace event.
      step_state->continue_type = CONTINUE_SYSCALL;
      break;

    default:
      ASSERT(t, false) << "Unhandled ptrace event " << ptrace_event_name(event)
                       << "(" << event << ")";
      break;
  }

  return true;
}

static void debug_exec_state(const char* msg, RecordTask* t) {
  LOG(debug) << msg << ": status=" << t->status();
}

void RecordSession::task_continue(const StepState& step_state) {
  RecordTask* t = scheduler().current();

  ASSERT(t, step_state.continue_type != DONT_CONTINUE);
  // A task in an emulated ptrace-stop must really stay stopped
  ASSERT(t, !t->emulated_ptrace_stop_pending);

  bool may_restart = t->at_may_restart_syscall();

  if (may_restart && t->seccomp_bpf_enabled) {
    LOG(debug) << "  PTRACE_SYSCALL to possibly-restarted " << t->ev();
  }

  if (!t->vm()->first_run_event()) {
    t->vm()->set_first_run_event(trace_writer().time());
  }

  TicksRequest ticks_request;
  ResumeRequest resume;
  if (step_state.continue_type == CONTINUE_SYSCALL) {
    ticks_request = RESUME_NO_TICKS;
    resume = RESUME_SYSCALL;
  } else {
    ticks_request = (TicksRequest)max<Ticks>(
        0, scheduler().current_timeslice_end() - t->tick_count());
    bool singlestep =
        t->emulated_ptrace_cont_command == PTRACE_SINGLESTEP ||
        t->emulated_ptrace_cont_command == PTRACE_SYSEMU_SINGLESTEP;
    if (singlestep && is_at_syscall_instruction(t, t->ip())) {
      // We're about to singlestep into a syscall instruction.
      // Act like we're NOT singlestepping since doing a PTRACE_SINGLESTEP would
      // skip over the system call.
      LOG(debug)
          << "Clearing singlestep because we're about to enter a syscall";
      singlestep = false;
    }
    if (singlestep) {
      resume = RESUME_SINGLESTEP;
    } else {
      if (!t->seccomp_bpf_enabled || may_restart) {
        /* We won't receive PTRACE_EVENT_SECCOMP events until
         * the seccomp filter is installed by the
         * syscall_buffer lib in the child, therefore we must
         * record in the traditional way (with PTRACE_SYSCALL)
         * until it is installed. */
        resume = RESUME_SYSCALL;
      } else {
        /* When the seccomp filter is on, instead of capturing
         * syscalls by using PTRACE_SYSCALL, the filter will
         * generate the ptrace events. This means we allow the
         * process to run using PTRACE_CONT, and rely on the
         * seccomp filter to generate the special
         * PTRACE_EVENT_SECCOMP event once a syscall happens.
         * This event is handled here by simply allowing the
         * process to continue to the actual entry point of
         * the syscall (using cont_syscall_block()) and then
         * using the same logic as before. */
        resume = RESUME_CONT;
      }
    }
  }
  t->resume_execution(resume, RESUME_NONBLOCKING, ticks_request);
}

/**
 * Step |t| forward until the tracee syscall that disarms the desched
 * event. If a signal becomes pending in the interim, we stash it.
 * This allows the caller to deliver the signal after this returns.
 * (In reality the desched event will already have been disarmed before we
 * enter this function.)
 */
static void advance_to_disarm_desched_syscall(RecordTask* t) {
  int old_sig = 0;

  LOG(debug) << "desched: DISARMING_DESCHED_EVENT";
  /* TODO: send this through main loop. */
  /* TODO: mask off signals and avoid this loop. */
  do {
    t->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_UNLIMITED_TICKS);
    /* We can safely ignore TIME_SLICE_SIGNAL while trying to
     * reach the disarm-desched ioctl: once we reach it,
     * the desched'd syscall will be "done" and the tracee
     * will be at a preemption point.  In fact, we *want*
     * to ignore this signal.  Syscalls like read() can
     * have large buffers passed to them, and we have to
     * copy-out the buffered out data to the user's
     * buffer.  This happens in the interval where we're
     * reaching the disarm-desched ioctl, so that code is
     * susceptible to receiving TIME_SLICE_SIGNAL. */
    int sig = t->stop_sig();
    if (PerfCounters::TIME_SLICE_SIGNAL == sig) {
      continue;
    }
    // We should not receive SYSCALLBUF_DESCHED_SIGNAL since it should already
    // have been disarmed.
    ASSERT(t, SYSCALLBUF_DESCHED_SIGNAL != sig);
    if (sig && sig == old_sig) {
      LOG(debug) << "  coalescing pending " << signal_name(sig);
      continue;
    }
    if (sig) {
      LOG(debug) << "  " << signal_name(sig) << " now pending";
      t->stash_sig();
    }
  } while (!t->is_disarm_desched_event_syscall());

  // Exit the syscall.
  t->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);
}

/**
 * |t| is at a desched event and some relevant aspect of its state
 * changed.  (For now, changes except the original desched'd syscall
 * being restarted.)
 */
void RecordSession::desched_state_changed(RecordTask* t) {
  LOG(debug) << "desched: IN_SYSCALL";
  /* We need to ensure that the syscallbuf code doesn't
   * try to commit the current record; we've already
   * recorded that syscall.  The following event sets
   * the abort-commit bit. */
  t->syscallbuf_hdr->abort_commit = 1;
  t->record_event(Event(EV_SYSCALLBUF_ABORT_COMMIT, NO_EXEC_INFO, t->arch()));

  advance_to_disarm_desched_syscall(t);

  t->pop_desched();

  /* The tracee has just finished sanity-checking the
   * aborted record, and won't touch the syscallbuf
   * during this (aborted) transaction again.  So now
   * is a good time for us to reset the record counter. */
  t->delay_syscallbuf_reset = false;
  ASSERT(t, t->syscallbuf_hdr);
  // Run the syscallbuf exit hook. This ensures we'll be able to reset
  // the syscallbuf before trying to buffer another syscall.
  t->syscallbuf_hdr->notify_on_syscall_hook_exit = true;
}

static void syscall_not_restarted(RecordTask* t) {
  LOG(debug) << "  " << t->tid << ": popping abandoned interrupted " << t->ev()
             << "; pending events:";
#ifdef DEBUGTAG
  t->log_pending_events();
#endif
  t->pop_syscall_interruption();

  t->record_event(
      Event(EV_INTERRUPTED_SYSCALL_NOT_RESTARTED, NO_EXEC_INFO, t->arch()));
}

/**
 * "Thaw" a frozen interrupted syscall if |t| is restarting it.
 * Return true if a syscall is indeed restarted.
 *
 * A postcondition of this function is that |t->ev| is no longer a
 * syscall interruption, whether or whether not a syscall was
 * restarted.
 */
static bool maybe_restart_syscall(RecordTask* t) {
  if (is_restart_syscall_syscall(t->regs().original_syscallno(), t->arch())) {
    LOG(debug) << "  " << t->tid << ": SYS_restart_syscall'ing " << t->ev();
  }
  if (t->is_syscall_restart()) {
    t->ev().transform(EV_SYSCALL);
    Registers regs = t->regs();
    regs.set_original_syscallno(t->ev().Syscall().regs.original_syscallno());
    t->set_regs(regs);
    return true;
  }
  if (EV_SYSCALL_INTERRUPTION == t->ev().type()) {
    syscall_not_restarted(t);
  }
  return false;
}

/**
 * After a SYS_sigreturn "exit" of task |t| with return value |ret|,
 * check to see if there's an interrupted syscall that /won't/ be
 * restarted, and if so, pop it off the pending event stack.
 */
static void maybe_discard_syscall_interruption(RecordTask* t, intptr_t ret) {
  int syscallno;

  if (EV_SYSCALL_INTERRUPTION != t->ev().type()) {
    /* We currently don't track syscalls interrupted with
     * ERESTARTSYS or ERESTARTNOHAND, so it's possible for
     * a sigreturn not to affect the event stack. */
    LOG(debug) << "  (no interrupted syscall to retire)";
    return;
  }

  syscallno = t->ev().Syscall().number;
  if (0 > ret) {
    syscall_not_restarted(t);
  } else {
    ASSERT(t, syscallno == ret)
        << "Interrupted call was " << t->syscall_name(syscallno)
        << " and sigreturn claims to be restarting " << t->syscall_name(ret);
  }
}

/**
 * Copy the registers used for syscall arguments (not including
 * syscall number) from |from| to |to|.
 */
static void copy_syscall_arg_regs(Registers* to, const Registers& from) {
  to->set_arg1(from.arg1());
  to->set_arg2(from.arg2());
  to->set_arg3(from.arg3());
  to->set_arg4(from.arg4());
  to->set_arg5(from.arg5());
  to->set_arg6(from.arg6());
}

static void maybe_trigger_emulated_ptrace_syscall_exit_stop(RecordTask* t) {
  if (t->emulated_ptrace_cont_command == PTRACE_SYSCALL) {
    t->emulate_ptrace_stop(WaitStatus::for_syscall(t));
  } else if (t->emulated_ptrace_cont_command == PTRACE_SINGLESTEP ||
             t->emulated_ptrace_cont_command == PTRACE_SYSEMU_SINGLESTEP) {
    // Deliver the singlestep trap now that we've finished executing the
    // syscall.
    t->emulate_ptrace_stop(WaitStatus::for_stop_sig(SIGTRAP), nullptr,
                           SI_KERNEL);
  }
}

static void save_interrupted_syscall_ret_in_syscallbuf(RecordTask* t,
                                                       intptr_t retval) {
  // Record storing the return value in the syscallbuf record, where
  // we expect to find it during replay.
  auto child_rec = ((t->syscallbuf_child + 1).cast<uint8_t>() +
                    t->syscallbuf_hdr->num_rec_bytes)
                       .cast<struct syscallbuf_record>();
  int64_t ret = retval;
  t->record_local(REMOTE_PTR_FIELD(child_rec, ret), &ret);
}

void RecordSession::syscall_state_changed(RecordTask* t,
                                          StepState* step_state) {
  switch (t->ev().Syscall().state) {
    case ENTERING_SYSCALL_PTRACE:
      debug_exec_state("EXEC_SYSCALL_ENTRY_PTRACE", t);
      step_state->continue_type = DONT_CONTINUE;
      last_task_switchable = ALLOW_SWITCH;
      if (t->emulated_stop_type != NOT_STOPPED) {
        // Don't go any further.
        return;
      }
      if (t->ev().Syscall().in_sysemu) {
        // We'll have recorded just the ENTERING_SYSCAL_PTRACE event and
        // nothing else. Resume with an invalid syscall to ensure no real
        // syscall runs.
        t->pop_syscall();
        Registers r = t->regs();
        Registers orig_regs = r;
        r.set_original_syscallno(-1);
        t->set_regs(r);
        t->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);
        ASSERT(t, t->ip() == r.ip());
        t->set_regs(orig_regs);
        maybe_trigger_emulated_ptrace_syscall_exit_stop(t);
        return;
      }
      last_task_switchable = PREVENT_SWITCH;
      t->ev().Syscall().regs = t->regs();
      t->ev().Syscall().state = ENTERING_SYSCALL;
      return;

    case ENTERING_SYSCALL: {
      debug_exec_state("EXEC_SYSCALL_ENTRY", t);
      ASSERT(t, !t->emulated_ptrace_stop_pending);

      last_task_switchable = rec_prepare_syscall(t);
      t->record_event(t->ev(), RecordTask::FLUSH_SYSCALLBUF,
                      &t->ev().Syscall().regs);

      debug_exec_state("after cont", t);
      t->ev().Syscall().state = PROCESSING_SYSCALL;

      if (t->emulated_ptrace_stop_pending) {
        step_state->continue_type = DONT_CONTINUE;
      } else {
        // Resume the syscall execution in the kernel context.
        step_state->continue_type = CONTINUE_SYSCALL;
      }

      if (t->session().done_initial_exec() && Flags::get().check_cached_mmaps) {
        t->vm()->verify(t);
      }

      if (t->desched_rec() && t->is_in_untraced_syscall() &&
          t->ev().Syscall().is_restart && t->has_stashed_sig()) {
        // We have a signal to deliver but we're about to restart an untraced
        // syscall that may block and the desched event has been disarmed.
        // Rearm the desched event so if the syscall blocks, it will be
        // interrupted and we'll have a chance to deliver our signal.
        arm_desched_event(t);
      }

      return;
    }

    case PROCESSING_SYSCALL:
      debug_exec_state("EXEC_IN_SYSCALL", t);

      // Linux kicks tasks out of syscalls before delivering
      // signals.
      ASSERT(t, !t->stop_sig()) << "Signal " << signal_name(t->stop_sig())
                                << " pending while in syscall???";

      t->ev().Syscall().state = EXITING_SYSCALL;
      step_state->continue_type = DONT_CONTINUE;
      return;

    case EXITING_SYSCALL: {
      debug_exec_state("EXEC_SYSCALL_DONE", t);

      assert(t->stop_sig() == 0);

      int syscallno = t->ev().Syscall().number;
      intptr_t retval = t->regs().syscall_result_signed();

      if (t->desched_rec()) {
        // If we enabled the desched event above, disable it.
        disarm_desched_event(t);
        // Write syscall return value to the syscallbuf now. This lets replay
        // get the correct value even though we're aborting the commit. This
        // value affects register values in the preload code (which must be
        // correct since register values may escape).
        save_interrupted_syscall_ret_in_syscallbuf(t, retval);
      }

      // sigreturn is a special snowflake, because it
      // doesn't actually return.  Instead, it undoes the
      // setup for signal delivery, which possibly includes
      // preparing the tracee for a restart-syscall.  So we
      // take this opportunity to possibly pop an
      // interrupted-syscall event.
      if (is_sigreturn(syscallno, t->arch())) {
        ASSERT(t, t->regs().original_syscallno() == -1);
        t->record_current_event();
        t->pop_syscall();

        // We've finished processing this signal now.
        t->pop_signal_handler();
        t->record_event(Event(EV_EXIT_SIGHANDLER, NO_EXEC_INFO, t->arch()));

        maybe_discard_syscall_interruption(t, retval);

        if (EV_DESCHED == t->ev().type()) {
          LOG(debug) << "  exiting desched critical section";
          // The signal handler could have modified the apparent syscall
          // return handler. Save that value into the syscall buf again so
          // replay will pick it up later.
          save_interrupted_syscall_ret_in_syscallbuf(t, retval);
          desched_state_changed(t);
        }
      } else {
        LOG(debug) << "  original_syscallno:" << t->regs().original_syscallno()
                   << " (" << t->syscall_name(syscallno)
                   << "); return val:" << HEX(t->regs().syscall_result());

        /* a syscall_restart ending is equivalent to the
         * restarted syscall ending */
        if (t->ev().Syscall().is_restart) {
          LOG(debug) << "  exiting restarted " << t->syscall_name(syscallno);
        }

        /* TODO: is there any reason a restart_syscall can't
         * be interrupted by a signal and itself restarted? */
        bool may_restart = !is_restart_syscall_syscall(syscallno, t->arch())
                           // SYS_pause is either interrupted or
                           // never returns.  It doesn't restart.
                           && !is_pause_syscall(syscallno, t->arch()) &&
                           t->regs().syscall_may_restart();
        /* no need to process the syscall in case its
         * restarted this will be done in the exit from the
         * restart_syscall */
        if (!may_restart) {
          rec_process_syscall(t);
          if (t->session().done_initial_exec() &&
              Flags::get().check_cached_mmaps) {
            t->vm()->verify(t);
          }
        } else {
          LOG(debug) << "  may restart " << t->syscall_name(syscallno)
                     << " (from retval " << HEX(retval) << ")";

          rec_prepare_restart_syscall(t);
          /* If we may restart this syscall, we've most
           * likely fudged some of the argument
           * registers with scratch pointers.  We don't
           * want to record those fudged registers,
           * because scratch doesn't exist in replay.
           * So cover our tracks here. */
          Registers r = t->regs();
          copy_syscall_arg_regs(&r, t->ev().Syscall().regs);
          t->set_regs(r);
        }
        t->record_current_event();

        /* If we're not going to restart this syscall, we're
         * done with it.  But if we are, "freeze" it on the
         * event stack until the execution point where it
         * might be restarted. */
        if (!may_restart) {
          t->pop_syscall();
          if (EV_DESCHED == t->ev().type()) {
            LOG(debug) << "  exiting desched critical section";
            desched_state_changed(t);
          }
        } else {
          t->ev().transform(EV_SYSCALL_INTERRUPTION);
          t->ev().Syscall().is_restart = true;
        }
      }

      last_task_switchable = ALLOW_SWITCH;
      step_state->continue_type = DONT_CONTINUE;

      maybe_trigger_emulated_ptrace_syscall_exit_stop(t);
      return;
    }

    default:
      FATAL() << "Unknown exec state " << t->ev().Syscall().state;
  }
}

/** If the perf counters seem to be working return, otherwise don't return. */
void RecordSession::check_initial_task_syscalls(RecordTask* t,
                                                RecordResult* step_result) {
  if (done_initial_exec()) {
    return;
  }

  if (is_write_syscall(t->ev().Syscall().number, t->arch()) &&
      t->regs().arg1_signed() == -1) {
    Ticks ticks = t->tick_count();
    LOG(debug) << "ticks on entry to dummy write: " << ticks;
    if (ticks == 0) {
      step_result->status = RecordSession::STEP_SPAWN_FAILED;
      step_result->failure_message = string(
          "rr internal recorder error: Performance counter doesn't seem to "
          "be working. Are you perhaps running rr in a VM but didn't enable "
          "perf-counter virtualization?");
    }
  }

  if (is_exit_group_syscall(t->ev().Syscall().number, t->arch())) {
    step_result->status = RecordSession::STEP_SPAWN_FAILED;
    step_result->failure_message = read_spawned_task_error();
  }
}

/**
 * Take a NativeArch::siginfo_t& here instead of siginfo_t because different
 * versions of system headers have inconsistent field naming.
 */
template <typename Arch>
static void setup_sigframe_siginfo_arch(RecordTask* t,
                                        const siginfo_t& siginfo) {
  remote_ptr<typename Arch::siginfo_t> dest;
  switch (Arch::arch()) {
    case x86: {
      auto p = t->regs().sp().cast<typename Arch::unsigned_word>() + 2;
      dest = t->read_mem(p);
      break;
    }
    case x86_64:
      dest = t->regs().si();
      break;
    default:
      assert(0 && "Unknown architecture");
      break;
  }
  typename Arch::siginfo_t si = t->read_mem(dest);
  set_arch_siginfo(siginfo, t->arch(), &si, sizeof(si));
  t->write_mem(dest, si);
}

static void setup_sigframe_siginfo(RecordTask* t, const siginfo_t& siginfo) {
  RR_ARCH_FUNCTION(setup_sigframe_siginfo_arch, t->arch(), t, siginfo);
}

/**
 * Get t into a state where resume_execution with a signal will actually work.
 */
static void preinject_signal(RecordTask* t) {
  int sig = t->ev().Signal().siginfo.si_signo;

  /* Signal injection is tricky. Per the ptrace(2) man page, injecting
   * a signal while the task is not in a signal-stop is not guaranteed to work
   * (and indeed, we see that the kernel sometimes ignores such signals).
   * But some signals must be delayed until after the signal-stop that notified
   * us of them.
   * So, first we check if we're in a signal-stop that we can use to inject
   * a signal. Some (all?) SIGTRAP stops are *not* usable for signal injection.
   */
  if (t->stop_sig() && t->stop_sig() != SIGTRAP) {
    LOG(debug) << "    in signal-stop for " << signal_name(t->stop_sig());
  } else {
    /* We're not in a usable signal-stop. Force a signal-stop by sending
     * a new signal with tgkill (as the ptrace(2) man page recommends).
     */
    LOG(debug) << "    maybe not in signal-stop; tgkill(" << signal_name(sig)
               << ")";
    t->tgkill(sig);

    /* Now singlestep the task until we're in a signal-stop for the signal
     * we've just sent. We must absorb and forget that signal here since we
     * don't want it delivered to the task for real.
     */
    while (true) {
      auto old_ip = t->ip();
      t->resume_execution(RESUME_SINGLESTEP, RESUME_WAIT, RESUME_NO_TICKS);
      ASSERT(t, old_ip == t->ip());
      if (t->status().group_stop()) {
        /* Sending SIGCONT (4.4.3-300.fc23.x86_64) triggers this. Unclear why
         * it would... */
        continue;
      }
      ASSERT(t, t->stop_sig());
      if (t->stop_sig() == sig) {
        LOG(debug) << "    stopped with signal " << signal_name(sig);
        break;
      }
      /* It's possible for other signals to arrive while we're trying to
       * get to the signal-stop for the signal we just sent. Stash them for
       * later delivery.
       */
      if (t->stop_sig() == SYSCALLBUF_DESCHED_SIGNAL) {
        LOG(debug) << "    stopped with signal " << signal_name(sig)
                   << "; ignoring it and carrying on";
      } else {
        LOG(debug) << "    stopped with signal " << signal_name(sig)
                   << "; stashing it and carrying on";
        t->stash_sig();
      }
    }
    /* We're now in a signal-stop (and for the right signal too, though that
     * doesn't really matter).
     */
  }

  /* Now that we're in a signal-stop, we can inject our signal and advance
   * to the signal handler with one single-step.
   */
  LOG(debug) << "    injecting signal number " << t->ev().Signal().siginfo;
  t->set_siginfo(t->ev().Signal().siginfo);
}

/**
 * Returns true if the signal should be delivered.
 * Returns false if this signal should not be delivered because another signal
 * occurred during delivery.
 */
static bool inject_handled_signal(RecordTask* t) {
  preinject_signal(t);

  int sig = t->ev().Signal().siginfo.si_signo;
  t->resume_execution(RESUME_SINGLESTEP, RESUME_WAIT, RESUME_NO_TICKS, sig);

  // It's been observed that when tasks enter
  // sighandlers, the singlestep operation above
  // doesn't retire any instructions; and
  // indeed, if an instruction could be retired,
  // this code wouldn't work.  This also
  // cross-checks the sighandler information we
  // maintain in |t->sighandlers|.
  assert(!PerfCounters::extra_perf_counters_enabled() ||
         0 == t->hpc.read_extra().instructions_retired);

  if (t->stop_sig() == SIGSEGV) {
    // Constructing the signal handler frame must have failed. The kernel will
    // kill the process after this. Stash the signal and mark it as blocked so
    // we know to treat it as fatal when we inject it.
    t->stash_sig();
    t->set_sig_blocked(SIGSEGV);
    return false;
  }

  // We stepped into a user signal handler.
  ASSERT(t, t->stop_sig() == SIGTRAP);
  ASSERT(t, t->get_signal_user_handler(sig) == t->ip());

  if (t->signal_handler_takes_siginfo(sig)) {
    // The kernel copied siginfo into userspace so it can pass a pointer to
    // the signal handler. Replace the contents of that siginfo with
    // the exact data we want to deliver. (We called Task::set_siginfo
    // above to set that data, but the kernel sanitizes the passed-in data
    // which wipes out certain fields; e.g. we can't set SI_KERNEL in si_code.)
    setup_sigframe_siginfo(t, t->ev().Signal().siginfo);
  }
  return true;
}

static bool is_fatal_signal(RecordTask* t, int sig,
                            SignalDeterministic deterministic) {
  signal_action action = default_action(sig);
  if (action != DUMP_CORE && action != TERMINATE) {
    // If the default action doesn't kill the process, it won't die.
    return false;
  }

  if (t->is_sig_ignored(sig)) {
    // Deterministic fatal signals can't be ignored.
    return deterministic == DETERMINISTIC_SIG;
  }
  if (!t->signal_has_user_handler(sig)) {
    // The default action is going to happen: killing the process.
    return true;
  }
  // If the signal's blocked, user handlers aren't going to run and the process
  // will die.
  return t->is_sig_blocked(sig);
}

/**
 * |t| is being delivered a signal, and its state changed.
 *
 * Return true if execution was incidentally resumed to a new event,
 * false otherwise.
 */
void RecordSession::signal_state_changed(RecordTask* t, StepState* step_state) {
  int sig = t->ev().Signal().siginfo.si_signo;

  switch (t->ev().type()) {
    case EV_SIGNAL: {
      // This event is used by the replayer to advance to
      // the point of signal delivery.
      t->record_current_event();
      t->ev().transform(EV_SIGNAL_DELIVERY);
      ssize_t sigframe_size = 0;

      bool blocked = t->is_sig_blocked(sig);
      // If this is the signal delivered by a sigsuspend, then clear
      // sigsuspend_blocked_sigs to indicate that future signals are not
      // being delivered by sigsuspend.
      t->sigsuspend_blocked_sigs = nullptr;

      // If a signal is blocked but is still delivered (e.g. a synchronous
      // terminating signal such as SIGSEGV), user handlers do not run.
      if (t->signal_has_user_handler(sig) && !blocked) {
        LOG(debug) << "  " << t->tid << ": " << signal_name(sig)
                   << " has user handler";

        if (!inject_handled_signal(t)) {
          // Signal delivery isn't happening. Prepare to process the new
          // signal that aborted signal delivery.
          t->signal_delivered(sig);
          t->pop_event(EV_SIGNAL_DELIVERY);
          step_state->continue_type = DONT_CONTINUE;
          last_task_switchable = PREVENT_SWITCH;
          break;
        }

        // It's somewhat difficult engineering-wise to
        // compute the sigframe size at compile time,
        // and it can vary across kernel versions.  So
        // this size is an overestimate of the real
        // size(s).  The estimate was made by
        // comparing $sp before and after entering the
        // sighandler, for a sighandler that used the
        // main task stack.  On linux 3.11.2, that
        // computed size was 1736 bytes, which is an
        // upper bound on the sigframe size.  We don't
        // want to mess with this code much, so we
        // overapproximate the overapproximation and
        // round off to 2048.
        //
        // If this size becomes too small in the
        // future, and unit tests that use sighandlers
        // are run with checksumming enabled, then
        // they can catch errors here.
        sigframe_size = 2048;

        t->ev().transform(EV_SIGNAL_HANDLER);
        t->signal_delivered(sig);
        // We already continued! Don't continue now, and allow switching.
        step_state->continue_type = DONT_CONTINUE;
        last_task_switchable = ALLOW_SWITCH;
      } else {
        LOG(debug) << "  " << t->tid << ": no user handler for "
                   << signal_name(sig);
        // Don't do another task continue. We want to deliver the signal
        // as the next thing that the task does.
        step_state->continue_type = DONT_CONTINUE;
        // If we didn't set up the sighandler frame, we need
        // to ensure that this tracee is scheduled next so
        // that we can deliver the signal normally.  We have
        // to do that because setting up the sighandler frame
        // is synchronous, but delivery otherwise is async.
        // But right after this, we may have to process some
        // syscallbuf state, so we can't let the tracee race
        // with us.
        last_task_switchable = PREVENT_SWITCH;
      }

      // We record this data regardless to simplify replay. If the addresses
      // are unmapped, write 0 bytes.
      t->record_remote_fallible(t->regs().sp(), sigframe_size);

      // This event is used by the replayer to set up the
      // signal handler frame, or to record the resulting
      // state of the stepi if there wasn't a signal
      // handler.
      t->record_current_event();
      break;
    }

    case EV_SIGNAL_DELIVERY: {
      // Only inject fatal signals. Non-fatal signals with signal handlers
      // were taken care of above; for non-fatal signals without signal
      // handlers, there is no need to deliver the signal at all. In fact,
      // there is really no way to inject a non-fatal, non-handled signal
      // without letting the task execute at least one instruction, which
      // we don't want to do here.
      if (is_fatal_signal(t, sig, t->ev().Signal().deterministic) &&
          sig != get_continue_through_sig()) {
        preinject_signal(t);
        t->resume_execution(RESUME_CONT, RESUME_NONBLOCKING, RESUME_NO_TICKS,
                            sig);
        LOG(warn) << "Delivered core-dumping signal; may misrecord "
                     "CLONE_CHILD_CLEARTID memory race";
        t->task_group()->destabilize();
      }
      t->signal_delivered(sig);
      t->pop_signal_delivery();
      // A fatal signal or SIGSTOP requires us to allow switching to another
      // task.
      last_task_switchable = ALLOW_SWITCH;
      step_state->continue_type = DONT_CONTINUE;
      break;
    }

    default:
      FATAL() << "Unhandled signal state " << t->ev().type();
      break;
  }
}

bool RecordSession::handle_signal_event(RecordTask* t, StepState* step_state) {
  int sig = t->stop_sig();
  if (!sig) {
    return false;
  }
  if (!done_initial_exec()) {
    // If the initial tracee isn't prepared to handle
    // signals yet, then us ignoring the ptrace
    // notification here will have the side effect of
    // declining to deliver the signal.
    //
    // This doesn't really occur in practice, only in
    // tests that force a degenerately low time slice.
    LOG(warn) << "Dropping " << signal_name(sig)
              << " because it can't be delivered yet";
    // No events to be recorded, so no syscallbuf updates
    // needed.
    return true;
  }
  SignalDeterministic deterministic = is_deterministic_signal(t);
  if (deterministic || sig == SYSCALLBUF_DESCHED_SIGNAL) {
    // Don't stash these signals; deliver them immediately.
    // We don't want them to be reordered around other signals.
    siginfo_t siginfo = t->get_siginfo();
    switch (handle_signal(t, &siginfo, deterministic)) {
      case SIGNAL_PTRACE_STOP:
        // Emulated ptrace-stop. Don't run the task again yet.
        last_task_switchable = ALLOW_SWITCH;
        step_state->continue_type = DONT_CONTINUE;
        return true;
      case DEFER_SIGNAL:
        ASSERT(t, false) << "Can't defer deterministic or internal signal "
                         << siginfo << " at ip " << t->ip();
        break;
      case SIGNAL_HANDLED:
        break;
    }
    return false;
  }
  if (sig == PerfCounters::TIME_SLICE_SIGNAL) {
    auto& si = t->get_siginfo();
    /* This implementation will of course fall over if rr tries to
     * record itself.
     *
     * NB: we can't check that the ticks is >= the programmed
     * target, because this signal may have become pending before
     * we reset the HPC counters.  There be a way to handle that
     * more elegantly, but bridge will be crossed in due time.
     *
     * We can't check that the fd matches t->hpc.ticks_fd() because this
     * signal could have been queued quite a long time ago and the PerfCounters
     * might have been stopped (and restarted!), perhaps even more than once,
     * since the signal was queued. possibly changing its fd. We could check
     * against all fds the PerfCounters have ever used, but that seems like
     * overkill.
     */
    ASSERT(t, PerfCounters::TIME_SLICE_SIGNAL == si.si_signo &&
                  (RecordTask::SYNTHETIC_TIME_SLICE_SI_CODE == si.si_code ||
                   POLL_IN == si.si_code))
        << "Tracee is using SIGSTKFLT??? (code=" << si.si_code
        << ", fd=" << si.si_fd << ")";
  }
  t->stash_sig();
  return true;
}

/**
 * The execution of |t| has just been resumed, and it most likely has
 * a new event that needs to be processed.  Prepare that new event.
 */
void RecordSession::runnable_state_changed(RecordTask* t,
                                           RecordResult* step_result,
                                           bool can_consume_wait_status) {
  switch (t->ev().type()) {
    case EV_NOOP:
      t->pop_noop();
      break;
    case EV_SEGV_RDTSC:
      t->record_current_event();
      t->pop_event(t->ev().type());
      break;

    case EV_SENTINEL:
    case EV_SIGNAL_HANDLER:
    case EV_SYSCALL_INTERRUPTION:
      if (!can_consume_wait_status) {
        return;
      }
      // We just entered a syscall.
      if (!maybe_restart_syscall(t)) {
        // Emit FLUSH_SYSCALLBUF if necessary before we do any patching work
        t->maybe_flush_syscallbuf();

        if (t->vm()->monkeypatcher().try_patch_syscall(t)) {
          // Syscall was patched. Emit event and continue execution.
          t->record_event(Event(EV_PATCH_SYSCALL, NO_EXEC_INFO, t->arch()));
          break;
        }

        t->push_event(SyscallEvent(t->regs().original_syscallno(), t->arch()));
      }
      check_initial_task_syscalls(t, step_result);
      note_entering_syscall(t);
      if (t->emulated_ptrace_cont_command == PTRACE_SYSCALL ||
          t->emulated_ptrace_cont_command == PTRACE_SYSEMU ||
          t->emulated_ptrace_cont_command == PTRACE_SYSEMU_SINGLESTEP) {
        t->ev().Syscall().state = ENTERING_SYSCALL_PTRACE;
        t->emulate_ptrace_stop(WaitStatus::for_syscall(t));
        t->record_current_event();

        t->ev().Syscall().in_sysemu =
            t->emulated_ptrace_cont_command == PTRACE_SYSEMU ||
            t->emulated_ptrace_cont_command == PTRACE_SYSEMU_SINGLESTEP;
      }
      break;

    default:
      return;
  }
}

bool RecordSession::prepare_to_inject_signal(RecordTask* t,
                                             StepState* step_state) {
  if (!t->has_stashed_sig() || !done_initial_exec() ||
      step_state->continue_type != CONTINUE) {
    return false;
  }
  union {
    NativeArch::siginfo_t native_api;
    siginfo_t linux_api;
  } si;
  si.linux_api = t->peek_stash_sig().siginfo;
  if (si.linux_api.si_signo == get_ignore_sig()) {
    LOG(info) << "Declining to deliver " << signal_name(si.linux_api.si_signo)
              << " by user request";
    t->pop_stash_sig();
    return false;
  }

  if (si.linux_api.si_signo == SIGSYS && si.linux_api.si_code == SYS_SECCOMP) {
    // Set call_addr to the current ip(). We don't do this when synthesizing
    // the SIGSYS because the SIGSYS might be triggered during syscallbuf
    // processing but be delivered later at a
    // SYS_rrcall_notify_syscall_hook_exit.
    // Documentation says that si_call_addr is the address of the syscall
    // instruction, but in tests it's immediately after the syscall
    // instruction.
    auto& native_si = si.native_api;
    native_si._sifields._sigsys._call_addr = t->ip().to_data_ptr<void>();
  }

  switch (handle_signal(t, &si.linux_api, t->peek_stash_sig().deterministic)) {
    case SIGNAL_PTRACE_STOP:
      // Emulated ptrace-stop. Don't run the task again yet.
      last_task_switchable = ALLOW_SWITCH;
      LOG(debug) << signal_name(si.linux_api.si_signo)
                 << ", emulating ptrace stop";
      break;
    case DEFER_SIGNAL:
      LOG(debug) << signal_name(si.linux_api.si_signo) << " deferred";
      // Leave signal on the stack and continue task execution. We'll try again
      // later.
      return false;
    case SIGNAL_HANDLED:
      LOG(debug) << signal_name(si.linux_api.si_signo) << " handled";
      if (t->ev().type() == EV_SCHED) {
        if (t->maybe_in_spinlock()) {
          LOG(debug) << "Detected possible spinlock, forcing one round-robin";
          scheduler().schedule_one_round_robin(t);
        }
        // Allow switching after a SCHED. We'll flush the SCHED if and only
        // if we really do a switch.
        last_task_switchable = ALLOW_SWITCH;
      }
      break;
  }
  step_state->continue_type = DONT_CONTINUE;
  t->pop_stash_sig();
  return true;
}

static string find_syscall_buffer_library() {
  string lib_path = exe_directory() + "../lib/";
  string file_name = lib_path + SYSCALLBUF_LIB_FILENAME;
  if (access(file_name.c_str(), F_OK) != 0) {
    // File does not exist. Assume install put it in LD_LIBRARY_PATH.
    lib_path = "";
  }
  return lib_path;
}

/*static*/ RecordSession::shr_ptr RecordSession::create(
    const vector<string>& argv, const vector<string>& extra_env,
    SyscallBuffering syscallbuf, BindCPU bind_cpu) {
  // The syscallbuf library interposes some critical
  // external symbols like XShmQueryExtension(), so we
  // preload it whether or not syscallbuf is enabled. Indicate here whether
  // syscallbuf is enabled.
  if (syscallbuf == DISABLE_SYSCALL_BUF) {
    unsetenv(SYSCALLBUF_ENABLED_ENV_VAR);
  } else {
    setenv(SYSCALLBUF_ENABLED_ENV_VAR, "1", 1);

    ScopedFd fd("/proc/sys/kernel/perf_event_paranoid", O_RDONLY);
    if (fd.is_open()) {
      char buf[100];
      ssize_t size = read(fd, buf, sizeof(buf) - 1);
      if (size >= 0) {
        buf[size] = 0;
        int val = atoi(buf);
        if (val > 1) {
          FATAL() << "rr needs /proc/sys/kernel/perf_event_paranoid <= 1, but "
                     "it is "
                  << val << ".\nChange it to 1, or use 'rr record -n' (slow).";
        }
      }
    }
  }

  vector<string> env;
  char** envp = environ;
  for (; *envp; ++envp) {
    env.push_back(*envp);
  }
  env.insert(env.end(), extra_env.begin(), extra_env.end());

  char cwd[PATH_MAX] = "";
  getcwd(cwd, sizeof(cwd));

  // LD_PRELOAD the syscall interception lib
  string syscall_buffer_lib_path = find_syscall_buffer_library();
  if (!syscall_buffer_lib_path.empty()) {
    string ld_preload = "LD_PRELOAD=";
    // Our preload lib *must* come first. We supply a placeholder which is
    // then mutated to the correct filename in Monkeypatcher::patch_after_exec.
    ld_preload += syscall_buffer_lib_path + SYSCALLBUF_LIB_FILENAME_PADDED;
    auto it = env.begin();
    for (; it != env.end(); ++it) {
      if (it->find("LD_PRELOAD=") != 0) {
        continue;
      }
      // Honor old preloads too.  This may cause
      // problems, but only in those libs, and
      // that's the user's problem.
      ld_preload += ":";
      ld_preload += it->substr(it->find("=") + 1);
      break;
    }
    if (it == env.end()) {
      env.push_back(ld_preload);
    } else {
      *it = ld_preload;
    }
  }

  string env_pair = create_pulseaudio_config();
  if (!env_pair.empty()) {
    env.push_back(env_pair);
  }

  env.push_back("RUNNING_UNDER_RR=1");
  env.push_back("LIBGL_DRI3_DISABLE=1");

  // Disable Gecko's "wait for gdb to attach on process crash" behavior, since
  // it is useless when running under rr.
  env.push_back("MOZ_GDB_SLEEP=0");

  shr_ptr session(new RecordSession(argv, env, cwd, syscallbuf, bind_cpu));
  return session;
}

RecordSession::RecordSession(const std::vector<std::string>& argv,
                             const std::vector<std::string>& envp,
                             const string& cwd, SyscallBuffering syscallbuf,
                             BindCPU bind_cpu)
    : trace_out(argv, envp, cwd, choose_cpu(bind_cpu)),
      scheduler_(*this),
      ignore_sig(0),
      continue_through_sig(0),
      last_task_switchable(PREVENT_SWITCH),
      syscall_buffer_size_(1024 * 1024),
      use_syscall_buffer_(syscallbuf == ENABLE_SYSCALL_BUF),
      use_file_cloning_(true),
      use_read_cloning_(true),
      enable_chaos_(false),
      wait_for_all_(false) {
  ScopedFd error_fd = create_spawn_task_error_pipe();
  RecordTask* t =
      static_cast<RecordTask*>(Task::spawn(*this, error_fd, trace_out));
  initial_task_group = t->task_group();
  on_create(t);
}

bool RecordSession::can_end() {
  if (wait_for_all_) {
    return task_map.empty();
  }
  return initial_task_group->task_set().empty();
}

RecordSession::RecordResult RecordSession::record_step() {
  RecordResult result;

  if (can_end()) {
    result.status = STEP_EXITED;
    result.exit_code = initial_task_group->exit_code;
    return result;
  }

  result.status = STEP_CONTINUE;

  RecordTask* prev_task = scheduler().current();
  auto rescheduled = scheduler().reschedule(last_task_switchable);
  if (rescheduled.interrupted_by_signal) {
    // The scheduler was waiting for some task to become active, but was
    // interrupted by a signal. Yield to our caller now to give the caller
    // a chance to do something triggered by the signal
    // (e.g. terminate the recording).
    return result;
  }
  RecordTask* t = scheduler().current();
  if (prev_task && prev_task->ev().type() == EV_SCHED) {
    if (prev_task != t) {
      // We did do a context switch, so record the SCHED event. Otherwise
      // we'll just discard it.
      prev_task->record_current_event();
    }
    prev_task->pop_event(EV_SCHED);
  }
  if (rescheduled.started_new_timeslice) {
    t->registers_at_start_of_last_timeslice = t->regs();
    t->time_at_start_of_last_timeslice = trace_writer().time();
  }

  // Have to disable context-switching until we know it's safe
  // to allow switching the context.
  last_task_switchable = PREVENT_SWITCH;

  LOG(debug) << "trace time " << t->trace_time() << ": Active task is "
             << t->tid << ". Events:";
#ifdef DEBUGTAG
  t->log_pending_events();
#endif
  if (handle_ptrace_exit_event(t)) {
    // t is dead and has been deleted.
    return result;
  }

  if (t->unstable) {
    // Do not record non-ptrace-exit events for tasks in
    // an unstable exit. We can't replay them. This happens in the
    // signal_deferred test; the signal gets re-reported to us.
    LOG(debug) << "Task in unstable exit; "
                  "refusing to record non-ptrace events";
    // Resume the task so hopefully we'll get to its exit.
    last_task_switchable = ALLOW_SWITCH;
    return result;
  }

  StepState step_state(CONTINUE);

  if (!(rescheduled.by_waitpid && handle_ptrace_event(t, &step_state)) &&
      !(rescheduled.by_waitpid && handle_signal_event(t, &step_state))) {
    runnable_state_changed(t, &result, rescheduled.by_waitpid);

    if (result.status != STEP_CONTINUE ||
        step_state.continue_type == DONT_CONTINUE) {
      return result;
    }

    switch (t->ev().type()) {
      case EV_DESCHED:
        desched_state_changed(t);
        break;
      case EV_SYSCALL:
        syscall_state_changed(t, &step_state);
        break;
      case EV_SIGNAL:
      case EV_SIGNAL_DELIVERY:
        signal_state_changed(t, &step_state);
        break;
      default:
        break;
    }
  }

  // We try to inject a signal if there's one pending; otherwise we continue
  // task execution.
  if (!prepare_to_inject_signal(t, &step_state) &&
      step_state.continue_type != DONT_CONTINUE) {
    // Ensure that we aren't allowing switches away from a running task.
    // Only tasks blocked in a syscall can be switched away from, otherwise
    // we have races.
    ASSERT(t, last_task_switchable == PREVENT_SWITCH || t->unstable ||
                  t->may_be_blocked());

    debug_exec_state("EXEC_START", t);

    task_continue(step_state);
  }

  return result;
}

void RecordSession::terminate_recording() {
  RecordTask* t = scheduler().current();
  if (t) {
    t->maybe_flush_syscallbuf();
  }

  LOG(info) << "Processing termination request ...";

  // This will write unstable exit events for all tasks.
  kill_all_tasks();

  LOG(info) << "  recording final TRACE_TERMINATION event ...";

  TraceFrame frame(trace_out.time(), t ? t->tid : 0,
                   Event(EV_TRACE_TERMINATION, NO_EXEC_INFO, RR_NATIVE_ARCH),
                   t ? t->tick_count() : 0);
  trace_out.write_frame(frame);
  trace_out.close();
}

Task* RecordSession::new_task(pid_t tid, pid_t, uint32_t serial,
                              SupportedArch a) {
  return new RecordTask(*this, tid, serial, a);
}

void RecordSession::on_create(Task* t) {
  Session::on_create(t);
  scheduler().on_create(static_cast<RecordTask*>(t));
}

void RecordSession::on_destroy(Task* t) {
  scheduler().on_destroy(static_cast<RecordTask*>(t));
  Session::on_destroy(t);
}

RecordTask* RecordSession::find_task(pid_t rec_tid) const {
  return static_cast<RecordTask*>(Session::find_task(rec_tid));
}

RecordTask* RecordSession::find_task(const TaskUid& tuid) const {
  return static_cast<RecordTask*>(Session::find_task(tuid));
}

} // namespace rr
