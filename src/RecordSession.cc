/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RecordSession.h"

#include <elf.h>
#include <limits.h>
#include <linux/futex.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <algorithm>
#include <sstream>
#include <string>

#include "AutoRemoteSyscalls.h"
#include "ElfReader.h"
#include "Flags.h"
#include "RecordTask.h"
#include "VirtualPerfCounterMonitor.h"
#include "core.h"
#include "ftrace.h"
#include "kernel_metadata.h"
#include "log.h"
#include "record_signal.h"
#include "record_syscall.h"
#include "seccomp-bpf.h"

namespace rr {

// Undef si_addr_lsb since it's an alias for a field name that doesn't exist,
// and we need to use the actual field name.
#ifdef si_addr_lsb
#undef si_addr_lsb
#endif

using namespace rr;
using namespace std;

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
  if (t->did_record_robust_futex_changes) {
    return;
  }
  t->did_record_robust_futex_changes = true;

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

static void record_exit_trace_event(RecordTask* t, WaitStatus exit_status) {
  t->session().trace_writer().write_task_event(
      TraceTaskEvent::for_exit(t->tid, exit_status));
  if (t->thread_group()->tgid == t->tid) {
    t->thread_group()->exit_status = exit_status;
  }
}

static bool looks_like_syscall_entry(RecordTask* t) {
  bool ok;
  bool at_syscall = is_at_syscall_instruction(t,
      t->regs().ip().decrement_by_syscall_insn_length(t->arch()), &ok);
  // It's possible for the task to have died (e.g. if it got signaled twice
  // in rapid succession). In that case, try to just go by register contents.
  if (ok && !at_syscall) {
    return false;
  }
  if (is_x86ish(t->arch())) {
    // On x86 rax gets set to ENOSYS on entry. Elsewhere this does not happen.
    // Further, even if we did ask about the syscallno, it might have been
    // reset by the signal handler. However, on non-x86 platforms we currently
    // count taken braches, rather than only conditional ones, so it should
    // be impossible to see the same syscall ip twice without intervening
    // ticks, so the check that follows these conditions, should be sufficient
    // there.
    return t->regs().original_syscallno() >= 0 &&
           t->regs().syscall_result_signed() == -ENOSYS;
  }
  // Getting a sched event here is better than a spurious syscall event.
  // Syscall entry does not cause visible register modification, so upon
  // hitting the sched event the register state would indeed match.
  return ok;
}

/**
 * Return true if we handle a ptrace exit event for task t. When this returns
 * true, t has been deleted and cannot be referenced again.
 */
static bool handle_ptrace_exit_event(RecordTask* t) {
  if (t->already_reaped()) {
    t->did_reach_zombie();
    return true;
  }

  if (t->ptrace_event() != PTRACE_EVENT_EXIT) {
    return false;
  }

  if (t->stable_exit) {
    LOG(debug) << "stable exit";
  } else {
    /* XXX: We could try to find some tasks here to unmap our buffers, but it
     *      seems hardly worth it.
     */
    t->destroy_buffers(nullptr, nullptr);
    if (!t->may_be_blocked()) {
      // might have been hit by a SIGKILL or a SECCOMP_RET_KILL, in which case
      // there might be some execution since its last recorded event that we
      // need to replay.
      // There's a weird case (in 4.13.5-200.fc26.x86_64 at least) where the
      // task can enter the kernel but instead of receiving a syscall ptrace
      // event, we receive a PTRACE_EVENT_EXIT due to a concurrent execve
      // (and probably a concurrent SIGKILL could do the same). The task state
      // has been updated to reflect syscall entry. If we record a SCHED in
      // that state replay of the SCHED will fail. So detect that state and fix
      // it up.
      if (looks_like_syscall_entry(t)) {
        // Either we're in a syscall, or we're immediately after a syscall
        // and it exited.
        if (t->ticks_at_last_recorded_syscall_exit == t->tick_count() &&
            t->regs().ip() == t->ip_at_last_recorded_syscall_exit) {
          LOG(debug) << "Nothing to record after PTRACE_EVENT_EXIT";
          // It's the latter case; do nothing.
        } else {
          // It's the former case ... probably. Theoretically we could have
          // re-executed a syscall without any ticks in between, but that seems
          // highly improbable.
          // Record the syscall-entry event that we otherwise failed to record.
          t->canonicalize_regs(t->arch());
          t->apply_syscall_entry_regs();
          // Assume it's a native-arch syscall. If it isn't, it doesn't matter
          // all that much since we aren't actually going to do anything with it
          // in this task.
          // Avoid calling detect_syscall_arch here since it could fail if the
          // task is already completely dead and gone.
          SyscallEvent event(t->regs().original_syscallno(), t->arch());
          event.state = ENTERING_SYSCALL;
          t->record_event(event);
        }
      } else {
        // Don't try to reset the syscallbuf here. The task may be exiting
        // while in arbitrary syscallbuf code. And of course, because it's
        // exiting, it doesn't matter if we don't reset the syscallbuf.
        // XXX flushing the syscallbuf may be risky too...
        t->record_event(Event::sched(), RecordTask::FLUSH_SYSCALLBUF,
                        RecordTask::DONT_RESET_SYSCALLBUF);
      }
    }
  }

  record_robust_futex_changes(t);

  WaitStatus exit_status;
  unsigned long msg = 0;
  // We can get ESRCH here if the child was killed by SIGKILL and
  // we made a synthetic PTRACE_EVENT_EXIT to handle it.
  if (t->ptrace_if_alive(PTRACE_GETEVENTMSG, nullptr, &msg)) {
    exit_status = WaitStatus(msg);
  } else {
    exit_status = WaitStatus::for_fatal_sig(SIGKILL);
  }

  t->did_handle_ptrace_exit_event();

  // If we died because of a coredumping signal, that is a barrier event, and
  // every task in the address space needs to pass its PTRACE_EXIT_EVENT before
  // they proceed to (potentially hidden) zombie state, so we can't wait for
  // that to happen/
  // Similarly we can't wait for this task to exit if there are other
  // tasks in its pid namespace that need to exit and this is the last thread
  // of pid-1 in that namespace, because the kernel must reap them before
  // letting this task complete its exit.
  bool may_wait_exit = !is_coredumping_signal(exit_status.fatal_sig()) &&
    !t->waiting_for_pid_namespace_tasks_to_exit();
  if (!t->already_reaped()) {
    t->proceed_to_exit(may_wait_exit);
  }
  record_exit_trace_event(t, exit_status);
  t->record_exit_event(exit_status.fatal_sig());
  if (t->do_ptrace_exit_stop(exit_status)) {
    // Keep the RecordTask alive until the ptracer reaps it
    t->waiting_for_reap = true;
  }
  if (!may_wait_exit) {
    t->waiting_for_zombie = true;
    return true;
  }
  t->did_reach_zombie();
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
  } else {
    t->ev().Syscall().regs.set_syscallno(t->regs().syscallno());
    // We may have intentionally stored the syscall result here.
    // Now that we're safely past the signal delivery, make the
    // registers look like they did at the original syscall entry
    // again.
    t->ev().Syscall().regs.set_arg1(t->ev().Syscall().regs.orig_arg1());
    if (t->arch() == aarch64) {
      // We probably got here with a PTRACE_SYSCALL. The x7
      // value will be wrong due to the aarch64 kernel bug.
      // Get it from the syscall event.
      Registers r = t->regs();
      r.set_x7(t->ev().Syscall().regs.x7());
      t->set_regs(r);
    }
  }
}

#if defined (__x86_64__)
static bool is_in_vsyscall(remote_code_ptr ip)
{
  // This is hardcoded by the Linux ABI
  remote_code_ptr vsyscall_start = 0xffffffffff600000;
  remote_code_ptr vsyscall_end = 0xffffffffff601000;
  return vsyscall_start <= ip && ip < vsyscall_end;
}
#else
static bool is_in_vsyscall(remote_code_ptr)
{
  return false;
}
#endif

void RecordSession::handle_seccomp_traced_syscall(RecordTask* t,
                                                  StepState* step_state,
                                                  RecordResult* result,
                                                  bool* did_enter_syscall) {
  *did_enter_syscall = false;

  // Special case: If the tracee issues a vsyscall, we will get a seccomp trap,
  // but no syscall traps whatsover. In particular, we wouldn't see it during
  // replay either. We try to moneypatch the caller on the assumption that known
  // callers of this (deprecated) interface all follow a common pattern. If we
  // can't patch the caller, this is a fatal error, since the recording will
  // otherwise be broken.
  if (is_in_vsyscall(t->regs().ip())) {
    // The kernel assumes the return address is on the stack - we do the same
    remote_ptr<remote_code_ptr> ret_addr_addr = t->regs().sp().as_int();
    remote_code_ptr ret_addr = t->read_mem(ret_addr_addr);

    // Skip this syscall. We will attempt to patch it to the vdso entry and
    // let the tracee retry there.
    Registers regs = t->regs();
    regs.set_original_syscallno(-1);
    // We can't modify the ip here, the kernel will kill the tracee with
    // SIGSYS. Instead, we set a breakpoint at the return instruction.
    t->set_regs(regs);
    t->vm()->add_breakpoint(ret_addr, BKPT_INTERNAL);
    t->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);
    t->vm()->remove_breakpoint(ret_addr, BKPT_INTERNAL);

    ASSERT(t, t->regs().ip().undo_executed_bkpt(t->arch()) == ret_addr);

    // Now that we're in a sane state, ask the Moneypatcher to try and patch
    // that.
    if (!t->vm()->monkeypatcher().try_patch_vsyscall_caller(t, ret_addr)) {
      FATAL() << "The tracee issues a vsyscall, but we failed to moneypatch the\n"
              << "caller. Recording will not succeed. Exiting.";
    }

    // Reset to the start of the region and continue
    regs = t->regs();
    regs.set_ip(ret_addr.decrement_by_vsyscall_entry_length(t->arch()));
    t->set_regs(regs);

    // We patched this syscall, record that
    auto ev = Event::patch_syscall();
    ev.PatchSyscall().patch_vsyscall = true;
    t->record_event(ev);

    step_state->continue_type = RecordSession::CONTINUE;
    return;
  }

  int syscallno = t->regs().original_syscallno();
  if (syscallno < 0) {
    // negative syscall numbers after a SECCOMP event
    // are treated as "skip this syscall". There will be one syscall event
    // reported instead of two. So fake an enter-syscall event now.
    // It doesn't really matter what the syscall-arch is.
    t->canonicalize_regs(t->arch());
    if (syscall_seccomp_ordering_ == SECCOMP_BEFORE_PTRACE_SYSCALL) {
      // If the ptrace entry stop hasn't happened yet, we're at a weird
      // intermediate state where the behavior of the next PTRACE_SYSCALL
      // will depend on the register state (i.e. whether we see an entry
      // trap or proceed right to the exit trap). To make things easier
      // on the rest of the system, do a fake syscall entry, then reset
      // the register state.
      Registers orig_regs = t->regs();
      Registers r = orig_regs;
      r.set_original_syscallno(syscall_number_for_gettid(t->arch()));
      t->set_regs(r);
      t->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);
      t->set_regs(orig_regs);
    }

    // Don't continue yet. At the next iteration of record_step, we'll
    // enter syscall_state_changed and that will trigger a continue to
    // the syscall exit.
    step_state->continue_type = RecordSession::DONT_CONTINUE;
    if (!process_syscall_entry(t, step_state, result, t->arch())) {
      return;
    }
    *did_enter_syscall = true;
    return;
  }

  if (syscall_seccomp_ordering_ == SECCOMP_BEFORE_PTRACE_SYSCALL) {
    // The next continue needs to be a PTRACE_SYSCALL to observe
    // the enter-syscall event.
    step_state->continue_type = RecordSession::CONTINUE_SYSCALL;
  } else {
    ASSERT(t, syscall_seccomp_ordering_ == PTRACE_SYSCALL_BEFORE_SECCOMP);
    if (t->ev().is_syscall_event() &&
        t->ev().Syscall().state == PROCESSING_SYSCALL) {
      // We did PTRACE_SYSCALL and already saw a syscall trap. Just ignore this.
      LOG(debug) << "Ignoring SECCOMP syscall trap since we already got a "
                    "PTRACE_SYSCALL trap";
      // The next continue needs to be a PTRACE_SYSCALL to observe
      // the exit-syscall event.
      step_state->continue_type = RecordSession::CONTINUE_SYSCALL;
      // Need to restore last_task_switchable since it will have been
      // reset to PREVENT_SWITCH
      last_task_switchable = t->ev().Syscall().switchable;
    } else {
      // We've already passed the PTRACE_SYSCALL trap for syscall entry, so
      // we need to handle that now.
      SupportedArch syscall_arch = t->detect_syscall_arch();
      t->canonicalize_regs(syscall_arch);
      if (!process_syscall_entry(t, step_state, result, syscall_arch)) {
        step_state->continue_type = RecordSession::DONT_CONTINUE;
        return;
      }
      *did_enter_syscall = true;
    }
  }
}

static void seccomp_trap_done(RecordTask* t) {
  t->pop_seccomp_trap();

  // It's safe to reset the syscall buffer now.
  t->delay_syscallbuf_reset_for_seccomp_trap = false;

  t->write_mem(REMOTE_PTR_FIELD(t->syscallbuf_child, failed_during_preparation),
               (uint8_t)1);
  uint8_t one = 1;
  t->record_local(
      REMOTE_PTR_FIELD(t->syscallbuf_child, failed_during_preparation), &one);

  if (EV_DESCHED == t->ev().type()) {
    // Desched processing will do the rest for us
    return;
  }

  // Abort the current syscallbuf record, which corresponds to the syscall that
  // wasn't actually executed due to seccomp.
  t->write_mem(REMOTE_PTR_FIELD(t->syscallbuf_child, abort_commit), (uint8_t)1);
  t->record_event(Event::syscallbuf_abort_commit());

  // In fact, we need to. Running the syscall exit hook will ensure we
  // reset the buffer before we try to buffer another a syscall.
  t->write_mem(
      REMOTE_PTR_FIELD(t->syscallbuf_child, notify_on_syscall_hook_exit),
      (uint8_t)1);
}

static void handle_seccomp_trap(RecordTask* t,
                                RecordSession::StepState* step_state,
                                uint16_t seccomp_data) {
  // The architecture may be wrong, but that's ok, because an actual syscall
  // entry did happen, so the registers are already updated according to the
  // architecture of the system call.
  t->canonicalize_regs(t->detect_syscall_arch());
  t->apply_syscall_entry_regs();

  Registers r = t->regs();
  int syscallno = r.original_syscallno();
  // Cause kernel processing to skip the syscall
  r.set_original_syscallno(SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO);
  t->set_regs(r);

  bool syscall_entry_already_recorded = false;
  if (t->ev().is_syscall_event()) {
    // A syscall event was already pushed, probably because we did a
    // PTRACE_SYSCALL to enter the syscall during handle_desched_event. Cancel
    // that event now since the seccomp SIGSYS aborts it completely.
    ASSERT(t, t->ev().Syscall().number == syscallno);
    // Make sure any prepared syscall state is discarded and any temporary
    // effects (e.g. redirecting pointers to scratch) undone.
    rec_abort_prepared_syscall(t);
    if (t->ev().type() == EV_SYSCALL_INTERRUPTION) {
      // The event could be a syscall-interruption if it was pushed by
      // `handle_desched_event`. In that case, it has not been recorded yet.
      t->pop_syscall_interruption();
    } else {
      t->pop_syscall();
      syscall_entry_already_recorded = true;
    }
  }

  if (t->is_in_untraced_syscall()) {
    ASSERT(t, !t->delay_syscallbuf_reset_for_seccomp_trap);
    // Don't reset the syscallbuf immediately after delivering the trap. We have
    // to wait until this buffered syscall aborts completely before resetting
    // the buffer.
    t->delay_syscallbuf_reset_for_seccomp_trap = true;

    t->push_event(Event::seccomp_trap());

    // desched may be armed but we're not going to execute the syscall, let
    // alone block. If it fires, ignore it.
    t->write_mem(
        REMOTE_PTR_FIELD(t->syscallbuf_child, desched_signal_may_be_relevant),
        (uint8_t)0);
  }

  t->push_syscall_event(syscallno);
  t->ev().Syscall().failed_during_preparation = true;
  note_entering_syscall(t);

  if (t->is_in_untraced_syscall() && !syscall_entry_already_recorded) {
    t->record_current_event();
  }

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
    #ifdef AUDIT_ARCH_AARCH64
    case aarch64:
      si.native_api._sifields._sigsys._arch = AUDIT_ARCH_AARCH64;
      break;
    #endif
    default:
      DEBUG_ASSERT(0 && "Unknown architecture");
      break;
  }
  si.native_api._sifields._sigsys._syscall = syscallno;
  // Documentation says that si_call_addr is the address of the syscall
  // instruction, but in tests it's immediately after the syscall
  // instruction.
  si.native_api._sifields._sigsys._call_addr = t->ip().to_data_ptr<void>();
  LOG(debug) << "Synthesizing " << si.linux_api;
  t->stash_synthetic_sig(si.linux_api, DETERMINISTIC_SIG);

  // Tests show that the current registers are preserved (on x86, eax/rax
  // retains the syscall number).
  r.set_syscallno(syscallno);
  t->set_regs(r);
  t->maybe_restore_original_syscall_registers();

  if (t->is_in_untraced_syscall()) {
    // For buffered syscalls, go ahead and record the exit state immediately.
    t->ev().Syscall().state = EXITING_SYSCALL;
    t->record_current_event();
    t->pop_syscall();

    // The tracee is currently in the seccomp ptrace-stop. Advance it to the
    // syscall-exit stop so that when we try to deliver the SIGSYS via
    // PTRACE_SINGLESTEP, that doesn't trigger a SIGTRAP stop.
    t->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);
  }

  // Don't continue yet. At the next iteration of record_step, if we
  // recorded the syscall-entry we'll enter syscall_state_changed and
  // that will trigger a continue to the syscall exit. If we recorded the
  // syscall-exit we'll go straight into signal delivery.
  step_state->continue_type = RecordSession::DONT_CONTINUE;
}

static void handle_seccomp_errno(RecordTask* t,
                                 RecordSession::StepState* step_state,
                                 uint16_t seccomp_data) {
  t->canonicalize_regs(t->detect_syscall_arch());

  Registers r = t->regs();
  int syscallno = r.original_syscallno();
  // Cause kernel processing to skip the syscall
  r.set_original_syscallno(SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO);
  t->set_regs(r);

  if (!t->is_in_untraced_syscall()) {
    t->push_syscall_event(syscallno);
    // Note that the syscall failed. prepare_clone() needs to know
    // this during replay of the syscall entry.
    t->ev().Syscall().failed_during_preparation = true;
    note_entering_syscall(t);
  }

  r.set_syscall_result(-seccomp_data);
  t->set_regs(r);
  // Don't continue yet. At the next iteration of record_step, if we
  // recorded the syscall-entry we'll enter syscall_state_changed and
  // that will trigger a continue to the syscall exit.
  step_state->continue_type = RecordSession::DONT_CONTINUE;
}

bool RecordSession::handle_ptrace_event(RecordTask** t_ptr,
                                        StepState* step_state,
                                        RecordResult* result,
                                        bool* did_enter_syscall) {
  *did_enter_syscall = false;

  RecordTask* t = *t_ptr;
  if (t->status().group_stop() || t->has_stashed_group_stop()) {
    t->clear_stashed_group_stop();
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
      if (syscall_seccomp_ordering_ == PTRACE_SYSCALL_BEFORE_SECCOMP_UNKNOWN) {
        syscall_seccomp_ordering_ = SECCOMP_BEFORE_PTRACE_SYSCALL;
      }

      uint16_t seccomp_data = t->get_ptrace_eventmsg_seccomp_data();
      t->apply_syscall_entry_regs();
      int syscallno = t->regs().original_syscallno();
      if (seccomp_data == SECCOMP_RET_DATA) {
        LOG(debug) << "  traced syscall entered: "
                   << syscall_name(syscallno, t->arch());
        handle_seccomp_traced_syscall(t, step_state, result, did_enter_syscall);
      } else {
        // Note that we make no attempt to patch the syscall site when the
        // user handle does not return ALLOW. Apart from the ERRNO case,
        // handling these syscalls is necessarily slow anyway.
        uint32_t real_result;
        if (!seccomp_filter_rewriter().map_filter_data_to_real_result(
                t, seccomp_data, &real_result)) {
          LOG(debug)
              << "Process terminated unexpectedly during PTRACE_GETEVENTMSG";
          step_state->continue_type = RecordSession::CONTINUE;
          break;
        }
        uint16_t real_result_data = real_result & SECCOMP_RET_DATA;
        switch (real_result & SECCOMP_RET_ACTION) {
          case SECCOMP_RET_TRAP:
            LOG(debug) << "  seccomp trap for syscall: "
                       << syscall_name(syscallno, t->arch());
            handle_seccomp_trap(t, step_state, real_result_data);
            break;
          case SECCOMP_RET_ERRNO:
            LOG(debug) << "  seccomp errno " << errno_name(real_result_data)
                       << " for syscall: "
                       << syscall_name(syscallno, t->arch());
            handle_seccomp_errno(t, step_state, real_result_data);
            break;
          case SECCOMP_RET_KILL:
            LOG(debug) << "  seccomp kill for syscall: "
                       << syscall_name(syscallno, t->arch());
            t->tgkill(SIGKILL);
            // Rely on the SIGKILL to bump us out of the ptrace stop.
            step_state->continue_type = RecordSession::DONT_CONTINUE;
            // Now wait for us to actually exit our ptrace-stop and proceed
            // to the PTRACE_EVENT_EXIT. This avoids the race where our
            // PTRACE_CONT might kick us out of the PTRACE_EVENT_EXIT before
            // we can process it.
            t->wait();
            break;
          default:
            ASSERT(t, false) << "Seccomp result not handled";
            break;
        }
      }
      break;
    }

    case PTRACE_EVENT_EXEC: {
      if (t->thread_group()->task_set().size() > 1) {
        // All tasks but the task that did the execve should have exited by
        // now and notified us of their exits. However, it's possible that
        // while running the thread-group leader, our PTRACE_CONT raced with its
        // PTRACE_EVENT_EXIT and it exited, and the next event we got is this
        // PTRACE_EVENT_EXEC after the exec'ing task changed its tid to the
        // leader's tid. Or maybe there are kernel bugs; on
        // 4.2.0-42-generic running exec_from_other_thread, we reproducibly
        // enter PTRACE_EVENT_EXEC for the thread-group leader without seeing
        // its PTRACE_EVENT_EXIT.

        // So, record this task's exit and destroy it.
        // XXX We can't do record_robust_futex_changes here because the address
        // space has already gone. That would only matter if some of them were
        // in memory accessible to another process even after exec, i.e. a
        // shared-memory mapping or two different thread-groups sharing the same
        // address space.
        pid_t tid = t->rec_tid;
        WaitStatus status = t->status();
        record_exit_trace_event(t, WaitStatus(0));
        t->record_exit_event();
        // Don't call RecordTask::destroy() because we don't want to
        // PTRACE_DETACH.
        delete t;
        // Steal the exec'ing task and make it the thread-group leader, and
        // carry on!
        t = revive_task_for_exec(tid);
        scheduler().set_current(t);
        *t_ptr = t;
        // Tell t that it is actually stopped, because the stop we got is really
        // for this task, not the old dead task.
        t->did_waitpid(status);
      }
      t->post_exec();

      // Skip past the ptrace event.
      step_state->continue_type = CONTINUE_SYSCALL;
      break;
    }

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

template <typename Arch>
static bool is_ptrace_any_singlestep_arch(int command) {
  return command >= 0 &&
    (command == PTRACE_SINGLESTEP || command == Arch::PTRACE_SYSEMU_SINGLESTEP);
}

static bool is_ptrace_any_singlestep(SupportedArch arch, int command)
{
  RR_ARCH_FUNCTION(is_ptrace_any_singlestep_arch, arch, command);
}

void RecordSession::task_continue(const StepState& step_state) {
  RecordTask* t = scheduler().current();

  ASSERT(t, step_state.continue_type != DONT_CONTINUE);
  // A task in an emulated ptrace-stop must really stay stopped
  ASSERT(t, !t->emulated_stop_pending);

  bool may_restart = t->at_may_restart_syscall();

  if (may_restart && t->seccomp_bpf_enabled) {
    LOG(debug) << "  PTRACE_SYSCALL to possibly-restarted " << t->ev();
  }

  if (!t->vm()->first_run_event()) {
    t->vm()->set_first_run_event(trace_writer().time());
  }

  if (!t->thread_group()->first_run_event()) {
    t->thread_group()->set_first_run_event(trace_writer().time());
  }

  TicksRequest ticks_request;
  ResumeRequest resume;
  if (step_state.continue_type == CONTINUE_SYSCALL) {
    ticks_request = RESUME_NO_TICKS;
    resume = RESUME_SYSCALL;
  } else {
    if (t->has_stashed_sig(PerfCounters::TIME_SLICE_SIGNAL)) {
      // timeslice signal already stashed, no point in generating another one
      // (and potentially slow)
      ticks_request = RESUME_UNLIMITED_TICKS;
    } else if (scheduler().may_use_unlimited_ticks()) {
      ticks_request = RESUME_UNLIMITED_TICKS;
    } else {
      ticks_request = (TicksRequest)max<Ticks>(
          0, scheduler().current_timeslice_end() - t->tick_count());
    }

    // Clear any lingering state, then see if we need to stop earlier for a
    // tracee-requested pmc interrupt on the virtualized performance counter.
    t->next_pmc_interrupt_is_for_user = false;
    if (auto vpmc =
            VirtualPerfCounterMonitor::interrupting_virtual_pmc_for_task(t)) {
      ASSERT(t, vpmc->target_tuid() == t->tuid());

      Ticks after = max<Ticks>(vpmc->target_ticks() - t->tick_count(), 0);
      if ((uint64_t)after < (uint64_t)ticks_request) {
        LOG(debug) << "ticks_request constrained from " << ticks_request
                   << " to " << after << " for vpmc";
        ticks_request = (TicksRequest)after;
        t->next_pmc_interrupt_is_for_user = true;
      }
    }

    bool singlestep = is_ptrace_any_singlestep(t->arch(),
      t->emulated_ptrace_cont_command);
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
      /* We won't receive PTRACE_EVENT_SECCOMP events until
       * the seccomp filter is installed by the
       * syscall_buffer lib in the child, therefore we must
       * record in the traditional way (with PTRACE_SYSCALL)
       * until it is installed. */
      /* Kernel commit
         https://github.com/torvalds/linux/commit/93e35efb8de45393cf61ed07f7b407629bf698ea
         makes PTRACE_SYSCALL traps be delivered *before* seccomp RET_TRACE
         traps.
         Detect and handle this. */
      if (!t->seccomp_bpf_enabled || may_restart ||
          syscall_seccomp_ordering_ == PTRACE_SYSCALL_BEFORE_SECCOMP_UNKNOWN) {
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
  if (t->is_running()) {
    scheduler().started(t);
  }
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
    // have been disarmed. However, we observe these being received here when
    // we arm the desched signal before we restart a blocking syscall, which
    // completes successfully, then we disarm, then we see a desched signal
    // here.
    if (t->session().syscallbuf_desched_sig() == sig) {
      continue;
    }
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
  t->write_mem(REMOTE_PTR_FIELD(t->syscallbuf_child, abort_commit), (uint8_t)1);
  t->record_event(Event::syscallbuf_abort_commit());

  advance_to_disarm_desched_syscall(t);

  t->pop_desched();

  /* The tracee has just finished sanity-checking the
   * aborted record, and won't touch the syscallbuf
   * during this (aborted) transaction again.  So now
   * is a good time for us to reset the record counter. */
  t->delay_syscallbuf_reset_for_desched = false;
  // Run the syscallbuf exit hook. This ensures we'll be able to reset
  // the syscallbuf before trying to buffer another syscall.
  t->write_mem(
      REMOTE_PTR_FIELD(t->syscallbuf_child, notify_on_syscall_hook_exit),
      (uint8_t)1);
}

static void syscall_not_restarted(RecordTask* t) {
  LOG(debug) << "  " << t->tid << ": popping abandoned interrupted " << t->ev()
             << "; pending events:";
  if (IS_LOGGING(debug)) {
    t->log_pending_events();
  }
  t->pop_syscall_interruption();
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
    t->canonicalize_regs(t->arch());
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
  } else if (t->arch() == x86 || t->arch() == x86_64) {
    // On x86, we would have expected this to get restored to the syscallno.
    // Since the syscallno is in a different register on other platforms, this
    // assert does not apply.
    ASSERT(t, syscallno == ret)
        << "Interrupted call was " << t->ev().Syscall().syscall_name()
        << " and sigreturn claims to be restarting "
        << syscall_name(ret, t->ev().Syscall().arch());
  }
}

/**
 * Copy the registers used for syscall arguments (not including
 * syscall number) from |from| to |to|.
 */
static void copy_syscall_arg_regs(Registers* to, const Registers& from) {
  to->set_orig_arg1(from.arg1());
  to->set_arg2(from.arg2());
  to->set_arg3(from.arg3());
  to->set_arg4(from.arg4());
  to->set_arg5(from.arg5());
  to->set_arg6(from.arg6());
}

static void maybe_trigger_emulated_ptrace_syscall_exit_stop(RecordTask* t) {
  if (t->emulated_ptrace_cont_command == PTRACE_SYSCALL) {
    t->emulate_ptrace_stop(WaitStatus::for_syscall(t));
  } else if (is_ptrace_any_singlestep(t->arch(), t->emulated_ptrace_cont_command)) {
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
  auto child_rec = t->next_syscallbuf_record();
  int64_t ret = retval;
  t->record_local(REMOTE_PTR_FIELD(child_rec, ret), &ret);
}

static bool is_in_privileged_syscall(RecordTask* t) {
  auto type = AddressSpace::rr_page_syscall_from_exit_point(t->arch(), t->ip());
  return type && type->privileged == AddressSpace::PRIVILEGED;
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
        // We'll have recorded just the ENTERING_SYSCALL_PTRACE event and
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
      // The syscallno may have been changed by the ptracer
      t->ev().Syscall().number = t->regs().original_syscallno();
      return;

    case ENTERING_SYSCALL: {
      debug_exec_state("EXEC_SYSCALL_ENTRY", t);
      ASSERT(t, !t->emulated_stop_pending);

      last_task_switchable = t->ev().Syscall().switchable =
          rec_prepare_syscall(t);
      t->record_event(t->ev(), RecordTask::FLUSH_SYSCALLBUF,
                      RecordTask::ALLOW_RESET_SYSCALLBUF,
                      &t->ev().Syscall().regs);

      debug_exec_state("after cont", t);
      t->ev().Syscall().state = PROCESSING_SYSCALL;

      if (t->emulated_stop_pending) {
        step_state->continue_type = DONT_CONTINUE;
      } else {
        // Resume the syscall execution in the kernel context.
        step_state->continue_type = CONTINUE_SYSCALL;
      }

      if (t->session().done_initial_exec() && Flags::get().check_cached_mmaps) {
        t->vm()->verify(t);
      }

      if (t->desched_rec() && t->is_in_untraced_syscall() &&
          t->has_stashed_sig()) {
        // We have a signal to deliver but we're about to (re?)enter an untraced
        // syscall that may block and the desched event has been disarmed.
        // Rearm the desched event so if the syscall blocks, it will be
        // interrupted and we'll have a chance to deliver our signal.
        LOG(debug) << "Rearming desched event so we'll get a chance to deliver "
                      "stashed signal";
        arm_desched_event(t);
      }

      if (t->detached_proxy) {
        // We detached. Record that.
        t->record_event(Event::exit(), RecordTask::DONT_FLUSH_SYSCALLBUF,
          RecordTask::DONT_RESET_SYSCALLBUF);
        t->session().trace_writer().write_task_event(
            TraceTaskEvent::for_detach(t->tid));
        step_state->continue_type = DONT_CONTINUE;
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

      DEBUG_ASSERT(t->stop_sig() == 0);

      SupportedArch syscall_arch = t->ev().Syscall().arch();
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
      if (is_sigreturn(syscallno, syscall_arch)) {
        if (is_x86ish(t->arch())) {
          ASSERT(t, t->regs().original_syscallno() == -1);
        }
        rec_did_sigreturn(t);
        t->record_current_event();
        t->pop_syscall();

        // We've finished processing this signal now.
        t->pop_signal_handler();
        t->invalidate_sigmask();

        maybe_discard_syscall_interruption(t, retval);

        if (EV_SECCOMP_TRAP == t->ev().type()) {
          LOG(debug) << "  exiting seccomp trap";
          save_interrupted_syscall_ret_in_syscallbuf(t, retval);
          seccomp_trap_done(t);
        }
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
                   << " (" << syscall_name(syscallno, syscall_arch)
                   << "); return val:" << HEX(t->regs().syscall_result());

        /* a syscall_restart ending is equivalent to the
         * restarted syscall ending */
        if (t->ev().Syscall().is_restart) {
          LOG(debug) << "  exiting restarted "
                     << syscall_name(syscallno, syscall_arch);
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
          LOG(debug) << "  may restart "
                     << syscall_name(syscallno, syscall_arch)
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
          // We need to track what the return value was on architectures
          // where the kernel replaces the return value by the new arg1
          // on restart.
          t->ev().Syscall().regs = r;
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

        t->canonicalize_regs(syscall_arch);

        if (!may_restart) {
          if (t->retry_syscall_patching) {
            LOG(debug) << "Retrying deferred syscall patching";
            if (t->vm()->monkeypatcher().try_patch_syscall(t, false)) {
              // Syscall was patched. Emit event and continue execution.
              auto ev = Event::patch_syscall();
              ev.PatchSyscall().patch_after_syscall = true;
              t->record_event(ev);
            }
            t->retry_syscall_patching = false;
          }
        }
      }

      last_task_switchable = ALLOW_SWITCH;
      step_state->continue_type = DONT_CONTINUE;

      if (!is_in_privileged_syscall(t)) {
        maybe_trigger_emulated_ptrace_syscall_exit_stop(t);
      }
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

RecordTask* RecordSession::revive_task_for_exec(pid_t rec_tid) {
  unsigned long msg = 0;
  int ret =
      ptrace(__ptrace_request(PTRACE_GETEVENTMSG), rec_tid, nullptr, &msg);
  if (ret < 0) {
    FATAL() << "Can't get old tid for execve (leader=" << rec_tid << ")";
  }
  RecordTask* t = find_task(msg);
  if (!t) {
    FATAL() << "Can't find old task for execve";
  }
  ASSERT(t, rec_tid == t->tgid());
  pid_t own_namespace_tid = t->thread_group()->tgid_own_namespace;

  LOG(debug) << "Changing task tid from " << t->tid << " to " << rec_tid;

  // Pretend the old task cloned a new task with the right tid, and then exited
  trace_writer().write_task_event(TraceTaskEvent::for_clone(
      rec_tid, t->tid, own_namespace_tid,
      CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
          CLONE_SYSVSEM));
  trace_writer().write_task_event(
      TraceTaskEvent::for_exit(t->tid, WaitStatus::for_exit_code(0)));

  // Account for tid change
  task_map.erase(t->tid);
  task_map.insert(make_pair(rec_tid, t));
  // Update the serial as if this task was really created by cloning the old
  // task.
  t->set_tid_and_update_serial(rec_tid, own_namespace_tid);

  return t;
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
    case aarch64:
      dest = t->regs().x1();
      break;
    default:
      DEBUG_ASSERT(0 && "Unknown architecture");
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
static bool preinject_signal(RecordTask* t) {
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
    LOG(debug) << "    maybe not in signal-stop (status " << t->status()
               << "); doing tgkill(SYSCALLBUF_DESCHED_SIGNAL)";
    // Always send SYSCALLBUF_DESCHED_SIGNAL because other signals (except
    // TIME_SLICE_SIGNAL) will be blocked by
    // RecordTask::will_resume_execution().
    t->tgkill(t->session().syscallbuf_desched_sig());

    t->move_to_signal_stop();

    if (t->status().ptrace_event() == PTRACE_EVENT_EXIT) {
      /* We raced with an exit (e.g. due to a pending SIGKILL). */
      return false;
    }

    ASSERT(t, t->stop_sig() == t->session().syscallbuf_desched_sig())
        << "Expected SYSCALLBUF_DESCHED_SIGNAL, got " << t->status();
    /* We're now in a signal-stop */
  }

  /* Now that we're in a signal-stop, we can inject our signal and advance
   * to the signal handler with one single-step.
   */
  LOG(debug) << "    injecting signal " << signal_name(sig);
  t->set_siginfo(t->ev().Signal().siginfo);
  return true;
}

/**
 * Returns true if the signal should be delivered.
 * Returns false if this signal should not be delivered because another signal
 * occurred during delivery.
 * Must call t->stashed_signal_processed() once we're ready to unmask signals.
 */
static bool inject_handled_signal(RecordTask* t) {
  if (!preinject_signal(t)) {
    // Task prematurely exited.
    return false;
  }
  // If there aren't any more stashed signals, it's OK to stop blocking all
  // signals.
  t->stashed_signal_processed();

  int sig = t->ev().Signal().siginfo.si_signo;
  do {
    // We are ready to inject our signal.
    // XXX we assume the kernel won't respond by notifying us of a different
    // signal. We don't want to do this with signals blocked because that will
    // save a bogus signal mask in the signal frame.
    t->resume_execution(RESUME_SINGLESTEP, RESUME_WAIT, RESUME_NO_TICKS, sig);
    // Signal injection can change the sigmask due to sa_mask effects, lack of
    // SA_NODEFER, and signal frame construction triggering a synchronous
    // SIGSEGV.
    t->invalidate_sigmask();
    // Repeat injection if we got a desched signal. We observe in Linux 4.14.12
    // that we get SYSCALLBUF_DESCHED_SIGNAL here once in a while.
  } while (t->stop_sig() == t->session().syscallbuf_desched_sig());

  if (t->stop_sig() == SIGSEGV) {
    // Constructing the signal handler frame must have failed. Stash the signal
    // to deliver it later.
    t->stash_sig();
    if (sig == SIGSEGV) {
      // The kernel will kill the process after this. Make sure we know to treat
      // it as fatal when we inject it. Also disable the signal handler to match
      // what the kernel does.
      t->did_set_sig_handler_default(SIGSEGV);
      t->thread_group()->received_sigframe_SIGSEGV = true;
    }
    return false;
  }

  // We stepped into a user signal handler.
  ASSERT(t, t->stop_sig() == SIGTRAP)
      << "Got unexpected status " << t->status();
  ASSERT(t, t->get_signal_user_handler(sig) == t->ip())
      << "Expected handler IP " << t->get_signal_user_handler(sig) << ", got "
      << t->ip()
      << "; actual signal mask=" << HEX(t->read_sigmask_from_process())
      << " (cached " << HEX(t->get_sigmask()) << ")";

  if (t->signal_handler_takes_siginfo(sig)) {
    // The kernel copied siginfo into userspace so it can pass a pointer to
    // the signal handler. Replace the contents of that siginfo with
    // the exact data we want to deliver. (We called Task::set_siginfo
    // above to set that data, but the kernel sanitizes the passed-in data
    // which wipes out certain fields; e.g. we can't set SI_KERNEL in si_code.)
    setup_sigframe_siginfo(t, t->ev().Signal().siginfo);
  }

  // The kernel clears the FPU state on entering the signal handler, but prior
  // to 4.7 or thereabouts ptrace can still return stale values. Fix that here.
  // This also sets bit 0 of the XINUSE register to 1 to avoid issues where it
  // get set to 1 nondeterministically.
  ExtraRegisters e = t->extra_regs();
  e.reset();
  t->set_extra_regs(e);

  return true;
}

/**
 * |t| is being delivered a signal, and its state changed.
 * Must call t->stashed_signal_processed() once we're ready to unmask signals.
 */
bool RecordSession::signal_state_changed(RecordTask* t, StepState* step_state) {
  int sig = t->ev().Signal().siginfo.si_signo;

  switch (t->ev().type()) {
    case EV_SIGNAL: {
      // This event is used by the replayer to advance to
      // the point of signal delivery.
      t->record_current_event();
      t->ev().transform(EV_SIGNAL_DELIVERY);
      ssize_t sigframe_size = 0;

      bool has_handler = t->signal_has_user_handler(sig);
      if (has_handler) {
        LOG(debug) << "  " << t->tid << ": " << signal_name(sig)
                   << " has user handler";

        if (!inject_handled_signal(t)) {
          // Signal delivery isn't happening. Prepare to process the new
          // signal that aborted signal delivery.
          t->signal_delivered(sig);
          t->pop_signal_delivery();
          step_state->continue_type = DONT_CONTINUE;
          last_task_switchable = PREVENT_SWITCH;
          break;
        }

        if (is_x86ish(t->arch())) {
          // It's somewhat difficult engineering-wise to
          // compute the sigframe size at compile time,
          // and it can vary across kernel versions and CPU
          // microarchitectures. So this size is an overestimate
          // of the real size(s).
          //
          // If this size becomes too small in the
          // future, and unit tests that use sighandlers
          // are run with checksumming enabled, then
          // they can catch errors here.
          sigframe_size = 1152 /* Overestimate of kernel sigframe */ +
                          128 /* Redzone */ +
                          /* this returns 512 when XSAVE unsupported */
                          xsave_area_size();
        } else if (t->arch() == aarch64) {
          sigframe_size = sizeof(ARM64Arch::rt_sigframe) +
                          sizeof(ARM64Arch::user_fpsimd_state);
        } else {
          DEBUG_ASSERT(0 && "Add sigframe size for your architecture here");
        }

        t->ev().transform(EV_SIGNAL_HANDLER);
        t->signal_delivered(sig);
        // We already continued! Don't continue now, and allow switching.
        step_state->continue_type = DONT_CONTINUE;
        last_task_switchable = ALLOW_SWITCH;
      } else {
        t->stashed_signal_processed();
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

      // We record this data even if sigframe_size is zero to simplify replay.
      // Stop recording data if we run off the end of a writable mapping.
      // Our sigframe size is conservative so we need to do this.
      t->record_remote_writable(t->regs().sp(), sigframe_size);

      // This event is used by the replayer to set up the signal handler frame.
      // But if we don't have a handler, we don't want to record the event
      // until we deal with the EV_SIGNAL_DELIVERY.
      if (has_handler) {
        t->record_current_event();
      }
      break;
    }

    case EV_SIGNAL_DELIVERY: {
      // A SIGSTOP requires us to allow switching to another task.
      // So does a fatal, core-dumping signal, since we need to allow other
      // tasks to proceed to their exit events.
      bool is_fatal = t->ev().Signal().disposition == DISPOSITION_FATAL;
      bool is_deterministic = t->ev().Signal().deterministic == DETERMINISTIC_SIG;
      Switchable can_switch = ((is_fatal && is_coredumping_signal(sig)) || sig == SIGSTOP) ?
        ALLOW_SWITCH : PREVENT_SWITCH;

      // We didn't record this event above, so do that now.
      // NB: If there is no handler, and we interrupted a syscall, and there are
      // no more actionable signals, the kernel sets us up for a syscall
      // restart. But it does that *after* the ptrace trap. To replay this
      // correctly we need to fake those changes here. But we don't do this
      // if we're going to switch away at the ptrace trap, and for the moment,
      // 'can_switch' is actually 'will_switch'.
      // This is essentially copied from do_signal in arch/x86/kernel/signal.c
      bool has_other_signals = t->has_any_actionable_signal();
      auto r = t->regs();
      if (!is_fatal) {
        Event *prev_ev = t->prev_ev();
        if (can_switch == PREVENT_SWITCH && !has_other_signals && prev_ev &&
            EV_SYSCALL_INTERRUPTION == prev_ev->type()) {
          switch (prev_ev->Syscall().regs.syscall_result_signed()) {
            case -ERESTARTNOHAND:
            case -ERESTARTSYS:
            case -ERESTARTNOINTR:
              r.set_syscallno(r.original_syscallno());
              break;
            case -ERESTART_RESTARTBLOCK:
              r.set_syscallno(syscall_number_for_restart_syscall(t->arch()));
              break;
          }
          r.set_ip(r.ip().decrement_by_syscall_insn_length(t->arch()));
          // Now that we've mucked with the registers, we can't switch tasks. That
          // could allow more signals to be generated, breaking our assumption
          // that we are the last signal.
        } else {
          // But if we didn't touch the registers switching here is ok.
          can_switch = ALLOW_SWITCH;
        }
      }

      t->record_event(t->ev(), RecordTask::FLUSH_SYSCALLBUF,
                      RecordTask::ALLOW_RESET_SYSCALLBUF, &r);
      // Don't actually set_regs(r), the kernel does these modifications.

      // If the task is a container init, the kernel will ignore injection
      // of fatal signals. Usually, the kernel removes the killable-protection
      // when a determinisic fatal signal gets executed, but (due to what is
      // arguably a bug) when a ptracer is attached, this does not happen.
      // If we try to inject it here, the kernel will just ignore it,
      // and we'll go around again. As a hack, we detach here, in the
      // expectation that the deterministic instruction will run again and
      // actually kill the task now that it isn't under ptrace control anymore.
      if (t->is_container_init() && is_fatal && is_deterministic) {
        t->destroy_buffers(nullptr, nullptr);
        WaitStatus exit_status = WaitStatus::for_fatal_sig(sig);
        record_exit_trace_event(t, exit_status);
        t->record_exit_event(sig);
        // On a real affected kernel, we probably would have never gotten here,
        // since the signal we would be seeing was not deterministic, but let's
        // be conservative and still try to emulate the ptrace stop.
        if (t->do_ptrace_exit_stop(exit_status)) {
          t->waiting_for_reap = true;
        }
        t->did_kill();
        t->detach();
        // Not really, but we detached, so we're never gonna see that event
        // anyway, so just pretend we're there already
        t->did_reach_zombie();
        return true;
      }

      // Only inject fatal signals. Non-fatal signals with signal handlers
      // were taken care of above; for non-fatal signals without signal
      // handlers, there is no need to deliver the signal at all. In fact,
      // there is really no way to inject a non-fatal, non-handled signal
      // without letting the task execute at least one instruction, which
      // we don't want to do here.
      bool inject_signal = is_fatal && sig != get_continue_through_sig();
      if (inject_signal) {
        preinject_signal(t);
        t->resume_execution(RESUME_CONT, RESUME_NONBLOCKING, RESUME_NO_TICKS,
                            sig);
      }

      t->signal_delivered(sig);
      if (!inject_signal || !is_coredumping_signal(sig)) {
        /* Fatal signals may core-dump, so we don't consider the signal
         * delivery complete until we've actually managed to advance past that
         */
        t->pop_signal_delivery();
      }

      // Mark each task in this address space as expecting a ptrace exit
      // to avoid causing any ptrace_exit reaces.
      if (is_fatal && is_coredumping_signal(sig)) {
        for (Task *ot : t->vm()->task_set()) {
          if (t != ot) {
            ((RecordTask *)ot)->waiting_for_ptrace_exit = true;
          }
        }
      }

      last_task_switchable = can_switch;
      step_state->continue_type = DONT_CONTINUE;
      break;
    }

    default:
      FATAL() << "Unhandled signal state " << t->ev().type();
      break;
  }
  return false;
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
    // These signals might have effects on the sigmask.
    t->invalidate_sigmask();
    // No events to be recorded, so no syscallbuf updates
    // needed.
    return true;
  }

  if (sig == SIGTRAP && handle_syscallbuf_breakpoint(t)) {
    return true;
  }

  SignalDeterministic deterministic = is_deterministic_signal(t);
  // The kernel might have forcibly unblocked the signal. Check whether it
  // was blocked now, before we update our cached sigmask.
  SignalBlocked signal_was_blocked =
      t->is_sig_blocked(sig) ? SIG_BLOCKED : SIG_UNBLOCKED;
  if (deterministic || sig == t->session().syscallbuf_desched_sig()) {
    // Don't stash these signals; deliver them immediately.
    // We don't want them to be reordered around other signals.
    // invalidate_sigmask() must not be called before we reach handle_signal!
    siginfo_t siginfo = t->get_siginfo();
    switch (handle_signal(t, &siginfo, deterministic, signal_was_blocked)) {
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
        if (t->ptrace_event() == PTRACE_EVENT_SECCOMP) {
          // `handle_desched_event` detected a spurious desched followed
          // by a SECCOMP event, which it left pending. Handle that SECCOMP
          // event now.
          bool dummy_did_enter_syscall;
          handle_ptrace_event(&t, step_state, nullptr,
                              &dummy_did_enter_syscall);
          ASSERT(t, !dummy_did_enter_syscall);
        }
        break;
    }
    return false;
  }
  // Conservatively invalidate the sigmask in case just accepting a signal has
  // sigmask effects.
  t->invalidate_sigmask();
  if (sig == PerfCounters::TIME_SLICE_SIGNAL) {
    if (t->next_pmc_interrupt_is_for_user) {
      auto vpmc =
          VirtualPerfCounterMonitor::interrupting_virtual_pmc_for_task(t);
      ASSERT(t, vpmc);

      // Synthesize the requested signal.
      vpmc->synthesize_signal(t);

      t->next_pmc_interrupt_is_for_user = false;
      return true;
    }

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
    ASSERT(t,
           PerfCounters::TIME_SLICE_SIGNAL == si.si_signo &&
               (RecordTask::SYNTHETIC_TIME_SLICE_SI_CODE == si.si_code ||
                POLL_IN == si.si_code))
        << "Tracee is using SIGSTKFLT??? (code=" << si.si_code
        << ", fd=" << si.si_fd << ")";
  }
  t->stash_sig();
  return true;
}

template <typename Arch>
static bool is_ptrace_any_sysemu_arch(int command) {
  return command >= 0 &&
    (command == Arch::PTRACE_SYSEMU ||
     command == Arch::PTRACE_SYSEMU_SINGLESTEP);
}

static bool is_ptrace_any_sysemu(SupportedArch arch, int command)
{
  RR_ARCH_FUNCTION(is_ptrace_any_sysemu_arch, arch, command);
}

bool RecordSession::process_syscall_entry(RecordTask* t, StepState* step_state,
                                          RecordResult* step_result,
                                          SupportedArch syscall_arch) {
  if (const siginfo_t* si = t->stashed_sig_not_synthetic_SIGCHLD()) {
    // The only four cases where we allow a stashed signal to be pending on
    // syscall entry are:
    // -- the signal is a ptrace-related signal, in which case if it's generated
    // during a blocking syscall, it does not interrupt the syscall
    // -- rrcall_notify_syscall_hook_exit, which is effectively a noop and
    // lets us dispatch signals afterward
    // -- when we're entering a blocking untraced syscall. If it really blocks,
    // we'll get the desched-signal notification and dispatch our stashed
    // signal.
    // -- when we're doing a privileged syscall that's internal to the preload
    // logic
    // We do not generally want to have stashed signals pending when we enter
    // a syscall, because that will execute with a hacked signal mask
    // (see RecordTask::will_resume_execution) which could make things go wrong.
    ASSERT(t,
           t->desched_rec() || is_rrcall_notify_syscall_hook_exit_syscall(
                                   t->regs().original_syscallno(), t->arch()) ||
               t->ip() ==
                   t->vm()
                       ->privileged_traced_syscall_ip()
                       .increment_by_syscall_insn_length(t->arch()))
      << "Stashed signal pending on syscall entry when it shouldn't be: "
      << *si << "; IP=" << t->ip();
  }

  // We just entered a syscall.
  if (!maybe_restart_syscall(t)) {
    // Emit FLUSH_SYSCALLBUF if necessary before we do any patching work
    t->maybe_flush_syscallbuf();

    if (syscall_seccomp_ordering_ == PTRACE_SYSCALL_BEFORE_SECCOMP_UNKNOWN &&
        t->seccomp_bpf_enabled) {
      // We received a PTRACE_SYSCALL notification before the seccomp
      // notification. Ignore it and continue to the seccomp notification.
      syscall_seccomp_ordering_ = PTRACE_SYSCALL_BEFORE_SECCOMP;
      step_state->continue_type = CONTINUE;
      return true;
    }

    // Don't ever patch a sigreturn syscall. These can't go through the syscallbuf.
    if (!is_sigreturn(t->regs().original_syscallno(), t->arch())) {
      if (t->vm()->monkeypatcher().try_patch_syscall(t)) {
        // Syscall was patched. Emit event and continue execution.
        t->record_event(Event::patch_syscall());
        return true;
      }
    }

    if (t->ptrace_event() == PTRACE_EVENT_EXIT) {
      // task exited while we were trying to patch it.
      // Make sure that this exit event gets processed
      step_state->continue_type = DONT_CONTINUE;
      return false;
    }

    t->push_event(SyscallEvent(t->regs().original_syscallno(), syscall_arch));
  }

  check_initial_task_syscalls(t, step_result);
  note_entering_syscall(t);
  if ((t->emulated_ptrace_cont_command == PTRACE_SYSCALL ||
       is_ptrace_any_sysemu(t->arch(),
        t->emulated_ptrace_cont_command)) &&
      !is_in_privileged_syscall(t)) {
    t->ev().Syscall().state = ENTERING_SYSCALL_PTRACE;
    t->emulate_ptrace_stop(WaitStatus::for_syscall(t));
    t->record_current_event();

    t->ev().Syscall().in_sysemu = is_ptrace_any_sysemu(t->arch(),
      t->emulated_ptrace_cont_command);
  }
  return true;
}

/**
 * The execution of |t| has just been resumed, and it most likely has
 * a new event that needs to be processed.  Prepare that new event.
 * Returns false if the task exits during processing
 */
void RecordSession::runnable_state_changed(RecordTask* t, StepState* step_state,
                                           RecordResult* step_result,
                                           bool can_consume_wait_status) {
  switch (t->ev().type()) {
    case EV_NOOP:
      t->pop_noop();
      return;
    case EV_INSTRUCTION_TRAP:
      t->record_current_event();
      t->pop_event(t->ev().type());
      return;
    case EV_SENTINEL:
    case EV_SIGNAL_HANDLER:
    case EV_SYSCALL_INTERRUPTION: {
      if (!can_consume_wait_status) {
        return;
      }

      SupportedArch syscall_arch = t->detect_syscall_arch();
      t->canonicalize_regs(syscall_arch);
      t->apply_syscall_entry_regs();
      process_syscall_entry(t, step_state, step_result, syscall_arch);
      return;
    }

    default:
      return;
  }
}

bool RecordSession::prepare_to_inject_signal(RecordTask* t,
                                             StepState* step_state) {
  if (!done_initial_exec() || step_state->continue_type != CONTINUE) {
    return false;
  }

  union {
    NativeArch::siginfo_t native_api;
    siginfo_t linux_api;
  } si;
  const RecordTask::StashedSignal* sig;

  while (true) {
    sig = t->peek_stashed_sig_to_deliver();
    if (!sig) {
      return false;
    }
    si.linux_api = sig->siginfo;
    if (si.linux_api.si_signo == get_ignore_sig()) {
      LOG(debug) << "Declining to deliver "
                 << signal_name(si.linux_api.si_signo) << " by user request";
      t->pop_stash_sig(sig);
      t->stashed_signal_processed();
    } else {
      break;
    }
  }

  if (sig->deterministic == DETERMINISTIC_SIG &&
      sig->siginfo.si_signo == SIGSYS &&
      t->is_sig_blocked(sig->siginfo.si_signo) == SIG_BLOCKED) {
    // Our synthesized deterministic SIGSYS (seccomp trap) needs to match the
    // kernel behavior of unblocking the signal and resetting disposition to
    // default.
    t->unblock_signal(SIGSYS);
    t->set_sig_handler_default(SIGSYS);
  }
  switch (handle_signal(t, &si.linux_api, sig->deterministic, SIG_UNBLOCKED)) {
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
      // Signal is now a pending event on |t|'s event stack

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
  t->pop_stash_sig(sig);
  if (t->ev().type() != EV_SIGNAL) {
    t->stashed_signal_processed();
  }
  return true;
}

static string find_helper_library(const char* basepath) {
  string lib_path = resource_path() + "lib64/rr/";
  string file_name = lib_path + basepath;
  if (access(file_name.c_str(), F_OK) == 0) {
    return lib_path;
  }
  lib_path = resource_path() + "lib/rr/";
  file_name = lib_path + basepath;
  if (access(file_name.c_str(), F_OK) == 0) {
    return lib_path;
  }
  // File does not exist. Assume install put it in LD_LIBRARY_PATH.
  lib_path = "";
  return lib_path;
}

static void inject_ld_helper_library(vector<string>& env,
                                     string env_var,
                                     string value) {
  // Our preload lib should come first if possible, because that will speed up
  // the loading of the other libraries; it's also a good idea to put our audit
  // library at the head of the list, since there's only sixteen possible link
  // namespaces on glibc and each audit library uses up one.
  //
  // We supply a placeholder which is then mutated to the correct filename in
  // Monkeypatcher::patch_after_exec.
  auto env_assignment = env_var + "=";
  auto it = env.begin();
  for (; it != env.end(); ++it) {
    if (it->find(env_assignment) != 0) {
      continue;
    }
    // Honor old preloads too.  This may cause
    // problems, but only in those libs, and
    // that's the user's problem.
    value += ":";
    value += it->substr(it->find("=") + 1);
    break;
  }
  value = env_assignment + value;
  if (it == env.end()) {
    env.push_back(value);
  } else {
    *it = value;
  }
}

void strip_outer_ld_preload(vector<string>& env) {
  auto env_assignment = "LD_PRELOAD=";
  auto it = env.begin();
  for (; it != env.end(); ++it) {
    if (it->find(env_assignment) != 0) {
      continue;
    }
    size_t colon_pos = it->find(":");
    if (colon_pos != string::npos) {
      // If the preload library is loaded at all, it must be first
      size_t preload_pos = it->find("librrpreload");
      if (preload_pos < colon_pos) {
        string new_ld_preload = it->substr(++colon_pos);
        *it = env_assignment + new_ld_preload;
        return;
      } else {
        DEBUG_ASSERT(preload_pos == string::npos);
      }
    }
  }
}

struct ExeInfo {
  ExeInfo() : has_asan_symbols(false) {}
  // Empty if anything fails
  string libasan_path;
  bool has_asan_symbols;
};

static ExeInfo read_exe_info(const string& exe_file) {
  ExeInfo ret;
  ScopedFd fd(exe_file.c_str(), O_RDONLY);
  if (!fd.is_open()) {
    return ret;
  }
  ElfFileReader reader(fd);

  DynamicSection dynamic = reader.read_dynamic();
  for (auto& entry : dynamic.entries) {
    if (entry.tag == DT_NEEDED && entry.val < dynamic.strtab.size()) {
      const char* name = &dynamic.strtab[entry.val];
      if (!strncmp(name, "libasan", 7)) {
        ret.libasan_path = string(name);
      }
    }
  }

  auto syms = reader.read_symbols(".dynsym", ".dynstr");
  for (size_t i = 0; i < syms.size(); ++i) {
    if (syms.is_name(i, "__asan_init")) {
      ret.has_asan_symbols = true;
    }
  }

  return ret;
}

static string lookup_by_path(const string& name) {
  if (name.find('/') != string::npos) {
    return name;
  }
  const char* env = getenv("PATH");
  if (!env) {
    return name;
  }
  char* p = strdup(env);
  char* s = p;
  while (*s) {
    char* next = strchr(s, ':');
    if (next) {
      *next = 0;
    }
    string file = string(s) + "/" + name;
    struct stat st;
    if (!stat(file.c_str(), &st) && S_ISREG(st.st_mode) &&
        !access(file.c_str(), X_OK)) {
      free(p);
      return file;
    }
    if (!next) {
      break;
    }
    s = next + 1;
  }
  free(p);
  return name;
}

/*static*/ RecordSession::shr_ptr RecordSession::create(
    const vector<string>& argv, const vector<string>& extra_env,
    const DisableCPUIDFeatures& disable_cpuid_features,
    SyscallBuffering syscallbuf,
    unsigned char syscallbuf_desched_sig,
    BindCPU bind_cpu,
    const string& output_trace_dir,
    const TraceUuid* trace_id,
    bool use_audit,
    bool unmap_vdso,
    bool force_asan_active) {
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
          fprintf(stderr,
                  "rr needs /proc/sys/kernel/perf_event_paranoid <= 1, but it is %d.\n"
                  "Change it to 1, or use 'rr record -n' (slow).\n"
                  "Consider putting 'kernel.perf_event_paranoid = 1' in /etc/sysctl.conf.\n"
                  "See 'man 8 sysctl', 'man 5 sysctl.d' and 'man 5 sysctl.conf' for more details.\n",
                  val);
          exit(1);
        }
      }
    }
  }

  vector<string> env = current_env();

  // Have extra_env override anything already in the environment
  for (string extra : extra_env) {
    string extra_var = extra.substr(0, extra.find('='));
    auto it = env.begin();
    for (; it != env.end(); ++it) {
      if (it->find(extra_var) != 0) {
        continue;
      }
      it = env.erase(it);
      break;
    }
  }
  env.insert(env.end(), extra_env.begin(), extra_env.end());

  string full_path = lookup_by_path(argv[0]);
  ExeInfo exe_info = read_exe_info(full_path);

  // Strip any LD_PRELOAD that an outer rr may have inserted
  strip_outer_ld_preload(env);

  // LD_PRELOAD the syscall interception lib
  string syscall_buffer_lib_path = find_helper_library(SYSCALLBUF_LIB_FILENAME);
  if (!syscall_buffer_lib_path.empty()) {
    string ld_preload = "";
    if (!exe_info.libasan_path.empty()) {
      LOG(debug) << "Prepending " << exe_info.libasan_path << " to LD_PRELOAD";
      // Put an LD_PRELOAD entry for it before our preload library, because
      // it checks that it's loaded first
      ld_preload += exe_info.libasan_path + ":";
    }
    ld_preload += syscall_buffer_lib_path + SYSCALLBUF_LIB_FILENAME_PADDED;
    inject_ld_helper_library(env, "LD_PRELOAD", ld_preload);
  }

  if (use_audit) {
    string rtld_audit_lib_path = find_helper_library(RTLDAUDIT_LIB_FILENAME);
    if (!rtld_audit_lib_path.empty()) {
      string ld_audit = rtld_audit_lib_path + RTLDAUDIT_LIB_FILENAME_PADDED;
      inject_ld_helper_library(env, "LD_AUDIT", ld_audit);
    }
  }

  env.push_back("RUNNING_UNDER_RR=1");
  // Stop Mesa using the GPU
  env.push_back("LIBGL_ALWAYS_SOFTWARE=1");
  env.push_back("GBM_ALWAYS_SOFTWARE=1");
  env.push_back("SDL_RENDER_DRIVER=software");
  // Stop sssd from using shared-memory with its daemon
  env.push_back("SSS_NSS_USE_MEMCACHE=NO");

  // Disable Gecko's "wait for gdb to attach on process crash" behavior, since
  // it is useless when running under rr.
  env.push_back("MOZ_GDB_SLEEP=0");

  // If we have CPUID faulting, don't use these environment hacks. We don't
  // need them and the user might want to use them themselves for other reasons.
  if (!Session::has_cpuid_faulting()) {
    // OpenSSL uses RDRAND, but we can disable it. These bitmasks are inverted
    // and ANDed with the results of CPUID. The number below is 2^62, which is the
    // bit for RDRAND support.
    env.push_back("OPENSSL_ia32cap=~4611686018427387904:~0");
    // Disable Qt's use of RDRAND/RDSEED/RTM
    env.push_back("QT_NO_CPU_FEATURE=rdrand rdseed rtm");
    // Disable systemd's use of RDRAND
    env.push_back("SYSTEMD_RDRAND=0");
  }

  shr_ptr session(
      new RecordSession(full_path, argv, env, disable_cpuid_features,
                        syscallbuf, syscallbuf_desched_sig, bind_cpu,
                        output_trace_dir, trace_id, use_audit, unmap_vdso));
  session->set_asan_active(force_asan_active ||
                           !exe_info.libasan_path.empty() ||
                           exe_info.has_asan_symbols);
  return session;
}

RecordSession::RecordSession(const std::string& exe_path,
                             const std::vector<std::string>& argv,
                             const std::vector<std::string>& envp,
                             const DisableCPUIDFeatures& disable_cpuid_features,
                             SyscallBuffering syscallbuf,
                             int syscallbuf_desched_sig,
                             BindCPU bind_cpu,
                             const string& output_trace_dir,
                             const TraceUuid* trace_id,
                             bool use_audit,
                             bool unmap_vdso)
    : trace_out(argv[0], output_trace_dir, ticks_semantics_),
      scheduler_(*this),
      trace_id(trace_id),
      disable_cpuid_features_(disable_cpuid_features),
      ignore_sig(0),
      continue_through_sig(0),
      last_task_switchable(PREVENT_SWITCH),
      syscall_buffer_size_(1024 * 1024),
      syscallbuf_desched_sig_(syscallbuf_desched_sig),
      use_syscall_buffer_(syscallbuf == ENABLE_SYSCALL_BUF),
      use_file_cloning_(true),
      use_read_cloning_(true),
      enable_chaos_(false),
      asan_active_(false),
      wait_for_all_(false),
      use_audit_(use_audit),
      unmap_vdso_(unmap_vdso) {
  if (!has_cpuid_faulting() &&
      disable_cpuid_features.any_features_disabled()) {
    FATAL() << "CPUID faulting required to disable CPUID features";
  }

  if (rr::syscall_number_for_rrcall_init_preload(x86_64) != RR_CALL_BASE) {
    FATAL() << "RR_CALL_BASE is incorrect";
  }

  trace_out.set_bound_cpu(choose_cpu(bind_cpu, cpu_lock));
  do_bind_cpu(trace_out);
  ScopedFd error_fd = create_spawn_task_error_pipe();
  RecordTask* t = static_cast<RecordTask*>(
      Task::spawn(*this, error_fd, &tracee_socket_fd(),
                  &tracee_socket_receiver_fd(),
                  &tracee_socket_fd_number,
                  exe_path, argv, envp));

  if (NativeArch::is_x86ish()) {
    // CPU affinity has been set.
    trace_out.setup_cpuid_records(has_cpuid_faulting(), disable_cpuid_features_);
    if (cpu_has_xsave_fip_fdp_quirk()) {
      trace_out.set_xsave_fip_fdp_quirk(true);
      // Clear FIP/FDP on every event to reduce the probability of this quirk
      // causing divergence, especially when porting traces to Intel machines
      trace_out.set_clear_fip_fdp(true);
    }
    if (cpu_has_fdp_exception_only_quirk()) {
      trace_out.set_fdp_exception_only_quirk(true);
    }
  }

  initial_thread_group = t->thread_group();
  on_create(t);
}

bool RecordSession::can_end() {
  if (wait_for_all_) {
    return task_map.empty();
  }
  return initial_thread_group->task_set().empty();
}

RecordSession::RecordResult RecordSession::record_step() {
  RecordResult result;

  if (can_end()) {
    result.status = STEP_EXITED;
    result.exit_status = initial_thread_group->exit_status;
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
  if (IS_LOGGING(debug)) {
    t->log_pending_events();
  }

  if (handle_ptrace_exit_event(t)) {
    // t may have been deleted.
    last_task_switchable = ALLOW_SWITCH;
    return result;
  }

  StepState step_state(CONTINUE);

  bool did_enter_syscall;
  if (rescheduled.by_waitpid &&
      handle_ptrace_event(&t, &step_state, &result, &did_enter_syscall)) {
    if (result.status != STEP_CONTINUE ||
        step_state.continue_type == DONT_CONTINUE) {
      return result;
    }

    if (did_enter_syscall && t->ev().type() == EV_SYSCALL) {
      syscall_state_changed(t, &step_state);
    }
  } else if (rescheduled.by_waitpid && handle_signal_event(t, &step_state)) {
  } else {
    runnable_state_changed(t, &step_state, &result, rescheduled.by_waitpid);

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
        if (signal_state_changed(t, &step_state)) {
          // t may have been deleted
          return result;
        }
        break;
      default:
        break;
    }
  }

  t->verify_signal_states();

  // We try to inject a signal if there's one pending; otherwise we continue
  // task execution.
  if (!prepare_to_inject_signal(t, &step_state) &&
      step_state.continue_type != DONT_CONTINUE) {
    // Ensure that we aren't allowing switches away from a running task.
    // Only tasks blocked in a syscall can be switched away from, otherwise
    // we have races.
    ASSERT(t,
           last_task_switchable == PREVENT_SWITCH ||
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

  kill_all_record_tasks();
  t = nullptr; // t is now deallocated
  close_trace_writer(TraceWriter::CLOSE_OK);
}

void RecordSession::kill_all_record_tasks() {
  LOG(debug) << "Killing all tasks ...";
  for (int pass = 0; pass <= 2; ++pass) {
    /* We delete tasks in three passes. First we complete any coredumps in
     * progress. Then, we kill every non-thread-group-leader,
     * lastly we kill every group leader.
     * Linux expects threads group leaders to survive until the last
     * member of the thread group has exited, so we accomodate that.
     */
    for (auto& v : task_map) {
      RecordTask* t = static_cast<RecordTask*>(v.second);
      // If the task was detached and none of our tasks explicitly waited for
      // it, we let the detached task just run freely (the zombie proxy we
      // keep around kill get reaped when we destroy the RecordTask itself)
      if (pass == 0) {
        if (t->waiting_for_ptrace_exit && !t->seen_ptrace_exit_event) {
          t->wait();
          if (!t->already_exited()) {
            record_exit_trace_event(t, t->status());
            t->record_exit_event(t->status().fatal_sig());
          }
          t->did_kill();
          t->fallible_ptrace(PTRACE_CONT, nullptr, nullptr);
        }
        continue;
      }
      if (t->detached_proxy) {
        continue;
      }
      if (t->already_reaped()) {
        continue;
      }
      bool is_group_leader = t->tid == t->real_tgid();
      if (pass == 1 ? is_group_leader : !is_group_leader) {
        continue;
      }
      if (t->waiting_for_ptrace_exit) {
        t->reap();
      } else {
        WaitStatus status = t->kill();
        if (!t->already_exited()) {
          record_exit_trace_event(t, status);
          t->record_exit_event(status.fatal_sig());
        }
      }
    }
  }
  while (!task_map.empty()) {
    Task* t = task_map.rbegin()->second;
    delete t;
  }
  assert(task_map.empty());
}

void RecordSession::close_trace_writer(TraceWriter::CloseStatus status) {
  trace_out.close(status, trace_id.get());
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

void RecordSession::on_proxy_detach(RecordTask *t, pid_t new_tid) {
  Session::on_destroy(t);
  task_map[new_tid] = t;
}

uint64_t RecordSession::rr_signal_mask() const {
  return signal_bit(PerfCounters::TIME_SLICE_SIGNAL) |
         signal_bit(syscallbuf_desched_sig_);
}

static const uint32_t CPUID_RDRAND_FLAG = 1 << 30;
static const uint32_t CPUID_RTM_FLAG = 1 << 11;
static const uint32_t CPUID_RDSEED_FLAG = 1 << 18;
static const uint32_t CPUID_XSAVEOPT_FLAG = 1 << 0;

void DisableCPUIDFeatures::amend_cpuid_data(uint32_t eax_in, uint32_t ecx_in,
                                            CPUIDData* cpuid_data) const {
  switch (eax_in) {
    case CPUID_GETFEATURES:
      cpuid_data->ecx &= ~(CPUID_RDRAND_FLAG | features_ecx);
      cpuid_data->edx &= ~features_edx;
      break;
    case CPUID_GETEXTENDEDFEATURES:
      if (ecx_in == 0) {
        cpuid_data->ebx &= ~(CPUID_RDSEED_FLAG | CPUID_RTM_FLAG
            | extended_features_ebx);
        cpuid_data->ecx &= ~extended_features_ecx;
        cpuid_data->edx &= ~extended_features_edx;
      }
      break;
    case CPUID_GETXSAVE:
      if (ecx_in == 1) {
        // Always disable XSAVEOPT because it's nondeterministic,
        // possibly depending on context switching behavior. Intel
        // recommends not using it from user space.
        cpuid_data->eax &= ~(CPUID_XSAVEOPT_FLAG | xsave_features_eax);
      }
      break;
    default:
      break;
  }
}

} // namespace rr
