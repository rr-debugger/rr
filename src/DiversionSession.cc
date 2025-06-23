/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DiversionSession.h"

#include <linux/prctl.h>

#include "AutoRemoteSyscalls.h"
#include "ReplaySession.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"

using namespace std;

namespace rr {

DiversionSession::DiversionSession(BindCPU cpu_binding) :
  emu_fs(EmuFs::create()), fake_timer_counter(uint64_t(1) << 60), cpu_binding_(cpu_binding) {}

DiversionSession::~DiversionSession() {
  // We won't permanently leak any OS resources by not ensuring
  // we've cleaned up here, but sessions can be created and
  // destroyed many times, and we don't want to temporarily hog
  // resources.
  kill_all_tasks();
  DEBUG_ASSERT(tasks().size() == 0 && vms().size() == 0);
  DEBUG_ASSERT(emu_fs->size() == 0);
}

static void finish_emulated_syscall_with_ret(Task* t, long ret) {
  t->finish_emulated_syscall();
  Registers r = t->regs();
  r.set_syscall_result(ret);
  t->set_regs(r);
}

/**
 * Execute the syscall contained in |t|'s current register set.  The
 * return value of the syscall is set for |t|'s registers, to be
 * returned to the tracee task.
 */
static void execute_syscall(Task* t) {
  t->finish_emulated_syscall();

  AutoRemoteSyscalls remote(t);
  remote.syscall(remote.regs().original_syscallno(), remote.regs().arg1(),
                 remote.regs().arg2(), remote.regs().arg3(),
                 remote.regs().arg4(), remote.regs().arg5(),
                 remote.regs().arg6());
  remote.regs().set_syscall_result(t->regs().syscall_result());
}

uint64_t DiversionSession::next_timer_counter() {
  uint64_t value = fake_timer_counter;
  fake_timer_counter += 1 << 20; // 1M cycles
  return value;
}

template <typename Arch>
static void process_syscall_arch(Task* t, int syscallno) {
  LOG(debug) << "Processing " << syscall_name(syscallno, Arch::arch());

  if (syscallno == Arch::ioctl && t->is_desched_event_syscall()) {
    // The arm/disarm-desched ioctls are emulated as no-ops.
    // However, because the rr preload library expects these
    // syscalls to succeed and aborts if they don't, we fudge a
    // "0" return value.
    finish_emulated_syscall_with_ret(t, 0);
    return;
  }

  if (syscallno == t->session().syscall_number_for_rrcall_rdtsc()) {
    uint64_t rdtsc_value = static_cast<DiversionSession*>(&t->session())->next_timer_counter();
    LOG(debug) << "Faking rrcall_rdtsc syscall with value " << rdtsc_value;
    remote_ptr<uint64_t> out_param(t->regs().arg1());
    t->write_mem(out_param, rdtsc_value);
    finish_emulated_syscall_with_ret(t, 0);
    return;
  }

  switch (syscallno) {
    // We blacklist these syscalls because the params include
    // namespaced identifiers that are different in replay than
    // recording, and during replay they may refer to different,
    // live resources.  For example, if a recorded tracees kills
    // one of its threads, then during replay that killed pid
    // might refer to a live process outside the tracee tree.  We
    // don't want diversion tracees randomly shooting down other
    // processes!
    //
    // We optimistically assume that filesystem operations were
    // intended by the user.
    //
    // There's a potential problem with "fd confusion": in the
    // diversion tasks, fds returned from open() during replay are
    // emulated.  But those fds may accidentally refer to live fds
    // in the task fd table.  So write()s etc may not be writing
    // to the file the tracee expects.  However, the only real fds
    // that leak into tracees are the stdio fds, and there's not
    // much harm that can be caused by accidental writes to them.
    case Arch::ipc:
    case Arch::kill:
    case Arch::rt_sigqueueinfo:
    case Arch::rt_tgsigqueueinfo:
    case Arch::tgkill:
    case Arch::tkill:
    // fork/vfork/clone are likely to lead to disaster because we only
    // ever allow a single task to run.
    case Arch::fork:
    case Arch::vfork:
    case Arch::clone: {
      LOG(debug) << "Suppressing syscall "
                 << syscall_name(syscallno, t->arch());
      Registers r = t->regs();
      r.set_syscall_result(-ENOSYS);
      t->set_regs(r);
      return;
    }

    case Arch::prctl: {
      Registers r = t->regs();
      int op = r.arg1();
      if (op == PR_SET_TSC) {
        LOG(debug) << "Suppressing syscall "
                   << syscall_name(syscallno, t->arch());
        r.set_syscall_result(-ENOSYS);
        t->set_regs(r);
        return;
      }
      break;
    }

    case Arch::gettid: {
      auto tid = t->own_namespace_tid();
      LOG(debug) << "Emulating gettid with " << tid;
      Registers r = t->regs();
      r.set_syscall_result(tid);
      t->set_regs(r);
      return;
    }

    case Arch::getpid: {
      auto pid = t->thread_group()->tgid_own_namespace;
      LOG(debug) << "Emulating getpid with " << pid;
      Registers r = t->regs();
      r.set_syscall_result(pid);
      t->set_regs(r);
      return;
    }
  }

  LOG(debug) << "Executing syscall " << syscall_name(syscallno, t->arch());
  execute_syscall(t);
}

static void process_syscall(Task* t, int syscallno){
  RR_ARCH_FUNCTION(process_syscall_arch, t->arch(), t, syscallno)
}

static bool maybe_handle_task_exit(Task* t, TaskContext* context,
                                   DiversionSession::DiversionResult* result) {
  if (t->ptrace_event() != PTRACE_EVENT_EXIT && !t->was_reaped()) {
    return false;
  }
  t->did_kill();
  t->detach();
  delete t;
  // This is now a dangling pointer, so clear it.
  context->task = nullptr;
  result->status = DiversionSession::DIVERSION_EXITED;
  result->break_status.task_context = *context;
  result->break_status.task_exit = true;
  return true;
}

/**
 * Advance execution until either a signal is received (including a SIGTRAP
 * generated by a single-step) or a syscall is made.
 */
DiversionSession::DiversionResult DiversionSession::diversion_step(
    Task* t, RunCommand command, int signal_to_deliver) {
  DEBUG_ASSERT(command != RUN_SINGLESTEP_FAST_FORWARD);
  assert_fully_initialized();

  DiversionResult result;
  TaskContext context(t);

  // An exit might have occurred while processing a previous syscall.
  if (maybe_handle_task_exit(t, &context, &result)) {
    return result;
  }

  t->set_in_diversion(true);

  while (true) {
    switch (command) {
      case RUN_CONTINUE: {
        LOG(debug) << "Continuing to next syscall";
        bool ok = t->resume_execution(RESUME_SYSEMU, RESUME_WAIT,
                                      RESUME_UNLIMITED_TICKS, signal_to_deliver);
        ASSERT(t, ok) << "Tracee was killed unexpectedly";
        break;
      }
      case RUN_SINGLESTEP: {
        LOG(debug) << "Stepping to next insn/syscall";
        bool ok = t->resume_execution(RESUME_SYSEMU_SINGLESTEP, RESUME_WAIT,
                                      RESUME_UNLIMITED_TICKS, signal_to_deliver);
        ASSERT(t, ok) << "Tracee was killed unexpectedly";
        break;
      }
      default:
        FATAL() << "Illegal run command " << command;
    }

    if (maybe_handle_task_exit(t, &context, &result)) {
      return result;
    }

    result.status = DIVERSION_CONTINUE;
    if (t->stop_sig()) {
      LOG(debug) << "Pending signal: " << t->get_siginfo();
      result.break_status = diagnose_debugger_trap(t, command);
      if (t->stop_sig() == SIGTRAP &&
          !result.break_status.breakpoint_hit &&
          result.break_status.watchpoints_hit.empty() &&
          !result.break_status.singlestep_complete) {
        result.break_status.signal = unique_ptr<siginfo_t>(new siginfo_t(t->get_siginfo()));
        result.break_status.signal->si_signo = t->stop_sig();
      } else if (t->stop_sig() == SIGSEGV) {
        auto special_instruction = special_instruction_at(t, t->ip());
        if (special_instruction.opcode == SpecialInstOpcode::X86_RDTSC) {
          size_t len = special_instruction_len(special_instruction.opcode);
          uint64_t rdtsc_value = next_timer_counter();
          LOG(debug) << "Faking RDTSC instruction with value " << rdtsc_value;
          Registers r = t->regs();
          r.set_ip(r.ip() + len);
          r.set_ax((uint32_t)rdtsc_value);
          r.set_dx(rdtsc_value >> 32);
          t->set_regs(r);
          result.break_status = BreakStatus();
          continue;
        } else if (special_instruction.opcode == SpecialInstOpcode::ARM_MRS_CNTVCT_EL0 ||
                   special_instruction.opcode == SpecialInstOpcode::ARM_MRS_CNTVCTSS_EL0) {
          size_t len = special_instruction_len(special_instruction.opcode);
          uint64_t cntvct_value = next_timer_counter();
          Registers r = t->regs();
          r.set_ip(r.ip() + len);
          if (special_instruction.regno != 31) {
            r.set_x(special_instruction.regno, cntvct_value);
          }
          t->set_regs(r);
          result.break_status = BreakStatus();
          continue;
        } else if (special_instruction.opcode == SpecialInstOpcode::ARM_MRS_CNTFRQ_EL0) {
          size_t len = special_instruction_len(special_instruction.opcode);
          Registers r = t->regs();
          r.set_ip(r.ip() + len);
          if (special_instruction.regno != 31) {
            r.set_x(special_instruction.regno, cntfrq());
          }
          t->set_regs(r);
          result.break_status = BreakStatus();
          continue;
        }
      }
      LOG(debug) << "Diversion break at ip=" << (void*)t->ip().register_value()
                 << "; break=" << result.break_status.breakpoint_hit
                 << ", watch=" << !result.break_status.watchpoints_hit.empty()
                 << ", singlestep=" << result.break_status.singlestep_complete;
      ASSERT(t,
             !result.break_status.singlestep_complete ||
                 command == RUN_SINGLESTEP);
      return result;
    }
    break;
  }

  if (t->status().is_syscall()) {
    t->apply_syscall_entry_regs();
  }

  process_syscall(t, t->regs().original_syscallno());
  check_for_watchpoint_changes(t, result.break_status);
  return result;
}

} // namespace rr
