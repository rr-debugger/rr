/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "record_signal.h"

#include <fcntl.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/user.h>
#include <syscall.h>
#include <x86intrin.h>

#include "preload/preload_interface.h"

#include "AutoRemoteSyscalls.h"
#include "Flags.h"
#include "PerfCounters.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "TraceStream.h"
#include "VirtualPerfCounterMonitor.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

static __inline__ unsigned long long rdtsc(void) { return __rdtsc(); }

template <typename Arch> static size_t sigaction_sigset_size_arch() {
  return sizeof(typename Arch::kernel_sigset_t);
}

static size_t sigaction_sigset_size(SupportedArch arch) {
  RR_ARCH_FUNCTION(sigaction_sigset_size_arch, arch);
}

static void restore_sighandler_if_not_default(RecordTask* t, int sig) {
  if (t->sig_disposition(sig) != SIGNAL_DEFAULT) {
    LOG(debug) << "Restoring signal handler for " << signal_name(sig);
    AutoRemoteSyscalls remote(t);
    size_t sigset_size = sigaction_sigset_size(remote.arch());
    const vector<uint8_t>& sa = t->signal_action(sig);
    AutoRestoreMem child_sa(remote, sa.data(), sa.size());
    remote.infallible_syscall(syscall_number_for_rt_sigaction(remote.arch()),
                              sig, child_sa.get().as_int(), nullptr,
                              sigset_size);
  }
}

/**
 * Restore the blocked-ness and sigaction for |sig| from |t|'s local
 * copy.
 */
static void restore_signal_state(RecordTask* t, int sig,
                                 SignalBlocked signal_was_blocked) {
  restore_sighandler_if_not_default(t, sig);
  if (signal_was_blocked) {
    LOG(debug) << "Restoring signal blocked-ness for " << signal_name(sig);
    AutoRemoteSyscalls remote(t);
    size_t sigset_size = sigaction_sigset_size(remote.arch());
    vector<uint8_t> bytes;
    bytes.resize(sigset_size);
    memset(bytes.data(), 0, sigset_size);
    sig_set_t mask = signal_bit(sig);
    ASSERT(t, sigset_size >= sizeof(mask));
    memcpy(bytes.data(), &mask, sizeof(mask));
    AutoRestoreMem child_block(remote, bytes.data(), bytes.size());
    remote.infallible_syscall(syscall_number_for_rt_sigprocmask(remote.arch()),
                              SIG_BLOCK, child_block.get().as_int(), nullptr,
                              sigset_size);
    // We just changed the sigmask ourselves.
    t->invalidate_sigmask();
  }
}

/**
 * Return true if |t| was stopped because of a SIGSEGV resulting
 * from a disabled instruction and |t| was updated appropriately, false
 * otherwise.
 */
static bool try_handle_trapped_instruction(RecordTask* t, siginfo_t* si) {
  ASSERT(t, si->si_signo == SIGSEGV);

  auto trapped_instruction = trapped_instruction_at(t, t->ip());
  switch (trapped_instruction) {
    case TrappedInstruction::RDTSC:
    case TrappedInstruction::RDTSCP:
      if (t->tsc_mode == PR_TSC_SIGSEGV) {
        return false;
      }
      break;
    case TrappedInstruction::CPUID:
      if (t->cpuid_mode == 0) {
        return false;
      }
      break;
    default:
      return false;
  }

  size_t len = trapped_instruction_len(trapped_instruction);
  ASSERT(t, len > 0);

  Registers r = t->regs();
  if (trapped_instruction == TrappedInstruction::RDTSC ||
      trapped_instruction == TrappedInstruction::RDTSCP) {
    unsigned long long current_time = rdtsc();
    r.set_rdtsc_output(current_time);

    LOG(debug) << " trapped for rdtsc: returning " << current_time;
  } else if (trapped_instruction == TrappedInstruction::CPUID) {
    auto eax = r.syscallno();
    auto ecx = r.cx();
    auto cpuid_data = cpuid(eax, ecx);
    t->session().disable_cpuid_features()
        .amend_cpuid_data(eax, ecx, &cpuid_data);
    r.set_cpuid_output(cpuid_data.eax, cpuid_data.ebx, cpuid_data.ecx,
                       cpuid_data.edx);
    LOG(debug) << " trapped for cpuid: " << HEX(eax) << ":" << HEX(ecx);
  }

  r.set_ip(r.ip() + len);
  t->set_regs(r);

  t->push_event(Event::instruction_trap());
  return true;
}

/**
 * Return true if |t| was stopped because of a SIGSEGV and we want to retry
 * the instruction after emulating MAP_GROWSDOWN.
 */
static bool try_grow_map(RecordTask* t, siginfo_t* si) {
  ASSERT(t, si->si_signo == SIGSEGV);

  // Use kernel_abi to avoid odd inconsistencies between distros
  auto arch_si = reinterpret_cast<NativeArch::siginfo_t*>(si);
  auto addr = arch_si->_sifields._sigfault.si_addr_.rptr();

  if (t->vm()->has_mapping(addr)) {
    LOG(debug) << "try_grow_map " << addr << ": address already mapped";
    return false;
  }
  auto maps = t->vm()->maps_starting_at(floor_page_size(addr));
  auto it = maps.begin();
  if (it == maps.end()) {
    LOG(debug) << "try_grow_map " << addr << ": no later map to grow downward";
    return false;
  }
  if (!(it->map.flags() & MAP_GROWSDOWN)) {
    LOG(debug) << "try_grow_map " << addr << ": map is not MAP_GROWSDOWN ("
               << it->map << ")";
    return false;
  }
  if (addr >= page_size() && t->vm()->has_mapping(addr - page_size())) {
    LOG(debug) << "try_grow_map " << addr << ": address would be in guard page";
    return false;
  }
  struct rlimit stack_limit;
  remote_ptr<void> limit_bottom;
  int ret = prlimit(t->tid, RLIMIT_STACK, NULL, &stack_limit);
  if (ret >= 0 && stack_limit.rlim_cur != RLIM_INFINITY) {
    limit_bottom = ceil_page_size(it->map.end() - stack_limit.rlim_cur);
    if (limit_bottom > addr) {
      LOG(debug) << "try_grow_map " << addr << ": RLIMIT_STACK exceeded";
      return false;
    }
  }

  // Try to grow by 64K at a time to reduce signal frequency.
  auto new_start = floor_page_size(addr);
  static const uintptr_t grow_size = 0x10000;
  if (it->map.start().as_int() >= grow_size) {
    auto possible_new_start = std::max(
        limit_bottom, std::min(new_start, it->map.start() - grow_size));
    // Ensure that no mapping exists between possible_new_start - page_size()
    // and new_start. If there is, possible_new_start is not valid, in which
    // case we just abandon the optimization.
    if (possible_new_start >= page_size() &&
        !t->vm()->has_mapping(possible_new_start - page_size()) &&
        t->vm()->maps_starting_at(possible_new_start - page_size())
                .begin()
                ->map.start() == it->map.start()) {
      new_start = possible_new_start;
    }
  }
  LOG(debug) << "try_grow_map " << addr << ": trying to grow map " << it->map;

  {
    AutoRemoteSyscalls remote(t, AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS);
    remote.infallible_mmap_syscall(
        new_start, it->map.start() - new_start, it->map.prot(),
        (it->map.flags() & ~MAP_GROWSDOWN) | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  }

  KernelMapping km =
      t->vm()->map(t, new_start, it->map.start() - new_start, it->map.prot(),
                   it->map.flags() | MAP_ANONYMOUS, 0, string(),
                   KernelMapping::NO_DEVICE, KernelMapping::NO_INODE);
  t->trace_writer().write_mapped_region(t, km, km.fake_stat());
  // No need to flush syscallbuf here. It's safe to map these pages "early"
  // before they're really needed.
  t->record_event(Event::grow_map(), RecordTask::DONT_FLUSH_SYSCALLBUF);
  t->push_event(Event::noop());
  LOG(debug) << "try_grow_map " << addr << ": extended map "
             << t->vm()->mapping_of(addr).map;
  return true;
}

void disarm_desched_event(RecordTask* t) {
  if (ioctl(t->desched_fd, PERF_EVENT_IOC_DISABLE, 0)) {
    FATAL() << "Failed to disarm desched event";
  }
}

void arm_desched_event(RecordTask* t) {
  if (ioctl(t->desched_fd, PERF_EVENT_IOC_ENABLE, 0)) {
    FATAL() << "Failed to disarm desched event";
  }
}

template <typename Arch>
static remote_code_ptr get_stub_scratch_1_arch(RecordTask* t) {
  auto locals = t->read_mem(AddressSpace::preload_thread_locals_start()
                                .cast<preload_thread_locals<Arch>>());
  return locals.stub_scratch_1.rptr().as_int();
}

static remote_code_ptr get_stub_scratch_1(RecordTask* t) {
  RR_ARCH_FUNCTION(get_stub_scratch_1_arch, t->arch(), t);
}

/**
 * This function is responsible for handling breakpoints we set in syscallbuf
 * code to detect sigprocmask calls and syscallbuf exit. It's called when we
 * get a SIGTRAP. Returns true if the SIGTRAP was called by one of our
 * breakpoints and should be hidden from the application.
 * If it was triggered by one of our breakpoints, we have to call
 * restore_sighandler_if_not_default(t, SIGTRAP) to make sure the SIGTRAP
 * handler is properly restored if the kernel cleared it.
 */
bool handle_syscallbuf_breakpoint(RecordTask* t) {
  if (t->is_at_syscallbuf_final_instruction_breakpoint()) {
    LOG(debug) << "Reached final syscallbuf instruction, singlestepping to "
                  "enable signal dispatch";
    // This is a single instruction that jumps to the location stored in
    // preload_thread_locals::stub_scratch_1. Emulate it.
    Registers r = t->regs();
    r.set_ip(get_stub_scratch_1(t));
    t->set_regs(r);

    restore_sighandler_if_not_default(t, SIGTRAP);
    // Now we're back in application code so any pending stashed signals
    // will be handled.
    return true;
  }

  if (!t->is_at_syscallbuf_syscall_entry_breakpoint()) {
    return false;
  }

  Registers r = t->regs();
  r.set_ip(r.ip().decrement_by_bkpt_insn_length(t->arch()));
  t->set_regs(r);

  if (t->is_at_traced_syscall_entry()) {
    // We will automatically dispatch stashed signals now since this is an
    // allowed place to dispatch signals.
    LOG(debug) << "Allowing signal dispatch at traced-syscall breakpoint";
    restore_sighandler_if_not_default(t, SIGTRAP);
    return true;
  }

  // We're at an untraced-syscall entry point.
  // To allow an AutoRemoteSyscall, we need to make sure desched signals are
  // disarmed (and rearmed afterward).
  bool armed_desched_event = t->read_mem(
      REMOTE_PTR_FIELD(t->syscallbuf_child, desched_signal_may_be_relevant));
  if (armed_desched_event) {
    disarm_desched_event(t);
  }
  restore_sighandler_if_not_default(t, SIGTRAP);
  if (armed_desched_event) {
    arm_desched_event(t);
  }

  // This is definitely a native-arch syscall.
  if (is_rt_sigprocmask_syscall(r.syscallno(), t->arch())) {
    // Don't proceed with this syscall. Emulate it returning EAGAIN.
    // Syscallbuf logic will retry using a traced syscall instead.
    r.set_syscall_result(-EAGAIN);
    r.set_ip(r.ip().increment_by_syscall_insn_length(t->arch()));
    t->set_regs(r);
    t->canonicalize_regs(t->arch());
    LOG(debug) << "Emulated EAGAIN to avoid untraced sigprocmask with pending "
                  "stashed signal";
    // Leave breakpoints enabled since we want to break at the traced-syscall
    // fallback for rt_sigprocmask.
    return true;
  }

  // We can proceed with the untraced syscall. Either it will complete and
  // execution will continue until we reach some point where we can deliver our
  // signal, or it will block at which point we'll be able to deliver our
  // signal.
  LOG(debug) << "Disabling breakpoints at untraced syscalls";
  t->break_at_syscallbuf_untraced_syscalls = false;
  return true;
}

/**
 * Return the event needing to be processed after this desched of |t|.
 * The tracee's execution may be advanced, and if so |regs| is updated
 * to the tracee's latest state.
 */
static void handle_desched_event(RecordTask* t, const siginfo_t* si) {
  ASSERT(t, SYSCALLBUF_DESCHED_SIGNAL == si->si_signo && si->si_code == POLL_IN)
      << "Tracee is using SIGPWR??? (siginfo=" << *si << ")";

  /* If the tracee isn't in the critical section where a desched
   * event is relevant, we can ignore it.  See the long comments
   * in syscall_buffer.c.
   *
   * It's OK if the tracee is in the critical section for a
   * may-block syscall B, but this signal was delivered by an
   * event programmed by a previous may-block syscall A.
   *
   * If we're running in a signal handler inside an interrupted syscallbuf
   * system call, never do anything here. Syscall buffering is disabled and
   * the desched_signal_may_be_relevant was set by the outermost syscallbuf
   * invocation.
   */
  if (!t->read_mem(REMOTE_PTR_FIELD(t->syscallbuf_child,
                                    desched_signal_may_be_relevant)) ||
      t->running_inside_desched()) {
    LOG(debug) << "  (not entering may-block syscall; resuming)";
    /* We have to disarm the event just in case the tracee
     * has cleared the relevancy flag, but not yet
     * disarmed the event itself. */
    disarm_desched_event(t);
    t->push_event(Event::noop());
    return;
  }

  /* TODO: how can signals interrupt us here? */

  /* The desched event just fired.  That implies that the
   * arm-desched ioctl went into effect, and that the
   * disarm-desched syscall didn't take effect.  Since a signal
   * is pending for the tracee, then if the tracee was in a
   * syscall, linux has exited it with an -ERESTART* error code.
   * That means the tracee is about to (re-)enter either
   *
   *  1. buffered syscall
   *  2. disarm-desched ioctl syscall
   *
   * We can figure out which one by simply issuing a
   * ptrace(SYSCALL) and examining the tracee's registers.
   *
   * If the tracee enters the disarm-desched ioctl, it's going
   * to commit a record of the buffered syscall to the
   * syscallbuf, and we can safely send the tracee back on its
   * way, ignoring the desched completely.
   *
   * If it enters the buffered syscall, then the desched event
   * has served its purpose and we need to prepare the tracee to
   * be context-switched.
   *
   * An annoyance of the desched signal is that when the tracer
   * is descheduled in interval (C) above, we see normally (see
   * below) see *two* signals.  The current theory of what's
   * happening is
   *
   *  o child gets descheduled, bumps counter to i and schedules
   *    signal
   *  o signal notification "schedules" child, but it doesn't
   *    actually run any application code
   *  o child is being ptraced, so we "deschedule" child to
   *    notify parent and bump counter to i+1.  (The parent
   *    hasn't had a chance to clear the counter yet.)
   *  o another counter signal is generated, but signal is
   *    already pending so this one is queued
   *  o parent is notified and sees counter value i+1
   *  o parent stops delivery of first signal and disarms
   *    counter
   *  o second signal dequeued and delivered, notififying parent
   *    (counter is disarmed now, so no pseudo-desched possible
   *    here)
   *  o parent notifiedand sees counter value i+1 again
   *  o parent stops delivery of second signal and we continue on
   *
   * So we "work around" this by the tracer expecting two signal
   * notifications, and silently discarding both.
   *
   * One really fun edge case is that sometimes the desched
   * signal will interrupt the arm-desched syscall itself.
   * Continuing to the next syscall boundary seems to restart
   * the arm-desched syscall, and advancing to the boundary
   * again exits it and we start receiving desched signals
   * again.
   *
   * That may be a kernel bug, but we handle it by just
   * continuing until we we continue past the arm-desched
   * syscall *and* stop seeing signals. */
  while (true) {
    // Prevent further desched notifications from firing
    // while we're advancing the tracee.  We're going to
    // leave it in a consistent state anyway, so the event
    // is no longer useful.  We have to do this in each
    // loop iteration because a restarted arm-desched
    // syscall may have re-armed the event.
    disarm_desched_event(t);

    t->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_UNLIMITED_TICKS);

    if (t->status().is_syscall()) {
      if (t->is_arm_desched_event_syscall()) {
        continue;
      }
      break;
    }
    if (t->ptrace_event() == PTRACE_EVENT_SECCOMP) {
      ASSERT(t,
             t->session().syscall_seccomp_ordering() ==
                 Session::SECCOMP_BEFORE_PTRACE_SYSCALL);
      // This is the old kernel event ordering. This must be a SECCOMP event
      // for the buffered syscall; it's not rr-generated because this is an
      // untraced syscall, but it could be generated by a tracee's
      // seccomp filter.
      break;
    }

    // Completely ignore spurious desched signals and
    // signals that aren't going to be delivered to the
    // tracee.
    //
    // Also ignore time-slice signals.  If the tracee ends
    // up at the disarm-desched ioctl, we'll reschedule it
    // with the ticks interrupt still programmed.  At worst,
    // the tracee will get an extra time-slice out of
    // this, on average, so we don't worry too much about
    // it.
    //
    // TODO: it's theoretically possible for this to
    // happen an unbounded number of consecutive times
    // and the tracee never switched out.
    int sig = t->stop_sig();
    ASSERT(t, sig) << "expected stop-signal, got " << t->status();
    if (SIGTRAP == sig && handle_syscallbuf_breakpoint(t)) {
      // We stopped at a breakpoint on an untraced may-block syscall.
      // This can't be relevant to us since sigprocmask isn't may-block.
      LOG(debug) << " disabling breakpoints on untraced syscalls";
      continue;
    }
    if (SYSCALLBUF_DESCHED_SIGNAL == sig ||
        PerfCounters::TIME_SLICE_SIGNAL == sig || t->is_sig_ignored(sig)) {
      LOG(debug) << "  dropping ignored " << signal_name(sig);
      continue;
    }

    LOG(debug) << "  stashing " << signal_name(sig);
    t->stash_sig();
  }

  if (t->is_disarm_desched_event_syscall()) {
    LOG(debug)
        << "  (at disarm-desched, so finished buffered syscall; resuming)";
    t->push_event(Event::noop());
    return;
  }

  if (t->desched_rec()) {
    // We're already processing a desched. We probably reexecuted the
    // system call (e.g. because a signal was processed) and the syscall
    // blocked again. Carry on with the current desched.
  } else {
    /* This prevents the syscallbuf record counter from being
     * reset until we've finished guiding the tracee through this
     * interrupted call.  We use the record counter for
     * assertions. */
    ASSERT(t, !t->delay_syscallbuf_reset_for_desched);
    t->delay_syscallbuf_reset_for_desched = true;
    LOG(debug) << "Desched initiated";

    /* The tracee is (re-)entering the buffered syscall.  Stash
     * away this breadcrumb so that we can figure out what syscall
     * the tracee was in, and how much "scratch" space it carved
     * off the syscallbuf, if needed. */
    remote_ptr<const struct syscallbuf_record> desched_rec =
        t->next_syscallbuf_record();
    t->push_event(DeschedEvent(desched_rec));
    int call = t->read_mem(REMOTE_PTR_FIELD(t->desched_rec(), syscallno));

    /* The descheduled syscall was interrupted by a signal, like
     * all other may-restart syscalls, with the exception that
     * this one has already been restarted (which we'll detect
     * back in the main loop). */
    t->push_event(Event(interrupted, SyscallEvent(call, t->arch())));
    SyscallEvent& ev = t->ev().Syscall();
    ev.desched_rec = desched_rec;
  }

  SyscallEvent& ev = t->ev().Syscall();
  ev.regs = t->regs();
  /* For some syscalls (at least poll) but not all (at least not read),
   * repeated cont_syscall()s above of the same interrupted syscall
   * can set $orig_eax to 0 ... for unclear reasons. Fix that up here
   * otherwise we'll get a divergence during replay, which will not
   * encounter this problem.
   */
  int call = t->read_mem(REMOTE_PTR_FIELD(t->desched_rec(), syscallno));
  ev.regs.set_original_syscallno(call);
  t->set_regs(ev.regs);
  // runnable_state_changed will observe us entering this syscall and change
  // state to ENTERING_SYSCALL

  LOG(debug) << "  resuming (and probably switching out) blocked `"
             << syscall_name(call, ev.arch()) << "'";
}

static bool is_safe_to_deliver_signal(RecordTask* t, siginfo_t* si) {
  if (!t->is_in_syscallbuf()) {
    /* The tracee is outside the syscallbuf code,
     * so in most cases can't possibly affect
     * syscallbuf critical sections.  The
     * exception is signal handlers "re-entering"
     * desched'd syscalls, which are OK. */
    LOG(debug) << "Safe to deliver signal at " << t->ip()
               << " because not in syscallbuf";
    return true;
  }

  if (t->is_in_traced_syscall()) {
    LOG(debug) << "Safe to deliver signal at " << t->ip()
               << " because in traced syscall";
    return true;
  }
  if (t->is_at_traced_syscall_entry()) {
    LOG(debug) << "Safe to deliver signal at " << t->ip()
               << " because at entry to traced syscall";
    return true;
  }

  if (t->is_in_untraced_syscall() && t->desched_rec()) {
    // Untraced syscalls always use the architecture of the process
    LOG(debug) << "Safe to deliver signal at " << t->ip()
               << " because tracee interrupted by desched of "
               << syscall_name(t->read_mem(REMOTE_PTR_FIELD(t->desched_rec(),
                                                            syscallno)),
                               t->arch());
    return true;
  }

  if (t->is_in_untraced_syscall() && si->si_signo == SIGSYS &&
      si->si_code == SYS_SECCOMP) {
    LOG(debug) << "Safe to deliver signal at " << t->ip()
               << " because signal is seccomp trap.";
    return true;
  }

  // If the syscallbuf buffer hasn't been created yet, just delay the signal
  // with no need to set notify_on_syscall_hook_exit; the signal will be
  // delivered when rrcall_init_buffers is called.
  if (t->syscallbuf_child) {
    if (t->read_mem(REMOTE_PTR_FIELD(t->syscallbuf_child, locked)) & 2) {
      LOG(debug) << "Safe to deliver signal at " << t->ip()
                 << " because the syscallbuf is locked";
      return true;
    }

    // A signal (e.g. seccomp SIGSYS) interrupted a untraced syscall in a
    // non-restartable way. Defer it until SYS_rrcall_notify_syscall_hook_exit.
    if (t->is_in_untraced_syscall()) {
      // Our emulation of SYS_rrcall_notify_syscall_hook_exit clears this flag.
      t->write_mem(
          REMOTE_PTR_FIELD(t->syscallbuf_child, notify_on_syscall_hook_exit),
          (uint8_t)1);
    }
  }

  LOG(debug) << "Not safe to deliver signal at " << t->ip();
  return false;
}

SignalHandled handle_signal(RecordTask* t, siginfo_t* si,
                            SignalDeterministic deterministic,
                            SignalBlocked signal_was_blocked) {
  int sig = si->si_signo;
  LOG(debug) << t->tid << ": handling signal " << signal_name(sig)
             << " (pevent: " << ptrace_event_name(t->ptrace_event())
             << ", event: " << t->ev();

  // Conservatively invalidate the sigmask in case just accepting a signal has
  // sigmask effects.
  t->invalidate_sigmask();

  if (deterministic == DETERMINISTIC_SIG) {
    // When a deterministic signal is triggered, but the signal is currently
    // blocked or ignored, the kernel (in |force_sig_info|) unblocks it and
    // sets its disposition to SIG_DFL. It never undoes this (probably
    // because it expects the signal to be fatal, which it always would be
    // unless a ptracer intercepts the signal as we do). Therefore, if the
    // signal was generated for rr's purposes, we need to restore the signal
    // state ourselves.
    if (sig == SIGSEGV &&
        (try_handle_trapped_instruction(t, si) || try_grow_map(t, si))) {
      if (signal_was_blocked || t->is_sig_ignored(sig)) {
        restore_signal_state(t, sig, signal_was_blocked);
      }
      return SIGNAL_HANDLED;
    }

    // Since we're not undoing the kernel's changes, update our signal handler
    // state to match the kernel's.
    if (signal_was_blocked || t->is_sig_ignored(sig)) {
      t->set_sig_handler_default(sig);
    }
  }

  if (!VirtualPerfCounterMonitor::is_virtual_perf_counter_signal(si)) {
    /* We have to check for a desched event first, because for
     * those we *do not* want to (and cannot, most of the time)
     * step the tracee out of the syscallbuf code before
     * attempting to deliver the signal. */
    if (SYSCALLBUF_DESCHED_SIGNAL == si->si_signo) {
      handle_desched_event(t, si);
      return SIGNAL_HANDLED;
    }

    if (!is_safe_to_deliver_signal(t, si)) {
      return DEFER_SIGNAL;
    }

    if (!t->set_siginfo_for_synthetic_SIGCHLD(si)) {
      return DEFER_SIGNAL;
    }

    if (sig == PerfCounters::TIME_SLICE_SIGNAL) {
      t->push_event(Event::sched());
      return SIGNAL_HANDLED;
    }
  } else {
    // Clear the magic flag so it doesn't leak into the program.
    si->si_errno = 0;
  }

  /* This signal was generated by the program or an external
   * source, record it normally. */

  if (t->emulate_ptrace_stop(WaitStatus::for_stop_sig(sig), si)) {
    // Record an event so that replay progresses the tracee to the
    // current point before we notify the tracer.
    // If the signal is deterministic, record it as an EV_SIGNAL so that
    // we replay it using the deterministic-signal replay path. This is
    // more efficient than emulate_async_signal. Also emulate_async_signal
    // currently assumes it won't encounter a deterministic SIGTRAP (due to
    // a hardcoded breakpoint in the tracee).
    if (deterministic == DETERMINISTIC_SIG) {
      t->record_event(Event(EV_SIGNAL, SignalEvent(*si, deterministic,
                                                   t->sig_resolved_disposition(
                                                       sig, deterministic))));
    } else {
      t->record_event(Event::sched());
    }
    // ptracer has been notified, so don't deliver the signal now.
    // The signal won't be delivered for real until the ptracer calls
    // PTRACE_CONT with the signal number (which we don't support yet!).
    return SIGNAL_PTRACE_STOP;
  }

  t->push_event(Event(
      EV_SIGNAL, SignalEvent(*si, deterministic,
                             t->sig_resolved_disposition(sig, deterministic))));
  return SIGNAL_HANDLED;
}

} // namespace rr
