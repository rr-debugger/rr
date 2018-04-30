/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#define USE_BREAKPOINT_TARGET 1

#include "ReplaySession.h"

#include <linux/futex.h>
#include <sys/prctl.h>
#include <syscall.h>

#include <algorithm>

#include "AutoRemoteSyscalls.h"
#include "Flags.h"
#include "ReplayTask.h"
#include "ThreadGroup.h"
#include "core.h"
#include "fast_forward.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"
#include "replay_syscall.h"
#include "util.h"

using namespace std;

namespace rr {

static void debug_memory(ReplayTask* t) {
  FrameTime current_time = t->current_frame_time();
  if (should_dump_memory(t->current_trace_frame().event(), current_time)) {
    dump_process_memory(t, current_time, "rep");
  }
  if (t->session().done_initial_exec() &&
      should_checksum(t->current_trace_frame().event(), current_time)) {
    /* Validate the checksum we computed during the
     * recording phase. */
    validate_process_memory(t, current_time);
  }
}

static void split_at_address(ReplaySession::MemoryRanges& ranges,
                             remote_ptr<void> addr) {
  ReplaySession::MemoryRanges::iterator it =
      ranges.lower_bound(MemoryRange(addr, addr + 1));
  if (it != ranges.end() && it->contains(addr) && it->start() != addr) {
    MemoryRange r1(it->start(), addr);
    MemoryRange r2(addr, it->end());
    ranges.erase(it);
    ranges.insert(r1);
    ranges.insert(r2);
  }
}

static void delete_range(ReplaySession::MemoryRanges& ranges,
                         const MemoryRange& r) {
  split_at_address(ranges, r.start());
  split_at_address(ranges, r.end());
  auto first = ranges.lower_bound(MemoryRange(r.start(), r.start() + 1));
  auto last = ranges.lower_bound(MemoryRange(r.end(), r.end() + 1));
  ranges.erase(first, last);
}

ReplaySession::MemoryRanges ReplaySession::always_free_address_space(
    const TraceReader& reader) {
  MemoryRanges result;
  remote_ptr<void> addressable_min = remote_ptr<void>(64 * 1024);
  // Assume 64-bit address spaces with the 47-bit user-space limitation,
  // for now.
  remote_ptr<void> addressable_max = uintptr_t(
      sizeof(void*) == 8 ? uint64_t(1) << 47 : (uint64_t(1) << 32) - PAGE_SIZE);
  result.insert(MemoryRange(addressable_min, addressable_max));
  TraceReader tmp_reader(reader);
  bool found;
  while (true) {
    KernelMapping km = tmp_reader.read_mapped_region(
        nullptr, &found, TraceReader::DONT_VALIDATE, TraceReader::ANY_TIME);
    if (!found) {
      break;
    }
    delete_range(result, km);
  }
  delete_range(result, MemoryRange(AddressSpace::rr_page_start(),
                                   AddressSpace::rr_page_end()));
  return result;
}

static bool tracee_xsave_enabled(const TraceReader& trace_in) {
  const CPUIDRecord* record =
    find_cpuid_record(trace_in.cpuid_records(), CPUID_GETFEATURES, 0);
  return (record->out.ecx & OSXSAVE_FEATURE_FLAG) != 0;
}

static void check_xsave_compatibility(const TraceReader& trace_in) {
  if (!tracee_xsave_enabled(trace_in)) {
    // Tracee couldn't use XSAVE so everything should be fine.
    // If it didn't detect absence of XSAVE and actually executed an XSAVE
    // and got a fault then replay will probably diverge :-(
    return;
  }
  if (!xsave_enabled()) {
    // Replaying on a super old CPU that doesn't even support XSAVE!
    if (!Flags::get().suppress_environment_warnings) {
      fprintf(stderr, "rr: Tracees had XSAVE but XSAVE is not available "
              "now; Replay will probably fail because glibc dynamic loader "
              "uses XSAVE\n\n");
    }
    return;
  }

  uint64_t tracee_xcr0 = trace_in.xcr0();
  uint64_t our_xcr0 = xcr0();
  const CPUIDRecord* record =
    find_cpuid_record(trace_in.cpuid_records(), CPUID_GETXSAVE, 1);
  bool tracee_xsavec = record && (record->out.eax & XSAVEC_FEATURE_FLAG);
  CPUIDData data = cpuid(CPUID_GETXSAVE, 1);
  bool our_xsavec = (data.eax & XSAVEC_FEATURE_FLAG) != 0;
  if (tracee_xsavec && !our_xsavec &&
      !Flags::get().suppress_environment_warnings) {
    fprintf(stderr, "rr: Tracees had XSAVEC but XSAVEC is not available "
            "now; Replay will probably fail because glibc dynamic loader "
            "uses XSAVEC\n\n");
  }

  if (tracee_xcr0 != our_xcr0) {
    if (tracee_xsavec) {
      LOG(warn) << "Trace XCR0 value " << HEX(tracee_xcr0) << " != our XCR0 "
          << "value " << HEX(our_xcr0) << "; Replay will fail if the tracee "
          << "used plain XSAVE";
    } else if (!Flags::get().suppress_environment_warnings) {
      // Tracee may have used XSAVE instructions which write different components
      // to XSAVE instructions executed on our CPU. This will cause divergence.
      cerr << "Trace XCR0 value " << HEX(tracee_xcr0) << " != our XCR0 "
          << "value " << HEX(our_xcr0) << "; Replay will probably fail "
          << "because glibc dynamic loader uses XSAVE\n\n";
    }
  }

  bool check_alignment = tracee_xsavec && our_xsavec;
  // Check that sizes and offsets of supported XSAVE areas area all identical.
  // An Intel employee promised this on a mailing list...
  // https://lists.xen.org/archives/html/xen-devel/2013-09/msg00484.html
  for (int feature = 2; feature <= 63; ++feature) {
    if (!(tracee_xcr0 & our_xcr0 & (uint64_t(1) << feature))) {
      continue;
    }
    record =
      find_cpuid_record(trace_in.cpuid_records(), CPUID_GETXSAVE, feature);
    CPUIDData data = cpuid(CPUID_GETXSAVE, feature);
    if (!record || record->out.eax != data.eax ||
        record->out.ebx != data.ebx ||
        (check_alignment && (record->out.ecx & 2) != (data.ecx & 2))) {
      CLEAN_FATAL()
          << "XSAVE offset/size/alignment differs for feature " << feature
          << "; H. Peter Anvin said this would never happen!";
    }
  }
}

ReplaySession::ReplaySession(const std::string& dir)
    : emu_fs(EmuFs::create()),
      trace_in(dir),
      trace_frame(),
      current_step(),
      ticks_at_start_of_event(0),
      trace_start_time(0) {
  memset(&last_siginfo_, 0, sizeof(last_siginfo_));
  advance_to_next_trace_frame();

  trace_start_time = trace_frame.monotonic_time();

  if (trace_in.uses_cpuid_faulting() && !has_cpuid_faulting()) {
    CLEAN_FATAL()
        << "Trace was recorded with CPUID faulting enabled, but this\n"
           "system does not support CPUID faulting.";
  }
  if (!has_cpuid_faulting() && !cpuid_compatible(trace_in.cpuid_records())) {
    CLEAN_FATAL()
        << "Trace was recorded on a machine with different CPUID values\n"
           "and CPUID faulting is not enabled; replay will not work.";
  }
  if (has_cpuid_faulting() && trace_in.bound_to_cpu() >= 0) {
    // The recorded trace was bound to a CPU, but we have CPUID faulting so
    // we can bind to a different CPU and preserve CPUID values, so let's do
    // that. This avoids problems if the tracees were bound to a CPU number
    // that doesn't exist on this machine.
    trace_in.set_bound_cpu(choose_cpu(BIND_CPU));
  }

  check_xsave_compatibility(trace_in);
}

ReplaySession::ReplaySession(const ReplaySession& other)
    : Session(other),
      emu_fs(EmuFs::create()),
      trace_in(other.trace_in),
      trace_frame(other.trace_frame),
      current_step(other.current_step),
      ticks_at_start_of_event(other.ticks_at_start_of_event),
      cpuid_bug_detector(other.cpuid_bug_detector),
      last_siginfo_(other.last_siginfo_),
      flags(other.flags),
      trace_start_time(other.trace_start_time) {}

ReplaySession::~ReplaySession() {
  // We won't permanently leak any OS resources by not ensuring
  // we've cleaned up here, but sessions can be created and
  // destroyed many times, and we don't want to temporarily hog
  // resources.
  kill_all_tasks();
  syscall_bp_vm = nullptr;
  DEBUG_ASSERT(task_map.empty() && vm_map.empty());
  DEBUG_ASSERT(emufs().size() == 0);
}

ReplaySession::shr_ptr ReplaySession::clone() {
  LOG(debug) << "Deepforking ReplaySession " << this << " ...";

  finish_initializing();
  clear_syscall_bp();

  shr_ptr session(new ReplaySession(*this));
  LOG(debug) << "  deepfork session is " << session.get();

  copy_state_to(*session, emufs(), session->emufs());

  return session;
}

/**
 * Return true if it's possible/meaningful to make a checkpoint at the
 * |frame| that |t| will replay.
 */
static bool can_checkpoint_at(const TraceFrame& frame) {
  const Event& ev = frame.event();
  if (ev.has_ticks_slop()) {
    return false;
  }
  switch (ev.type()) {
    case EV_EXIT:
    // At exits, we can't clone the exiting tasks, so
    // don't event bother trying to checkpoint.
    case EV_SYSCALLBUF_RESET:
    // RESETs are usually inserted in between syscall
    // entry/exit.  Do not attempting to checkpoint at
    // RESETs.  Users would never want to do that anyway.
    case EV_TRACE_TERMINATION:
      // There's nothing to checkpoint at the end of a trace.
      return false;
    default:
      return true;
  }
}

bool ReplaySession::can_clone() {
  finish_initializing();

  ReplayTask* t = current_task();
  return t && done_initial_exec() && can_checkpoint_at(current_trace_frame());
}

DiversionSession::shr_ptr ReplaySession::clone_diversion() {
  finish_initializing();
  clear_syscall_bp();

  LOG(debug) << "Deepforking ReplaySession " << this
             << " to DiversionSession...";

  DiversionSession::shr_ptr session(new DiversionSession());
  session->tracee_socket = tracee_socket;
  session->tracee_socket_fd_number = tracee_socket_fd_number;
  LOG(debug) << "  deepfork session is " << session.get();

  copy_state_to(*session, emufs(), session->emufs());
  session->finish_initializing();

  return session;
}

Task* ReplaySession::new_task(pid_t tid, pid_t rec_tid, uint32_t serial,
                              SupportedArch a) {
  return new ReplayTask(*this, tid, rec_tid, serial, a);
}

/*static*/ ReplaySession::shr_ptr ReplaySession::create(const string& dir) {
  shr_ptr session(new ReplaySession(dir));

  // It doesn't really matter what we use for argv/env here, since
  // replay_syscall's process_execve is going to follow the recording and
  // ignore the parameters.
  string exe_path;
  vector<string> argv;
  vector<string> env;

  ScopedFd error_fd = session->create_spawn_task_error_pipe();
  ReplayTask* t = static_cast<ReplayTask*>(
      Task::spawn(*session, error_fd, &session->tracee_socket_fd(),
                  &session->tracee_socket_fd_number,
                  session->trace_in, exe_path, argv, env,
                  session->trace_reader().peek_frame().tid()));
  session->on_create(t);

  return session;
}

void ReplaySession::advance_to_next_trace_frame() {
  if (trace_in.at_end()) {
    trace_frame = TraceFrame(trace_frame.time(), 0, Event::trace_termination(),
                             trace_frame.ticks(), trace_frame.monotonic_time());
    return;
  }

  trace_frame = trace_in.read_frame();
}

bool ReplaySession::is_ignored_signal(int sig) {
  switch (sig) {
    // TIME_SLICE_SIGNALs can be queued but not delivered before we stop
    // execution for some other reason. Ignore them.
    case PerfCounters::TIME_SLICE_SIGNAL:
      return true;
    default:
      return false;
  }
}

/* Why a skid region?  Interrupts generated by perf counters don't
 * fire at exactly the programmed point (as of 2013 kernel/HW);
 * there's a variable slack region, which is technically unbounded.
 * This means that an interrupt programmed for retired branch k might
 * fire at |k + 50|, for example.  To counteract the slack, we program
 * interrupts just short of our target, by the |SKID_SIZE| region
 * below, and then more slowly advance to the real target.
 *
 * How was this magic number determined?  Trial and error: we want it
 * to be as small as possible for efficiency, but not so small that
 * overshoots are observed.  If all other possible causes of overshoot
 * have been ruled out, like memory divergence, then you'll know that
 * this magic number needs to be increased if the following symptom is
 * observed during replay.  Running with DEBUGLOG enabled (see above),
 * a sequence of log messages like the following will appear
 *
 * 1. programming interrupt for [target - SKID_SIZE] ticks
 * 2. Error: Replay diverged.  Dumping register comparison.
 * 3. Error: [list of divergent registers; arbitrary]
 * 4. Error: overshot target ticks=[target] by [i]
 *
 * The key is that no other replayer log messages occur between (1)
 * and (2).  This spew means that the replayer programmed an interrupt
 * for ticks=[target-SKID_SIZE], but the tracee was actually interrupted
 * at ticks=[target+i].  And that in turn means that the kernel/HW
 * skidded too far past the programmed target for rr to handle it.
 *
 * If that occurs, the SKID_SIZE needs to be increased by at least
 * [i].
 *
 * NB: there are probably deeper reasons for the target slack that
 * could perhaps let it be deduced instead of arrived at empirically;
 * perhaps pipeline depth and things of that nature are involved.  But
 * those reasons if they exit are currently not understood.
 */
static bool compute_ticks_request(
    ReplayTask* t, const ReplaySession::StepConstraints& constraints,
    TicksRequest* ticks_request) {
  *ticks_request = RESUME_UNLIMITED_TICKS;
  if (constraints.ticks_target > 0) {
    Ticks ticks_period =
        constraints.ticks_target - PerfCounters::skid_size() - t->tick_count();
    if (ticks_period <= 0) {
      // Behave as if we actually executed something. Callers assume we did.
      t->clear_wait_status();
      return false;
    }
    if (ticks_period > MAX_TICKS_REQUEST) {
      // Avoid overflow. The execution will stop early but we'll treat that
      // just like a stray TIME_SLICE_SIGNAL and continue as needed.
      *ticks_request = MAX_TICKS_REQUEST;
    } else {
      *ticks_request = (TicksRequest)ticks_period;
    }
  }
  return true;
}

static void perform_interrupted_syscall(ReplayTask* t) {
  t->finish_emulated_syscall();
  AutoRemoteSyscalls remote(t);
  const Registers& r = t->regs();
  long ret = remote.syscall(r.original_syscallno(), r.arg1(), r.arg2(),
                            r.arg3(), r.arg4(), r.arg5(), r.arg6());
  remote.regs().set_syscall_result(ret);
}

bool ReplaySession::handle_unrecorded_cpuid_fault(
    ReplayTask* t, const StepConstraints& constraints) {
  if (t->stop_sig() != SIGSEGV || !has_cpuid_faulting() ||
      trace_in.uses_cpuid_faulting() ||
      trapped_instruction_at(t, t->ip()) != TrappedInstruction::CPUID) {
    return false;
  }
  // OK, this is a case where we did not record using CPUID faulting but we are
  // replaying with CPUID faulting and the tracee just executed a CPUID.
  // We try to find the results in the "all CPUID leaves" we saved.

  const vector<CPUIDRecord>& records = trace_in.cpuid_records();
  Registers r = t->regs();
  const CPUIDRecord* rec = find_cpuid_record(records, r.ax(), r.cx());
  ASSERT(t, rec) << "Can't find CPUID record for request AX=" << HEX(r.ax())
                 << " CX=" << HEX(r.cx());
  r.set_cpuid_output(rec->out.eax, rec->out.ebx, rec->out.ecx, rec->out.edx);
  r.set_ip(r.ip() + trapped_instruction_len(TrappedInstruction::CPUID));
  t->set_regs(r);
  // Clear SIGSEGV status since we're handling it
  t->set_status(constraints.is_singlestep() ? WaitStatus::for_stop_sig(SIGTRAP)
                                            : WaitStatus());
  return true;
}

/**
 * Continue until reaching either the "entry" of an emulated syscall,
 * or the entry or exit of an executed syscall.  |emu| is nonzero when
 * we're emulating the syscall.  Return COMPLETE when the next syscall
 * boundary is reached, or INCOMPLETE if advancing to the boundary was
 * interrupted by an unknown trap.
 * When |syscall_trace_frame| is non-null, we continue to the syscall by
 * setting a breakpoint instead of running until we execute a system
 * call instruction. In that case we will not actually enter the kernel.
 */
Completion ReplaySession::cont_syscall_boundary(
    ReplayTask* t, const StepConstraints& constraints) {
  TicksRequest ticks_request;
  if (!compute_ticks_request(t, constraints, &ticks_request)) {
    return INCOMPLETE;
  }

  if (constraints.command == RUN_SINGLESTEP_FAST_FORWARD) {
    // ignore ticks_period. We can't add more than one tick during a
    // fast_forward so it doesn't matter.
    did_fast_forward |= fast_forward_through_instruction(
        t, RESUME_SYSEMU_SINGLESTEP, constraints.stop_before_states);
  } else {
    ResumeRequest resume_how =
        constraints.is_singlestep() ? RESUME_SYSEMU_SINGLESTEP : RESUME_SYSEMU;
    t->resume_execution(resume_how, RESUME_WAIT, ticks_request);
  }

  switch (t->stop_sig()) {
    case 0:
      break;
    case PerfCounters::TIME_SLICE_SIGNAL:
      // This would normally be triggered by constraints.ticks_target but it's
      // also possible to get stray signals here.
      return INCOMPLETE;
    case SIGSEGV:
      if (handle_unrecorded_cpuid_fault(t, constraints)) {
        return INCOMPLETE;
      }
      break;
    case SIGTRAP:
      return INCOMPLETE;
    default:
      break;
  }
  if (t->stop_sig()) {
      ASSERT(t, false) << "Replay got unrecorded signal " << t->get_siginfo();
  }

  if (t->seccomp_bpf_enabled &&
      syscall_seccomp_ordering_ == PTRACE_SYSCALL_BEFORE_SECCOMP_UNKNOWN) {
    ASSERT(t, !constraints.is_singlestep());
    if (t->ptrace_event() == PTRACE_EVENT_SECCOMP) {
      syscall_seccomp_ordering_ = SECCOMP_BEFORE_PTRACE_SYSCALL;
    } else {
      syscall_seccomp_ordering_ = PTRACE_SYSCALL_BEFORE_SECCOMP;
    }
    // Eat the following event, either a seccomp or syscall notification
    t->resume_execution(RESUME_SYSEMU, RESUME_WAIT, ticks_request);
  }

  auto type = AddressSpace::rr_page_syscall_from_exit_point(t->ip());
  if (type && type->traced == AddressSpace::UNTRACED &&
      type->enabled == AddressSpace::REPLAY_ONLY) {
    // Actually perform it. We can hit these when replaying through syscallbuf
    // code that was interrupted.
    perform_interrupted_syscall(t);
    return INCOMPLETE;
  }

  return COMPLETE;
}

void ReplaySession::clear_syscall_bp() {
  if (syscall_bp_vm) {
    syscall_bp_vm->remove_breakpoint(syscall_bp_addr, BKPT_INTERNAL);
    syscall_bp_vm = nullptr;
    syscall_bp_addr = nullptr;
  }
}

/**
 * Advance to the next syscall entry (or virtual entry) according to
 * |step|.  Return COMPLETE if successful, or INCOMPLETE if an unhandled trap
 * occurred.
 */
Completion ReplaySession::enter_syscall(ReplayTask* t,
                                        const StepConstraints& constraints) {
  if (t->regs().matches(trace_frame.regs()) &&
      t->tick_count() == trace_frame.ticks()) {
    // We already entered the syscall via an ENTERING_SYSCALL_PTRACE
    ASSERT(t,
           current_trace_frame().event().Syscall().state == ENTERING_SYSCALL);
  } else {
    remote_code_ptr syscall_instruction;

    if (done_initial_exec()) {
      syscall_instruction =
          current_trace_frame().regs().ip().decrement_by_syscall_insn_length(
              t->arch());
      // If the breakpoint already exists, it must have been from a previous
      // invocation of this function for the same event (once the event
      // completes, the breakpoint is cleared).
      DEBUG_ASSERT(!syscall_bp_vm || (syscall_bp_vm == t->vm() &&
                                      syscall_instruction == syscall_bp_addr &&
                                      t->vm()->get_breakpoint_type_at_addr(
                                          syscall_instruction) != BKPT_NONE));
      // Skip this optimization if we can't set the breakpoint, or if it's
      // in writeable or shared memory, since in those cases it could be
      // overwritten by the tracee. It could even be dynamically generated and
      // not generated yet.
      if (!syscall_bp_vm &&
          t->vm()->is_breakpoint_in_private_read_only_memory(
              syscall_instruction) &&
          t->vm()->add_breakpoint(syscall_instruction, BKPT_INTERNAL)) {
        syscall_bp_vm = t->vm();
        syscall_bp_addr = syscall_instruction;
      }
    }

    if (cont_syscall_boundary(t, constraints) == INCOMPLETE) {
      bool reached_target = syscall_bp_vm && SIGTRAP == t->stop_sig() &&
                            t->ip().decrement_by_bkpt_insn_length(t->arch()) ==
                                syscall_instruction &&
                            t->vm()->get_breakpoint_type_at_addr(
                                syscall_instruction) == BKPT_INTERNAL;
      if (reached_target) {
        // Emulate syscall state change
        Registers r = t->regs();
        r.set_ip(
            syscall_instruction.increment_by_syscall_insn_length(t->arch()));
        r.set_original_syscallno(r.syscallno());
        r.set_syscall_result(-ENOSYS);
        t->set_regs(r);
        t->canonicalize_regs(current_trace_frame().event().Syscall().arch());
        t->validate_regs();
        clear_syscall_bp();
      } else {
        return INCOMPLETE;
      }
    } else {
      // If we use the breakpoint optimization, we must get a SIGTRAP before
      // reaching a syscall, so cont_syscall_boundary must return INCOMPLETE.
      ASSERT(t, !syscall_bp_vm);
      t->canonicalize_regs(current_trace_frame().event().Syscall().arch());
      t->validate_regs();
      t->finish_emulated_syscall();
    }
  }

  if (current_trace_frame().event().Syscall().state == ENTERING_SYSCALL) {
    rep_after_enter_syscall(t);
  }
  return COMPLETE;
}

/**
 * Advance past the reti (or virtual reti) according to |step|.
 * Return COMPLETE if successful, or INCOMPLETE if an unhandled trap occurred.
 */
Completion ReplaySession::exit_syscall(ReplayTask* t) {
  t->on_syscall_exit(current_step.syscall.number, current_step.syscall.arch,
                     current_trace_frame().regs());

  t->apply_all_data_records_from_trace();
  t->set_return_value_from_trace();

  uint32_t flags = 0;
  if (t->arch() == SupportedArch::x86 &&
      (X86Arch::pwrite64 == current_step.syscall.number ||
       X86Arch::pread64 == current_step.syscall.number)) {
    flags |= ReplayTask::IGNORE_ESI;
  }
  t->validate_regs(flags);

  return COMPLETE;
}

void ReplaySession::check_pending_sig(ReplayTask* t) {
  if (!t->stop_sig()) {
    ASSERT(t, false) << "Replaying `" << trace_frame.event()
                     << "': expecting tracee signal or trap, but instead at `"
                     << syscall_name(t->regs().original_syscallno(),
                                     t->detect_syscall_arch())
                     << "' (ticks: " << t->tick_count() << ")";
  }
}

/**
 * Advance |t| to the next signal or trap according to |constraints.command|.
 *
 * Default |resume_how| is RESUME_SYSEMU for error checking:
 * since the next event is supposed to be a signal, entering a syscall here
 * means divergence.  There shouldn't be any straight-line execution overhead
 * for SYSEMU vs. CONT, so the difference in cost should be negligible.
 *
 * Some callers pass RESUME_CONT because they want to execute any syscalls
 * encountered.
 *
 * If we return INCOMPLETE, callers need to recalculate the constraints and
 * tick_request and try again.
 */
Completion ReplaySession::continue_or_step(ReplayTask* t,
                                           const StepConstraints& constraints,
                                           TicksRequest tick_request,
                                           ResumeRequest resume_how) {
  if (constraints.command == RUN_SINGLESTEP) {
    t->resume_execution(RESUME_SINGLESTEP, RESUME_WAIT, tick_request);
    handle_unrecorded_cpuid_fault(t, constraints);
  } else if (constraints.command == RUN_SINGLESTEP_FAST_FORWARD) {
    did_fast_forward |= fast_forward_through_instruction(
        t, RESUME_SINGLESTEP, constraints.stop_before_states);
    handle_unrecorded_cpuid_fault(t, constraints);
  } else {
    t->resume_execution(resume_how, RESUME_WAIT, tick_request);
    if (t->stop_sig() == 0) {
      auto type = AddressSpace::rr_page_syscall_from_exit_point(t->ip());
      if (type && type->traced == AddressSpace::UNTRACED) {
        // If we recorded an rr replay of an application doing a
        // syscall-buffered 'mprotect', the replay's `flush_syscallbuf`
        // PTRACE_CONT'ed to execute the mprotect syscall and nothing was
        // recorded for that until we hit the replay's breakpoint, when we
        // record a SIGTRAP. However, when we replay that SIGTRAP via
        // `emulate_deterministic_signal`, we call `continue_or_step`
        // with `RESUME_SYSEMU` (to detect bugs when we reach a stray
        // syscall instead of the SIGTRAP). So, we'll stop for the
        // `mprotect` syscall here. We need to execute it and continue
        // as if it wasn't hit.
        // (Alternatively we could just replay with RESUME_CONT, but that
        // would make it harder to track down bugs. There is a performance hit
        // to stopping for each mprotect, but replaying recordings of replays
        // is not fast anyway.)
        perform_interrupted_syscall(t);
        return INCOMPLETE;
      }
    } else if (handle_unrecorded_cpuid_fault(t, constraints)) {
      return INCOMPLETE;
    }
  }
  check_pending_sig(t);
  return COMPLETE;
}

static void guard_overshoot(ReplayTask* t, const Registers& target_regs,
                            Ticks target_ticks, Ticks remaining_ticks,
                            const Registers* closest_matching_regs) {
  if (remaining_ticks < 0) {
    remote_code_ptr target_ip = target_regs.ip();

    /* Cover up the internal breakpoint that we may have
     * set, and restore the tracee's $ip to what it would
     * have been had it not hit the breakpoint (if it did
     * hit the breakpoint).*/
    t->vm()->remove_breakpoint(target_ip, BKPT_INTERNAL);
    if (t->regs().ip() == target_ip.increment_by_bkpt_insn_length(t->arch())) {
      t->move_ip_before_breakpoint();
    }
    if (closest_matching_regs) {
      LOG(error)
          << "Replay diverged; target registers at ticks target mismatched: ";
      Registers::compare_register_files(t, "rep overshoot", t->regs(), "rec",
                                        *closest_matching_regs, LOG_MISMATCHES);
    } else {
      LOG(error) << "Replay diverged; target registers mismatched: ";
      Registers::compare_register_files(t, "rep overshoot", t->regs(), "rec",
                                        target_regs, LOG_MISMATCHES);
    }
    ASSERT(t, false) << "overshot target ticks=" << target_ticks << " by "
                     << -remaining_ticks;
  }
}

static void guard_unexpected_signal(ReplayTask* t) {
  if (ReplaySession::is_ignored_signal(t->stop_sig()) ||
      SIGTRAP == t->stop_sig()) {
    return;
  }

  if (t->stop_sig()) {
    ASSERT(t, false) << "Replay got unrecorded signal "
                     << signal_name(t->stop_sig()) << " while awaiting signal";
  } else {
    ASSERT(t, false) << "Replay got unrecorded syscall "
                     << syscall_name(t->regs().original_syscallno(), t->arch())
                     << " while awaiting signal";
  }
}

static bool is_same_execution_point(ReplayTask* t, const Registers& rec_regs,
                                    Ticks ticks_left,
                                    Registers* mismatched_regs,
                                    const Registers** mismatched_regs_ptr) {
  MismatchBehavior behavior =
      IS_LOGGING(debug) ? LOG_MISMATCHES : EXPECT_MISMATCHES;

  if (ticks_left != 0) {
    LOG(debug) << "  not same execution point: " << ticks_left
               << " ticks left (@" << rec_regs.ip() << ")";
    if (IS_LOGGING(debug)) {
      Registers::compare_register_files(t, "(rep)", t->regs(), "(rec)",
                                        rec_regs, LOG_MISMATCHES);
    }
    return false;
  }
  if (!Registers::compare_register_files(t, "rep", t->regs(), "rec", rec_regs,
                                         behavior)) {
    LOG(debug) << "  not same execution point: regs differ (@" << rec_regs.ip()
               << ")";
    *mismatched_regs = t->regs();
    *mismatched_regs_ptr = mismatched_regs;
    return false;
  }
  LOG(debug) << "  same execution point";
  return true;
}

/**
 * Run execution forwards for |t| until |ticks| is reached, and the $ip
 * reaches the recorded $ip.  Return COMPLETE if successful or INCOMPLETE if an
 * unhandled interrupt occurred.  |sig| is the pending signal to be
 * delivered; it's only used to distinguish debugger-related traps
 * from traps related to replaying execution.  |ticks| is an inout param
 * that will be decremented by branches retired during this attempted
 * step.
 */
Completion ReplaySession::emulate_async_signal(
    ReplayTask* t, const StepConstraints& constraints, Ticks ticks) {
  const Registers& regs = trace_frame.regs();
  remote_code_ptr ip = regs.ip();
  bool did_set_internal_breakpoint = false;

  /* Step 1: advance to the target ticks (minus a slack region) as
   * quickly as possible by programming the hpc. */
  Ticks ticks_left = ticks - t->tick_count();

  LOG(debug) << "advancing " << ticks_left << " ticks to reach " << ticks << "/"
             << ip;

  /* XXX should we only do this if (ticks > 10000)? */
  while (ticks_left - PerfCounters::skid_size() > PerfCounters::skid_size()) {
    LOG(debug) << "  programming interrupt for "
               << (ticks_left - PerfCounters::skid_size()) << " ticks";

    // Avoid overflow. If ticks_left > MAX_TICKS_REQUEST, execution will stop
    // early but we'll treat that just like a stray TIME_SLICE_SIGNAL and
    // continue as needed.
    continue_or_step(t, constraints,
                     (TicksRequest)(min<Ticks>(MAX_TICKS_REQUEST, ticks_left) -
                                    PerfCounters::skid_size()));
    guard_unexpected_signal(t);

    ticks_left = ticks - t->tick_count();

    if (SIGTRAP == t->stop_sig()) {
      /* We proved we're not at the execution
       * target, and we haven't set any internal
       * breakpoints, and we're not temporarily
       * internally single-stepping, so we must have
       * hit a debugger breakpoint or the debugger
       * was single-stepping the tracee.  (The
       * debugging code will verify that.) */
      return INCOMPLETE;
    }
  }
  guard_overshoot(t, regs, ticks, ticks_left, NULL);

  /* True when our advancing has triggered a tracee SIGTRAP that needs to
   * be dealt with. */
  bool pending_SIGTRAP = false;
  RunCommand SIGTRAP_run_command = RUN_CONTINUE;

  /* Step 2: more slowly, find our way to the target ticks and
   * execution point.  We set an internal breakpoint on the
   * target $ip and then resume execution.  When that *internal*
   * breakpoint is hit (i.e., not one incidentally also set on
   * that $ip by the debugger), we check again if we're at the
   * target ticks and execution point.  If not, we temporarily
   * remove the breakpoint, single-step over the insn, and
   * repeat.
   *
   * What we really want to do is set a (precise)
   * retired-instruction interrupt and do away with all this
   * cruft. */
  Registers mismatched_regs;
  const Registers* mismatched_regs_ptr = NULL;
  while (true) {
    /* Invariants here are
     *  o ticks_left is up-to-date
     *  o ticks_left >= 0
     *
     * Possible state of the execution of |t|
     *  0. at a debugger trap (breakpoint, watchpoint, stepi)
     *  1. at an internal breakpoint
     *  2. at the execution target
     *  3. not at the execution target, but incidentally
     *     at the target $ip
     *  4. otherwise not at the execution target
     *
     * Determining whether we're at a debugger trap is
     * surprisingly complicated. */
    bool at_target = is_same_execution_point(
        t, regs, ticks_left, &mismatched_regs, &mismatched_regs_ptr);
    if (pending_SIGTRAP) {
      TrapReasons trap_reasons = t->compute_trap_reasons();
      BreakpointType breakpoint_type =
          t->vm()->get_breakpoint_type_for_retired_insn(t->ip());

      if (constraints.is_singlestep()) {
        ASSERT(t, trap_reasons.singlestep);
      }
      if (constraints.is_singlestep() ||
          (trap_reasons.watchpoint && t->vm()->has_any_watchpoint_changes()) ||
          (trap_reasons.breakpoint && BKPT_USER == breakpoint_type)) {
        /* Case (0) above: interrupt for the debugger. */
        LOG(debug) << "    trap was debugger singlestep/breakpoint";
        if (did_set_internal_breakpoint) {
          t->vm()->remove_breakpoint(ip, BKPT_INTERNAL);
        }
        return INCOMPLETE;
      }

      if (trap_reasons.breakpoint) {
        // We didn't hit a user breakpoint, and executing an explicit
        // breakpoint instruction in the tracee would have triggered a
        // deterministic signal instead of an async one.
        // So we must have hit our internal breakpoint.
        ASSERT(t, did_set_internal_breakpoint);
        ASSERT(t,
               regs.ip().increment_by_bkpt_insn_length(t->arch()) == t->ip());
        // We didn't do an internal singlestep, and if we'd done a
        // user-requested singlestep we would have hit the above case.
        ASSERT(t, !trap_reasons.singlestep);
        /* Case (1) above: cover the tracks of
         * our internal breakpoint, and go
         * check again if we're at the
         * target. */
        LOG(debug) << "    trap was for target $ip";
        /* (The breakpoint would have trapped
         * at the $ip one byte beyond the
         * target.) */
        DEBUG_ASSERT(!at_target);

        pending_SIGTRAP = false;
        t->move_ip_before_breakpoint();
        /* We just backed up the $ip, but
         * rewound it over an |int $3|
         * instruction, which couldn't have
         * retired a branch.  So we don't need
         * to adjust |tick_count()|. */
        continue;
      }

      /* Otherwise, either we did an internal singlestep or a hardware
       * watchpoint fired but values didn't change. */
      if (trap_reasons.singlestep) {
        ASSERT(t, is_singlestep(SIGTRAP_run_command));
        LOG(debug) << "    (SIGTRAP; stepi'd target $ip)";
      } else {
        ASSERT(t, trap_reasons.watchpoint);
        LOG(debug) << "    (SIGTRAP; HW watchpoint fired without changes)";
      }
    }

    /* We had to keep the internal breakpoint set (if it
     * was when we entered the loop) for the checks above.
     * But now we're either done (at the target) or about
     * to resume execution in one of a variety of ways,
     * and it's simpler to start out knowing that the
     * breakpoint isn't set. */
    if (did_set_internal_breakpoint) {
      t->vm()->remove_breakpoint(ip, BKPT_INTERNAL);
      did_set_internal_breakpoint = false;
    }

    if (at_target) {
      /* Case (2) above: done. */
      return COMPLETE;
    }

    /* At this point, we've proven that we're not at the
     * target execution point, and we've ensured the
     * internal breakpoint is unset. */
    if (USE_BREAKPOINT_TARGET && regs.ip() != t->regs().ip()) {
      /* Case (4) above: set a breakpoint on the
       * target $ip and PTRACE_CONT in an attempt to
       * execute as many non-trapped insns as we
       * can.  (Unless the debugger is stepping, of
       * course.)  Trapping and checking
       * are-we-at-target is slow.  It bears
       * repeating that the ideal implementation
       * would be programming a precise counter
       * interrupt (insns-retired best of all), but
       * we're forced to be conservative by observed
       * imprecise counters.  This should still be
       * no slower than single-stepping our way to
       * the target execution point. */
      LOG(debug) << "    breaking on target $ip";
      t->vm()->add_breakpoint(ip, BKPT_INTERNAL);
      did_set_internal_breakpoint = true;
      continue_or_step(t, constraints, RESUME_UNLIMITED_TICKS);
      SIGTRAP_run_command = constraints.command;
    } else {
      /* Case (3) above: we can't put a breakpoint
       * on the $ip, because resuming execution
       * would just trap and we'd be back where we
       * started.  Single-step or fast-forward past it. */
      LOG(debug) << "    (fast-forwarding over target $ip)";
      /* Just do whatever the user asked for if the user requested
       * singlestepping
       * or there is user breakpoint at the run address. The latter is safe
       * because the breakpoint will be triggered immediately. This gives us the
       * invariant that an internal singlestep never triggers a user breakpoint.
       */
      if (constraints.command == RUN_SINGLESTEP ||
          t->vm()->get_breakpoint_type_at_addr(t->regs().ip()) == BKPT_USER) {
        continue_or_step(t, constraints, RESUME_UNLIMITED_TICKS);
        SIGTRAP_run_command = constraints.command;
      } else {
        vector<const Registers*> states = constraints.stop_before_states;
        // This state may not be relevant if we don't have the correct tick
        // count yet. But it doesn't hurt to push it on anyway.
        states.push_back(&regs);
        did_fast_forward |=
            fast_forward_through_instruction(t, RESUME_SINGLESTEP, states);
        SIGTRAP_run_command = RUN_SINGLESTEP_FAST_FORWARD;
        check_pending_sig(t);
      }
    }
    pending_SIGTRAP = SIGTRAP == t->stop_sig();

    /* Maintain the "'ticks_left'-is-up-to-date"
     * invariant. */
    ticks_left = ticks - t->tick_count();

    /* Sometimes (e.g. in the ptrace_signal_32 test), we're in almost
     * the correct state when we enter |advance_to|, except that exotic
     * registers (i.e. segment registers) need to be normalized by the kernel
     * by continuing and hitting a deterministic signal without actually
     * advancing execution. So we allow |advance_to| to proceed and actually
     * reach the desired state.
     */
    if (!is_same_execution_point(t, regs, ticks_left, &mismatched_regs,
                                 &mismatched_regs_ptr)) {
      guard_unexpected_signal(t);
    }

    guard_overshoot(t, regs, ticks, ticks_left, mismatched_regs_ptr);
  }
}

static bool is_fatal_default_action(int sig) {
  signal_action action = default_action(sig);
  return action == DUMP_CORE || action == TERMINATE;
}

/**
 * Emulates delivery of |sig| to |oldtask|.  Returns INCOMPLETE if
 * emulation was interrupted, COMPLETE if completed.
 */
Completion ReplaySession::emulate_signal_delivery(ReplayTask* oldtask,
                                                  int sig) {
  ReplayTask* t = current_task();
  if (!t) {
    // Trace terminated abnormally.  We'll pop out to code
    // that knows what to do.
    return INCOMPLETE;
  }
  ASSERT(oldtask, t == oldtask) << "emulate_signal_delivery changed task";

  const Event& ev = trace_frame.event();
  ASSERT(t, ev.type() == EV_SIGNAL_DELIVERY || ev.type() == EV_SIGNAL_HANDLER)
      << "Unexpected signal disposition";
  // Entering a signal handler seems to clear FP/SSE registers for some
  // reason. So we saved those cleared values, and now we restore that
  // state so they're cleared during replay.
  if (ev.type() == EV_SIGNAL_HANDLER) {
    t->set_extra_regs(trace_frame.extra_regs());
  }

  /* Restore the signal-hander frame data, if there was one. */
  bool restored_sighandler_frame = 0 < t->set_data_from_trace();
  if (restored_sighandler_frame) {
    LOG(debug) << "--> restoring sighandler frame for " << signal_name(sig);
  }
  // Note that fatal signals are not actually injected into the task!
  // This is very important; we must never actually inject fatal signals
  // into a task. All replay task death must go through exit_task.
  /* If this signal had a user handler, and we just set up the
   * callframe, and we need to restore the $sp for continued
   * execution. */
  t->set_regs(trace_frame.regs());

  t->validate_regs();
  return COMPLETE;
}

void ReplaySession::check_ticks_consistency(ReplayTask* t, const Event& ev) {
  if (!done_initial_exec()) {
    return;
  }

  Ticks ticks_now = t->tick_count();
  Ticks trace_ticks = trace_frame.ticks();

  ASSERT(t, ticks_now == trace_ticks)
      << "ticks mismatch for '" << ev << "'; expected " << trace_ticks
      << ", got " << ticks_now << "";
}

static bool treat_signal_event_as_deterministic(const SignalEvent& ev) {
  return ev.deterministic == DETERMINISTIC_SIG;
}

/**
 * Advance to the delivery of the deterministic signal |sig| and
 * update registers to what was recorded.  Return COMPLETE if successful or
 * INCOMPLETE  if an unhandled interrupt occurred.
 */
Completion ReplaySession::emulate_deterministic_signal(
    ReplayTask* t, int sig, const StepConstraints& constraints) {
  while (true) {
    if (t->regs().matches(trace_frame.regs()) &&
        t->tick_count() == trace_frame.ticks()) {
      // We're already at the target. This can happen when multiple signals
      // are delivered with no intervening execution.
      return COMPLETE;
    }

    auto complete = continue_or_step(t, constraints, RESUME_UNLIMITED_TICKS);
    if (complete == COMPLETE && !is_ignored_signal(t->stop_sig())) {
      break;
    }
  }

  if (SIGTRAP == t->stop_sig()) {
    TrapReasons trap_reasons = t->compute_trap_reasons();
    if (trap_reasons.singlestep || trap_reasons.watchpoint) {
      // Singlestep or watchpoint must have been debugger-requested
      return INCOMPLETE;
    }
    if (trap_reasons.breakpoint) {
      // An explicit breakpoint instruction in the tracee would produce a
      // |breakpoint| reason as we emulate the deterministic SIGTRAP.
      BreakpointType type =
          t->vm()->get_breakpoint_type_for_retired_insn(t->ip());
      if (BKPT_NONE != type) {
        ASSERT(t, BKPT_USER == type);
        return INCOMPLETE;
      }
    }
  }
  ASSERT(t, t->stop_sig() == sig)
      << "Replay got unrecorded signal " << signal_name(t->stop_sig())
      << " (expecting " << signal_name(sig) << ")";
  const Event& ev = trace_frame.event();
  check_ticks_consistency(t, ev);

  if (EV_INSTRUCTION_TRAP == ev.type()) {
    t->set_regs(trace_frame.regs());
  }

  return COMPLETE;
}

/**
 * Restore the recorded syscallbuf data to the tracee, preparing the
 * tracee for replaying the records.
 */
void ReplaySession::prepare_syscallbuf_records(ReplayTask* t) {
  // Read the recorded syscall buffer back into the buffer
  // region.
  auto buf = t->trace_reader().read_raw_data();
  ASSERT(t, buf.data.size() >= sizeof(struct syscallbuf_hdr));
  ASSERT(t, buf.data.size() <= t->syscallbuf_size);
  ASSERT(t, buf.addr == t->syscallbuf_child.cast<void>());

  struct syscallbuf_hdr recorded_hdr;
  memcpy(&recorded_hdr, buf.data.data(), sizeof(struct syscallbuf_hdr));
  // Don't overwrite syscallbuf_hdr. That needs to keep tracking the current
  // syscallbuf state.
  t->write_bytes_helper(t->syscallbuf_child + 1,
                        buf.data.size() - sizeof(struct syscallbuf_hdr),
                        buf.data.data() + sizeof(struct syscallbuf_hdr));

  ASSERT(t,
         recorded_hdr.num_rec_bytes + sizeof(struct syscallbuf_hdr) <=
             t->syscallbuf_size);

  current_step.flush.stop_breakpoint_addr =
      t->stopping_breakpoint_table.to_data_ptr<void>().as_int() +
      (recorded_hdr.num_rec_bytes / 8) *
          t->stopping_breakpoint_table_entry_size;

  LOG(debug) << "Prepared " << (uint32_t)recorded_hdr.num_rec_bytes
             << " bytes of syscall records";
}

/**
 * Returns mprotect_record_count
 */
static uint32_t apply_mprotect_records(ReplayTask* t,
                                       uint32_t skip_mprotect_records) {
  uint32_t final_mprotect_record_count =
      t->read_mem(REMOTE_PTR_FIELD(t->syscallbuf_child, mprotect_record_count));
  if (skip_mprotect_records < final_mprotect_record_count) {
    auto records =
        t->read_mem(REMOTE_PTR_FIELD(t->preload_globals, mprotect_records[0]) +
                        skip_mprotect_records,
                    final_mprotect_record_count - skip_mprotect_records);
    for (size_t i = 0; i < records.size(); ++i) {
      auto& r = records[i];
      uint32_t completed_count = t->read_mem(REMOTE_PTR_FIELD(
          t->syscallbuf_child, mprotect_record_count_completed));
      if (i >= completed_count) {
        auto km = t->vm()->read_kernel_mapping(t, r.start);
        if (km.prot() != r.prot) {
          // mprotect didn't happen yet.
          continue;
        }
      }
      t->vm()->protect(t, r.start, r.size, r.prot);
      if (running_under_rr()) {
        syscall(SYS_rrcall_mprotect_record, t->tid, (uintptr_t)r.start,
                (uintptr_t)r.size, r.prot);
      }
    }
  }
  return final_mprotect_record_count;
}

/**
 * Replay all the syscalls recorded in the interval between |t|'s
 * current execution point and the next non-syscallbuf event (the one
 * that flushed the buffer).  Return COMPLETE if successful or INCOMPLETE if an
 * unhandled interrupt occurred.
 */
Completion ReplaySession::flush_syscallbuf(ReplayTask* t,
                                           const StepConstraints& constraints) {
  bool user_breakpoint_at_addr = false;

  while (true) {
    auto next_rec = t->next_syscallbuf_record();
    uint32_t skip_mprotect_records = t->read_mem(
        REMOTE_PTR_FIELD(t->syscallbuf_child, mprotect_record_count_completed));

    TicksRequest ticks_request;
    if (!compute_ticks_request(t, constraints, &ticks_request)) {
      return INCOMPLETE;
    }

    bool added = t->vm()->add_breakpoint(
        current_step.flush.stop_breakpoint_addr, BKPT_INTERNAL);
    ASSERT(t, added);
    auto complete =
        continue_or_step(t, constraints, ticks_request, RESUME_CONT);
    user_breakpoint_at_addr =
        t->vm()->get_breakpoint_type_at_addr(
            current_step.flush.stop_breakpoint_addr) != BKPT_INTERNAL;
    t->vm()->remove_breakpoint(current_step.flush.stop_breakpoint_addr,
                               BKPT_INTERNAL);

    // Account for buffered syscalls just completed
    auto end_rec = t->next_syscallbuf_record();
    while (next_rec != end_rec) {
      accumulate_syscall_performed();
      next_rec = next_rec.as_int() + t->stored_record_size(next_rec);
    }

    // Apply the mprotect records we just completed.
    apply_mprotect_records(t, skip_mprotect_records);

    if (t->stop_sig() == PerfCounters::TIME_SLICE_SIGNAL) {
      // This would normally be triggered by constraints.ticks_target but it's
      // also possible to get stray signals here.
      return INCOMPLETE;
    }

    if (complete == COMPLETE && !is_ignored_signal(t->stop_sig())) {
      break;
    }
  }

  ASSERT(t, t->stop_sig() == SIGTRAP)
      << "Replay got unexpected signal (or none) " << t->stop_sig();
  if (t->ip().decrement_by_bkpt_insn_length(t->arch()) ==
          remote_code_ptr(current_step.flush.stop_breakpoint_addr) &&
      !user_breakpoint_at_addr) {
    Registers r = t->regs();
    r.set_ip(current_step.flush.stop_breakpoint_addr);
    t->set_regs(r);

    return COMPLETE;
  }

  return INCOMPLETE;
}

Completion ReplaySession::patch_next_syscall(
    ReplayTask* t, const StepConstraints& constraints) {
  if (cont_syscall_boundary(t, constraints) == INCOMPLETE) {
    return INCOMPLETE;
  }

  t->canonicalize_regs(t->arch());
  t->exit_syscall_and_prepare_restart();

  // All patching effects have been recorded to the trace.
  // First, replay any memory mapping done by Monkeypatcher. There should be
  // at most one but we might as well be general.
  while (true) {
    TraceReader::MappedData data;
    bool found;
    KernelMapping km = t->trace_reader().read_mapped_region(&data, &found);
    if (!found) {
      break;
    }
    AutoRemoteSyscalls remote(t);
    ASSERT(t, km.flags() & MAP_ANONYMOUS);
    remote.infallible_mmap_syscall(km.start(), km.size(), km.prot(),
                                   km.flags() | MAP_FIXED, -1, 0);
    t->vm()->map(t, km.start(), km.size(), km.prot(), km.flags(), 0, string(),
                 KernelMapping::NO_DEVICE, KernelMapping::NO_INODE, nullptr,
                 &km);
    t->vm()->mapping_flags_of(km.start()) |=
        AddressSpace::Mapping::IS_PATCH_STUBS;
  }

  // Now replay all data records.
  t->apply_all_data_records_from_trace();
  return COMPLETE;
}

/**
 * Return true if replaying |ev| by running |step| should result in
 * the target task having the same ticks value as it did during
 * recording.
 */
static bool has_deterministic_ticks(const Event& ev,
                                    const ReplayTraceStep& step) {
  if (ev.has_ticks_slop()) {
    return false;
  }
  // We won't necessarily reach the same ticks when replaying an
  // async signal, due to debugger interrupts and other
  // implementation details.  This is checked in |advance_to()|
  // anyway.
  return TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT != step.action;
}

void ReplaySession::check_approaching_ticks_target(
    ReplayTask* t, const StepConstraints& constraints,
    BreakStatus& break_status) {
  if (constraints.ticks_target > 0) {
    Ticks ticks_left = constraints.ticks_target - t->tick_count();
    if (ticks_left <= PerfCounters::skid_size()) {
      break_status.approaching_ticks_target = true;
    }
  }
}

Completion ReplaySession::advance_to_ticks_target(
    ReplayTask* t, const StepConstraints& constraints) {
  while (true) {
    TicksRequest ticks_request;
    if (!compute_ticks_request(t, constraints, &ticks_request)) {
      return INCOMPLETE;
    }
    continue_or_step(t, constraints, ticks_request);
    if (SIGTRAP == t->stop_sig()) {
      return INCOMPLETE;
    }
  }
}

/**
 * Try to execute |step|, adjusting for |req| if needed.  Return COMPLETE if
 * |step| was made, or INCOMPLETE if there was a trap or |step| needs
 * more work.
 */
Completion ReplaySession::try_one_trace_step(
    ReplayTask* t, const StepConstraints& constraints) {
  if (constraints.ticks_target > 0 && !trace_frame.event().has_ticks_slop() &&
      t->current_trace_frame().ticks() > constraints.ticks_target) {
    // Instead of doing this step, just advance to the ticks_target, since
    // that happens before this event completes.
    // Unfortunately we can't do this for TSTEP_FLUSH_SYSCALLBUF
    // because its tick count can't be trusted.
    // cont_syscall_boundary handles the ticks constraint for those cases.
    return advance_to_ticks_target(t, constraints);
  }

  switch (current_step.action) {
    case TSTEP_RETIRE:
      return COMPLETE;
    case TSTEP_ENTER_SYSCALL:
      return enter_syscall(t, constraints);
    case TSTEP_EXIT_SYSCALL:
      return exit_syscall(t);
    case TSTEP_DETERMINISTIC_SIGNAL:
      return emulate_deterministic_signal(t, current_step.target.signo,
                                          constraints);
    case TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT:
      return emulate_async_signal(t, constraints, current_step.target.ticks);
    case TSTEP_DELIVER_SIGNAL:
      return emulate_signal_delivery(t, current_step.target.signo);
    case TSTEP_FLUSH_SYSCALLBUF:
      return flush_syscallbuf(t, constraints);
    case TSTEP_PATCH_SYSCALL:
      return patch_next_syscall(t, constraints);
    case TSTEP_EXIT_TASK:
      return exit_task(t);
    default:
      FATAL() << "Unhandled step type " << current_step.action;
      return COMPLETE;
  }
}

/**
 * Task death during replay always goes through here (except for
 * Session::kill_all_tasks when we forcibly kill all tasks in the session at
 * once). |exit| and |exit_group| syscalls are both emulated so the real
 * task doesn't die until we reach the EXIT/UNSTABLE_EXIT events in the trace.
 * This ensures the real tasks are alive and available as long as our Task
 * object exists, which simplifies code like Session cloning.
 *
 * Killing tasks with fatal signals doesn't work because a fatal signal will
 * try to kill all the tasks in the thread group. Instead we inject an |exit|
 * syscall, which is apparently the only way to kill one specific thread.
 */
static void end_task(ReplayTask* t) {
  ASSERT(t, t->ptrace_event() != PTRACE_EVENT_EXIT);

  t->destroy_buffers();

  Registers r = t->regs();
  r.set_ip(t->vm()->privileged_traced_syscall_ip());
  r.set_syscallno(syscall_number_for_exit(t->arch()));
  t->set_regs(r);
  // Enter the syscall.
  t->resume_execution(RESUME_CONT, RESUME_WAIT, RESUME_NO_TICKS);
  ASSERT(t, t->ptrace_event() == PTRACE_EVENT_EXIT);

  t->stable_exit = true;
  t->destroy();
}

Completion ReplaySession::exit_task(ReplayTask* t) {
  ASSERT(t, !t->seen_ptrace_exit_event);
  // Apply robust-futex updates captured during recording.
  t->apply_all_data_records_from_trace();
  end_task(t);
  /* |t| is dead now. */
  return COMPLETE;
}

ReplayTask* ReplaySession::revive_task_for_exec() {
  const Event& ev = trace_frame.event();
  if (!ev.is_syscall_event() ||
      !is_execve_syscall(ev.Syscall().number, ev.Syscall().arch())) {
    FATAL() << "Can't find task, but we're not in an execve";
  }

  ThreadGroup* tg = nullptr;
  for (auto& p : thread_group_map) {
    if (p.second->tgid == trace_frame.tid()) {
      tg = p.second;
      break;
    }
  }
  if (!tg) {
    FATAL()
        << "Dead task tid should be task-group leader, but we can't find it";
  }
  if (tg->task_set().size() != 1) {
    FATAL() << "Should only be one task left in the taskgroup";
  }

  ReplayTask* t = static_cast<ReplayTask*>(*tg->task_set().begin());
  LOG(debug) << "Changing task tid from " << t->rec_tid << " to "
             << trace_frame.tid();
  task_map.erase(t->rec_tid);
  t->rec_tid = trace_frame.tid();
  task_map.insert(make_pair(t->rec_tid, t));
  // The real tid is not changing yet. It will, in process_execve.
  return t;
}

/**
 * Set up rep_trace_step state in t's Session to start replaying towards
 * the event given by the session's current_trace_frame --- but only if
 * it's not already set up.
 * Return true if we should continue replaying, false if the debugger
 * requested a restart. If this returns false, t's Session state was not
 * modified.
 */
ReplayTask* ReplaySession::setup_replay_one_trace_frame(ReplayTask* t) {
  const Event& ev = trace_frame.event();

  if (!t) {
    t = revive_task_for_exec();
  }

  LOG(debug) << "[event " << trace_frame.time() << "] " << t->rec_tid
             << ": replaying " << Event(ev) << "; state "
             << (ev.is_syscall_event() ? state_name(ev.Syscall().state)
                                       : " (none)");
  if (t->syscallbuf_child) {
    LOG(debug) << "    (syscllbufsz:"
               << (uint32_t)t->read_mem(
                      REMOTE_PTR_FIELD(t->syscallbuf_child, num_rec_bytes))
               << ", abrtcmt:" << bool(t->read_mem(REMOTE_PTR_FIELD(
                                      t->syscallbuf_child, abort_commit)))
               << ", locked:" << bool(t->read_mem(REMOTE_PTR_FIELD(
                                     t->syscallbuf_child, locked)))
               << ")";
  }

  /* Ask the trace-interpretation code what to do next in order
   * to retire the current frame. */
  memset(&current_step, 0, sizeof(current_step));

  switch (ev.type()) {
    case EV_EXIT:
      current_step.action = TSTEP_EXIT_TASK;
      break;
    case EV_SYSCALLBUF_ABORT_COMMIT:
      t->write_mem(REMOTE_PTR_FIELD(t->syscallbuf_child, abort_commit),
                   (uint8_t)1);
      t->apply_all_data_records_from_trace();
      current_step.action = TSTEP_RETIRE;
      break;
    case EV_SYSCALLBUF_FLUSH:
      current_step.action = TSTEP_FLUSH_SYSCALLBUF;
      prepare_syscallbuf_records(t);
      break;
    case EV_SYSCALLBUF_RESET:
      // Reset syscallbuf_hdr->num_rec_bytes and zero out the recorded data.
      // Zeroing out the data is important because we only save and restore
      // the recorded data area when making checkpoints. We want the checkpoint
      // to have the same syscallbuf contents as its original, i.e. zero outside
      // the recorded data area. This is important because stray reads such
      // as those performed by return_addresses should be consistent.
      t->reset_syscallbuf();
      current_step.action = TSTEP_RETIRE;
      break;
    case EV_PATCH_SYSCALL:
      current_step.action = TSTEP_PATCH_SYSCALL;
      break;
    case EV_SCHED:
      current_step.action = TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT;
      current_step.target.ticks = trace_frame.ticks();
      current_step.target.signo = 0;
      break;
    case EV_INSTRUCTION_TRAP:
      current_step.action = TSTEP_DETERMINISTIC_SIGNAL;
      current_step.target.ticks = -1;
      current_step.target.signo = SIGSEGV;
      break;
    case EV_GROW_MAP:
      process_grow_map(t);
      current_step.action = TSTEP_RETIRE;
      break;
    case EV_SIGNAL: {
      last_siginfo_ = ev.Signal().siginfo;
      if (treat_signal_event_as_deterministic(ev.Signal())) {
        current_step.action = TSTEP_DETERMINISTIC_SIGNAL;
        current_step.target.signo = ev.Signal().siginfo.si_signo;
        current_step.target.ticks = -1;
      } else {
        current_step.action = TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT;
        current_step.target.signo = ev.Signal().siginfo.si_signo;
        current_step.target.ticks = trace_frame.ticks();
      }
      break;
    }
    case EV_SIGNAL_DELIVERY:
    case EV_SIGNAL_HANDLER:
      current_step.action = TSTEP_DELIVER_SIGNAL;
      current_step.target.signo = ev.Signal().siginfo.si_signo;
      break;
    case EV_SYSCALL:
      if (trace_frame.event().Syscall().state == ENTERING_SYSCALL ||
          trace_frame.event().Syscall().state == ENTERING_SYSCALL_PTRACE) {
        rep_prepare_run_to_syscall(t, &current_step);
      } else {
        rep_process_syscall(t, &current_step);
        if (current_step.action == TSTEP_RETIRE) {
          t->on_syscall_exit(current_step.syscall.number,
                             current_step.syscall.arch, trace_frame.regs());
        }
      }
      break;
    default:
      FATAL() << "Unexpected event " << ev;
  }

  return t;
}

bool ReplaySession::next_step_is_successful_syscall_exit(int syscallno) {
  return current_step.action == TSTEP_NONE &&
         trace_frame.event().is_syscall_event() &&
         trace_frame.event().Syscall().number == syscallno &&
         trace_frame.event().Syscall().state == EXITING_SYSCALL &&
         !trace_frame.regs().syscall_failed();
}

ReplayResult ReplaySession::replay_step(const StepConstraints& constraints) {
  finish_initializing();

  ReplayResult result(REPLAY_CONTINUE);

  ReplayTask* t = current_task();

  if (EV_TRACE_TERMINATION == trace_frame.event().type()) {
    result.status = REPLAY_EXITED;
    return result;
  }

  /* If we restored from a checkpoint, the steps might have been
   * computed already in which case step.action will not be TSTEP_NONE.
   */
  if (current_step.action == TSTEP_NONE) {
    t = setup_replay_one_trace_frame(t);
    if (current_step.action == TSTEP_NONE) {
      // Already at the destination event.
      advance_to_next_trace_frame();
    }
    if (current_step.action == TSTEP_EXIT_TASK) {
      result.break_status.task = t;
      result.break_status.task_exit = true;
    }
    return result;
  }

  did_fast_forward = false;

  // Now we know |t| hasn't died, so save it in break_status.
  result.break_status.task = t;

  /* Advance towards fulfilling |current_step|. */
  if (try_one_trace_step(t, constraints) == INCOMPLETE) {
    if (EV_TRACE_TERMINATION == trace_frame.event().type()) {
      // An irregular trace step had to read the
      // next trace frame, and that frame was an
      // early-termination marker.  Otherwise we
      // would have seen the marker above.
      result.status = REPLAY_EXITED;
      return result;
    }

    // We got INCOMPLETE because there was some kind of debugger trap or
    // we got close to ticks_target.
    result.break_status = diagnose_debugger_trap(t, constraints.command);
    ASSERT(t, !result.break_status.signal)
        << "Expected either SIGTRAP at $ip " << t->ip()
        << " or USER breakpoint just after it";
    ASSERT(t,
           !result.break_status.singlestep_complete ||
               constraints.is_singlestep());

    check_approaching_ticks_target(t, constraints, result.break_status);
    result.did_fast_forward = did_fast_forward;
    return result;
  }

  result.did_fast_forward = did_fast_forward;

  switch (current_step.action) {
    case TSTEP_DETERMINISTIC_SIGNAL:
    case TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT:
      if (current_step.target.signo) {
        if (trace_frame.event().type() != EV_INSTRUCTION_TRAP) {
          ASSERT(t, current_step.target.signo == last_siginfo_.si_signo);
          result.break_status.signal =
              unique_ptr<siginfo_t>(new siginfo_t(last_siginfo_));
        }
        if (constraints.is_singlestep()) {
          result.break_status.singlestep_complete = true;
        }
      }
      break;
    case TSTEP_DELIVER_SIGNAL:
      // When we deliver a terminating signal, do not let the singlestep
      // complete; proceed on to report our synthetic SIGKILL or task death.
      if (constraints.is_singlestep() &&
          !(trace_frame.event().type() == EV_SIGNAL_DELIVERY &&
            is_fatal_default_action(current_step.target.signo))) {
        result.break_status.singlestep_complete = true;
      }
      break;
    case TSTEP_EXIT_TASK:
      result.break_status.task = nullptr;
      t = nullptr;
      DEBUG_ASSERT(!result.break_status.any_break());
      break;
    case TSTEP_ENTER_SYSCALL:
      cpuid_bug_detector.notify_reached_syscall_during_replay(t);
      break;
    case TSTEP_EXIT_SYSCALL:
      if (constraints.is_singlestep()) {
        result.break_status.singlestep_complete = true;
      }
      break;
    default:
      break;
  }

  if (t) {
    const Event& ev = trace_frame.event();
    if (done_initial_exec() && ev.is_syscall_event() &&
        rr::Flags::get().check_cached_mmaps) {
      t->vm()->verify(t);
    }

    if (has_deterministic_ticks(ev, current_step)) {
      check_ticks_consistency(t, ev);
    }

    debug_memory(t);

    check_for_watchpoint_changes(t, result.break_status);
    check_approaching_ticks_target(t, constraints, result.break_status);
  }

  advance_to_next_trace_frame();
  // Record that this step completed successfully.
  current_step.action = TSTEP_NONE;

  ReplayTask* next_task = current_task();
  if (next_task && !next_task->vm()->first_run_event() && done_initial_exec()) {
    next_task->vm()->set_first_run_event(trace_frame.time());
  }
  if (next_task) {
    ticks_at_start_of_event = next_task->tick_count();
  }

  return result;
}

ReplayTask* ReplaySession::find_task(pid_t rec_tid) const {
  return static_cast<ReplayTask*>(Session::find_task(rec_tid));
}

ReplayTask* ReplaySession::find_task(const TaskUid& tuid) const {
  return static_cast<ReplayTask*>(Session::find_task(tuid));
}

double ReplaySession::get_trace_start_time(){
  return trace_start_time;
}

} // namespace rr
