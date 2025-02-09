/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#define USE_BREAKPOINT_TARGET 1

#include "ReplaySession.h"

#include <linux/futex.h>
#include <syscall.h>
#include <sys/prctl.h>

#include <algorithm>
#include <ostream>
#include <sstream>
#include <unordered_map>

#include "AutoRemoteSyscalls.h"
#include "Flags.h"
#include "ProcessorTraceDecoder.h"
#include "processor_trace_check.h"
#include "ReplayTask.h"
#include "ThreadGroup.h"
#include "core.h"
#include "fast_forward.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"
#include "replay_syscall.h"
#include "util.h"

#include "PersistentCheckpointing.h"
#include "PreserveFileMonitor.h"
#include <fcntl.h>

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

void ReplaySession::delete_range(ReplaySession::MemoryRanges& ranges,
                                 const MemoryRange& r) {
  split_at_address(ranges, r.start());
  split_at_address(ranges, r.end());
  auto first = ranges.lower_bound(MemoryRange(r.start(), r.start() + 1));
  auto last = ranges.lower_bound(MemoryRange(r.end(), r.end() + 1));
  ranges.erase(first, last);
}

const ReplaySession::MemoryRanges& ReplaySession::always_free_address_space(
    PerfTradeoff perf_tradeoff) {
  shared_ptr<MemoryRanges>& result =
      perf_tradeoff == ACCURATE ? always_free_address_space_accurate :
        always_free_address_space_fast;
  if (!result->empty()) {
    return *result;
  }

  remote_ptr<void> addressable_min = remote_ptr<void>(64 * 1024);
  // Assume 64-bit address spaces with the 47-bit user-space limitation,
  // for now.
  remote_ptr<void> addressable_max = uintptr_t(
      sizeof(void*) == 8 ? uint64_t(1) << 47 : (uint64_t(1) << 32) - page_size());
  result->insert(MemoryRange(addressable_min, addressable_max));
  TraceReader tmp_reader(trace_reader());
  bool found;
  while (true) {
    KernelMapping km = tmp_reader.read_mapped_region(
        nullptr, &found, TraceReader::DONT_VALIDATE, TraceReader::ANY_TIME);
    if (!found) {
      break;
    }
    // We can use PROT_NONE space, since any access of it by the application
    // would have triggered a SIGSEGV.
    // This is important when processing traces recorded with sanitizers compiled
    // in.
    // If it's mapped PROT_NONE but later mprotect() is used to make it usable, that
    // is handled below. In FAST mode we don't use this memory, since we don't
    // want to scan the trace frames.
    if (perf_tradeoff == ACCURATE && km.prot() == PROT_NONE) {
      continue;
    }
    delete_range(*result, km);
  }
  while (perf_tradeoff == ACCURATE && !tmp_reader.at_end()) {
    auto frame = tmp_reader.read_frame();
    auto event = frame.event();
    // If a region was ever mprotected to something that's not PROT_NONE,
    // or had PR_SET_VMA_ANON_NAME called on it, we need to delete it as well.
    if (event.is_syscall_event()) {
      auto syscall_event = event.Syscall();
      if (is_mprotect_syscall(syscall_event.number, syscall_event.arch()) ||
          is_pkey_mprotect_syscall(syscall_event.number, syscall_event.arch())) {
        auto regs = frame.regs();
        if (regs.arg3() != PROT_NONE) {
          remote_ptr<void> start = regs.arg1();
          size_t size = regs.arg2();
          delete_range(*result, MemoryRange(start, size));
        }
      }
      if (is_prctl_syscall(syscall_event.number, syscall_event.arch())) {
        auto regs = frame.regs();
        if (regs.arg2() == PR_SET_VMA_ANON_NAME) {
          remote_ptr<void> start = regs.arg3();
          size_t size = regs.arg4();
          delete_range(*result, MemoryRange(start, size));
        }
      }
    } else if (event.is_syscallbuf_flush_event()) {
      auto syscallbuf_flush_event = event.SyscallbufFlush();
      for (auto& record : syscallbuf_flush_event.mprotect_records) {
        if (record.prot != PROT_NONE) {
          delete_range(*result, MemoryRange(record.start, record.size));
        }
      }
    }
  }
  delete_range(*result, MemoryRange(AddressSpace::rr_page_start(),
                                    AddressSpace::rr_page_end()));
  return *result;
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
    if (!Flags::get().suppress_environment_warnings) {
      // If the tracee used XSAVE instructions which write different components
      // to XSAVE instructions executed on our CPU, or examines XCR0 directly,
      // This will cause divergence. The dynamic linker examines XCR0 so this
      // is nearly guaranteed.
      cerr << "Trace XCR0 value " << HEX(tracee_xcr0) << " != our XCR0 "
          << "value " << HEX(our_xcr0) << "; Replay will probably fail "
          << "because glibc dynamic loader examines XCR0\n\n";
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

ReplaySession::ReplaySession(const std::string& dir, const Flags& flags)
    : emu_fs(EmuFs::create()),
      trace_in(dir),
      trace_frame(),
      current_step(),
      ticks_at_start_of_event(0),
      flags_(flags),
      skip_next_execution_event(false),
      replay_stops_at_first_execve_(flags.replay_stops_at_first_execve),
      detected_transient_error_(false),
      trace_start_time(0),
      suppress_stdio_before_event_(0),
      always_free_address_space_fast(make_shared<MemoryRanges>()),
      always_free_address_space_accurate(make_shared<MemoryRanges>()) {
  if (trace_in.required_forward_compatibility_version() > FORWARD_COMPATIBILITY_VERSION) {
    CLEAN_FATAL()
      << "This rr build is too old to replay the trace (we support forward compatibility version "
      << FORWARD_COMPATIBILITY_VERSION << " but the trace needs " << trace_in.required_forward_compatibility_version() << ")";
  }

  ticks_semantics_ = trace_in.ticks_semantics();
  rrcall_base_ = trace_in.rrcall_base();
  syscallbuf_fds_disabled_size_ = trace_in.syscallbuf_fds_disabled_size();
  syscallbuf_hdr_size_ = trace_in.syscallbuf_hdr_size();

  if (!flags.redirect_stdio_file.empty()) {
    tracee_output_fd_ = make_shared<ScopedFd>(flags.redirect_stdio_file.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (!tracee_output_fd_->is_open()) {
      FATAL() << "Can't open/create tracee output file " << flags.redirect_stdio_file;
    }
  }

  memset(&last_siginfo_, 0, sizeof(last_siginfo_));
  advance_to_next_trace_frame();

  trace_start_time = trace_frame.monotonic_time();

  if (!flags.replay_stops_at_first_execve) {
    if (!PerfCounters::supports_ticks_semantics(ticks_semantics_)) {
      CLEAN_FATAL()
          << "Trace was recorded on a machine that defines ticks differently\n"
             "to this machine; replay will not work.";
    }

    if (is_x86ish(trace_in.arch())) {
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

      check_xsave_compatibility(trace_in);
    }
  }

  set_intel_pt_enabled(flags.intel_pt_start_checking_event >= 0);

  check_virtual_address_size();
}

ReplaySession::ReplaySession(const ReplaySession& other)
    : Session(other),
      emu_fs(EmuFs::create()),
      tracee_output_fd_(other.tracee_output_fd_),
      trace_in(other.trace_in),
      trace_frame(other.trace_frame),
      current_step(other.current_step),
      ticks_at_start_of_event(other.ticks_at_start_of_event),
      cpuid_bug_detector(other.cpuid_bug_detector),
      last_siginfo_(other.last_siginfo_),
      flags_(other.flags_),
      fast_forward_status(other.fast_forward_status),
      skip_next_execution_event(other.skip_next_execution_event),
      replay_stops_at_first_execve_(other.replay_stops_at_first_execve_),
      detected_transient_error_(other.detected_transient_error_),
      trace_start_time(other.trace_start_time),
      suppress_stdio_before_event_(other.suppress_stdio_before_event_),
      always_free_address_space_fast(other.always_free_address_space_fast),
      always_free_address_space_accurate(other.always_free_address_space_accurate) {}

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

void ReplaySession::check_virtual_address_size() const
{
  uint8_t virtual_address_size_needed = trace_in.max_virtual_address_size();
  if (virtual_address_size_supported(virtual_address_size_needed)) {
    return;
  }

  if (rr::Flags::get().force_things) {
    LOG(warn) << "Virtual address size is unsupported but forcing anyways.";
    return;
  }

  CLEAN_FATAL() << "The trace uses " << (uint32_t)virtual_address_size_needed <<
      " bit virtual addresses but this system does not support that size.";
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

bool ReplaySession::can_clone() {
  finish_initializing();

  ReplayTask* t = current_task();
  return t && done_initial_exec() &&
         current_trace_frame().event().can_checkpoint_at();
}

DiversionSession::shr_ptr ReplaySession::clone_diversion() {
  finish_initializing();
  clear_syscall_bp();

  LOG(debug) << "Deepforking ReplaySession " << this
             << " to DiversionSession...";

  DiversionSession::shr_ptr session(new DiversionSession(cpu_binding()));
  session->ticks_semantics_ = ticks_semantics_;
  session->tracee_socket = tracee_socket;
  session->tracee_socket_fd_number = tracee_socket_fd_number;
  session->rrcall_base_ = rrcall_base_;
  session->syscallbuf_fds_disabled_size_ = syscallbuf_fds_disabled_size_;
  LOG(debug) << "  deepfork session is " << session.get();

  copy_state_to(*session, emufs(), session->emufs());
  session->finish_initializing();

  return session;
}

Task* ReplaySession::new_task(pid_t tid, pid_t rec_tid, uint32_t serial,
                              SupportedArch a, const std::string& name) {
  return new ReplayTask(*this, tid, rec_tid, serial, a, name);
}

/*static*/ ReplaySession::shr_ptr ReplaySession::create(const string& dir,
                                                        const ReplaySession::Flags& flags) {
  shr_ptr session(new ReplaySession(dir, flags));

  // It doesn't really matter what we use for argv/env here, since
  // replay_syscall's process_execve is going to follow the recording and
  // ignore the parameters.
  string exe_path;
  vector<string> argv;
  vector<string> env;

  session->do_bind_cpu();
  ScopedFd error_fd = session->create_spawn_task_error_pipe();
  ReplayTask* t = static_cast<ReplayTask*>(
      Task::spawn(*session, error_fd, &session->tracee_socket_fd(),
                  &session->tracee_socket_receiver_fd(),
                  &session->tracee_socket_fd_number,
                  exe_path, argv, env,
                  session->trace_reader().peek_frame().tid()));
  session->on_create(t);

  return session;
}

int ReplaySession::cpu_binding() const {
  if (flags_.cpu_unbound) {
    return -1;
  }
  return Session::cpu_binding();
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
        constraints.ticks_target - t->hpc.skid_size() - t->tick_count();
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
      special_instruction_at(t, t->ip()).opcode != SpecialInstOpcode::X86_CPUID) {
    return false;
  }
  // OK, this is a case where we did not record using CPUID faulting but we are
  // replaying with CPUID faulting and the tracee just executed a CPUID.
  // We try to find the results in the "all CPUID leaves" we saved.

  const vector<CPUIDRecord>& records = trace_in.cpuid_records();
  Registers r = t->regs();
  const CPUIDRecord* rec = find_cpuid_record(records, r.ax(), r.cx());
  if (rec) {
    if (rec->ecx_in == UINT32_MAX &&
        (r.ax() == CPUID_AMD_CACHE_TOPOLOGY || r.ax() == CPUID_AMD_PLATFORM_QOS)) {
      const CPUIDRecord* rec2 = find_cpuid_record(records, CPUID_GETVENDORSTRING, 0);
      if (!rec2 || is_cpu_vendor_amd(rec2->out)) {
        LOG(error) << "Can't find extended AMD CPUID records. Replay will likely fail. " <<
          "Please re-record the trace with an up-to-date version of rr.";
      }
    }
    r.set_cpuid_output(rec->out.eax, rec->out.ebx, rec->out.ecx, rec->out.edx);
  } else {
    LOG(warn) << "Can't find CPUID record for request AX=" << HEX(r.ax())
              << " CX=" << HEX(r.cx()) << "; defaulting to 0/0/0/0";
    r.set_cpuid_output(0, 0, 0, 0);
  }
  r.set_ip(r.ip() + special_instruction_len(SpecialInstOpcode::X86_CPUID));
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
  TicksRequest ticks_request = RESUME_UNLIMITED_TICKS;
  if (constraints.ticks_target <= trace_frame.ticks()) {
    if (!compute_ticks_request(t, constraints, &ticks_request)) {
      return INCOMPLETE;
    }
  }

  if (constraints.command == RUN_SINGLESTEP_FAST_FORWARD) {
    // ignore ticks_period. We can't add more than one tick during a
    // fast_forward so it doesn't matter.
    fast_forward_status |= fast_forward_through_instruction(
        t, RESUME_SYSEMU_SINGLESTEP, constraints.stop_before_states);
  } else {
    ResumeRequest resume_how =
        constraints.is_singlestep() ? RESUME_SYSEMU_SINGLESTEP : RESUME_SYSEMU;
    bool ok = t->resume_execution(resume_how, RESUME_WAIT_NO_EXIT, ticks_request);
    ASSERT(t, ok) << "Tracee died unexpectedly";
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
    bool ok = t->resume_execution(RESUME_SYSEMU, RESUME_WAIT_NO_EXIT, ticks_request);
    ASSERT(t, ok) << "Tracee died unexpectedly";
  }

  t->apply_syscall_entry_regs();

  auto type = AddressSpace::rr_page_syscall_from_exit_point(t->arch(), t->ip());
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
 * Make it look like |t| entered the syscall at |syscall_instruction|
 */
static void emulate_syscall_entry(ReplayTask* t, const TraceFrame& frame,
                                  remote_code_ptr syscall_instruction) {
  Registers r = t->regs();
  r.set_ip(syscall_instruction.increment_by_syscall_insn_length(t->arch()));
  r.emulate_syscall_entry();
  t->set_regs(r);
  t->canonicalize_regs(frame.event().Syscall().arch());
  t->validate_regs();
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
              syscall_instruction)) {
        if (t->vm()->add_breakpoint(syscall_instruction, BKPT_INTERNAL)) {
          syscall_bp_vm = t->vm();
          syscall_bp_addr = syscall_instruction;
        }
      }
    }

    if (cont_syscall_boundary(t, constraints) == INCOMPLETE) {
      bool reached_target = syscall_bp_vm && SIGTRAP == t->stop_sig() &&
                            t->ip().undo_executed_bkpt(t->arch()) ==
                                syscall_instruction;
      if (reached_target) {
        // Check if we've hit a user break/watchpoint
        if (t->vm()->get_breakpoint_type_at_addr(syscall_instruction) != BKPT_INTERNAL) {
          reached_target = false;
        }
        else if (t->vm()->is_exec_watchpoint(syscall_instruction)) {
          reached_target = false;
        }
      }
      if (reached_target) {
        emulate_syscall_entry(t, current_trace_frame(), syscall_instruction);
        clear_syscall_bp();
      } else {
        return INCOMPLETE;
      }
    } else {
      // If we use the breakpoint optimization, we must get a SIGTRAP before
      // reaching a syscall, so cont_syscall_boundary must return INCOMPLETE.
      if (syscall_bp_vm) {
        ASSERT(t, false)
            << "Expected syscall_bp_vm to be clear but it's " << syscall_bp_vm->leader_tid()
            << "'s address space with a breakpoint at " << syscall_bp_addr
            << " while we're at " << t->ip();
      }
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

static bool do_replay_assist(Task* t) {
  auto orig_ip = t->ip();
  auto exit_ip = orig_ip.advance_past_executed_bkpt(t->arch());
  auto type = AddressSpace::rr_page_syscall_from_exit_point(t->arch(), exit_ip);
  if (!type || type->enabled != AddressSpace::REPLAY_ASSIST) {
    return false;
  }
  auto next_rec_ptr = t->next_syscallbuf_record();
  auto next_rec = t->read_mem(next_rec_ptr);
  ASSERT(t, next_rec.replay_assist);
  Registers regs = t->regs();
  regs.set_syscall_result(next_rec.ret);
  t->on_syscall_exit(next_rec.syscallno, t->arch(), regs);
  if (orig_ip != exit_ip) {
    auto r = t->regs();
    r.set_ip(exit_ip);
    t->set_regs(r);
  }
  return true;
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
 * tick_request and try again. We may return INCOMPLETE because we successfully
 * processed a CPUID trap.
 */
Completion ReplaySession::continue_or_step(ReplayTask* t,
                                           const StepConstraints& constraints,
                                           TicksRequest tick_request,
                                           ResumeRequest resume_how) {
  if (constraints.command == RUN_SINGLESTEP) {
    bool ok = t->resume_execution(RESUME_SINGLESTEP, RESUME_WAIT_NO_EXIT, tick_request);
    ASSERT(t, ok) << "Tracee died unexpectedly";
    handle_unrecorded_cpuid_fault(t, constraints);
  } else if (constraints.command == RUN_SINGLESTEP_FAST_FORWARD) {
    fast_forward_status |= fast_forward_through_instruction(
        t, RESUME_SINGLESTEP, constraints.stop_before_states);
    handle_unrecorded_cpuid_fault(t, constraints);
  } else {
    bool ok = t->resume_execution(resume_how, RESUME_WAIT_NO_EXIT, tick_request);
    ASSERT(t, ok) << "Tracee died unexpectedly";
    if (t->stop_sig() == 0) {
      auto type = AddressSpace::rr_page_syscall_from_exit_point(t->arch(), t->ip());
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
        t->apply_syscall_entry_regs();
        perform_interrupted_syscall(t);
        return INCOMPLETE;
      }
    } else if (t->stop_sig() == SIGTRAP) {
      // Detect replay assist but handle it later in flush_syscallbuf
      auto type = AddressSpace::rr_page_syscall_from_exit_point(t->arch(), t->ip().advance_past_executed_bkpt(t->arch()));
      if (type && type->enabled == AddressSpace::REPLAY_ASSIST) {
        t->apply_syscall_entry_regs();
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
    if (t->regs().ip().undo_executed_bkpt(t->arch()) == target_ip) {
      t->move_ip_before_breakpoint();
    }
    if (closest_matching_regs) {
      ASSERT(t, false) << "overshot target ticks=" << target_ticks << " by "
        << -remaining_ticks << "; target registers at ticks target mismatched: "
        << "replay != rec: " << t->regs().compare_with(*closest_matching_regs);
    } else {
      ASSERT(t, false) << "overshot target ticks=" << target_ticks << " by "
        << -remaining_ticks << "; target registers mismatched: "
        << "replay != rec: " << t->regs().compare_with(target_regs);
    }
  }
}

static void guard_unexpected_signal(ReplayTask* t) {
  if (ReplaySession::is_ignored_signal(t->stop_sig()) ||
      SIGTRAP == t->stop_sig()) {
    return;
  }

  if (t->stop_sig()) {
    ASSERT(t, false) << "Replay got unrecorded signal "
                     << signal_name(t->stop_sig()) << " while awaiting signal"
                     << "\n" << t->get_siginfo();
  } else if (t->status().is_syscall()) {
    ASSERT(t, false) << "Replay got unrecorded syscall "
                     << syscall_name(t->regs().original_syscallno(), t->arch())
                     << " while awaiting signal";
  }
}

static bool is_same_execution_point(ReplayTask* t, const Registers& rec_regs,
                                    const ExtraRegisters& rec_extra_regs,
                                    Ticks ticks_left,
                                    Registers* mismatched_regs,
                                    const Registers** mismatched_regs_ptr,
                                    bool in_syscallbuf) {
  if (ticks_left != 0) {
    if (IS_LOGGING(debug)) {
      LOG(debug) << "  not same execution point: " << ticks_left
                 << " ticks left (@" << rec_regs.ip() << ")"
                 << " replay vs rec: " << t->regs().compare_with(rec_regs);
    }
    return false;
  }
  if (in_syscallbuf) {
    // In the syscallbuf, only check IP. The values of registers may diverge between
    // recording and replay.
    // If this is too loose (i.e. we can reach the same IP with no ticks in between),
    // we should add instructions to the syscallbuf code to explicitly increase the tick
    // count, e.g. dummy conditional branches.
    if (t->ip() != rec_regs.ip()) {
      LOG(debug) << "  not same execution point: expected IP " << rec_regs.ip()
                 << ", got " << t->ip();
      *mismatched_regs = t->regs();
      *mismatched_regs_ptr = mismatched_regs;
      return false;
    }
  } else if (!t->regs().matches(rec_regs)) {
    if (IS_LOGGING(debug)) {
      LOG(debug) << "  not same execution point: regs differ (@" << rec_regs.ip()
                 << ") replay vs rec: " << t->regs().compare_with(rec_regs);
    }
    *mismatched_regs = t->regs();
    *mismatched_regs_ptr = mismatched_regs;
    return false;
  } else if (!t->extra_regs().matches(rec_extra_regs)) {
    if (IS_LOGGING(debug)) {
      LOG(debug) << "  not same execution point: extra regs differ (@" << rec_regs.ip()
                 << ") replay vs rec: " << t->extra_regs().compare_with(rec_extra_regs);
    }
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
 * If in_syscallbuf_syscall_hook is non-null we'll stop if execution
 * reaches that address and return COMPLETE.
 */
Completion ReplaySession::emulate_async_signal(
    ReplayTask* t, const StepConstraints& constraints, Ticks ticks,
    remote_code_ptr in_syscallbuf_syscall_hook) {
  bool in_syscallbuf = !in_syscallbuf_syscall_hook.is_null();

  const Registers& regs = trace_frame.regs();
  const ExtraRegisters& extra_regs = trace_frame.extra_regs();
  remote_code_ptr ip = regs.ip();

  /* Step 1: advance to the target ticks (minus a slack region) as
   * quickly as possible by programming the hpc. */
  Ticks ticks_left = ticks - t->tick_count();

  LOG(debug) << "advancing " << ticks_left << " ticks to reach " << ticks << "/"
             << ip;

  auto skid_size = t->hpc.skid_size();
  /* XXX should we only do this if (ticks > 10000)? */
  while (ticks_left - skid_size > skid_size) {
    LOG(debug) << "  programming interrupt for "
               << (ticks_left - skid_size) << " ticks";

    // Avoid overflow. If ticks_left > MAX_TICKS_REQUEST, execution will stop
    // early but we'll treat that just like a stray TIME_SLICE_SIGNAL and
    // continue as needed.
    if (in_syscallbuf_syscall_hook) {
      // Advance no further than syscall_hook.
      t->vm()->add_breakpoint(in_syscallbuf_syscall_hook, BKPT_INTERNAL);
    }
    continue_or_step(t, constraints,
                     (TicksRequest)(min<Ticks>(MAX_TICKS_REQUEST, ticks_left) -
                                    skid_size));
    guard_unexpected_signal(t);
    if (in_syscallbuf_syscall_hook) {
      t->vm()->remove_breakpoint(in_syscallbuf_syscall_hook, BKPT_INTERNAL);
    }

    ticks_left = ticks - t->tick_count();

    if (SIGTRAP == t->stop_sig()) {
      if (t->ip().undo_executed_bkpt(t->arch()) == in_syscallbuf_syscall_hook) {
        t->move_ip_before_breakpoint();
        // Advance no further.
        return COMPLETE;
      }
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
  bool did_set_internal_breakpoints = false;
  bool did_set_bpf_breakpoint = false;
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
        t, regs, extra_regs, ticks_left, &mismatched_regs, &mismatched_regs_ptr, in_syscallbuf);
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
        if (did_set_internal_breakpoints) {
          t->vm()->remove_breakpoint(ip, BKPT_INTERNAL);
          if (in_syscallbuf_syscall_hook) {
            t->vm()->remove_breakpoint(in_syscallbuf_syscall_hook, BKPT_INTERNAL);
          }
        }
        return INCOMPLETE;
      }

      if (trap_reasons.breakpoint) {
        // We didn't hit a user breakpoint, and executing an explicit
        // breakpoint instruction in the tracee would have triggered a
        // deterministic signal instead of an async one.
        // So we must have hit our internal breakpoint.
        ASSERT(t, did_set_internal_breakpoints || did_set_bpf_breakpoint);
        // We didn't do an internal singlestep, and if we'd done a
        // user-requested singlestep we would have hit the above case.
        ASSERT(t, !trap_reasons.singlestep);
        if (did_set_internal_breakpoints) {
          if (t->ip().undo_executed_bkpt(t->arch()) == in_syscallbuf_syscall_hook) {
            t->vm()->remove_breakpoint(ip, BKPT_INTERNAL);
            t->vm()->remove_breakpoint(in_syscallbuf_syscall_hook, BKPT_INTERNAL);
            t->move_ip_before_breakpoint();
            return COMPLETE;
          }
          ASSERT(t, regs.ip() == t->ip().undo_executed_bkpt(t->arch()));
        } else {
          LOG(debug) << "    fast-forwarded through " << t->hpc.bpf_skips() << " breakpoint hits with bpf";
        }
        /* Case (1) above: cover the tracks of
         * our internal breakpoint, and go
         * check again if we're at the
         * target. */
        LOG(debug) << "    trap was for target $ip";

        pending_SIGTRAP = false;
        if (did_set_internal_breakpoints) {
          t->move_ip_before_breakpoint();
        }
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
    if (did_set_internal_breakpoints) {
      t->vm()->remove_breakpoint(ip, BKPT_INTERNAL);
      if (in_syscallbuf_syscall_hook) {
        t->vm()->remove_breakpoint(in_syscallbuf_syscall_hook, BKPT_INTERNAL);
      }
      did_set_internal_breakpoints = false;
    }
    did_set_bpf_breakpoint = false;

    if (at_target) {
      /* Case (2) above: done. */
      return COMPLETE;
    }

    /* At this point, we've proven that we're not at the
     * target execution point, and we've ensured the
     * internal breakpoints are unset. */
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
      if (is_x86_string_instruction_at(t, ip) || !t->hpc.accelerate_async_signal(regs)) {
        t->vm()->add_breakpoint(ip, BKPT_INTERNAL);

        if (in_syscallbuf_syscall_hook) {
          t->vm()->add_breakpoint(in_syscallbuf_syscall_hook, BKPT_INTERNAL);
        }
        did_set_internal_breakpoints = true;
      } else {
        did_set_bpf_breakpoint = true;
      }
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
        fast_forward_status |=
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
    if (!is_same_execution_point(t, regs, extra_regs, ticks_left, &mismatched_regs,
                                 &mismatched_regs_ptr, in_syscallbuf)) {
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
Completion ReplaySession::emulate_signal_delivery(ReplayTask* oldtask) {
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
  t->apply_data_record_from_trace();
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
  if (ev.siginfo.si_signo == SIGBUS) {
    return false;
  }
  if (ev.siginfo.si_signo == SIGSEGV && ev.siginfo.si_code == SEGV_PKUERR) {
    // We don't set up memory protection key state, so pkey-triggered signals
    // won't happen.
    return false;
  }
  return ev.deterministic == DETERMINISTIC_SIG;
}

/**
 * Advance to the delivery of the deterministic signal |sig| and
 * update registers to what was recorded.  Return COMPLETE if successful or
 * INCOMPLETE if an unhandled interrupt occurred.
 */
Completion ReplaySession::emulate_deterministic_signal(
    ReplayTask* t, int sig, const StepConstraints& constraints) {
  const Event& ev = trace_frame.event();

  while (true) {
    if (t->regs().matches(trace_frame.regs()) &&
        t->tick_count() == trace_frame.ticks() &&
        EV_INSTRUCTION_TRAP != ev.type()) {
      // We're already at the target. This can happen when multiple signals
      // are delivered with no intervening execution. It *can't* happen
      // when we're supposed to be emulating an instruction trap.
      // XXX I guess in theory we could have multiple signals arriving
      // at the same state but with intervening execution that we're supposed
      // to replay, but won't :-(.
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
      << " (expecting " << signal_name(sig) << ")"
      << "\n" << t->get_siginfo();
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
void ReplaySession::prepare_syscallbuf_records(ReplayTask* t, Ticks ticks) {
  // Read the recorded syscall buffer back into the buffer
  // region.
  TraceReader::RawData buf;
  bool ok = t->trace_reader().read_raw_data_for_frame(buf);
  size_t hdr_size = syscallbuf_hdr_size();
  ASSERT(t, ok);
  ASSERT(t, buf.data.size() >= hdr_size);
  ASSERT(t, buf.data.size() <= t->syscallbuf_size);
  ASSERT(t, buf.addr == t->syscallbuf_child.cast<void>());

  struct syscallbuf_hdr recorded_hdr;
  memcpy(&recorded_hdr, buf.data.data(), hdr_size);
  // Don't overwrite syscallbuf_hdr. That needs to keep tracking the current
  // syscallbuf state.
  t->write_bytes_helper(t->syscallbuf_child.cast<void>() + hdr_size,
                        buf.data.size() - hdr_size,
                        buf.data.data() + hdr_size);

  ASSERT(t, recorded_hdr.num_rec_bytes + hdr_size <= t->syscallbuf_size);

  current_step.flush.stop_breakpoint_offset = recorded_hdr.num_rec_bytes / 8;
  current_step.flush.recorded_ticks = ticks;

  LOG(debug) << "Prepared " << (uint32_t)recorded_hdr.num_rec_bytes
             << " bytes of syscall records";
}

#define PRELOAD_GLOBALS_FIELD_AFTER_SYSCALLBUF_FDS_DISABLED(t, f) \
    REMOTE_PTR_FIELD_MINUS_OFFSET(t->preload_globals, f,          \
      SYSCALLBUF_FDS_DISABLED_SIZE - t->session().syscallbuf_fds_disabled_size())

static string mprotect_record_string(const mprotect_record& record) {
  stringstream s;
  s << HEX(record.start) << "," << HEX(record.size) << ","
    << prot_flags_string(record.prot);
  return s.str();
}

/**
 * Returns mprotect_record_count
 */
static uint32_t apply_mprotect_records(ReplayTask* t,
                                       uint32_t skip_mprotect_records) {
  uint32_t final_mprotect_record_count =
      t->read_mem(REMOTE_PTR_FIELD(t->syscallbuf_child, mprotect_record_count));
  if (skip_mprotect_records < final_mprotect_record_count) {
    auto mprotect_records_ptr =
        PRELOAD_GLOBALS_FIELD_AFTER_SYSCALLBUF_FDS_DISABLED(t, mprotect_records[0]);
    auto records =
        t->read_mem(mprotect_records_ptr + skip_mprotect_records,
                    final_mprotect_record_count - skip_mprotect_records);
    auto recorded_records =
        t->current_trace_frame().event().SyscallbufFlush().mprotect_records;
    uint32_t completed_count = t->read_mem(REMOTE_PTR_FIELD(
        t->syscallbuf_child, mprotect_record_count_completed));
    size_t record_index = skip_mprotect_records;
    for (const auto& r : records) {
      if (record_index >= completed_count) {
        auto km = t->vm()->read_kernel_mapping(t, r.start);
        if (km.prot() != r.prot) {
          // mprotect didn't happen yet.
          continue;
        }
      } else {
        auto& recorded_r = recorded_records[record_index];
        ASSERT(t, r.start == recorded_r.start &&
               r.size == recorded_r.size &&
               r.prot == recorded_r.prot)
          << "Mismatched mprotect record " << record_index
          << ": recorded " << mprotect_record_string(recorded_r)
          << ", got " << mprotect_record_string(r);
      }
      t->vm()->protect(t, r.start, r.size, r.prot);
      if (running_under_rr()) {
        syscall(SYS_rrcall_mprotect_record, t->tid, (uintptr_t)r.start,
                (uintptr_t)r.size, r.prot);
      }
      ++record_index;
    }
  }
  return final_mprotect_record_count;
}

static void write_breakpoint_value(ReplayTask *t, uint64_t breakpoint_value, uint32_t flags = 0)
{
  if (t->session().has_trace_quirk(TraceReader::UsesGlobalsInReplay)) {
    t->write_mem(
      PRELOAD_GLOBALS_FIELD_AFTER_SYSCALLBUF_FDS_DISABLED(t, reserved_legacy_breakpoint_value),
      breakpoint_value, nullptr, flags);
  } else {
    t->write_mem(remote_ptr<uint64_t>(RR_PAGE_BREAKPOINT_VALUE),
      breakpoint_value, nullptr, flags);
  }
}

template <typename Arch>
static void maybe_handle_rseq_arch(ReplayTask* t) {
  auto remote_locals = AddressSpace::preload_thread_locals_start()
    .cast<preload_thread_locals<Arch>>();
  if (!remote_locals) {
    return;
  }
  auto rseq_ptr = REMOTE_PTR_FIELD(remote_locals, rseq);
  auto rseq = t->read_mem(rseq_ptr);
  if (rseq.len) {
    t->rseq_state = make_unique<RseqState>(rseq.rseq.rptr(), rseq.sig);
  }
}

static void maybe_handle_rseq(ReplayTask* t) {
  RR_ARCH_FUNCTION(maybe_handle_rseq_arch, t->arch(), t);
}

/**
 * Replay all the syscalls recorded in the interval between |t|'s
 * current execution point and the next non-syscallbuf event (the one
 * that flushed the buffer).  Return COMPLETE if successful or INCOMPLETE if an
 * unhandled interrupt occurred.
 */
Completion ReplaySession::flush_syscallbuf(ReplayTask* t,
                                           const StepConstraints& constraints) {
  bool legacy_breakpoint_mode = t->vm()->legacy_breakpoint_mode();
  bool user_breakpoint_at_addr = false;
  remote_code_ptr remote_brkpt_addr;
  while (true) {
    auto next_rec = t->next_syscallbuf_record();
    uint32_t skip_mprotect_records = t->read_mem(
        REMOTE_PTR_FIELD(t->syscallbuf_child, mprotect_record_count_completed));

    TicksRequest ticks_request;
    if (!compute_ticks_request(t, constraints, &ticks_request)) {
      return INCOMPLETE;
    }

    // We don't use this in new traces, but we retain this for replayability
    if (legacy_breakpoint_mode) {
      remote_brkpt_addr =
        t->vm()->stopping_breakpoint_table().to_data_ptr<void>().as_int() +
          current_step.flush.stop_breakpoint_offset *
            t->vm()->stopping_breakpoint_table_entry_size();
      bool added = t->vm()->add_breakpoint(remote_brkpt_addr, BKPT_INTERNAL);
      ASSERT(t, added);
    } else {
      LOG(debug) << "Adding breakpoint";
      write_breakpoint_value(t,
        (uint64_t)current_step.flush.stop_breakpoint_offset);
    }

    auto complete =
        continue_or_step(t, constraints, ticks_request, RESUME_CONT);

    if (legacy_breakpoint_mode) {
      user_breakpoint_at_addr =
          t->vm()->get_breakpoint_type_at_addr(remote_brkpt_addr) != BKPT_INTERNAL;
      t->vm()->remove_breakpoint(remote_brkpt_addr,
                                 BKPT_INTERNAL);
    } else {
      LOG(debug) << "Removing breakpoint " << t->status();
      write_breakpoint_value(t, (uint64_t)-1);
    }

    // Account for buffered syscalls just completed
    auto end_rec = t->next_syscallbuf_record();
    while (next_rec != end_rec) {
      accumulate_syscall_performed();
      next_rec = next_rec.as_int() + t->stored_record_size(next_rec);
    }

    // Apply the mprotect records we just completed.
    apply_mprotect_records(t, skip_mprotect_records);

    if (complete == INCOMPLETE && t->stop_sig() == SIGTRAP) {
      do_replay_assist(t);
    }

    if (t->stop_sig() == PerfCounters::TIME_SLICE_SIGNAL) {
      // This would normally be triggered by constraints.ticks_target but it's
      // also possible to get stray signals here.
      return INCOMPLETE;
    }

    if (complete == COMPLETE && !is_ignored_signal(t->stop_sig())) {
      break;
    }
  }

  if (legacy_breakpoint_mode) {
    ASSERT(t, t->stop_sig() == SIGTRAP)
        << "Replay got unexpected signal (or none) " << t->stop_sig();
    if (t->ip().undo_executed_bkpt(t->arch()) ==
            remote_code_ptr(remote_brkpt_addr) &&
        !user_breakpoint_at_addr) {
      Registers r = t->regs();
      r.set_ip(remote_brkpt_addr);
      t->set_regs(r);
    } else {
      return INCOMPLETE;
    }
  } else {
    if (t->stop_sig() == SIGTRAP) {
      return INCOMPLETE;
    }

    Registers r = t->regs();
    ASSERT(t, t->stop_sig() == SIGSEGV && r.ip() == t->vm()->do_breakpoint_fault_addr())
        << "Replay got unexpected signal (or none) " << t->stop_sig()
        << " ip " << r.ip() << " breakpoint_fault_addr " << t->vm()->do_breakpoint_fault_addr();
    r.set_ip(r.ip().increment_by_movrm_insn_length(t->arch()));
    t->set_regs(r);

    if (current_step.flush.recorded_ticks <= t->tick_count() && has_trace_quirk(TraceReader::BufferedSyscallForcedTick)) {
      // We've reached the breakpoint and executed at least as many ticks as were recorded for the FLUSH_SYSCALLBUF.
      // That means the flush was actually performed before we left the syscallbuf code, i.e. due to a SIGKILL
      // in syscallbuf code. We will have recorded another execution event that triggered a flush, but just ignore it,
      // since we probably already passed it and this task is about to die anyway.
      skip_next_execution_event = true;
    }
  }

  maybe_handle_rseq(t);
  t->apply_all_data_records_from_trace();
  return COMPLETE;
}

Completion ReplaySession::patch_ip(ReplayTask* t, const StepConstraints& constraints)
{
  TicksRequest ticks_request;
  if (!compute_ticks_request(t, constraints, &ticks_request)) {
    return INCOMPLETE;
  }

  remote_code_ptr vsyscall_entry = current_trace_frame().regs().ip();
  bool added = t->vm()->add_breakpoint(vsyscall_entry, BKPT_INTERNAL);
  ASSERT(t, added);
  auto complete = continue_or_step(t, constraints, ticks_request, RESUME_CONT);
  TrapReasons reasons;
  if (complete == COMPLETE && t->stop_sig() == SIGTRAP) {
    reasons = t->compute_trap_reasons();
  }
  t->vm()->remove_breakpoint(vsyscall_entry, BKPT_INTERNAL);

  if (complete == INCOMPLETE) {
    return complete;
  }

  if (t->stop_sig() == PerfCounters::TIME_SLICE_SIGNAL) {
    // This would normally be triggered by constraints.ticks_target but it's
    // also possible to get stray signals here.
    return INCOMPLETE;
  }

  ASSERT(t, t->stop_sig() == SIGTRAP)
      << "Replay got unexpected signal (or none) " << t->stop_sig();
  if (!reasons.breakpoint || t->ip().undo_executed_bkpt(t->arch()) != vsyscall_entry) {
    return INCOMPLETE;
  }

  apply_patch_data(t);
  Registers r = t->regs();
  r.set_ip(vsyscall_entry);
  t->set_regs(r);
  return COMPLETE;
}

void ReplaySession::apply_patch_data(ReplayTask* t) {
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
    remote.infallible_mmap_syscall_if_alive(km.start(), km.size(), km.prot(),
                                            km.flags() | MAP_FIXED, -1, 0);
    t->vm()->map(t, km.start(), km.size(), km.prot(), km.flags(), 0, string(),
                 KernelMapping::NO_DEVICE, KernelMapping::NO_INODE, nullptr,
                 &km);
    t->vm()->mapping_flags_of(km.start()) |=
        AddressSpace::Mapping::IS_PATCH_STUBS;
  }

  // Now replay all data records.
  t->apply_all_data_records_from_trace();
}

Completion ReplaySession::patch_next_syscall(
    ReplayTask* t, const StepConstraints& constraints, bool before_syscall) {
  if (before_syscall) {
    if (cont_syscall_boundary(t, constraints) == INCOMPLETE) {
      return INCOMPLETE;
    }

    t->canonicalize_regs(t->arch());
    t->exit_syscall_and_prepare_restart();
  }
  apply_patch_data(t);
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
    if (ticks_left <= t->hpc.skid_size()) {
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
      current_trace_frame().ticks() > constraints.ticks_target) {
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
    case TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT: {
      Completion completion = emulate_async_signal(t, constraints, current_step.target.ticks, current_step.target.in_syscallbuf_syscall_hook);
      if (completion == COMPLETE) {
        remote_code_ptr rseq_new_ip = t->ip();
        bool invalid_rseq_cs;
        if (t->should_apply_rseq_abort(current_trace_frame().event().type(), &rseq_new_ip, &invalid_rseq_cs)
            && t->ip() != rseq_new_ip) {
          Registers r = t->regs();
          r.set_ip(rseq_new_ip);
          t->set_regs(r);
        }
        t->apply_all_data_records_from_trace();
      }
      return completion;
    }
    case TSTEP_DELIVER_SIGNAL:
      return emulate_signal_delivery(t);
    case TSTEP_FLUSH_SYSCALLBUF:
      return flush_syscallbuf(t, constraints);
    case TSTEP_PATCH_IP:
      return patch_ip(t, constraints);
    case TSTEP_PATCH_SYSCALL:
      return patch_next_syscall(t, constraints, true);
    case TSTEP_PATCH_AFTER_SYSCALL:
      return patch_next_syscall(t, constraints, false);
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
 * task doesn't die until we reach the EXIT events in the trace.
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
  remote_code_ptr syscall_ip = t->vm()->privileged_traced_syscall_ip();
  if (!syscall_ip) {
    // Fall back to unprivileged. If someone uses a seccomp policy to
    // block `exit` *and* unmaps the rr page, they lose.
    syscall_ip = t->vm()->traced_syscall_ip();
  }
  r.set_ip(syscall_ip);
  r.set_syscallno(syscall_number_for_exit(t->arch()));
  t->set_regs(r);
  // Enter the syscall.
  bool ok = t->resume_execution(RESUME_CONT, RESUME_WAIT, RESUME_NO_TICKS);
  ASSERT(t, ok) << "Tracee died unexpectedly";
  if (t->session().done_initial_exec()) {
    ASSERT(t, t->ptrace_event() == PTRACE_EVENT_EXIT);
    t->did_handle_ptrace_exit_event();
  } else {
    // If we never execed, the trace is totally hosed,
    // just clean up.
    t->did_kill();
  }
  t->detach();
  delete t;
}

Completion ReplaySession::exit_task(ReplayTask* t) {
  ASSERT(t, !t->seen_ptrace_exit_event());
  // Apply robust-futex updates captured during recording.
  t->apply_all_data_records_from_trace();
  end_task(t);
  /* |t| is dead now. */
  return COMPLETE;
}

ReplayTask* ReplaySession::revive_task_for_exec() {
  const Event& ev = trace_frame.event();
  if (!ev.is_syscall_event() || !ev.Syscall().is_exec()) {
    FATAL() << "Can't find task, but we're not in an execve";
  }

  ThreadGroup* tg = nullptr;
  for (auto& p : thread_group_map_) {
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
  t->serial = next_task_serial();
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

  if (t->tuid() != last_task_tuid) {
    t->will_schedule();
    last_task_tuid = t->tuid();
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
      prepare_syscallbuf_records(t, trace_frame.ticks());
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
      if (ev.PatchSyscall().patch_after_syscall) {
        current_step.action = TSTEP_PATCH_AFTER_SYSCALL;
      } else if (ev.PatchSyscall().patch_trapping_instruction ||
                 ev.PatchSyscall().patch_vsyscall) {
        current_step.action = TSTEP_PATCH_IP;
      } else {
        current_step.action = TSTEP_PATCH_SYSCALL;
      }
      break;
    case EV_SCHED:
      if (skip_next_execution_event) {
        current_step.action = TSTEP_NONE;
        break;
      }
      current_step.action = TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT;
      current_step.target.ticks = trace_frame.ticks();
      current_step.target.signo = 0;
      current_step.target.in_syscallbuf_syscall_hook = ev.Sched().in_syscallbuf_syscall_hook.register_value();
      if (current_step.target.in_syscallbuf_syscall_hook) {
        t->note_sched_in_syscallbuf_syscall_hook();
      }
      break;
    case EV_INSTRUCTION_TRAP:
      current_step.action = TSTEP_DETERMINISTIC_SIGNAL;
      current_step.target.ticks = -1;
      current_step.target.signo = SIGSEGV;
      current_step.target.in_syscallbuf_syscall_hook = 0;
      break;
    case EV_GROW_MAP:
      process_grow_map(t);
      current_step.action = TSTEP_RETIRE;
      break;
    case EV_SIGNAL: {
      if (skip_next_execution_event) {
        current_step.action = TSTEP_NONE;
        break;
      }
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
      current_step.target.in_syscallbuf_syscall_hook = 0;
      break;
    }
    case EV_SIGNAL_DELIVERY:
    case EV_SIGNAL_HANDLER:
      current_step.action = TSTEP_DELIVER_SIGNAL;
      current_step.target.signo = ev.Signal().siginfo.si_signo;
      current_step.target.in_syscallbuf_syscall_hook = 0;
      break;
    case EV_SYSCALL:
      if (skip_next_execution_event) {
        current_step.action = TSTEP_NONE;
        break;
      }
      if (trace_frame.event().Syscall().state == ENTERING_SYSCALL ||
          trace_frame.event().Syscall().state == ENTERING_SYSCALL_PTRACE) {
        rep_prepare_run_to_syscall(t, &current_step);
      } else {
        rep_process_syscall(t, &current_step);
        if (current_step.action == TSTEP_RETIRE) {
          t->on_syscall_exit(current_step.syscall.number,
                             current_step.syscall.arch, trace_frame.regs());
          if (t->arch() == aarch64 && t->regs().syscall_may_restart()) {
            // If we're restarting a system call, we may have to apply register
            // modifications to match what the kernel does. Whether or not we need
            // to do this depends on the ordering of the kernel's register
            // modification and the signal stop that interrupted the system
            // call. On x86, the ptrace stop happens first, and then all
            // register modifications happen. On aarch64, some register
            // modifications happen [1], then the ptrace stop and then
            // potentially more register modifications. Any register
            // modifications that happen after the ptrace signal stop will
            // get recorded in the signal frame and thus don't need any
            // special handling. However, for register modifications that
            // happen before the signal stop, we need to apply them here.
            // On x86, there are none, but on aarch64, we need to restore arg1
            // and pc.
            // [1] https://github.com/torvalds/linux/blob/caffb99b6929f41a69edbb5aef3a359bf45f3315/arch/arm64/kernel/signal.c#L855-L862
            Registers r = t->regs();
            r.set_arg1(r.orig_arg1());
            r.set_ip(r.ip().decrement_by_syscall_insn_length(t->arch()));
            t->set_regs(r);
          }
        }
      }
      break;
    default:
      FATAL() << "Unexpected event " << ev;
  }

  skip_next_execution_event = false;
  return t;
}

bool ReplaySession::next_step_is_successful_exec_syscall_exit() {
  const Event& ev = trace_frame.event();
  return current_step.action == TSTEP_NONE &&
         ev.is_syscall_event() &&
         ev.Syscall().is_exec() &&
         ev.Syscall().state == EXITING_SYSCALL &&
         !trace_frame.regs().syscall_failed();
}

ReplayResult ReplaySession::replay_step(const StepConstraints& constraints) {
  finish_initializing();

  ReplayResult result(REPLAY_CONTINUE);
  if (detected_transient_error_) {
    result.status = REPLAY_TRANSIENT_ERROR;
    return result;
  }

  if (EV_TRACE_TERMINATION == trace_frame.event().type()) {
    result.status = REPLAY_EXITED;
    return result;
  }

  /* If we restored from a checkpoint, the steps might have been
   * computed already in which case step.action will not be TSTEP_NONE.
   */
  ReplayTask* t = current_task();
  if (current_step.action == TSTEP_NONE) {
    t = setup_replay_one_trace_frame(t);
    if (current_step.action == TSTEP_NONE) {
      // Already at the destination event.
      advance_to_next_trace_frame();
    }
    if (current_step.action == TSTEP_EXIT_TASK) {
      result.break_status.task_context = TaskContext(t);
      result.break_status.task_exit = true;
    }
    return result;
  }

  fast_forward_status = FastForwardStatus();

  // Now we know |t| hasn't died, so save it in break_status.
  result.break_status.task_context = TaskContext(t);

  /* Advance towards fulfilling |current_step|. */
  Completion complete = try_one_trace_step(t, constraints);
  if (detected_transient_error_) {
    result.status = REPLAY_TRANSIENT_ERROR;
    return result;
  }
  if (complete == INCOMPLETE) {
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
    result.did_fast_forward = fast_forward_status.did_fast_forward;
    result.incomplete_fast_forward = fast_forward_status.incomplete_fast_forward;
    return result;
  }

  result.did_fast_forward = fast_forward_status.did_fast_forward;
  result.incomplete_fast_forward = fast_forward_status.incomplete_fast_forward;

  // If try_one_trace_step set extra-registers already, the values it used from the frame
  // will already have FIP/FDP cleared if necessary. Clearing them again here is fine.
  if (trace_reader().clear_fip_fdp() &&
      current_step.action != TSTEP_EXIT_TASK)
      /* TSTEP_EXIT_TASK means the task object got already
         deleted above in try_one_trace_step/exit_task/end_task. */
  {
    const ExtraRegisters* maybe_extra = t->extra_regs_fallible();
    if (maybe_extra) {
      ExtraRegisters extra_registers = *maybe_extra;
      extra_registers.clear_fip_fdp();
      t->set_extra_regs(extra_registers);
    }
  }

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
      result.break_status.task_context = TaskContext();
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
    check_intel_pt_if_enabled(t);

    check_for_watchpoint_changes(t, result.break_status);
    check_approaching_ticks_target(t, constraints, result.break_status);
  }

  advance_to_next_trace_frame();
  // Record that this step completed successfully.
  current_step.action = TSTEP_NONE;

  ReplayTask* next_task = current_task();
  if (next_task && done_initial_exec()) {
    if (!next_task->vm()->first_run_event()) {
      next_task->vm()->set_first_run_event(trace_frame.time());
    }
    if (!next_task->thread_group()->first_run_event()) {
      next_task->thread_group()->set_first_run_event(trace_frame.time());
    }
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

void ReplaySession::prepare_to_detach_tasks() {
  finish_initializing();

  for (auto& entry : task_map) {
    Task* t = entry.second;
    t->flush_regs();
  }
}

void ReplaySession::forget_tasks() {
  while (!task_map.empty()) {
    Task* t = task_map.begin()->second;
    t->forget();
    delete t;
  }
  while (!vm_map.empty()) {
    AddressSpace* a = vm_map.begin()->second;
    delete a;
  }
}

void ReplaySession::detach_tasks(pid_t new_ptracer, ScopedFd& new_tracee_socket_receiver) {
  // First tell Yama to let new_ptracer ptrace the tracees.
  // Do this before sending SIGSTOP to any tracees because SIGSTOP
  // might stop threads before we do their PR_SET_PTRACER.
  // Also push the new control socket into all tracees.
  for (auto& entry : task_map) {
    Task* t = entry.second;
    AutoRemoteSyscalls remote(t);
    long ret = remote.syscall(syscall_number_for_prctl(t->arch()), PR_SET_PTRACER, new_ptracer);
    ASSERT(t, ret >= 0 || ret == -EINVAL) << "Failed PR_SET_PTRACER";
    remote.infallible_send_fd_dup(new_tracee_socket_receiver, tracee_socket_fd_number, 0);
  }
  // Now PTRACE_DETACH and stop them all with SIGSTOP.
  for (auto& entry : task_map) {
    Task* t = entry.second;
    t->flush_regs();
    errno = 0;
    t->fallible_ptrace(PTRACE_DETACH, nullptr, (void*)SIGSTOP);
    ASSERT(t, !errno) << "failed to detach, with errno " << errno;
  }
  forget_tasks();
}

void ReplaySession::reattach_tasks(ScopedFd new_tracee_socket, ScopedFd new_tracee_socket_receiver) {
  tracee_socket = make_shared<ScopedFd>(std::move(new_tracee_socket));
  tracee_socket_receiver = make_shared<ScopedFd>(std::move(new_tracee_socket_receiver));
  // Seize all tasks.
  for (auto& entry : task_map) {
    Task* t = entry.second;
    long ret = Task::ptrace_seize(t->tid, *this);
    ASSERT(t, ret >= 0) << "Failed to PTRACE_SEIZE";
  }
  // Get stop events for all tasks
  for (auto& entry : task_map) {
    Task* t = entry.second;
    if (!t->wait()) {
      FATAL() << "Task " << t->tid << " killed unexpectedly";
    }
    WaitStatus status = t->status();
    // Normally the SIGSTOP from detach_tasks() will have been delivered to the tracee
    // while it was detached, putting it into a group stop, so we'll see the group stop
    // status here. However it is possible for the SIGSTOP to be queued but not delivered
    // because the tracee hasn't been scheduled yet. In that case we might see the
    // SIGSTOP signal stop here instead.
    if (status.group_stop() != SIGSTOP && status.stop_sig() != SIGSTOP) {
      FATAL() << "Unexpected stop " << status << " for " << t->tid;
    }
    t->clear_wait_status();
    t->open_mem_fd();
  }
}

bool ReplaySession::mark_stdio() const {
  return Session::mark_stdio() &&
    current_frame_time() >= suppress_stdio_before_event_;
}

bool ReplaySession::echo_stdio() const {
  return flags().redirect_stdio && visible_execution_ &&
    current_frame_time() >= suppress_stdio_before_event_;
}

void ReplaySession::serialize_checkpoint(
    pcp::CloneCompletionInfo::Builder& writer, CheckpointInfo& cp_info) {
  DEBUG_ASSERT(clone_completion != nullptr);

  auto addr_space_count = clone_completion->address_spaces.size();
  auto& as_data = clone_completion->address_spaces;
  auto addr_space_builders = writer.initAddressSpaces(addr_space_count);

  for (auto i = 0u; i < addr_space_count; i++) {
    const auto& as = as_data[i];
    const auto leader = static_cast<ReplayTask*>(as.clone_leader);

    auto addr_space_clone = addr_space_builders[i];
    addr_space_clone.setAuxv(kj::ArrayPtr<const capnp::byte>{
        leader->vm()->saved_auxv().data(), leader->vm()->saved_auxv().size() });
    auto cls = addr_space_clone.initCloneLeaderState();
    write_capture_state(cls, as.clone_leader_state);
    auto pspace = addr_space_builders[i].initProcessSpace();
    pspace.setTaskFirstRunEvent(leader->tg->first_run_event());
    pspace.setVmFirstRunEvent(leader->vm()->first_run_event());
    pspace.setExe(str_to_data(leader->vm()->exe_image()));
    const auto orig_exe = leader->original_exe();
    pspace.setOriginalExe(str_to_data(orig_exe));

    write_vm(as.clone_leader, pspace, cp_info.data_directory());
    auto captured_mem_list =
        addr_space_clone.initCapturedMemory(as.captured_memory.size());
    auto captured_idx = 0;
    for (const auto& mem : as.captured_memory) {
      auto cm = captured_mem_list[captured_idx++];
      cm.setStartAddress(mem.first.as_int());
      cm.setData(kj::ArrayPtr<const capnp::byte>(mem.second.data(),
                                                 mem.second.size()));
    }

    auto member_states =
        addr_space_clone.initMemberState(as.member_states.size());
    auto cs_idx = 0;
    for (const auto& state : as.member_states) {
      auto ms = member_states[cs_idx++];
      write_capture_state(ms, state);
    }
    clone_completion->cloned_fd_tables[as.clone_leader_state.fdtable_identity]
        ->serialize(pspace);
    writer.setUsesSyscallBuffering(leader->vm()->syscallbuf_enabled());
  }

  auto step = capnp::Data::Reader{ (std::uint8_t*)&current_step,
                                   sizeof(ReplayTraceStep) };
  writer.setSessionCurrentStep(step);

  auto siginfo =
      capnp::Data::Reader{ (std::uint8_t*)&last_siginfo_, sizeof(siginfo_t) };
  writer.setLastSigInfo(siginfo);
}

void ReplaySession::load_checkpoint(const CheckpointInfo& cp_info) {
  DEBUG_ASSERT(!partially_initialized());
  ScopedFd checkpoint_fd = cp_info.open_for_read();
  capnp::PackedFdMessageReader datum(checkpoint_fd);

  auto checkpointInfo = datum.getRoot<pcp::CheckpointInfo>();
  pcp::CloneCompletionInfo::Reader cc_reader =
      checkpointInfo.getCloneCompletion();

  const auto addr_spaces = cc_reader.getAddressSpaces();

  std::vector<CloneCompletion::AddressSpaceClone> partial_init_addr_spaces{};
  Task::ClonedFdTables cloned_fd_tables{};

  std::vector<ReplayTask*> cloned_leaders{};
  auto zygote = current_task();
  for (const auto& as : addr_spaces) {
    const auto taskInfo = as.getCloneLeaderState();
    AutoRemoteSyscalls remote(zygote,
                              AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS);
    Task* child = Task::os_clone(Task::SESSION_CLONE_LEADER, this, remote,
                                 taskInfo.getRecTid(), taskInfo.getSerial(),
                                 SIGCHLD, nullptr);
    cloned_leaders.push_back(static_cast<ReplayTask*>(child));
  }

  auto clone_leader_index = 0;
  LOG(debug) << "Restoring " << addr_spaces.size() << " clone leaders";
  for (const auto& as : addr_spaces) {
    ReplayTask* leader = cloned_leaders[clone_leader_index++];
    const auto proc_space = as.getProcessSpace();
    const auto cleader_captured_state = as.getCloneLeaderState();

    leader->is_stopped_ = true;
    leader->os_exec_stub(arch());
    std::string exe_name = data_to_str(proc_space.getExe());
    std::string original_exe_name = data_to_str(proc_space.getOriginalExe());
    leader->post_exec(original_exe_name);
    static_cast<Task*>(leader)->post_exec_syscall(original_exe_name);

    // set up the/a stack mapping in which we can make remote syscalls in
    // afterwards
    auto mappings_data = proc_space.getVirtualAddressSpace();
    auto mappings_it = mappings_data.begin();

    // Map an executable mapping first, so we can use that memory for remote sys
    // calls
    {
      AutoRemoteSyscalls remote(leader,
                                AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS);
      leader->vm()->unmap_all_but_rr_mappings(remote);
      DEBUG_ASSERT(mappings_it->getMapType().isPrivateAnon() &&
                   (mappings_it->getProtection() & (PROT_READ | PROT_WRITE)) ==
                       (PROT_READ | PROT_WRITE));
      KernelMapping stack_mapping{ mappings_it->getStart(),
                                   mappings_it->getEnd(),
                                   data_to_str(mappings_it->getFsname()),
                                   mappings_it->getDevice(),
                                   mappings_it->getInode(),
                                   mappings_it->getProtection(),
                                   mappings_it->getFlags(),
                                   static_cast<off64_t>(
                                       mappings_it->getOffset()) };
      map_private_anonymous(remote, stack_mapping);
      restore_map_contents(
          leader,
          data_to_str(
              mappings_it->getMapType().getPrivateAnon().getContentsPath()),
          stack_mapping);
      mappings_it++;
    }

    auto scratchPointer =
        remote_ptr<void>(cleader_captured_state.getScratchPtr());
    ASSERT(leader, scratchPointer != nullptr) << "No scratch pointer found!";
    if (proc_space.getBreakpointFaultAddress() != 0) {
      leader->vm()->set_breakpoint_fault_addr(
          proc_space.getBreakpointFaultAddress());
    }

    leader->thread_group()->set_first_run_event(
        proc_space.getTaskFirstRunEvent());
    leader->vm()->set_first_run_event(proc_space.getVmFirstRunEvent());

    std::vector<std::pair<KernelMapping, std::string>> syscallbuf_mappings;
    std::unique_ptr<std::pair<KernelMapping, std::string>> scratch_mem =
        nullptr;
    {
      AutoRemoteSyscalls remote(leader);
      for (; mappings_it != std::end(mappings_data); mappings_it++) {
        const auto& km_data = *mappings_it;
        auto map = km_data.getMapType();
        KernelMapping km(
            remote_ptr<void>(km_data.getStart()), km_data.getEnd(),
            km_data.hasFsname() ? data_to_str(km_data.getFsname()) : "",
            km_data.getDevice(), km_data.getInode(), km_data.getProtection(),
            km_data.getFlags(), km_data.getOffset());
        if (km.contains(scratchPointer)) {
          scratch_mem = std::make_unique<std::pair<KernelMapping, std::string>>(
              std::make_pair(
                  km, data_to_str(map.getPrivateAnon().getContentsPath())));
        } else if (map.isGuardSegment()) {
          // Guard segments: empty private anon mappings, where no data has been
          // written.
          map_private_anonymous(remote, km);
        } else if (map.isFile()) {
          auto p = data_to_str(map.getFile().getContentsPath());
          map_region_file(remote, km, p);
        } else if (map.isSharedAnon()) {
          auto sa = map.getSharedAnon();
          auto emufile = leader->session().emufs().get_or_create(km);
          struct stat real_file;
          std::string real_file_name;
          remote.finish_direct_mmap(
              km.start(), km.size(), km.prot(),
              (km.flags() | MAP_FIXED) & ~MAP_ANONYMOUS, emufile->proc_path(),
              O_RDWR, km.file_offset_bytes(), real_file, real_file_name);
          leader->vm()->map(leader, km.start(), km.size(), km.prot(),
                            km.flags(), km.file_offset_bytes(), real_file_name,
                            real_file.st_dev, real_file.st_ino, nullptr, &km,
                            emufile);
          restore_map_contents(leader, data_to_str(sa.getContentsPath()), km);
          if (sa.getIsSysVSegment()) {
            leader->vm()->set_shm_size(km.start(), km.size());
          }
        } else if (map.isPrivateAnon()) {
          auto f = map.getPrivateAnon();
          auto path = data_to_str(f.getContentsPath());
          map_private_anonymous(remote, km);
          restore_map_contents(leader, path, km);
        } else if (map.isRrPage()) {
          const auto path = data_to_str(map.getRrPage().getContentsPath());
          restore_map_contents(leader, path, km);
        } else if (map.isSyscallBuffer()) {
          const auto path =
              data_to_str(map.getSyscallBuffer().getContentsPath());
          syscallbuf_mappings.push_back(std::make_pair(km, path));
        } else {
          FATAL() << "Unknown serialized map type";
        }
      }

      auto index = original_exe_name.rfind('/');
      auto name = "rr:" + original_exe_name.substr(
                              index == std::string::npos ? 0 : index + 1);
      leader->set_name(remote, name);
    }

    ASSERT(leader, scratch_mem != nullptr)
        << "Scratch memory mapping could not be restored.";
    {
      auto& km = scratch_mem->first;
      auto& path = scratch_mem->second;
      init_scratch_memory(leader, km);
      restore_map_contents(leader, path, km);
    }

    std::vector<uint8_t> auxv{};
    auto auxv_data = as.getAuxv().asChars();
    std::copy(auxv_data.begin(), auxv_data.end(), std::back_inserter(auxv));

    leader->vm()->restore_auxv(leader, std::move(auxv));
    syscall(SYS_rrcall_reload_auxv, leader->tid);
    std::vector<Task::CapturedState> member_states;

    for (const auto& member_state : as.getMemberState()) {
      member_states.push_back(reconstitute_captured_state(*this, member_state));
    }

    CapturedMemory captured_memory;
    for (const auto& captured_mem : as.getCapturedMemory()) {
      std::vector<uint8_t> mem;
      auto mem_reader = captured_mem.getData();
      std::copy(mem_reader.begin(), mem_reader.end(), std::back_inserter(mem));
      captured_memory.push_back(
          std::make_pair(captured_mem.getStartAddress(), std::move(mem)));
    }

    Task::CapturedState cloneLeaderCaptureState =
        reconstitute_captured_state(*this, as.getCloneLeaderState());
    auto fd_table_key = cloneLeaderCaptureState.fdtable_identity;
    leader->preload_globals = cloneLeaderCaptureState.preload_globals;
    partial_init_addr_spaces.push_back(CloneCompletion::AddressSpaceClone{
        .clone_leader = leader,
        .clone_leader_state = std::move(cloneLeaderCaptureState),
        .member_states = std::move(member_states),
        .captured_memory = std::move(captured_memory) });
    on_create(leader);
    deserialize_fdtable(leader, proc_space);

    if (cc_reader.getUsesSyscallBuffering()) {
      leader->vm()->set_uses_syscall_buffer();
      for (const auto& sysbuf : syscallbuf_mappings) {
        const auto& km = sysbuf.first;
        const auto& path = sysbuf.second;
        AutoRemoteSyscalls remote(leader);
        if (km.contains(cleader_captured_state.getSyscallbufChild())) {
          const auto map_hint = km.start();
          leader->syscallbuf_size = cleader_captured_state.getSyscallbufSize();
          leader->init_syscall_buffer(remote, map_hint);
          leader->desched_fd_child = cleader_captured_state.getDeschedFdChild();
          if (!leader->fd_table()->get_monitor(leader->desched_fd_child)) {
            leader->fd_table()->add_monitor(leader, leader->desched_fd_child,
                                            new PreserveFileMonitor());
          }
          if (cleader_captured_state.getClonedFileDataFdChild() >= 0) {
            leader->cloned_file_data_fd_child =
                cleader_captured_state.getClonedFileDataFdChild();
            leader->cloned_file_data_fname =
                trace_reader().file_data_clone_file_name(leader->tuid());
            ScopedFd clone_file(leader->cloned_file_data_fname.c_str(),
                                O_RDONLY);
            ASSERT(leader, clone_file.is_open());
            remote.infallible_send_fd_dup(
                clone_file, leader->cloned_file_data_fd_child, O_CLOEXEC);
            leader->fd_table()->replace_monitor(
                leader, leader->cloned_file_data_fd_child,
                new PreserveFileMonitor());
          }
          for (const auto& mem :
               partial_init_addr_spaces.back().captured_memory) {
            if (km.contains(mem.first)) {
              leader->write_bytes_helper(mem.first, mem.second.size(),
                                         mem.second.data());
            }
          }
          restore_map_contents(leader, path, km);
        } else {
          // recreate shared map, i.e. some _other_ task's (A) syscall buffer
          // for this task (B), the mappings that just "float" due to being
          // inherited after a fork, but from what I understood, isn't ever
          // actually used. It's just "there". To keep the process' address
          // space identical with normal execution, it is therefore mapped here.
          char name[4096];
          strncpy(name, km.fsname().c_str(), sizeof(name) - 1);
          name[sizeof(name) - 1] = 0;
          create_shared_mmap(remote, km.size(), km.start(),
                             extract_name(name, sizeof(name)), km.prot(), 0,
                             nullptr);
          remote.task()->vm()->mapping_flags_of(km.start()) |=
              AddressSpace::Mapping::IS_SYSCALLBUF;
          restore_map_contents(leader, path, km);
        }
      }
      ASSERT(leader, leader->vm()->syscallbuf_enabled())
          << "syscall buffering should be enabled at this point";
      // Fool Task::copy_state that syscall buf has not been initialized. For
      // pcp we need to since we never hit the events where syscall buffers get
      // initialized like a normal executed tracee-replay would.
      leader->syscallbuf_child = nullptr;
    }
    leader->ticks = cleader_captured_state.getTicks();

    cloned_fd_tables[fd_table_key] = leader->fd_table();
  } // end of 1 clone leader setup iteration

  clone_completion = std::make_unique<CloneCompletion>();
  clone_completion->address_spaces = std::move(partial_init_addr_spaces);
  clone_completion->cloned_fd_tables = std::move(cloned_fd_tables);

  memcpy(&current_step, cc_reader.getSessionCurrentStep().begin(),
         sizeof(ReplayTraceStep));

  trace_reader().rewind();
  trace_reader().forward_to(cp_info.clone_data.time);

  trace_frame = trace_reader().read_frame();
  memcpy(&last_siginfo_, cc_reader.getLastSigInfo().begin(), sizeof(siginfo_t));
  restore_session_info(cp_info);
}

std::vector<CheckpointInfo> ReplaySession::get_persistent_checkpoints() {
  return rr::get_checkpoint_infos(resolve_trace_name(trace_reader().dir()),
                                  arch(), trace_reader().cpuid_records());
}

void ReplaySession::restore_session_info(const CheckpointInfo& cp) {
  ticks_at_start_of_event = cp.clone_data.ticks_at_event_start;
  next_task_serial_ = cp.next_serial;
  statistics_ = cp.stats;
}

} // namespace rr
