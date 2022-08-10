/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RecordTask.h"

#include <dirent.h>
#include <elf.h>
#include <limits.h>
#include <linux/perf_event.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "AutoRemoteSyscalls.h"
#include "PreserveFileMonitor.h"
#include "RecordSession.h"
#include "core.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"
#include "record_signal.h"
#include "rr/rr.h"
#include "util.h"

using namespace std;

namespace rr {

/**
 * Stores the table of signal dispositions and metadata for an
 * arbitrary set of tasks.  Each of those tasks must own one one of
 * the |refcount|s while they still refer to this.
 */
struct Sighandler {
  Sighandler() : resethand(false), takes_siginfo(false) {}

  template <typename Arch>
  void init_arch(const typename Arch::kernel_sigaction& ksa) {
    k_sa_handler = ksa.k_sa_handler;
    sa.resize(sizeof(ksa));
    memcpy(sa.data(), &ksa, sizeof(ksa));
    resethand = (ksa.sa_flags & SA_RESETHAND) != 0;
    takes_siginfo = (ksa.sa_flags & SA_SIGINFO) != 0;
  }

  template <typename Arch> void reset_arch() {
    typename Arch::kernel_sigaction ksa;
    memset(&ksa, 0, sizeof(ksa));
    DEBUG_ASSERT(uintptr_t(SIG_DFL) == 0);
    init_arch<Arch>(ksa);
  }

  SignalDisposition disposition() const {
    DEBUG_ASSERT(uintptr_t(SIG_DFL) == 0);
    DEBUG_ASSERT(uintptr_t(SIG_IGN) == 1);
    switch (k_sa_handler.as_int()) {
      case 0:
        return SIGNAL_DEFAULT;
      case 1:
        return SIGNAL_IGNORE;
      default:
        return SIGNAL_HANDLER;
    }
  }

  remote_code_ptr get_user_handler() const {
    return disposition() == SIGNAL_HANDLER
               ? remote_code_ptr(k_sa_handler.as_int())
               : remote_code_ptr();
  }

  remote_ptr<void> k_sa_handler;
  // Saved kernel_sigaction; used to restore handler
  vector<uint8_t> sa;
  bool resethand;
  bool takes_siginfo;
};

static void reset_handler(Sighandler* handler, SupportedArch arch) {
  RR_ARCH_FUNCTION(handler->reset_arch, arch);
}

struct Sighandlers {
  typedef shared_ptr<Sighandlers> shr_ptr;

  shr_ptr clone() const {
    shr_ptr s(new Sighandlers());
    // NB: depends on the fact that Sighandler is for all
    // intents and purposes a POD type, though not
    // technically.
    for (size_t i = 0; i < array_length(handlers); ++i) {
      s->handlers[i] = handlers[i];
    }
    return s;
  }

  Sighandler& get(int sig) {
    assert_valid(sig);
    return handlers[sig];
  }
  const Sighandler& get(int sig) const {
    assert_valid(sig);
    return handlers[sig];
  }

  void init_from_current_process() {
    for (size_t i = 1; i < array_length(handlers); ++i) {
      Sighandler& h = handlers[i];

      NativeArch::kernel_sigaction sa;
      if (::syscall(SYS_rt_sigaction, i, nullptr, &sa, sizeof(uint64_t))) {
        /* EINVAL means we're querying an
         * unused signal number. */
        DEBUG_ASSERT(EINVAL == errno);
        continue;
      }
      msan_unpoison(&sa, sizeof(NativeArch::kernel_sigaction));

      h.init_arch<NativeArch>(sa);
    }
  }

  /**
   * For each signal in |table| such that is_user_handler() is
   * true, reset the disposition of that signal to SIG_DFL, and
   * clear the resethand flag if it's set.  SIG_IGN signals are
   * not modified.
   *
   * (After an exec() call copies the original sighandler table,
   * this is the operation required by POSIX to initialize that
   * table copy.)
   */
  void reset_user_handlers(SupportedArch arch) {
    for (int i = 0; i < ssize_t(array_length(handlers)); ++i) {
      Sighandler& h = handlers[i];
      // If the handler was a user handler, reset to
      // default.  If it was SIG_IGN or SIG_DFL,
      // leave it alone.
      if (h.disposition() == SIGNAL_HANDLER) {
        reset_handler(&h, arch);
      }
    }
  }

  void assert_valid(int sig) const {
    DEBUG_ASSERT(0 < sig && sig < ssize_t(array_length(handlers)));
  }

  static shr_ptr create() { return shr_ptr(new Sighandlers()); }

  Sighandler handlers[_NSIG];

private:
  Sighandlers() {}
  Sighandlers(const Sighandlers&);
  Sighandlers operator=(const Sighandlers&);
};

RecordTask::RecordTask(RecordSession& session, pid_t _tid, uint32_t serial,
                       SupportedArch a)
    : Task(session, _tid, _tid, serial, a),
      ticks_at_last_recorded_syscall_exit(0),
      ip_at_last_recorded_syscall_exit(nullptr),
      time_at_start_of_last_timeslice(0),
      priority(0),
      in_round_robin_queue(false),
      stable_exit(false),
      detached_proxy(false),
      emulated_ptracer(nullptr),
      emulated_ptrace_event_msg(0),
      emulated_ptrace_options(0),
      emulated_ptrace_cont_command(0),
      emulated_stop_pending(false),
      emulated_ptrace_SIGCHLD_pending(false),
      emulated_SIGCHLD_pending(false),
      emulated_ptrace_seized(false),
      in_wait_type(WAIT_TYPE_NONE),
      in_wait_pid(0),
      emulated_stop_type(NOT_STOPPED),
      blocked_sigs_dirty(true),
      syscallbuf_blocked_sigs_generation(0),
      flushed_num_rec_bytes(0),
      flushed_syscallbuf(false),
      delay_syscallbuf_reset_for_desched(false),
      delay_syscallbuf_reset_for_seccomp_trap(false),
      prctl_seccomp_status(0),
      robust_futex_list_len(0),
      termination_signal(0),
      tsc_mode(PR_TSC_ENABLE),
      cpuid_mode(1),
      stashed_signals_blocking_more_signals(false),
      stashed_group_stop(false),
      break_at_syscallbuf_traced_syscalls(false),
      break_at_syscallbuf_untraced_syscalls(false),
      break_at_syscallbuf_final_instruction(false),
      syscallstub_exit_breakpoint(),
      next_pmc_interrupt_is_for_user(false),
      did_record_robust_futex_changes(false),
      waiting_for_reap(false),
      waiting_for_zombie(false),
      waiting_for_ptrace_exit(false),
      retry_syscall_patching(false),
      sent_shutdown_kill(false),
      did_execveat(false),
      tick_request_override((TicksRequest)0),
      schedule_frozen(false) {
  push_event(Event::sentinel());
  if (session.tasks().empty()) {
    // Initial tracee. It inherited its state from this process, so set it up.
    // The very first task we fork inherits the signal
    // dispositions of the current OS process (which should all be
    // default at this point, but ...).  From there on, new tasks
    // will transitively inherit from this first task.
    auto sh = Sighandlers::create();
    sh->init_from_current_process();
    sighandlers.swap(sh);
    own_namespace_rec_tid = _tid;
  }
}

RecordTask::~RecordTask() {
  if (emulated_ptracer) {
    emulated_ptracer->emulated_ptrace_tracees.erase(this);
    if (emulated_ptrace_options & PTRACE_O_TRACEEXIT) {
      ASSERT(this, stable_exit)
          << "PTRACE_O_TRACEEXIT only supported for stable exits for now";
    }
  }
  for (RecordTask* t : emulated_ptrace_tracees) {
    // XXX emulate PTRACE_O_EXITKILL
    ASSERT(this, t->emulated_ptracer == this);
    t->emulated_ptracer = nullptr;
    t->emulated_ptrace_options = 0;
    t->emulated_stop_pending = false;
    t->emulated_stop_type = NOT_STOPPED;
  }

  // We expect tasks to usually exit by a call to exit() or
  // exit_group(), so it's not helpful to warn about that.
  if (EV_SENTINEL != ev().type() &&
      (pending_events.size() > 2 ||
       !(ev().type() == EV_SYSCALL &&
         (is_exit_syscall(ev().Syscall().number, ev().Syscall().regs.arch()) ||
          is_exit_group_syscall(ev().Syscall().number,
                                ev().Syscall().regs.arch()))))) {
    LOG(info) << tid << " still has pending events.  From top down:";
    log_pending_events();
  }

  if (detached_proxy) {
    // We kept the zombie of the orginal task around to prevent its pid from
    // being re-used. Reap that now.
    proceed_to_exit();
    if (!already_reaped() && may_reap()) {
      reap();
    }
    did_kill();
  }
}

void RecordTask::record_exit_event(WriteChildTid write_child_tid) {
  // The kernel explicitly only clears the futex if the address space is shared.
  // If the address space has no other users then the futex will not be cleared
  // even if it lives in shared memory which other tasks can read.
  if (!tid_futex.is_null() && as->task_set().size() > 1 &&
     as->has_mapping(tid_futex)) {
    int val = 0;
    record_local(tid_futex, &val);
    if (write_child_tid == WRITE_CHILD_TID) {
      // Write the memory now, otherwise the kernel will write it later and that can
      // race with the execution of other threads if we don't wait for this
      // thread to fully exit.
      // This could fail since the address space might have gone away/been switched
      // by execve.
      bool ok = true;
      write_mem(tid_futex, 0, &ok);
      // The kernel will do an unconditional futex wake on that location so we don't
      // need to do it.
    }
  }

  // Write the exit event here so that the value recorded above is captured.
  // Don't flush syscallbuf. Whatever triggered the exit (syscall, signal)
  // should already have flushed it, if it was running. If it was blocked,
  // then the syscallbuf would already have been flushed too. Trying to flush
  // syscallbuf for an exiting task could be bad,
  // e.g. it could be in the middle of syscallbuf code that's supposed to be
  // atomic. For the same reasons don't allow syscallbuf to be reset here.
  record_event(Event::exit(), DONT_FLUSH_SYSCALLBUF, DONT_RESET_SYSCALLBUF);
}

RecordSession& RecordTask::session() const {
  return *Task::session().as_record();
}

TraceWriter& RecordTask::trace_writer() const {
  return session().trace_writer();
}

Task* RecordTask::clone(CloneReason reason, int flags, remote_ptr<void> stack,
                        remote_ptr<void> tls, remote_ptr<int> cleartid_addr,
                        pid_t new_tid, pid_t new_rec_tid, uint32_t new_serial,
                        Session* other_session, FdTable::shr_ptr new_fds,
                        ThreadGroup::shr_ptr new_tg) {
  ASSERT(this, reason == Task::TRACEE_CLONE);
  ASSERT(this, !new_fds);
  ASSERT(this, !new_tg);
  Task* t = Task::clone(reason, flags, stack, tls, cleartid_addr, new_tid,
                        new_rec_tid, new_serial, other_session, new_fds,
                        new_tg);
  if (t->session().is_recording()) {
    RecordTask* rt = static_cast<RecordTask*>(t);
    if (CLONE_CLEARTID & flags) {
      LOG(debug) << "cleartid futex is " << cleartid_addr;
      ASSERT(this, !cleartid_addr.is_null());
      rt->tid_futex = cleartid_addr;
    } else {
      LOG(debug) << "(clone child not enabling CLEARTID)";
    }
  }
  return t;
}

void RecordTask::post_wait_clone(Task* cloned_from, int flags) {
  ASSERT(cloned_from, cloned_from->session().is_recording());
  Task::post_wait_clone(cloned_from, flags);

  RecordTask* rt = static_cast<RecordTask*>(cloned_from);
  priority = rt->priority;
  syscallbuf_code_layout = rt->syscallbuf_code_layout;
  prctl_seccomp_status = rt->prctl_seccomp_status;
  robust_futex_list = rt->robust_futex_list;
  robust_futex_list_len = rt->robust_futex_list_len;
  tsc_mode = rt->tsc_mode;
  cpuid_mode = rt->cpuid_mode;
  if (CLONE_SHARE_SIGHANDLERS & flags) {
    sighandlers = rt->sighandlers;
  } else {
    auto sh = rt->sighandlers->clone();
    sighandlers.swap(sh);
  }

  update_own_namespace_tid();
}

void RecordTask::post_exec() {
  // Change syscall number to execve/execveat *for the new arch*. If we don't do this,
  // and the arch changes, then the syscall number for execve in the old arch/
  // is treated as the syscall we're executing in the new arch, with hilarious
  // results.
  int new_syscallno = did_execveat ? syscall_number_for_execveat(arch())
      : syscall_number_for_execve(arch());
  registers.set_original_syscallno(new_syscallno);
  // Fix event architecture and syscall number
  ev().Syscall().number = new_syscallno;
  ev().Syscall().set_arch(arch());

  // The signal mask is inherited across execve so we don't need to invalidate.
  Task::post_exec(exe_path(), exe_path());
  if (emulated_ptracer) {
    ASSERT(this, !(emulated_ptracer->arch() == x86 && arch() == x86_64))
        << "We don't support a 32-bit process tracing a 64-bit process";
  }

  // Clear robust_list state to match kernel state. If this task is cloned
  // soon after exec, we must not do a bogus set_robust_list syscall for
  // the clone.
  set_robust_list(nullptr, 0);
  sighandlers = sighandlers->clone();
  sighandlers->reset_user_handlers(arch());

  // Newly execed tasks always have non-faulting mode (from their point of
  // view, even if rr is secretly causing faults).
  cpuid_mode = 1;
}

template <typename Arch> static void do_preload_init_arch(RecordTask* t) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<Arch>>(t->regs().orig_arg1()));

  t->syscallbuf_code_layout.syscallbuf_syscall_hook =
      params.syscallbuf_syscall_hook.rptr().as_int();
  t->syscallbuf_code_layout.syscallbuf_final_exit_instruction =
      params.syscallbuf_final_exit_instruction.rptr().as_int();
  t->syscallbuf_code_layout.syscallbuf_code_start =
      params.syscallbuf_code_start.rptr().as_int();
  t->syscallbuf_code_layout.syscallbuf_code_end =
      params.syscallbuf_code_end.rptr().as_int();
  t->syscallbuf_code_layout.get_pc_thunks_start =
      params.get_pc_thunks_start.rptr().as_int();
  t->syscallbuf_code_layout.get_pc_thunks_end =
      params.get_pc_thunks_end.rptr().as_int();

  unsigned char in_chaos = t->session().enable_chaos();
  auto in_chaos_ptr REMOTE_PTR_FIELD(params.globals.rptr(), in_chaos);
  t->write_mem(in_chaos_ptr, in_chaos);
  t->record_local(in_chaos_ptr, &in_chaos);

  auto desched_sig = t->session().syscallbuf_desched_sig();
  auto desched_sig_ptr = REMOTE_PTR_FIELD(params.globals.rptr(), desched_sig);
  t->write_mem(desched_sig_ptr, desched_sig);
  t->record_local(desched_sig_ptr, &desched_sig);

  uint64_t random_seed;
  do {
    random_seed = rand() | (uint64_t(rand()) << 32);
  } while (!random_seed);
  auto random_seed_ptr REMOTE_PTR_FIELD(params.globals.rptr(), random_seed);
  t->write_mem(random_seed_ptr, random_seed);
  t->record_local(random_seed_ptr, &random_seed);
}

void RecordTask::push_syscall_event(int syscallno) {
  push_event(SyscallEvent(syscallno, detect_syscall_arch()));
}

static void do_preload_init(RecordTask* t) {
  RR_ARCH_FUNCTION(do_preload_init_arch, t->arch(), t);
}

void RecordTask::at_preload_init() {
  Task::at_preload_init();
  do_preload_init(this);
}

/**
 * Avoid using low-numbered file descriptors since that can confuse
 * developers.
 */
static int find_free_file_descriptor(pid_t for_tid) {
  int fd = 300 + (for_tid % 500);
  while (true) {
    char buf[PATH_MAX];
    sprintf(buf, "/proc/%d/fd/%d", for_tid, fd);
    if (access(buf, F_OK) == -1 && errno == ENOENT) {
      return fd;
    }
    ++fd;
  }
}

template <typename Arch> void RecordTask::init_buffers_arch() {
  // NB: the tracee can't be interrupted with a signal while
  // we're processing the rrcall, because it's masked off all
  // signals.
  AutoRemoteSyscalls remote(this);

  // Arguments to the rrcall.
  remote_ptr<rrcall_init_buffers_params<Arch>> child_args = regs().orig_arg1();
  auto args = read_mem(child_args);

  args.cloned_file_data_fd = -1;
  if (as->syscallbuf_enabled()) {
    args.syscallbuf_size = syscallbuf_size = session().syscall_buffer_size();
    KernelMapping syscallbuf_km = init_syscall_buffer(remote, nullptr);
    args.syscallbuf_ptr = syscallbuf_child;
    if (syscallbuf_child != nullptr) {
      // This needs to be skipped if we couldn't allocate the buffer
      // since replaying only reads (and advances) the mmap record
      // if `args.syscallbuf_ptr != nullptr`.
      auto record_in_trace = trace_writer().write_mapped_region(
        this, syscallbuf_km, syscallbuf_km.fake_stat(), syscallbuf_km.fsname(),
        vector<TraceRemoteFd>(),
        TraceWriter::RR_BUFFER_MAPPING);
      ASSERT(this, record_in_trace == TraceWriter::DONT_RECORD_IN_TRACE);
    } else {
      // This can fail, e.g. if the tracee died unexpectedly.
      LOG(debug) << "Syscallbuf initialization failed";
      args.syscallbuf_size = 0;
    }
  } else {
    args.syscallbuf_ptr = remote_ptr<void>(nullptr);
    args.syscallbuf_size = 0;
  }

  if (args.syscallbuf_ptr) {
    desched_fd_child = args.desched_counter_fd;
    // Prevent the child from closing this fd
    fds->add_monitor(this, desched_fd_child, new PreserveFileMonitor());
    desched_fd = remote.retrieve_fd(desched_fd_child);

    if (trace_writer().supports_file_data_cloning() &&
        session().use_read_cloning()) {
      cloned_file_data_fname = trace_writer().file_data_clone_file_name(tuid());
      ScopedFd clone_file(cloned_file_data_fname.c_str(), O_RDWR | O_CREAT, 0600);
      int cloned_file_data = remote.infallible_send_fd_if_alive(clone_file);
      if (cloned_file_data >= 0) {
        int free_fd = find_free_file_descriptor(tid);
        cloned_file_data_fd_child =
            remote.syscall(syscall_number_for_dup3(arch()), cloned_file_data,
                            free_fd, O_CLOEXEC);
        if (cloned_file_data_fd_child != free_fd) {
          ASSERT(this, cloned_file_data_fd_child < 0);
          LOG(warn) << "Couldn't dup clone-data file to free fd";
          cloned_file_data_fd_child = cloned_file_data;
        } else {
          // Prevent the child from closing this fd. We're going to close it
          // ourselves and we don't want the child closing it and then reopening
          // its own file with this fd.
          fds->add_monitor(this, cloned_file_data_fd_child,
                            new PreserveFileMonitor());
          remote.infallible_close_syscall_if_alive(cloned_file_data);
        }
        args.cloned_file_data_fd = cloned_file_data_fd_child;
      }
    }
  }
  args.scratch_buf = scratch_ptr;
  args.usable_scratch_size = usable_scratch_size();

  // Return the mapped buffers to the child.
  write_mem(child_args, args);

  // The tracee doesn't need this addr returned, because it's
  // already written to the inout |args| param, but we stash it
  // away in the return value slot so that we can easily check
  // that we map the segment at the same addr during replay.
  remote.regs().set_syscall_result(syscallbuf_child);
}

void RecordTask::init_buffers() { RR_ARCH_FUNCTION(init_buffers_arch, arch()); }

template <typename Arch>
void RecordTask::on_syscall_exit_arch(int syscallno, const Registers& regs) {
  switch (syscallno) {
    // These syscalls affect the sigmask even if they fail.
    case Arch::epoll_pwait:
    case Arch::pselect6:
    case Arch::pselect6_time64:
    case Arch::ppoll:
    case Arch::ppoll_time64:
      invalidate_sigmask();
      break;
  }

  if (regs.original_syscallno() == SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO ||
      regs.syscall_failed()) {
    return;
  }

  switch (syscallno) {
    case Arch::set_robust_list:
      set_robust_list(regs.orig_arg1(), (size_t)regs.arg2());
      return;
    case Arch::sigaction:
    case Arch::rt_sigaction:
      // TODO: SYS_signal
      update_sigaction(regs);
      return;
    case Arch::set_tid_address:
      set_tid_addr(regs.orig_arg1());
      return;
    case Arch::sigsuspend:
    case Arch::rt_sigsuspend:
    case Arch::sigprocmask:
    case Arch::rt_sigprocmask:
    case Arch::pselect6:
    case Arch::pselect6_time64:
    case Arch::ppoll:
    case Arch::ppoll_time64:
      invalidate_sigmask();
      return;
  }
}

void RecordTask::on_syscall_exit(int syscallno, SupportedArch arch,
                                 const Registers& regs) {
  with_converted_registers<void>(regs, arch, [&](const Registers& regs) {
    Task::on_syscall_exit(syscallno, arch, regs);
    RR_ARCH_FUNCTION(on_syscall_exit_arch, arch, syscallno, regs)
  });
}

bool RecordTask::is_at_syscallbuf_syscall_entry_breakpoint() {
  auto i = ip().undo_executed_bkpt(arch());
  for (auto p : syscallbuf_syscall_entry_breakpoints()) {
    if (i == p) {
      return true;
    }
  }
  return false;
}

bool RecordTask::is_at_syscallbuf_final_instruction_breakpoint() {
  if (!break_at_syscallbuf_final_instruction) {
    return false;
  }
  auto i = ip().undo_executed_bkpt(arch());
  return i == syscallbuf_code_layout.syscallbuf_final_exit_instruction;
}

bool RecordTask::is_at_syscallstub_exit_breakpoint() {
  if (!break_at_syscallbuf_final_instruction || !syscallstub_exit_breakpoint) {
    return false;
  }
  auto i = ip().undo_executed_bkpt(arch());
  return i == syscallstub_exit_breakpoint;
}

bool RecordTask::will_resume_execution(ResumeRequest, WaitRequest,
                                       TicksRequest ticks_request, int sig) {
  // We may execute user code, which could lead to an RDTSC or grow-map
  // operation which unblocks SIGSEGV, and we'll need to know whether to
  // re-block it. So we need our cached sigmask to be up to date.
  // We don't need to this if we're not going to execute user code
  // (i.e. ticks_request == RESUME_NO_TICKS) except that did_wait can't
  // easily check for that and may restore blocked_sigs so it had better be
  // accurate.
  get_sigmask();

  if (stashed_signals_blocking_more_signals) {
    // A stashed signal we have already accepted for this task may
    // have a sigaction::sa_mask that would block the next signal to be
    // delivered and cause it to be delivered to a different task. If we allow
    // such a signal to be delivered to this task then we run the risk of never
    // being able to process the signal (if it stays blocked indefinitely).
    // To prevent this, block any further signal delivery as long as there are
    // stashed signals.
    // We assume the kernel can't report a new signal of the same number
    // in response to us injecting a signal. XXX is this true??? We don't
    // have much choice, signal injection won't work if we block the signal.
    // We leave rr signals unblocked. TIME_SLICE_SIGNAL has to be unblocked
    // because blocking it seems to cause problems for some hardware/kernel
    // configurations (see https://github.com/rr-debugger/rr/issues/1979),
    // causing them to stop counting events.
    sig_set_t sigset = ~session().rr_signal_mask();
    if (sig) {
      // We're injecting a signal, so make sure that signal is unblocked.
      sigset &= ~signal_bit(sig);
    }
    if (!set_sigmask(sigset)) {
      return false;
    }
  }

  // RESUME_NO_TICKS means that tracee code is not going to run so there's no
  // need to set breakpoints and in fact they might interfere with rr
  // processing.
  if (ticks_request != RESUME_NO_TICKS) {
    if (!at_may_restart_syscall()) {
      // If the tracee has SIGTRAP blocked or ignored and we hit one of these
      // breakpoints, the kernel will automatically unblock the signal and set
      // its disposition to DFL, effects which we ought to undo to keep these
      // SIGTRAPs invisible to tracees. Fixing the sigmask happens
      // automatically in did_wait(). Restoring the signal-ignored status is
      // handled in `handle_syscallbuf_breakpoint`.

      // Set breakpoints at untraced syscalls to catch us entering an untraced
      // syscall. We don't need to do this (and shouldn't do this) if the
      // execution requestor wants to stop inside untraced syscalls.
      // If we have an interrupted syscall that we may restart, don't
      // set the breakpoints because we should restart the syscall instead
      // of breaking and delivering signals. The syscallbuf code doesn't
      // (and must not) perform more than one blocking syscall for any given
      // buffered syscall.
      for (auto p : syscallbuf_syscall_entry_breakpoints()) {
        vm()->add_breakpoint(p, BKPT_INTERNAL);
      }
    }
    if (break_at_syscallbuf_final_instruction) {
      vm()->add_breakpoint(
          syscallbuf_code_layout.syscallbuf_final_exit_instruction,
          BKPT_INTERNAL);
      auto stub_bp = as->monkeypatcher().get_jump_stub_exit_breakpoint(ip(), this);
      if (stub_bp) {
        syscallstub_exit_breakpoint = stub_bp;
        vm()->add_breakpoint(stub_bp, BKPT_INTERNAL);
      }
    }
  }
  return true;
}

vector<remote_code_ptr> RecordTask::syscallbuf_syscall_entry_breakpoints() {
  vector<remote_code_ptr> result;
  if (break_at_syscallbuf_untraced_syscalls) {
    result.push_back(AddressSpace::rr_page_syscall_entry_point(
        AddressSpace::UNTRACED, AddressSpace::UNPRIVILEGED,
        AddressSpace::RECORDING_ONLY, arch()));
    result.push_back(AddressSpace::rr_page_syscall_entry_point(
        AddressSpace::UNTRACED, AddressSpace::UNPRIVILEGED,
        AddressSpace::RECORDING_AND_REPLAY, arch()));
  }
  if (break_at_syscallbuf_traced_syscalls) {
    result.push_back(AddressSpace::rr_page_syscall_entry_point(
        AddressSpace::TRACED, AddressSpace::UNPRIVILEGED,
        AddressSpace::RECORDING_AND_REPLAY, arch()));
  }
  return result;
}

void RecordTask::did_wait() {
  for (auto p : syscallbuf_syscall_entry_breakpoints()) {
    vm()->remove_breakpoint(p, BKPT_INTERNAL);
  }
  if (break_at_syscallbuf_final_instruction) {
    vm()->remove_breakpoint(
        syscallbuf_code_layout.syscallbuf_final_exit_instruction,
        BKPT_INTERNAL);
  }
  if (syscallstub_exit_breakpoint) {
    vm()->remove_breakpoint(syscallstub_exit_breakpoint, BKPT_INTERNAL);
  }

  if (stashed_signals_blocking_more_signals) {
    // Saved 'blocked_sigs' must still be correct regardless of syscallbuf
    // state, because we do not allow stashed_signals_blocking_more_signals
    // to hold across syscalls (traced or untraced) that change the signal mask.
    ASSERT(this, !blocked_sigs_dirty);
    xptrace(PTRACE_SETSIGMASK, remote_ptr<void>(8), &blocked_sigs);
  } else if (syscallbuf_child) {
    // The syscallbuf struct is only 32 bytes currently so read the whole thing
    // at once to avoid multiple calls to read_mem. Even though this shouldn't
    // need a syscall because we use a local-mapping, apparently that lookup
    // is still noticeably expensive.
    auto syscallbuf = read_mem(syscallbuf_child);
    if (syscallbuf.in_sigprocmask_critical_section) {
      // |blocked_sigs| may have been updated but the syscall not yet issued.
      // Use the kernel's value.
      invalidate_sigmask();
    } else {
      uint32_t syscallbuf_generation = syscallbuf.blocked_sigs_generation;
      if (syscallbuf_generation > syscallbuf_blocked_sigs_generation) {
        syscallbuf_blocked_sigs_generation = syscallbuf_generation;
        blocked_sigs = syscallbuf.blocked_sigs;
      }
    }
  }
}

void RecordTask::set_emulated_ptracer(RecordTask* tracer) {
  if (tracer) {
    ASSERT(this, !emulated_ptracer);
    emulated_ptracer = tracer;
    emulated_ptracer->emulated_ptrace_tracees.insert(this);
  } else {
    ASSERT(this, emulated_ptracer);
    ASSERT(this,
           emulated_stop_type == NOT_STOPPED ||
               emulated_stop_type == GROUP_STOP);
    emulated_ptracer->emulated_ptrace_tracees.erase(this);
    emulated_ptracer = nullptr;
  }
}

bool RecordTask::emulate_ptrace_stop(WaitStatus status, EmulatedStopType stop_type,
                                     const siginfo_t* siginfo, int si_code) {
  ASSERT(this, emulated_stop_type == NOT_STOPPED);
  if (!emulated_ptracer) {
    return false;
  }
  if (siginfo) {
    ASSERT(this, status.ptrace_signal() == siginfo->si_signo);
    save_ptrace_signal_siginfo(*siginfo);
  } else {
    siginfo_t si;
    memset(&si, 0, sizeof(si));
    si.si_signo = status.ptrace_signal();
    if (status.ptrace_event() || status.is_syscall()) {
      si.si_code = status.get() >> 8;
    } else {
      si.si_code = si_code;
    }
    save_ptrace_signal_siginfo(si);
  }
  force_emulate_ptrace_stop(status, stop_type);
  return true;
}

void RecordTask::force_emulate_ptrace_stop(WaitStatus status, EmulatedStopType stop_type) {
  emulated_stop_type = stop_type;
  emulated_stop_code = status;
  emulated_stop_pending = true;
  emulated_ptrace_SIGCHLD_pending = true;

  emulated_ptracer->send_synthetic_SIGCHLD_if_necessary();
  // The SIGCHLD will eventually be reported to rr via a ptrace stop,
  // interrupting wake_task's syscall (probably a waitpid) if necessary. At
  // that point, we'll fix up the siginfo data with values that match what
  // the kernel would have delivered for a real ptracer's SIGCHLD. When the
  // signal handler (if any) returns, if wake_task was in a blocking wait that
  // wait will be resumed, at which point rec_prepare_syscall_arch will
  // discover the pending ptrace result and emulate the wait syscall to
  // return that result immediately.
}

void RecordTask::do_ptrace_exit_stop(WaitStatus exit_status) {
  // Notify ptracer of the exit if it's not going to receive it from the
  // kernel because it's not the parent. (The kernel has similar logic to
  // deliver two stops in this case.)
  if (emulated_ptracer &&
      (is_clone_child() ||
       get_parent_pid() != emulated_ptracer->real_tgid())) {
    // The task is dead so treat it as not stopped so we can deliver a new stop
    emulated_stop_type = NOT_STOPPED;
    // This is a bit wrong; this is an exit stop, not a signal/ptrace stop.
    emulate_ptrace_stop(exit_status);
  }
}

void RecordTask::did_reach_zombie() {
  waiting_for_zombie = false;
  // Remove from address-space and fds list since we really aren't associated
  // with them anymore (and we can't be used to operate on them)
  as->erase_task(this);
  fds->erase_task(this);

  if (!already_reaped()) {
    if (may_reap()) {
      reap();
    } else {
      waiting_for_reap = true;
    }
  }
  if ((already_reaped() || !waiting_for_reap) && !emulated_stop_pending) {
    delete this;
  }
}

void RecordTask::send_synthetic_SIGCHLD_if_necessary() {
  RecordTask* wake_task = nullptr;
  bool need_signal = false;
  for (RecordTask* tracee : emulated_ptrace_tracees) {
    if (tracee->emulated_ptrace_SIGCHLD_pending) {
      need_signal = true;
      // check to see if any thread in the ptracer process is in a waitpid that
      // could read the status of 'tracee'. If it is, we should wake up that
      // thread. Otherwise we send SIGCHLD to the ptracer thread.
      for (Task* t : thread_group()->task_set()) {
        auto rt = static_cast<RecordTask*>(t);
        if (rt->is_waiting_for_ptrace(tracee)) {
          wake_task = rt;
          break;
        }
      }
      if (wake_task) {
        break;
      }
    }
  }
  if (!need_signal) {
    for (ThreadGroup* child_tg : thread_group()->children()) {
      for (Task* child : child_tg->task_set()) {
        RecordTask* rchild = static_cast<RecordTask*>(child);
        if (rchild->emulated_SIGCHLD_pending) {
          need_signal = true;
          // check to see if any thread in the ptracer process is in a waitpid
          // that
          // could read the status of 'tracee'. If it is, we should wake up that
          // thread. Otherwise we send SIGCHLD to the ptracer thread.
          for (Task* t : thread_group()->task_set()) {
            auto rt = static_cast<RecordTask*>(t);
            if (rt->is_waiting_for(rchild)) {
              wake_task = rt;
              break;
            }
          }
          if (wake_task) {
            break;
          }
        }
      }
    }
    if (!need_signal) {
      return;
    }
  }

  // ptrace events trigger SIGCHLD in the ptracer's wake_task.
  // We can't set all the siginfo values to their correct values here, so
  // we'll patch this up when the signal is received.
  // If there's already a pending SIGCHLD, this signal will be ignored,
  // but at some point the pending SIGCHLD will be delivered and then
  // send_synthetic_SIGCHLD_if_necessary will be called again to deliver a new
  // SIGCHLD if necessary.
  siginfo_t si;
  memset(&si, 0, sizeof(si));
  si.si_code = SI_QUEUE;
  si.si_value.sival_int = SIGCHLD_SYNTHETIC;
  int ret;
  if (wake_task) {
    LOG(debug) << "Sending synthetic SIGCHLD to tid " << wake_task->tid;
    // We must use the raw SYS_rt_tgsigqueueinfo syscall here to ensure the
    // signal is sent to the correct thread by tid.
    ret = syscall(SYS_rt_tgsigqueueinfo, wake_task->tgid(), wake_task->tid,
                  SIGCHLD, &si);
    ASSERT(this, ret == 0);
    if (wake_task->is_sig_blocked(SIGCHLD)) {
      LOG(debug) << "SIGCHLD is blocked, kicking it out of the syscall";
      // Just sending SIGCHLD won't wake it up. Send it a TIME_SLICE_SIGNAL
      // as well to make sure it exits a blocking syscall. We ensure those
      // can never be blocked.
      // We have to send a negative code here because only the kernel can set
      // positive codes. We set a magic number so we can recognize it
      // when received.
      si.si_code = SYNTHETIC_TIME_SLICE_SI_CODE;
      ret = syscall(SYS_rt_tgsigqueueinfo, wake_task->tgid(), wake_task->tid,
                    PerfCounters::TIME_SLICE_SIGNAL, &si);
      ASSERT(this, ret == 0);
    }
  } else {
    // Send the signal to the process as a whole and let the kernel
    // decide which thread gets it.
    ret = syscall(SYS_rt_sigqueueinfo, tgid(), SIGCHLD, &si);
    ASSERT(this, ret == 0);
    LOG(debug) << "Sending synthetic SIGCHLD to pid " << tgid();
  }
}

static bool is_synthetic_SIGCHLD(const siginfo_t& si) {
  return si.si_signo == SIGCHLD && si.si_value.sival_int == SIGCHLD_SYNTHETIC;
}

bool RecordTask::set_siginfo_for_synthetic_SIGCHLD(siginfo_t* si) {
  if (!is_synthetic_SIGCHLD(*si)) {
    return true;
  }

  if (is_syscall_restart() && EV_SYSCALL_INTERRUPTION == ev().type()) {
    int syscallno = regs().original_syscallno();
    SupportedArch syscall_arch = ev().Syscall().arch();
    if (is_waitpid_syscall(syscallno, syscall_arch) ||
        is_waitid_syscall(syscallno, syscall_arch) ||
        is_wait4_syscall(syscallno, syscall_arch)) {
      // Wait-like syscalls always check for notifications from waited-for processes
      // before they check for pending signals. So, if the tracee has a pending
      // notification that also generated a signal, the wait syscall will return
      // normally rather than returning with ERESTARTSYS etc. (The signal will
      // be dequeued and any handler run on the return to userspace, however.)
      // We need to emulate this by deferring our synthetic ptrace signal
      // until after the wait syscall has returned.
      LOG(debug) << "Deferring signal because we're in a wait";
      // Return false to tell the caller to defer the signal and resume
      // the syscall.
      return false;
    }
  }

  for (RecordTask* tracee : emulated_ptrace_tracees) {
    if (tracee->emulated_ptrace_SIGCHLD_pending) {
      tracee->emulated_ptrace_SIGCHLD_pending = false;
      tracee->set_siginfo_for_waited_task<NativeArch>(
          reinterpret_cast<NativeArch::siginfo_t*>(si));
      si->si_value.sival_int = 0;
      return true;
    }
  }

  for (ThreadGroup* child_tg : thread_group()->children()) {
    for (Task* child : child_tg->task_set()) {
      auto rchild = static_cast<RecordTask*>(child);
      if (rchild->emulated_SIGCHLD_pending) {
        rchild->emulated_SIGCHLD_pending = false;
        rchild->set_siginfo_for_waited_task<NativeArch>(
            reinterpret_cast<NativeArch::siginfo_t*>(si));
        si->si_value.sival_int = 0;
        return true;
      }
    }
  }

  return true;
}

bool RecordTask::is_waiting_for_ptrace(RecordTask* t) {
  // This task's process must be a ptracer of t.
  if (!t->emulated_ptracer ||
      t->emulated_ptracer->thread_group() != thread_group()) {
    return false;
  }
  // XXX need to check |options| to make sure this task is eligible!!
  switch (in_wait_type) {
    case WAIT_TYPE_NONE:
      return false;
    case WAIT_TYPE_ANY:
      return true;
    case WAIT_TYPE_SAME_PGID:
      return getpgid(t->tgid()) == getpgid(tgid());
    case WAIT_TYPE_PGID:
      return getpgid(t->tgid()) == in_wait_pid;
    case WAIT_TYPE_PID:
      // When waiting for a ptracee, a specific pid is interpreted as the
      // exact tid.
      return t->tid == in_wait_pid;
    default:
      ASSERT(this, false);
      return false;
  }
}

bool RecordTask::is_waiting_for(RecordTask* t) {
  // t must be a child of this task.
  if (t->thread_group()->parent() != thread_group().get()) {
    return false;
  }
  switch (in_wait_type) {
    case WAIT_TYPE_NONE:
      return false;
    case WAIT_TYPE_ANY:
      return true;
    case WAIT_TYPE_SAME_PGID:
      return getpgid(t->tgid()) == getpgid(tgid());
    case WAIT_TYPE_PGID:
      return getpgid(t->tgid()) == in_wait_pid;
    case WAIT_TYPE_PID:
      return t->tgid() == in_wait_pid;
    default:
      ASSERT(this, false);
      return false;
  }
}

void RecordTask::save_ptrace_signal_siginfo(const siginfo_t& si) {
  for (auto it = saved_ptrace_siginfos.begin();
       it != saved_ptrace_siginfos.end(); ++it) {
    if (it->si_signo == si.si_signo) {
      saved_ptrace_siginfos.erase(it);
      break;
    }
  }
  saved_ptrace_siginfos.push_back(si);
}

siginfo_t& RecordTask::get_saved_ptrace_siginfo() {
  int sig = emulated_stop_code.ptrace_signal();
  ASSERT(this, sig > 0);
  for (auto it = saved_ptrace_siginfos.begin();
       it != saved_ptrace_siginfos.end(); ++it) {
    if (it->si_signo == sig) {
      return *it;
    }
  }
  ASSERT(this, false) << "No saved siginfo found for stop-signal???";
  while (true) {
    // Avoid having to return anything along this (unreachable) path
  }
}

siginfo_t RecordTask::take_ptrace_signal_siginfo(int sig) {
  for (auto it = saved_ptrace_siginfos.begin();
       it != saved_ptrace_siginfos.end(); ++it) {
    if (it->si_signo == sig) {
      siginfo_t si = *it;
      saved_ptrace_siginfos.erase(it);
      return si;
    }
  }
  siginfo_t si;
  memset(&si, 0, sizeof(si));
  si.si_signo = sig;
  return si;
}

static pid_t get_ppid(pid_t pid) {
  auto ppid_str = read_proc_status_fields(pid, "PPid");
  if (ppid_str.empty()) {
    return -1;
  }
  char* end;
  int actual_ppid = strtol(ppid_str[0].c_str(), &end, 10);
  return *end ? -1 : actual_ppid;
}

void RecordTask::apply_group_stop(int sig) {
  if (emulated_stop_type == NOT_STOPPED) {
    LOG(debug) << "setting " << tid << " to GROUP_STOP due to signal " << sig;
    WaitStatus status = WaitStatus::for_group_sig(sig, this);
    if (!emulate_ptrace_stop(status)) {
      emulated_stop_type = GROUP_STOP;
      emulated_stop_code = status;
      emulated_stop_pending = true;
      emulated_SIGCHLD_pending = true;
      RecordTask* t = session().find_task(get_ppid(tid));
      if (t) {
        t->send_synthetic_SIGCHLD_if_necessary();
      }
    }
  }
}

bool RecordTask::is_signal_pending(int sig) {
  auto pending_strs = read_proc_status_fields(tid, "SigPnd", "ShdPnd");
  if (pending_strs.size() < 2) {
    return false;
  }
  char* end1;
  sig_set_t mask1 = strtoull(pending_strs[0].c_str(), &end1, 16);
  char* end2;
  sig_set_t mask2 = strtoull(pending_strs[1].c_str(), &end2, 16);
  return !*end1 && !*end2 && ((mask1 | mask2) & signal_bit(sig));
}

bool RecordTask::has_any_actionable_signal() {
  auto sig_strs = read_proc_status_fields(tid, "SigPnd", "ShdPnd", "SigBlk");
  if (sig_strs.size() < 3) {
    return false;
  }

  char* end1;
  uint64_t mask1 = strtoull(sig_strs[0].c_str(), &end1, 16);
  char* end2;
  uint64_t mask2 = strtoull(sig_strs[1].c_str(), &end2, 16);
  char* end3;
  uint64_t mask_blk = strtoull(sig_strs[2].c_str(), &end3, 16);
  return !*end1 && !*end2 && !*end3 && ((mask1 | mask2) & ~mask_blk);
}

void RecordTask::emulate_SIGCONT() {
  // All threads in the process are resumed.
  for (Task* t : thread_group()->task_set()) {
    auto rt = static_cast<RecordTask*>(t);
    LOG(debug) << "setting " << tid << " to NOT_STOPPED due to SIGCONT";
    rt->clear_stashed_group_stop();
    rt->emulated_stop_pending = false;
    rt->emulated_stop_type = NOT_STOPPED;
  }
}

void RecordTask::signal_delivered(int sig) {
  Sighandler& h = sighandlers->get(sig);
  if (h.resethand) {
    reset_handler(&h, arch());
  }

  if (!is_sig_ignored(sig)) {
    switch (sig) {
      case SIGTSTP:
      case SIGTTIN:
      case SIGTTOU:
        if (h.disposition() == SIGNAL_HANDLER) {
          break;
        }
        RR_FALLTHROUGH;
      case SIGSTOP:
        // All threads in the process are stopped.
        for (Task* t : thread_group()->task_set()) {
          auto rt = static_cast<RecordTask*>(t);
          rt->apply_group_stop(sig);
        }
        break;
      case SIGCONT:
        emulate_SIGCONT();
        break;
    }
  }

  send_synthetic_SIGCHLD_if_necessary();
}

bool RecordTask::signal_has_user_handler(int sig) const {
  return sighandlers->get(sig).disposition() == SIGNAL_HANDLER;
}

remote_code_ptr RecordTask::get_signal_user_handler(int sig) const {
  return sighandlers->get(sig).get_user_handler();
}

const vector<uint8_t>& RecordTask::signal_action(int sig) const {
  return sighandlers->get(sig).sa;
}

bool RecordTask::signal_handler_takes_siginfo(int sig) const {
  return sighandlers->get(sig).takes_siginfo;
}

static bool is_unstoppable_signal(int sig) {
  return sig == SIGSTOP || sig == SIGKILL;
}

bool RecordTask::is_sig_blocked(int sig) {
  if (is_unstoppable_signal(sig)) {
    // These can never be blocked
    return false;
  }
  int sig_bit = sig - 1;
  return (get_sigmask() >> sig_bit) & 1;
}

bool RecordTask::is_sig_ignored(int sig) const {
  if (is_unstoppable_signal(sig)) {
    // These can never be ignored
    return false;
  }
  switch (sighandlers->get(sig).disposition()) {
    case SIGNAL_IGNORE:
      return true;
    case SIGNAL_DEFAULT:
      return IGNORE == default_action(sig);
    default:
      return false;
  }
}

SignalDisposition RecordTask::sig_disposition(int sig) const {
  return sighandlers->get(sig).disposition();
}

SignalResolvedDisposition RecordTask::sig_resolved_disposition(
    int sig, SignalDeterministic deterministic) {
  if (is_fatal_signal(sig, deterministic)) {
    return DISPOSITION_FATAL;
  }
  if (signal_has_user_handler(sig) && !is_sig_blocked(sig)) {
    return DISPOSITION_USER_HANDLER;
  }
  return DISPOSITION_IGNORED;
}

void RecordTask::set_siginfo(const siginfo_t& si) {
  pending_siginfo = si;
  ptrace_if_alive(PTRACE_SETSIGINFO, nullptr, (void*)&si);
}

template <typename Arch>
void RecordTask::update_sigaction_arch(const Registers& regs) {
  int sig = regs.orig_arg1_signed();
  remote_ptr<typename Arch::kernel_sigaction> new_sigaction = regs.arg2();
  if (0 == regs.syscall_result() && !new_sigaction.is_null()) {
    // A new sighandler was installed.  Update our
    // sighandler table.
    // TODO: discard attempts to handle or ignore signals
    // that can't be by POSIX
    typename Arch::kernel_sigaction sa;
    memset(&sa, 0, sizeof(sa));
    read_bytes_helper(new_sigaction, sizeof(sa), &sa);
    sighandlers->get(sig).init_arch<Arch>(sa);
  }
}

void RecordTask::update_sigaction(const Registers& regs) {
  RR_ARCH_FUNCTION(update_sigaction_arch, regs.arch(), regs);
}

sig_set_t RecordTask::read_sigmask_from_process() {
  // During syscall interruptions, PTRACE_GETSIGMASK may return the sigmask that is going
  // to be restored, not the kernel's current (internal) sigmask, which is what
  // /proc/.../status reports. Always go with what /proc/.../status reports. See
  // https://github.com/torvalds/linux/commit/fcfc2aa0185f4a731d05a21e9f359968fdfd02e7
  // XXXkhuey and yet that's not what we actually do here ...
  if (at_interrupted_non_restartable_signal_modifying_syscall()) {
    // Mark the sigmask as already invalid. The moment we exit the kernel and run more
    // of the tracee the sigmask will change, so we need to keep refetching the
    // sigmask until that happens.
    invalidate_sigmask();
  } else if (!at_may_restart_syscall()) {
    sig_set_t mask;
    long ret = fallible_ptrace(PTRACE_GETSIGMASK,
                               remote_ptr<void>(sizeof(sig_set_t)), &mask);
    if (ret >= 0) {
      return mask;
    }
  }

  auto results = read_proc_status_fields(tid, "SigBlk");
  if (results.empty()) {
    // Read failed, process probably died
    return 0;
  }
  ASSERT(this, results.size() == 1);
  return strtoull(results[0].c_str(), NULL, 16);
}

sig_set_t RecordTask::get_sigmask() {
  if (blocked_sigs_dirty) {
    // Clear this first, read_sigmask_from_process might set it again.
    blocked_sigs_dirty = false;
    blocked_sigs = read_sigmask_from_process();
    LOG(debug) << "Refreshed sigmask, now " << HEX(blocked_sigs);
  }
  return blocked_sigs;
}

bool RecordTask::unblock_signal(int sig) {
  sig_set_t mask = get_sigmask();
  mask &= ~signal_bit(sig);
  if (!set_sigmask(mask)) {
    return false;
  }
  invalidate_sigmask();
  return true;
}

bool RecordTask::set_sigmask(sig_set_t mask) {
  int ret = fallible_ptrace(PTRACE_SETSIGMASK, remote_ptr<void>(8), &mask);
  if (ret < 0) {
    if (errno == EIO) {
      FATAL() << "PTRACE_SETSIGMASK not supported; rr requires Linux kernel >= 3.11";
    }
    if (errno == ESRCH) {
      // Task most likely died while we at the ptrace stop.
      detected_unexpected_exit = true;
      return false;
    }
    ASSERT(this, errno == EINVAL);
  } else {
    LOG(debug) << "Set signal mask to block all signals (bar "
               << "SYSCALLBUF_DESCHED_SIGNAL/TIME_SLICE_SIGNAL) while we "
               << " have a stashed signal";
  }
  return true;
}

void RecordTask::set_sig_handler_default(int sig) {
  did_set_sig_handler_default(sig);
  // This could happen during a syscallbuf untraced syscall. In that case
  // our remote syscall here could trigger a desched signal if that event
  // is armed, making progress impossible. Disarm the event now.
  disarm_desched_event(this);
  AutoRemoteSyscalls remote(this);
  Sighandler& h = sighandlers->get(sig);
  AutoRestoreMem mem(remote, h.sa.data(), h.sa.size());
  remote.infallible_syscall(syscall_number_for_rt_sigaction(arch()),
      sig, mem.get().as_int(), nullptr,
      sigaction_sigset_size(arch()));
}

void RecordTask::did_set_sig_handler_default(int sig) {
  Sighandler& h = sighandlers->get(sig);
  reset_handler(&h, arch());
}

void RecordTask::verify_signal_states() {
#ifndef DEBUG
  return;
#endif
  if (ev().is_syscall_event()) {
    // If the syscall event is on the event stack with PROCESSING or EXITING
    // states, we won't have applied the signal-state updates yet while the
    // kernel may have.
    return;
  }
  if (detached_proxy) {
    // This task isn't real
    return;
  }

  auto results = read_proc_status_fields(tid, "SigBlk", "SigIgn", "SigCgt");
  if (results.empty()) {
    // Read failed, process probably died
    return;
  }
  ASSERT(this, results.size() == 3);
  sig_set_t blocked = strtoull(results[0].c_str(), NULL, 16);
  sig_set_t ignored = strtoull(results[1].c_str(), NULL, 16);
  sig_set_t caught = strtoull(results[2].c_str(), NULL, 16);
  for (int sig = 1; sig < _NSIG; ++sig) {
    sig_set_t mask = signal_bit(sig);
    if (is_unstoppable_signal(sig)) {
      ASSERT(this, !(blocked & mask))
          << "Expected " << signal_name(sig) << " to not be blocked, but it is";
      ASSERT(this, !(ignored & mask))
          << "Expected " << signal_name(sig) << " to not be ignored, but it is";
      ASSERT(this, !(caught & mask))
          << "Expected " << signal_name(sig) << " to not be caught, but it is";
    } else {
      ASSERT(this, !!(blocked & mask) == is_sig_blocked(sig))
          << signal_name(sig)
          << ((blocked & mask) ? " is blocked" : " is not blocked");
      if (sig == SIGCHLD && is_container_init() && (ignored & mask)) {
        // pid-1-in-its-own-pid-namespace tasks can have their SIGCHLD set
        // to "ignore" when they die (in zap_pid_ns_processes). We may
        // not have observed anything relating to this death yet. We could
        // probe to ensure it's already marked as a zombie but why bother.
        // XXX arguably we should actually change our disposition here but
        // it would only matter in certain very weird cases: a vfork() where
        // the child process is pid-1 in its namespace.
        continue;
      }
      auto disposition = sighandlers->get(sig).disposition();
      ASSERT(this, !!(ignored & mask) == (disposition == SIGNAL_IGNORE))
          << signal_name(sig)
          << ((ignored & mask) ? " is ignored" : " is not ignored");
      ASSERT(this, !!(caught & mask) == (disposition == SIGNAL_HANDLER))
          << signal_name(sig)
          << ((caught & mask) ? " is caught" : " is not caught");
    }
  }
}

void RecordTask::stash_sig() {
  int sig = stop_sig();
  ASSERT(this, sig);
  // Callers should avoid passing SYSCALLBUF_DESCHED_SIGNAL in here.
  ASSERT(this, sig != session().syscallbuf_desched_sig());
  // multiple non-RT signals coalesce
  if (sig < SIGRTMIN) {
    for (auto it = stashed_signals.begin(); it != stashed_signals.end(); ++it) {
      if (it->siginfo.si_signo == sig) {
        LOG(debug) << "discarding stashed signal " << sig
                   << " since we already have one pending";
        return;
      }
    }
  }

  const siginfo_t& si = get_siginfo();
  stashed_signals.push_back(StashedSignal(si, is_deterministic_signal(this), ip()));
  // Once we've stashed a signal, stop at the next traced/untraced syscall to
  // check whether we need to process the signal before it runs.
  stashed_signals_blocking_more_signals =
      break_at_syscallbuf_final_instruction =
          break_at_syscallbuf_traced_syscalls =
              break_at_syscallbuf_untraced_syscalls = true;
  syscallstub_exit_breakpoint = nullptr;
}

void RecordTask::stash_synthetic_sig(const siginfo_t& si,
                                     SignalDeterministic deterministic) {
  int sig = si.si_signo;
  DEBUG_ASSERT(sig);
  // Callers should avoid passing SYSCALLBUF_DESCHED_SIGNAL in here.
  DEBUG_ASSERT(sig != session().syscallbuf_desched_sig());
  // multiple non-RT signals coalesce
  if (sig < SIGRTMIN) {
    for (auto it = stashed_signals.begin(); it != stashed_signals.end(); ++it) {
      if (it->siginfo.si_signo == sig) {
        if (deterministic == DETERMINISTIC_SIG &&
            it->deterministic == NONDETERMINISTIC_SIG) {
          stashed_signals.erase(it);
          break;
        } else {
          LOG(debug) << "discarding stashed signal " << sig
                     << " since we already have one pending";
          return;
        }
      }
    }
  }

  stashed_signals.insert(stashed_signals.begin(),
                         StashedSignal(si, deterministic, ip()));
  stashed_signals_blocking_more_signals =
      break_at_syscallbuf_final_instruction =
          break_at_syscallbuf_traced_syscalls =
              break_at_syscallbuf_untraced_syscalls = true;
  syscallstub_exit_breakpoint = nullptr;
}

bool RecordTask::has_stashed_sig(int sig) const {
  for (auto it = stashed_signals.begin(); it != stashed_signals.end(); ++it) {
    if (it->siginfo.si_signo == sig) {
      return true;
    }
  }
  return false;
}

const RecordTask::StashedSignal* RecordTask::stashed_sig_not_synthetic_SIGCHLD() const {
  for (auto it = stashed_signals.begin(); it != stashed_signals.end(); ++it) {
    if (!is_synthetic_SIGCHLD(it->siginfo)) {
      return &*it;
    }
  }
  return nullptr;
}

void RecordTask::pop_stash_sig(const StashedSignal* stashed) {
  for (auto it = stashed_signals.begin(); it != stashed_signals.end(); ++it) {
    if (&*it == stashed) {
      stashed_signals.erase(it);
      return;
    }
  }
  ASSERT(this, false) << "signal not found";
}

void RecordTask::stashed_signal_processed() {
  break_at_syscallbuf_final_instruction = break_at_syscallbuf_traced_syscalls =
      break_at_syscallbuf_untraced_syscalls =
          stashed_signals_blocking_more_signals = has_stashed_sig();
  syscallstub_exit_breakpoint = nullptr;
}

const RecordTask::StashedSignal* RecordTask::peek_stashed_sig_to_deliver()
    const {
  if (stashed_signals.empty()) {
    return nullptr;
  }
  // Choose the first non-synthetic-SIGCHLD signal so that if a syscall should
  // be interrupted, we'll interrupt it.
  for (auto& sig : stashed_signals) {
    if (!is_synthetic_SIGCHLD(sig.siginfo)) {
      return &sig;
    }
  }
  return &stashed_signals[0];
}

bool RecordTask::is_syscall_restart() {
  if (EV_SYSCALL_INTERRUPTION != ev().type()) {
    return false;
  }

  int syscallno = regs().original_syscallno();
  SupportedArch syscall_arch = ev().Syscall().arch();
  string call_name = syscall_name(syscallno, syscall_arch);
  bool is_restart = false;
  LOG(debug) << "  is syscall interruption of recorded " << ev() << "? (now "
             << call_name << ")";

  /* It's possible for the tracee to resume after a sighandler
   * with a fresh syscall that happens to be the same as the one
   * that was interrupted.  So we check here if the args are the
   * same.
   *
   * Of course, it's possible (but less likely) for the tracee
   * to incidentally resume with a fresh syscall that just
   * happens to have the same *arguments* too.  But in that
   * case, we would usually set up scratch buffers etc the same
   * was as for the original interrupted syscall, so we just
   * save a step here.
   *
   * TODO: it's possible for arg structures to be mutated
   * between the original call and restarted call in such a way
   * that it might change the scratch allocation decisions. */
  if (is_restart_syscall_syscall(syscallno, syscall_arch)) {
    is_restart = true;
    syscallno = ev().Syscall().number;
    LOG(debug) << "  (SYS_restart_syscall)";
  }
  if (ev().Syscall().number != syscallno) {
    LOG(debug) << "  interrupted " << ev() << " != " << call_name;
    goto done;
  }

  {
    const Registers& old_regs = ev().Syscall().regs;
    if (!(old_regs.orig_arg1() == regs().arg1() &&
          old_regs.arg2() == regs().arg2() &&
          old_regs.arg3() == regs().arg3() &&
          old_regs.arg4() == regs().arg4() &&
          old_regs.arg5() == regs().arg5() &&
          old_regs.arg6() == regs().arg6())) {
      LOG(debug) << "  regs different at interrupted " << call_name << ": "
                 << old_regs << " vs " << regs();
      goto done;
    }
  }

  is_restart = true;

done:
  if (is_restart) {
    LOG(debug) << "  restart of " << call_name;
  }
  return is_restart;
}

template <typename Arch>
static uint64_t read_ptr_arch(Task* t, remote_ptr<void> p, bool* ok) {
  return t->read_mem(p.cast<typename Arch::unsigned_word>(), ok);
}

static uint64_t read_ptr(Task* t, remote_ptr<void> p, bool* ok) {
  RR_ARCH_FUNCTION(read_ptr_arch, t->arch(), t, p, ok);
}

bool RecordTask::is_in_syscallbuf() {
  if (!as->syscallbuf_enabled()) {
    // Even if we're in the rr page, if syscallbuf isn't enabled then the
    // rr page is not being used by syscallbuf.
    return false;
  }
  remote_code_ptr p = ip();
  if (is_in_rr_page() || (syscallbuf_code_layout.get_pc_thunks_start <= p &&
                          p < syscallbuf_code_layout.get_pc_thunks_end)) {
    // Look at the caller to see if we're in the syscallbuf or not.
    bool ok = true;
    uint64_t addr;
    if (arch() == aarch64) {
      addr = regs().xlr();
    }
    else {
      ASSERT(this, is_x86ish(arch())) << "Unknown architecture";
      addr = read_ptr(this, regs().sp(), &ok);
    }
    if (ok) {
      p = addr;
    }
  }
  return as->monkeypatcher().is_jump_stub_instruction(p, false) ||
         (syscallbuf_code_layout.syscallbuf_code_start <= p &&
          p < syscallbuf_code_layout.syscallbuf_code_end);
}

bool RecordTask::at_may_restart_syscall() const {
  ssize_t depth = pending_events.size();
  const Event* prev_ev = depth > 2 ? &pending_events[depth - 2] : nullptr;
  return EV_SYSCALL_INTERRUPTION == ev().type() ||
         (EV_SIGNAL_DELIVERY == ev().type() && prev_ev &&
          EV_SYSCALL_INTERRUPTION == prev_ev->type());
}

bool RecordTask::at_interrupted_non_restartable_signal_modifying_syscall() const {
  auto r = regs();
  // XXXkhuey io_uring_enter (not yet supported) can do this too.
  return r.syscall_result_signed() == -EINTR &&
    is_epoll_pwait_syscall(r.original_syscallno(), arch());
}

bool RecordTask::is_arm_desched_event_syscall() {
  return is_desched_event_syscall() && PERF_EVENT_IOC_ENABLE == regs().arg2();
}

bool RecordTask::is_disarm_desched_event_syscall() {
  return (is_desched_event_syscall() &&
          PERF_EVENT_IOC_DISABLE == regs().arg2());
}

bool RecordTask::may_be_blocked() const {
  return (EV_SYSCALL == ev().type() &&
          PROCESSING_SYSCALL == ev().Syscall().state) ||
         emulated_stop_type != NOT_STOPPED ||
         (EV_SIGNAL_DELIVERY == ev().type() &&
          DISPOSITION_FATAL == ev().Signal().disposition) ||
         waiting_for_zombie ||
         waiting_for_ptrace_exit;
}

bool RecordTask::maybe_in_spinlock() {
  return time_at_start_of_last_timeslice == session().trace_writer().time() &&
         regs().matches(registers_at_start_of_last_timeslice);
}

remote_ptr<const struct syscallbuf_record> RecordTask::desched_rec() const {
  return (ev().is_syscall_event()
              ? ev().Syscall().desched_rec
              : (EV_DESCHED == ev().type()) ? ev().Desched().rec : nullptr);
}

bool RecordTask::running_inside_desched() const {
  for (auto& e : pending_events) {
    if (e.type() == EV_DESCHED) {
      return e.Desched().rec != desched_rec();
    }
  }
  return false;
}

int RecordTask::get_ptrace_eventmsg_seccomp_data() {
  unsigned long data = 0;
  // in theory we could hit an assertion failure if the tracee suffers
  // a SIGKILL before we get here. But the SIGKILL would have to be
  // precisely timed between the generation of a PTRACE_EVENT_FORK/CLONE/
  // SYS_clone event, and us fetching the event message here.
  if (fallible_ptrace(PTRACE_GETEVENTMSG, nullptr, &data) < 0) {
    ASSERT(this, errno == ESRCH);
    return -1;
  }
  return data;
}

void RecordTask::record_local(remote_ptr<void> addr, ssize_t num_bytes,
                              const void* data) {
  maybe_flush_syscallbuf();

  ASSERT(this, num_bytes >= 0);

  if (!addr) {
    return;
  }

  trace_writer().write_raw(rec_tid, data, num_bytes, addr);
}

bool RecordTask::record_remote_by_local_map(remote_ptr<void> addr,
                                            size_t num_bytes) {
  if (uint8_t* local_addr = as->local_mapping(addr, num_bytes)) {
    record_local(addr, num_bytes, local_addr);
    return true;
  }
  return false;
}

void RecordTask::record_remote(remote_ptr<void> addr, ssize_t num_bytes) {
  maybe_flush_syscallbuf();

  ASSERT(this, num_bytes >= 0);

  if (!addr) {
    return;
  }

  if (record_remote_by_local_map(addr, num_bytes) != 0) {
    return;
  }

  auto buf = read_mem(addr.cast<uint8_t>(), num_bytes);
  trace_writer().write_raw(rec_tid, buf.data(), num_bytes, addr);
}

void RecordTask::record_remote_writable(remote_ptr<void> addr,
                                        ssize_t num_bytes) {
  ASSERT(this, num_bytes >= 0);

  remote_ptr<void> p = addr;
  bool seen_rr_mapping = false;
  int mapping_count = 0;
  while (p < addr + num_bytes) {
    if (!as->has_mapping(p)) {
      break;
    }
    ++mapping_count;
    auto m = as->mapping_of(p);
    if (m.flags) {
      seen_rr_mapping = true;
    }
    if (!(m.map.prot() & PROT_WRITE) ||
        (seen_rr_mapping && mapping_count > 1)) {
      break;
    }
    p = m.map.end();
  }
  num_bytes = min(num_bytes, p - addr);

  record_remote(addr, num_bytes);
}

ssize_t RecordTask::record_remote_fallible(remote_ptr<void> addr,
                                           uintptr_t num_bytes,
                                           const std::vector<WriteHole>& holes) {
  auto hole_iter = holes.begin();
  uintptr_t offset = 0;
  vector<uint8_t> buf;
  while (offset < num_bytes) {
    if (hole_iter != holes.end() && hole_iter->offset == offset) {
      offset += hole_iter->size;
      ++hole_iter;
      continue;
    }

    uintptr_t bytes = min(uintptr_t(4*1024*1024), num_bytes - offset);
    if (hole_iter != holes.end()) {
      ASSERT(this, hole_iter->offset > offset);
      bytes = min(bytes, uintptr_t(hole_iter->offset) - offset);
    }
    if (record_remote_by_local_map(addr + offset, bytes)) {
      offset += bytes;
      continue;
    }

    if (addr) {
      buf.resize(bytes);
      ssize_t nread = read_bytes_fallible(addr + offset, bytes, buf.data());
      if (nread <= 0) {
        break;
      }
      trace_writer().write_raw_data(buf.data(), nread);
      offset += nread;
    } else {
      offset += bytes;
    }
  }
  trace_writer().write_raw_header(rec_tid, offset, addr, holes);
  return offset;
}

void RecordTask::record_remote_even_if_null(remote_ptr<void> addr,
                                            ssize_t num_bytes) {
  maybe_flush_syscallbuf();

  DEBUG_ASSERT(num_bytes >= 0);

  if (!addr) {
    trace_writer().write_raw(rec_tid, nullptr, 0, addr);
    return;
  }

  if (record_remote_by_local_map(addr, num_bytes) != 0) {
    return;
  }

  auto buf = read_mem(addr.cast<uint8_t>(), num_bytes);
  trace_writer().write_raw(rec_tid, buf.data(), num_bytes, addr);
}

void RecordTask::pop_event(EventType expected_type) {
  ASSERT(this, pending_events.back().type() == expected_type);
  pending_events.pop_back();
}

void RecordTask::log_pending_events() const {
  ssize_t depth = pending_events.size();

  DEBUG_ASSERT(depth > 0);
  if (1 == depth) {
    LOG(info) << "(no pending events)";
    return;
  }

  /* The event at depth 0 is the placeholder event, which isn't
   * useful to log.  Skip it. */
  for (auto it = pending_events.rbegin(); it != pending_events.rend(); ++it) {
    LOG(info) << *it;
  }
}

void RecordTask::maybe_flush_syscallbuf() {
  if (EV_SYSCALLBUF_FLUSH == ev().type()) {
    // Already flushing.
    return;
  }
  if (!syscallbuf_child) {
    return;
  }

  // This can be called while the task is not stopped, when we prematurely
  // terminate the trace. In that case, the tracee could be concurrently
  // modifying the header. We'll take a snapshot of the header now.
  // The syscallbuf code ensures that writes to syscallbuf records
  // complete before num_rec_bytes is incremented.
  struct syscallbuf_hdr hdr = read_mem(syscallbuf_child);

  ASSERT(this,
         !flushed_syscallbuf || flushed_num_rec_bytes == hdr.num_rec_bytes);

  if (!hdr.num_rec_bytes || flushed_syscallbuf) {
    // no records, or we've already flushed.
    return;
  }

  push_event(Event(SyscallbufFlushEvent()));

  // Apply buffered mprotect operations and flush the buffer in the tracee.
  if (hdr.mprotect_record_count) {
    auto& records = ev().SyscallbufFlush().mprotect_records;
    records = read_mem(REMOTE_PTR_FIELD(preload_globals, mprotect_records[0]),
                       hdr.mprotect_record_count);
    for (auto& r : records) {
      as->protect(this, r.start, r.size, r.prot);
    }
  }

  // Write the entire buffer in one shot without parsing it,
  // because replay will take care of that.
  if (is_running()) {
    vector<uint8_t> buf;
    buf.resize(sizeof(hdr) + hdr.num_rec_bytes);
    memcpy(buf.data(), &hdr, sizeof(hdr));
    read_bytes_helper(syscallbuf_child + 1, hdr.num_rec_bytes,
                      buf.data() + sizeof(hdr));
    record_local(syscallbuf_child, buf.size(), buf.data());
  } else {
    record_remote(syscallbuf_child, syscallbuf_data_size());
  }
  record_current_event();
  pop_event(EV_SYSCALLBUF_FLUSH);

  flushed_syscallbuf = true;
  flushed_num_rec_bytes = hdr.num_rec_bytes;

  LOG(debug) << "Syscallbuf flushed with num_rec_bytes="
             << (uint32_t)hdr.num_rec_bytes;
}

/**
 * If the syscallbuf has just been flushed, and resetting hasn't been
 * overridden with a delay request, then record the reset event for
 * replay.
 */
void RecordTask::maybe_reset_syscallbuf() {
  if (flushed_syscallbuf && !delay_syscallbuf_reset_for_desched &&
      !delay_syscallbuf_reset_for_seccomp_trap) {
    flushed_syscallbuf = false;
    LOG(debug) << "Syscallbuf reset";
    reset_syscallbuf();
    syscallbuf_blocked_sigs_generation = 0;
    record_event(Event::syscallbuf_reset());
  }
}

void RecordTask::record_event(const Event& ev, FlushSyscallbuf flush,
                              AllowSyscallbufReset reset,
                              const Registers* registers) {
  if (flush == FLUSH_SYSCALLBUF) {
    maybe_flush_syscallbuf();
  }

  FrameTime current_time = trace_writer().time();
  if (should_dump_memory(ev, current_time)) {
    dump_process_memory(this, current_time, "rec");
  }
  if (should_checksum(ev, current_time)) {
    checksum_process_memory(this, current_time);
  }

  if (trace_writer().clear_fip_fdp()) {
    const ExtraRegisters* maybe_extra = extra_regs_fallible();
    if (maybe_extra) {
      ExtraRegisters extra_registers = *maybe_extra;
      extra_registers.clear_fip_fdp();
      set_extra_regs(extra_registers);
    }
  }

  const ExtraRegisters* extra_registers = nullptr;
  if (ev.record_regs()) {
    if (!registers) {
      registers = &regs();
    }
    if (ev.record_extra_regs()) {
      extra_registers = &extra_regs();
    }
  }

  if (ev.is_syscall_event()) {
    auto state = ev.Syscall().state;
    if (state == EXITING_SYSCALL) {
      ticks_at_last_recorded_syscall_exit = tick_count();
      ip_at_last_recorded_syscall_exit = registers->ip();
      if (ticks_at_last_recorded_syscall_exit == ticks_at_last_syscall_entry &&
          ip_at_last_recorded_syscall_exit == ip_at_last_syscall_entry) {
        // We've done processing this syscall so we can forget about the entry now
        // This makes sure that any restarted syscalls would not be treated
        // as the same entry.
        ticks_at_last_syscall_entry = 0;
        ip_at_last_syscall_entry = nullptr;
        last_syscall_entry_recorded = false;
      }
    } else if (state == ENTERING_SYSCALL || state == ENTERING_SYSCALL_PTRACE) {
      if (tick_count() == ticks_at_last_syscall_entry &&
          registers->ip() == ip_at_last_syscall_entry) {
        // Let the process handler know that we've recorded the entry already
        last_syscall_entry_recorded = true;
      }
    }
  }

  remote_code_ptr rseq_new_ip = ip();
  bool invalid_rseq_cs = false;
  if (should_apply_rseq_abort(ev.type(), &rseq_new_ip, &invalid_rseq_cs)) {
    auto addr = REMOTE_PTR_FIELD(rseq_state->ptr.cast<typename NativeArch::rseq_t>(), rseq_cs);
    uint64_t value = 0;
    write_mem(addr, value);
    record_local(addr, &value);
  } else {
    ASSERT(this, !invalid_rseq_cs) << "Invalid rseq_cs found, not currently emulated properly by rr (should segfault)";
  }

  trace_writer().write_frame(this, ev, registers, extra_registers);
  LOG(debug) << "Wrote event " << ev << " for time " << current_time;

  if (rseq_new_ip != ip()) {
    Registers r = regs();
    r.set_ip(rseq_new_ip);
    set_regs(r);
  }

  if (!ev.has_ticks_slop() && reset == ALLOW_RESET_SYSCALLBUF) {
    // After we've output an event, it's safe to reset the syscallbuf (if not
    // explicitly delayed) since we will have exited the syscallbuf code that
    // consumed the syscallbuf data.
    // This only works if the event has a reliable tick count so when we
    // reach it, we're done.
    maybe_reset_syscallbuf();
  }
}

bool RecordTask::is_fatal_signal(int sig,
                                 SignalDeterministic deterministic) const {
  if (thread_group()->received_sigframe_SIGSEGV) {
    // Can't be blocked, caught or ignored
    return true;
  }

  auto action = default_action(sig);
  if (action != DUMP_CORE && action != TERMINATE) {
    // If the default action doesn't kill the process, it won't die.
    return false;
  }

  if (is_sig_ignored(sig)) {
    // Deterministic fatal signals can't be ignored.
    return deterministic == DETERMINISTIC_SIG;
  }
  // If there's a signal handler, the signal won't be fatal.
  return !signal_has_user_handler(sig);
}

void RecordTask::record_current_event() { record_event(ev()); }

pid_t RecordTask::find_newborn_thread() {
  ASSERT(this, session().is_recording());
  ASSERT(this, ptrace_event() == PTRACE_EVENT_CLONE);

  pid_t hint = get_ptrace_eventmsg<pid_t>();
  char path[PATH_MAX];
  sprintf(path, "/proc/%d/task/%d", tid, hint);
  struct stat stat_buf;
  // This should always succeed, but may fail in old kernels due to
  // a kernel bug. See RecordSession::handle_ptrace_event.
  if (!session().find_task(hint) && 0 == stat(path, &stat_buf)) {
    return hint;
  }

  sprintf(path, "/proc/%d/task", tid);
  DIR* dir = opendir(path);
  ASSERT(this, dir);
  while (true) {
    struct dirent* result = readdir(dir);
    ASSERT(this, result);
    char* end;
    pid_t thread_tid = strtol(result->d_name, &end, 10);
    if (*end == '\0' && !session().find_task(thread_tid)) {
      closedir(dir);
      return thread_tid;
    }
  }
}

pid_t RecordTask::find_newborn_process(pid_t child_parent) {
  ASSERT(this, session().is_recording());
  ASSERT(this,
         ptrace_event() == PTRACE_EVENT_CLONE ||
             ptrace_event() == PTRACE_EVENT_VFORK ||
             ptrace_event() == PTRACE_EVENT_FORK);

  pid_t hint = get_ptrace_eventmsg<pid_t>();
  // This should always succeed, but may fail in old kernels due to
  // a kernel bug. See RecordSession::handle_ptrace_event.
  if (!session().find_task(hint) && get_ppid(hint) == child_parent) {
    return hint;
  }

  DIR* dir = opendir("/proc");
  ASSERT(this, dir);
  while (true) {
    struct dirent* result = readdir(dir);
    ASSERT(this, result);
    char* end;
    pid_t proc_tid = strtol(result->d_name, &end, 10);
    if (*end == '\0' && !session().find_task(proc_tid) &&
        get_ppid(proc_tid) == child_parent) {
      closedir(dir);
      return proc_tid;
    }
  }
}

void RecordTask::set_tid_addr(remote_ptr<int> tid_addr) {
  LOG(debug) << "updating cleartid futex to " << tid_addr;
  tid_futex = tid_addr;
}

void RecordTask::update_own_namespace_tid() {
  AutoRemoteSyscalls remote(this);
  own_namespace_rec_tid =
      remote.infallible_syscall_if_alive(syscall_number_for_gettid(arch()));
  if (own_namespace_rec_tid == -ESRCH) {
    own_namespace_rec_tid = -1;
  }
}

void RecordTask::kill_if_alive() {
  if (!is_dying()) {
    tgkill(SIGKILL);
  }
}

pid_t RecordTask::get_parent_pid() const { return get_ppid(tid); }

void RecordTask::set_tid_and_update_serial(pid_t tid,
                                           pid_t own_namespace_tid) {
  hpc.set_tid(tid);
  this->tid = rec_tid = tid;
  serial = session().next_task_serial();
  own_namespace_rec_tid = own_namespace_tid;
}

bool RecordTask::may_reap() {
  if (emulated_stop_pending) {
    LOG(debug) << "Declining to reap " << tid << "; emulated stop pending";
    // Don't reap until the emulated ptrace stop has been processed.
    return false;
  }
  // Non thread-group-leaders may always be reaped
  if (tid != real_tgid()) {
    return true;
  }
  for (auto it : thread_group()->task_set()) {
    if (&*it != this) {
      LOG(debug) << "Declining to reap " << tid << "; leader of non-empty thread-group with active thread " << it->tid;
      return false;
    }
  }
  return true;
}

void RecordTask::reap() {
  ASSERT(this, !was_reaped);
  LOG(debug) << "Reaping " << tid;
  siginfo_t info;
  memset(&info, 0, sizeof(info));
  int ret = waitid(P_PID, tid, &info, WEXITED | WNOHANG);
  if (ret != 0) {
    FATAL() << "Unexpected wait status for tid " << tid;
  }
  /* The sid_pid == 0 case here is the same as the case below where we're the
   * group leader whose pid gets stolen.
   */
  DEBUG_ASSERT(info.si_pid == tid ||
               info.si_pid == 0);
  was_reaped = true;
}

bool RecordTask::try_wait() {
  if (wait_unexpected_exit()) {
    return true;
  }

  // Check if there is a status change for us
  WaitStatus status;
  siginfo_t info;
  memset(&info, 0, sizeof(siginfo_t));
  int ret = waitid(P_PID, tid, &info, WSTOPPED | WNOHANG);
  ASSERT(this, 0 == ret || (-1 == ret && errno == ECHILD)) <<
    "waitid(" << tid << ", WSTOPPED | NOHANG) failed with "
                         << ret;
  LOG(debug) << "waitid(" << tid << ", NOHANG) returns " << ret;
  if (ret == 0 && info.si_pid == 0) {
    return false;
  }
  if (ret == 0) {
    status = WaitStatus(info);
  } else if (ret == -1) {
    ASSERT(this, errno == ECHILD);
    // Either we died/are dying unexpectedly, or we were in exec and changed the tid.
    // Try to differentiate the two situations by seeing if there is an exit
    // notification ready for us to de-queue, in which case we synthesize an
    // exit event (but don't actually reap the task, instead leaving that
    // for the generic cleanup code).
    int ret = waitid(P_PID, tid, &info, WEXITED | WNOWAIT | WNOHANG);
    if (ret == 0) {
      if (info.si_pid == tid) {
        LOG(debug) << "Synthesizing PTRACE_EVENT_EXIT for zombie process in try_wait " << tid;
        status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
      } else {
        // This can happen when the task is in zap_pid_ns_processes waiting for all tasks
        // in the pid-namespace to exit. It's not in a signal stop, but it's also not
        // ready to be reaped yet, yet we're still tracing it. Don't wait on this
        // task, we should be able to reap it later.
        ASSERT(this, info.si_pid == 0);
        return false;
      }
    } else {
      ASSERT(this, ret == -1 && errno == ECHILD) << "waitpid failed with " << ret;
      return false;
    }
  }
  did_waitpid(status);
  return true;
}

static uint64_t read_pid_ns(const RecordTask* t) {
  char buf[PATH_MAX];
  sprintf(buf, "/proc/%d/ns/pid", t->tid);
  char link[PATH_MAX];
  int ret = readlink(buf, link, sizeof(link));
  ASSERT(t, ret >= 0);
  ASSERT(t, ret < (int)sizeof(link));
  link[ret] = 0;
  ASSERT(t, strncmp(link, "pid:[", 5) == 0);
  char* end;
  uint64_t result = strtoul(link + 5, &end, 10);
  ASSERT(t, strcmp(end, "]") == 0);
  return result;
}

bool RecordTask::waiting_for_pid_namespace_tasks_to_exit() const {
  if (tg->tgid_own_namespace != 1) {
    return false;
  }
  // This might be the last live thread for pid-1 in the pid namespace.
  // Checking that it *is* the last live thread is tricky because other
  // threads could unexpectedly die asynchronously :-(.
  // See if there are any other tasks in the pid namespace.
  // Note that due to setns there can be tasks in the pid namespace
  // with parents outside the pid namespace other than our thread-group.

  // If there are multiple threads in our threadgroup, they're in our
  // pid namespace.
  if (thread_group()->task_set().size() > 1) {
    return true;
  }
  // If we have any child processes then those belong to our pid namespace
  // (or a descendant).
  for (auto p : session().thread_group_map()) {
    if (p.second->parent() == tg.get()) {
      return true;
    }
  }
  // If there are any other tasks in the pid namespace at least one must be
  // directly in the namespace.
  uint64_t pid_ns = read_pid_ns(this);
  for (auto it : session().tasks()) {
    auto rt = static_cast<RecordTask*>(it.second);
    if (rt == this) {
      continue;
    }
    if (read_pid_ns(rt) == pid_ns) {
      return true;
    }
  }
  return false;
}

int RecordTask::process_depth() const {
  int depth = 0;
  ThreadGroup* tg = this->tg.get();
  while (tg) {
    ++depth;
    tg = tg->parent();
  }
  return depth;
}

template <typename Arch>
static void maybe_restore_original_syscall_registers_arch(RecordTask* t,
                                                          void* local_addr) {
  if (!local_addr) {
    return;
  }
  auto locals = reinterpret_cast<preload_thread_locals<Arch>*>(local_addr);
  static_assert(sizeof(*locals) <= PRELOAD_THREAD_LOCALS_SIZE,
                "bad PRELOAD_THREAD_LOCALS_SIZE");
  if (!locals->original_syscall_parameters) {
    return;
  }
  auto args = t->read_mem(locals->original_syscall_parameters.rptr());
  Registers r = t->regs();
  if (args.no != r.syscallno()) {
    // Maybe a preparatory syscall before the real syscall (e.g. sys_read)
    return;
  }
  r.set_arg1(args.args[0]);
  r.set_arg2(args.args[1]);
  r.set_arg3(args.args[2]);
  r.set_arg4(args.args[3]);
  r.set_arg5(args.args[4]);
  r.set_arg6(args.args[5]);
  t->set_regs(r);
}

void RecordTask::maybe_restore_original_syscall_registers() {
  RR_ARCH_FUNCTION(maybe_restore_original_syscall_registers_arch, arch(), this,
                   preload_thread_locals());
}

bool RecordTask::post_vm_clone(CloneReason reason, int flags, Task* origin) {
  if (Task::post_vm_clone(reason, flags, origin)) {
    KernelMapping preload_thread_locals_mapping =
      vm()->mapping_of(AddressSpace::preload_thread_locals_start()).map;
    auto mode = trace_writer().write_mapped_region(
      this, preload_thread_locals_mapping,
      preload_thread_locals_mapping.fake_stat(),
      preload_thread_locals_mapping.fsname(),
      vector<TraceRemoteFd>(),
      TraceWriter::RR_BUFFER_MAPPING);
    ASSERT(this, mode == TraceWriter::DONT_RECORD_IN_TRACE);
    return true;
  }

  return false;
};

} // namespace rr
