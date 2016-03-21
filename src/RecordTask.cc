/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RecordTask.h"

#include <dirent.h>
#include <limits.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>

#include "AutoRemoteSyscalls.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"
#include "RecordSession.h"
#include "record_signal.h"

using namespace rr;
using namespace std;

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
    assert(uintptr_t(SIG_DFL) == 0);
    init_arch<Arch>(ksa);
  }

  bool ignored(int sig) const {
    if (sig == SIGSTOP || sig == SIGKILL) {
      // These can never be ignored
      return false;
    }
    return (uintptr_t)SIG_IGN == k_sa_handler.as_int() ||
           ((uintptr_t)SIG_DFL == k_sa_handler.as_int() &&
            IGNORE == default_action(sig));
  }
  bool is_default() const {
    return (uintptr_t)SIG_DFL == k_sa_handler.as_int() && !resethand;
  }
  bool is_user_handler() const {
    assert(1 == uintptr_t(SIG_IGN));
    return k_sa_handler.as_int() & ~(uintptr_t)SIG_IGN;
  }
  remote_code_ptr get_user_handler() const {
    return is_user_handler() ? remote_code_ptr(k_sa_handler.as_int())
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
    for (size_t i = 0; i < array_length(handlers); ++i) {
      Sighandler& h = handlers[i];

      NativeArch::kernel_sigaction sa;
      if (::syscall(SYS_rt_sigaction, i, nullptr, &sa, sizeof(sigset_t))) {
        /* EINVAL means we're querying an
         * unused signal number. */
        assert(EINVAL == errno);
        assert(h.is_default());
        continue;
      }

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
      if (h.is_user_handler()) {
        reset_handler(&h, arch);
      }
    }
  }

  void assert_valid(int sig) const {
    assert(0 < sig && sig < ssize_t(array_length(handlers)));
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
      time_at_start_of_last_timeslice(0),
      priority(0),
      in_round_robin_queue(false),
      emulated_ptracer(nullptr),
      emulated_ptrace_stop_code(0),
      emulated_ptrace_SIGCHLD_pending(false),
      in_wait_type(WAIT_TYPE_NONE),
      in_wait_pid(0),
      emulated_stop_type(NOT_STOPPED),
      blocked_sigs(),
      flushed_num_rec_bytes(0),
      flushed_syscallbuf(false),
      delay_syscallbuf_reset(false),
      seccomp_bpf_enabled(false),
      prctl_seccomp_status(0),
      robust_futex_list_len(0),
      own_namespace_rec_tid(0) {
  if (session.tasks().empty()) {
    // Initial tracee. It inherited its state from this process, so set it up.
    // The very first task we fork inherits the signal
    // dispositions of the current OS process (which should all be
    // default at this point, but ...).  From there on, new tasks
    // will transitively inherit from this first task.
    auto sh = Sighandlers::create();
    sh->init_from_current_process();
    sighandlers.swap(sh);
    // Don't use the POSIX wrapper, because it doesn't necessarily
    // read the entire sigset tracked by the kernel.
    if (::syscall(SYS_rt_sigprocmask, SIG_SETMASK, nullptr, &blocked_sigs,
                  sizeof(blocked_sigs))) {
      FATAL() << "Failed to read blocked signals";
    }
  }
}

RecordTask::~RecordTask() {
  if (emulated_ptracer) {
    emulated_ptracer->emulated_ptrace_tracees.erase(this);
  }
  for (RecordTask* t : emulated_ptrace_tracees) {
    // XXX emulate PTRACE_O_EXITKILL
    ASSERT(this, t->emulated_ptracer == this);
    t->emulated_ptracer = nullptr;
    t->emulated_stop_type = NOT_STOPPED;
  }

  // Task::destroy has already done PTRACE_DETACH so the task can complete
  // exiting.
  // The kernel explicitly only clears the futex if the address space is shared.
  // If the address space has no other users then the futex will not be cleared
  // even if it lives in shared memory which other tasks can read.
  // Unstable exits may result in the kernel *not* clearing the
  // futex, for example for fatal signals.  So we would
  // deadlock waiting on the futex.
  if (!unstable && !tid_futex.is_null() && as->task_set().size() > 1) {
    // clone()'d tasks can have a pid_t* |ctid| argument
    // that's written with the new task's pid.  That
    // pointer can also be used as a futex: when the task
    // dies, the original ctid value is cleared and a
    // FUTEX_WAKE is done on the address. So
    // pthread_join() is basically a standard futex wait
    // loop.
    LOG(debug) << "  waiting for tid futex " << tid_futex
               << " to be cleared ...";
    bool ok = true;
    futex_wait(tid_futex, 0, &ok);
    if (ok) {
      int val = 0;
      record_local(tid_futex, &val);
    }
  }

  // Write the exit event here so that the value recorded above is captured.
  EventType ev = unstable ? EV_UNSTABLE_EXIT : EV_EXIT;
  record_event(Event(ev, NO_EXEC_INFO, arch()));
}

void RecordTask::futex_wait(remote_ptr<int> futex, int val, bool* ok) {
  // Wait for *sync_addr == sync_val.  This implementation isn't
  // pretty, but it's pretty much the best we can do with
  // available kernel tools.
  //
  // TODO: find clever way to avoid busy-waiting.
  while (true) {
    int mem = read_mem(futex, ok);
    if (!*ok || val == mem) {
      // Invalid addresses are just ignored by the kernel
      break;
    }
    // Try to give our scheduling slot to the kernel
    // thread that's going to write sync_addr.
    sched_yield();
  }
}

RecordSession& RecordTask::session() const {
  return *Task::session().as_record();
}

Task* RecordTask::clone(int flags, remote_ptr<void> stack, remote_ptr<void> tls,
                        remote_ptr<int> cleartid_addr, pid_t new_tid,
                        pid_t new_rec_tid, uint32_t new_serial,
                        Session* other_session) {
  Task* t = Task::clone(flags, stack, tls, cleartid_addr, new_tid, new_rec_tid,
                        new_serial, other_session);
  if (t->session().is_recording()) {
    RecordTask* rt = static_cast<RecordTask*>(t);
    rt->priority = priority;
    rt->blocked_sigs = blocked_sigs;
    rt->prctl_seccomp_status = prctl_seccomp_status;
    rt->robust_futex_list = robust_futex_list;
    rt->robust_futex_list_len = robust_futex_list_len;
    if (CLONE_SHARE_SIGHANDLERS & flags) {
      rt->sighandlers = sighandlers;
    } else {
      auto sh = sighandlers->clone();
      rt->sighandlers.swap(sh);
    }
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

static string exe_path(RecordTask* t) {
  char proc_exe[PATH_MAX];
  snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", t->tid);
  char exe[PATH_MAX];
  ssize_t ret = readlink(proc_exe, exe, sizeof(exe) - 1);
  ASSERT(t, ret >= 0);
  exe[ret] = 0;
  return exe;
}

static SupportedArch determine_arch(RecordTask* t, const string& file_name) {
  ASSERT(t, file_name.size() > 0);
  switch (read_elf_class(file_name)) {
    case ELFCLASS32:
      return x86;
    case ELFCLASS64:
      ASSERT(t, NativeArch::arch() == x86_64) << "64-bit tracees not supported";
      return x86_64;
    case NOT_ELF:
      // Probably a script. Optimistically assume the same architecture as
      // the rr binary.
      return NativeArch::arch();
    default:
      ASSERT(t, false) << "Unknown ELF class";
      return x86;
  }
}

void RecordTask::post_exec() {
  string exe_file = exe_path(this);
  Task::post_exec(determine_arch(this, exe_file), exe_file);

  // Clear robust_list state to match kernel state. If this task is cloned
  // soon after exec, we must not do a bogus set_robust_list syscall for
  // the clone.
  set_robust_list(nullptr, 0);
  sighandlers = sighandlers->clone();
  sighandlers->reset_user_handlers(arch());
}

template <typename Arch> static void do_preload_init_arch(RecordTask* t) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<Arch> >(t->regs().arg1()));

  int cores = t->session().scheduler().pretend_num_cores();
  t->write_mem(params.pretend_num_cores.rptr(), cores);
  t->record_local(params.pretend_num_cores.rptr(), &cores);
}

static void do_preload_init(RecordTask* t) {
  RR_ARCH_FUNCTION(do_preload_init_arch, t->arch(), t);
}

void RecordTask::at_preload_init() {
  Task::at_preload_init();
  do_preload_init(this);
}

void RecordTask::init_buffers(remote_ptr<void> map_hint) {
  Task::init_buffers(map_hint);
  if (vm()->syscallbuf_enabled()) {
    AutoRemoteSyscalls remote(this);
    desched_fd = remote.retrieve_fd(desched_fd_child);
  }
}

template <typename Arch>
void RecordTask::on_syscall_exit_arch(int syscallno, const Registers& regs) {
  if (regs.syscall_failed()) {
    return;
  }

  switch (syscallno) {
    case Arch::set_robust_list:
      set_robust_list(regs.arg1(), (size_t)regs.arg2());
      return;
    case Arch::sigaction:
    case Arch::rt_sigaction:
      // TODO: SYS_signal
      update_sigaction(regs);
      return;
    case Arch::sigprocmask:
    case Arch::rt_sigprocmask:
      update_sigmask(regs);
      return;
    case Arch::set_tid_address:
      set_tid_addr(regs.arg1());
      return;
  }
}

void RecordTask::on_syscall_exit(int syscallno, const Registers& regs) {
  Task::on_syscall_exit(syscallno, regs);
  RR_ARCH_FUNCTION(on_syscall_exit_arch, arch(), syscallno, regs)
}

void RecordTask::set_emulated_ptracer(RecordTask* tracer) {
  if (tracer) {
    ASSERT(this, !emulated_ptracer);
    emulated_ptracer = tracer;
    emulated_ptracer->emulated_ptrace_tracees.insert(this);
  } else {
    ASSERT(this, emulated_ptracer);
    ASSERT(this, emulated_stop_type == NOT_STOPPED ||
                     emulated_stop_type == GROUP_STOP);
    emulated_ptracer->emulated_ptrace_tracees.erase(this);
    emulated_ptracer = nullptr;
  }
}

bool RecordTask::emulate_ptrace_stop(int code, EmulatedStopType stop_type) {
  ASSERT(this, emulated_stop_type == NOT_STOPPED);
  ASSERT(this, stop_type != NOT_STOPPED);
  if (!emulated_ptracer) {
    return false;
  }
  force_emulate_ptrace_stop(code, stop_type);
  return true;
}

void RecordTask::force_emulate_ptrace_stop(int code,
                                           EmulatedStopType stop_type) {
  emulated_stop_type = stop_type;
  emulated_ptrace_stop_code = code;
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

void RecordTask::send_synthetic_SIGCHLD_if_necessary() {
  RecordTask* wake_task = nullptr;
  bool need_signal = false;
  for (RecordTask* tracee : emulated_ptrace_tracees) {
    if (tracee->emulated_ptrace_SIGCHLD_pending) {
      need_signal = true;
      // check to see if any thread in the ptracer process is in a waitpid that
      // could read the status of 'tracee'. If it is, we should wake up that
      // thread. Otherwise we send SIGCHLD to the ptracer thread.
      for (Task* t : task_group()->task_set()) {
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
    return;
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
    ASSERT(wake_task, !wake_task->is_sig_blocked(SIGCHLD))
        << "Waiting task has SIGCHLD blocked so we have no way to wake it up "
           ":-(";
    // We must use the raw SYS_rt_tgsigqueueinfo syscall here to ensure the
    // signal is sent to the correct thread by tid.
    ret = syscall(SYS_rt_tgsigqueueinfo, wake_task->tgid(), wake_task->tid,
                  SIGCHLD, &si);
    LOG(debug) << "Sending synthetic SIGCHLD to tid " << wake_task->tid;
  } else {
    // Send the signal to the process as a whole and let the kernel
    // decide which thread gets it.
    ret = syscall(SYS_rt_sigqueueinfo, tgid(), SIGCHLD, &si);
    LOG(debug) << "Sending synthetic SIGCHLD to pid " << tgid();
  }
  ASSERT(this, ret == 0);
}

void RecordTask::set_siginfo_for_synthetic_SIGCHLD(siginfo_t* si) {
  if (si->si_signo != SIGCHLD || si->si_value.sival_int != SIGCHLD_SYNTHETIC) {
    return;
  }

  for (RecordTask* tracee : emulated_ptrace_tracees) {
    if (tracee->emulated_ptrace_SIGCHLD_pending) {
      tracee->emulated_ptrace_SIGCHLD_pending = false;
      si->si_code = CLD_TRAPPED;
      si->si_pid = tracee->tgid();
      si->si_uid = tracee->getuid();
      si->si_status = WSTOPSIG(tracee->emulated_ptrace_stop_code);
      si->si_value.sival_int = 0;
      return;
    }
  }
}

bool RecordTask::is_waiting_for_ptrace(RecordTask* t) {
  // This task's process must be a ptracer of t.
  if (!t->emulated_ptracer ||
      t->emulated_ptracer->task_group() != task_group()) {
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
  if (t->task_group()->parent() != task_group().get()) {
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

void RecordTask::signal_delivered(int sig) {
  Sighandler& h = sighandlers->get(sig);
  bool is_user_handler = h.is_user_handler();
  if (h.resethand) {
    reset_handler(&h, arch());
  }

  if (!h.ignored(sig)) {
    switch (sig) {
      case SIGTSTP:
      case SIGTTIN:
      case SIGTTOU:
        if (is_user_handler) {
          break;
        }
      // Fall through...
      case SIGSTOP:
        // All threads in the process are stopped.
        for (Task* t : task_group()->task_set()) {
          auto rt = static_cast<RecordTask*>(t);
          LOG(debug) << "setting " << tid << " to GROUP_STOP due to signal "
                     << sig;
          rt->emulated_stop_type = GROUP_STOP;
        }
        break;
      case SIGCONT:
        // All threads in the process are resumed.
        for (Task* t : task_group()->task_set()) {
          auto rt = static_cast<RecordTask*>(t);
          LOG(debug) << "setting " << tid << " to NOT_STOPPED due to signal "
                     << sig;
          rt->emulated_stop_type = NOT_STOPPED;
        }
        break;
    }
  }

  send_synthetic_SIGCHLD_if_necessary();
}

bool RecordTask::signal_has_user_handler(int sig) const {
  return sighandlers->get(sig).is_user_handler();
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

bool RecordTask::is_sig_blocked(int sig) const {
  int sig_bit = sig - 1;
  if (sigsuspend_blocked_sigs) {
    return (*sigsuspend_blocked_sigs >> sig_bit) & 1;
  }
  return (blocked_sigs >> sig_bit) & 1;
}

void RecordTask::set_sig_blocked(int sig) {
  int sig_bit = sig - 1;
  blocked_sigs |= (sig_set_t)1 << sig_bit;
}

bool RecordTask::is_sig_ignored(int sig) const {
  return sighandlers->get(sig).ignored(sig);
}

template <typename Arch>
void RecordTask::update_sigaction_arch(const Registers& regs) {
  int sig = regs.arg1_signed();
  remote_ptr<typename Arch::kernel_sigaction> new_sigaction = regs.arg2();
  if (0 == regs.syscall_result() && !new_sigaction.is_null()) {
    // A new sighandler was installed.  Update our
    // sighandler table.
    // TODO: discard attempts to handle or ignore signals
    // that can't be by POSIX
    typename Arch::kernel_sigaction sa;
    size_t sigset_size = min(sizeof(typename Arch::sigset_t), regs.arg4());
    memset(&sa, 0, sizeof(sa));
    read_bytes_helper(
        new_sigaction,
        sizeof(sa) - (sizeof(typename Arch::sigset_t) - sigset_size), &sa);
    sighandlers->get(sig).init_arch<Arch>(sa);
  }
}

void RecordTask::update_sigaction(const Registers& regs) {
  RR_ARCH_FUNCTION(update_sigaction_arch, regs.arch(), regs);
}

void RecordTask::update_sigmask(const Registers& regs) {
  int how = regs.arg1_signed();
  remote_ptr<sig_set_t> setp = regs.arg2();

  if (regs.syscall_failed() || !setp) {
    return;
  }

  auto set = read_mem(setp);

  // Update the blocked signals per |how|.
  switch (how) {
    case SIG_BLOCK:
      blocked_sigs |= set;
      break;
    case SIG_UNBLOCK:
      blocked_sigs &= ~set;
      break;
    case SIG_SETMASK:
      blocked_sigs = set;
      break;
    default:
      FATAL() << "Unknown sigmask manipulator " << how;
  }
}

void RecordTask::stash_sig() {
  int sig = pending_sig();
  ASSERT(this, sig);
  // Callers should avoid passing SYSCALLBUF_DESCHED_SIGNAL in here.
  ASSERT(this, sig != SYSCALLBUF_DESCHED_SIGNAL);
  // multiple non-RT signals coalesce
  if (sig < SIGRTMIN) {
    for (auto it = stashed_signals.begin(); it != stashed_signals.end(); ++it) {
      if (it->si_signo == sig) {
        LOG(debug) << "discarding stashed signal " << sig
                   << " since we already have one pending";
        return;
      }
    }
  }

  const siginfo_t& si = get_siginfo();
  stashed_signals.push_back(si);
  wait_status = 0;
}

void RecordTask::stash_synthetic_sig(const siginfo_t& si) {
  int sig = si.si_signo;
  assert(sig);
  // Callers should avoid passing SYSCALLBUF_DESCHED_SIGNAL in here.
  assert(sig != SYSCALLBUF_DESCHED_SIGNAL);
  // multiple non-RT signals coalesce
  if (sig < SIGRTMIN) {
    for (auto it = stashed_signals.begin(); it != stashed_signals.end(); ++it) {
      if (it->si_signo == sig) {
        LOG(debug) << "discarding stashed signal " << sig
                   << " since we already have one pending";
        return;
      }
    }
  }

  stashed_signals.push_back(si);
}

void RecordTask::pop_stash_sig() {
  assert(has_stashed_sig());
  stashed_signals.pop_front();
}

siginfo_t RecordTask::peek_stash_sig() {
  assert(has_stashed_sig());
  return stashed_signals.front();
}

bool RecordTask::is_syscall_restart() {
  int syscallno = regs().original_syscallno();
  bool is_restart = false;

  LOG(debug) << "  is syscall interruption of recorded " << ev() << "? (now "
             << syscall_name(syscallno) << ")";

  if (EV_SYSCALL_INTERRUPTION != ev().type()) {
    goto done;
  }

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
  if (is_restart_syscall_syscall(syscallno, arch())) {
    is_restart = true;
    syscallno = ev().Syscall().number;
    LOG(debug) << "  (SYS_restart_syscall)";
  }
  if (ev().Syscall().number != syscallno) {
    LOG(debug) << "  interrupted " << ev() << " != " << syscall_name(syscallno);
    goto done;
  }

  {
    const Registers& old_regs = ev().Syscall().regs;
    if (!(old_regs.arg1() == regs().arg1() &&
          old_regs.arg2() == regs().arg2() &&
          old_regs.arg3() == regs().arg3() &&
          old_regs.arg4() == regs().arg4() &&
          old_regs.arg5() == regs().arg5() &&
          old_regs.arg6() == regs().arg6())) {
      LOG(debug) << "  regs different at interrupted "
                 << syscall_name(syscallno);
      goto done;
    }
  }

  is_restart = true;

done:
  if (is_restart) {
    LOG(debug) << "  restart of " << syscall_name(syscallno);
  }
  return is_restart;
}

bool RecordTask::at_may_restart_syscall() const {
  ssize_t depth = pending_events.size();
  const Event* prev_ev = depth > 2 ? &pending_events[depth - 2] : nullptr;
  return EV_SYSCALL_INTERRUPTION == ev().type() ||
         (EV_SIGNAL_DELIVERY == ev().type() && prev_ev &&
          EV_SYSCALL_INTERRUPTION == prev_ev->type());
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
         emulated_stop_type != NOT_STOPPED;
}

bool RecordTask::maybe_in_spinlock() {
  return time_at_start_of_last_timeslice == session().trace_writer().time() &&
         regs().matches(registers_at_start_of_last_timeslice);
}

const struct syscallbuf_record* RecordTask::desched_rec() const {
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

void RecordTask::record_local(remote_ptr<void> addr, ssize_t num_bytes,
                              const void* data) {
  maybe_flush_syscallbuf();

  ASSERT(this, num_bytes >= 0);

  if (!addr) {
    return;
  }

  trace_writer().write_raw(data, num_bytes, addr);
}

void RecordTask::record_remote(remote_ptr<void> addr, ssize_t num_bytes) {
  maybe_flush_syscallbuf();

  // We shouldn't be recording a scratch address.
  ASSERT(this, !addr || addr != scratch_ptr);

  assert(num_bytes >= 0);

  if (!addr) {
    return;
  }

  auto buf = read_mem(addr.cast<uint8_t>(), num_bytes);
  trace_writer().write_raw(buf.data(), num_bytes, addr);
}

void RecordTask::record_remote_fallible(remote_ptr<void> addr,
                                        ssize_t num_bytes) {
  maybe_flush_syscallbuf();

  // We shouldn't be recording a scratch address.
  ASSERT(this, !addr || addr != scratch_ptr);
  ASSERT(this, num_bytes >= 0);

  vector<uint8_t> buf;
  if (!addr.is_null()) {
    buf.resize(num_bytes);
    ssize_t nread = read_bytes_fallible(addr, num_bytes, buf.data());
    buf.resize(max<ssize_t>(0, nread));
  }
  trace_writer().write_raw(buf.data(), buf.size(), addr);
}

void RecordTask::record_remote_even_if_null(remote_ptr<void> addr,
                                            ssize_t num_bytes) {
  maybe_flush_syscallbuf();

  // We shouldn't be recording a scratch address.
  ASSERT(this, !addr || addr != scratch_ptr);

  assert(num_bytes >= 0);

  if (!addr) {
    trace_writer().write_raw(nullptr, 0, addr);
    return;
  }

  auto buf = read_mem(addr.cast<uint8_t>(), num_bytes);
  trace_writer().write_raw(buf.data(), num_bytes, addr);
}

void RecordTask::maybe_flush_syscallbuf() {
  if (EV_SYSCALLBUF_FLUSH == ev().type()) {
    // Already flushing.
    return;
  }
  if (!syscallbuf_hdr) {
    return;
  }

  // This can be called while the task is not stopped, when we prematurely
  // terminate the trace. In that case, the tracee could be concurrently
  // modifying the header. We'll take a snapshot of the header now.
  // The syscallbuf code ensures that writes to syscallbuf records
  // complete before num_rec_bytes is incremented.
  struct syscallbuf_hdr hdr = *syscallbuf_hdr;

  ASSERT(this,
         !flushed_syscallbuf || flushed_num_rec_bytes == hdr.num_rec_bytes);

  if (!hdr.num_rec_bytes || flushed_syscallbuf) {
    // no records, or we've already flushed.
    return;
  }

  // Write the entire buffer in one shot without parsing it,
  // because replay will take care of that.
  push_event(Event(EV_SYSCALLBUF_FLUSH, NO_EXEC_INFO, arch()));
  if (is_running()) {
    vector<uint8_t> buf;
    buf.resize(sizeof(hdr) + hdr.num_rec_bytes);
    memcpy(buf.data(), &hdr, sizeof(hdr));
    memcpy(buf.data() + sizeof(hdr), syscallbuf_hdr + 1, hdr.num_rec_bytes);
    record_local(syscallbuf_child, buf.size(), buf.data());
  } else {
    record_local(syscallbuf_child, syscallbuf_data_size(), syscallbuf_hdr);
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
  if (flushed_syscallbuf && !delay_syscallbuf_reset) {
    flushed_syscallbuf = false;
    LOG(debug) << "Syscallbuf reset";
    reset_syscallbuf();
    record_event(Event(EV_SYSCALLBUF_RESET, NO_EXEC_INFO, arch()));
  }
}

static bool record_extra_regs(const Event& ev) {
  switch (ev.type()) {
    case EV_SYSCALL:
      // sigreturn/rt_sigreturn restores register state
      return ev.Syscall().state == EXITING_SYSCALL &&
             (is_sigreturn(ev.Syscall().number, ev.arch()) ||
              is_execve_syscall(ev.Syscall().number, ev.arch()));
    case EV_SIGNAL_HANDLER:
      // entering a signal handler seems to clear FP/SSE regs,
      // so record these effects.
      return true;
    default:
      return false;
  }
}

void RecordTask::record_event(const Event& ev, FlushSyscallbuf flush) {
  if (flush == FLUSH_SYSCALLBUF) {
    maybe_flush_syscallbuf();
  }

  TraceFrame frame(trace_writer().time(), tid, ev, tick_count());
  if (ev.record_exec_info() == HAS_EXEC_INFO) {
    PerfCounters::Extra extra_perf_values;
    if (PerfCounters::extra_perf_counters_enabled()) {
      extra_perf_values = hpc.read_extra();
    }
    frame.set_exec_info(regs(), PerfCounters::extra_perf_counters_enabled()
                                    ? &extra_perf_values
                                    : nullptr,
                        record_extra_regs(ev) ? &extra_regs() : nullptr);
  }

  if (should_dump_memory(frame)) {
    dump_process_memory(this, frame.time(), "rec");
  }
  if (should_checksum(frame)) {
    checksum_process_memory(this, frame.time());
  }

  trace_writer().write_frame(frame);

  if (!ev.has_ticks_slop()) {
    ASSERT(this, flush == FLUSH_SYSCALLBUF);
    // After we've output an event, it's safe to reset the syscallbuf (if not
    // explicitly delayed) since we will have exited the syscallbuf code that
    // consumed the syscallbuf data.
    // This only works if the event has a reliable tick count so when we
    // reach it, we're done.
    maybe_reset_syscallbuf();
  }
}

void RecordTask::record_current_event() { record_event(ev()); }

pid_t RecordTask::find_newborn_thread() {
  ASSERT(this, session().is_recording());
  ASSERT(this, ptrace_event() == PTRACE_EVENT_CLONE);

  pid_t hint = get_ptrace_eventmsg_pid();
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
    struct dirent* result;
    struct dirent entry;
    int ret = readdir_r(dir, &entry, &result);
    ASSERT(this, !ret && result == &entry);
    char* end;
    pid_t thread_tid = strtol(entry.d_name, &end, 10);
    if (*end == '\0' && !session().find_task(thread_tid)) {
      closedir(dir);
      return thread_tid;
    }
  }
}

static bool is_ppid_of(pid_t ppid, pid_t pid) {
  char path[PATH_MAX];
  sprintf(path, "/proc/%d/status", pid);
  FILE* status = fopen(path, "r");
  if (!status) {
    return false;
  }
  while (true) {
    char line[1024];
    if (!fgets(line, sizeof(line), status)) {
      fclose(status);
      return false;
    }
    if (strncmp(line, "PPid:", 5) == 0) {
      fclose(status);
      char* end;
      int actual_ppid = strtol(line + 5, &end, 10);
      return *end == '\n' && actual_ppid == ppid;
    }
  }
}

pid_t RecordTask::find_newborn_child_process() {
  ASSERT(this, session().is_recording());
  ASSERT(this, ptrace_event() == PTRACE_EVENT_CLONE ||
                   ptrace_event() == PTRACE_EVENT_FORK);

  pid_t hint = get_ptrace_eventmsg_pid();
  // This should always succeed, but may fail in old kernels due to
  // a kernel bug. See RecordSession::handle_ptrace_event.
  if (!session().find_task(hint) && is_ppid_of(real_tgid(), hint)) {
    return hint;
  }

  DIR* dir = opendir("/proc");
  ASSERT(this, dir);
  while (true) {
    struct dirent* result;
    struct dirent entry;
    int ret = readdir_r(dir, &entry, &result);
    ASSERT(this, !ret && result == &entry);
    char* end;
    pid_t proc_tid = strtol(entry.d_name, &end, 10);
    if (*end == '\0' && !session().find_task(proc_tid) &&
        is_ppid_of(real_tgid(), proc_tid)) {
      closedir(dir);
      return proc_tid;
    }
  }
}

void RecordTask::set_tid_addr(remote_ptr<int> tid_addr) {
  LOG(debug) << "updating cleartid futex to " << tid_addr;
  tid_futex = tid_addr;
}

void RecordTask::tgkill(int sig) {
  ASSERT(this, 0 == syscall(SYS_tgkill, real_tgid(), tid, sig));
}
