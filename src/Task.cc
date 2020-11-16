/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <errno.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/elf.h>
#include <linux/ipc.h>
#include <linux/net.h>
#include <linux/perf_event.h>
#include <linux/prctl.h>
#include <linux/unistd.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>

#include <limits>
#include <set>
#include <sstream>

#include <rr/rr.h>

#include "Task.h"

#include "preload/preload_interface.h"

#include "AutoRemoteSyscalls.h"
#include "CPUIDBugDetector.h"
#include "Flags.h"
#include "MagicSaveDataMonitor.h"
#include "PreserveFileMonitor.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "ScopedFd.h"
#include "StdioMonitor.h"
#include "StringVectorToCharArray.h"
#include "ThreadDb.h"
#include "fast_forward.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "kernel_supplement.h"
#include "log.h"
#include "record_signal.h"
#include "seccomp-bpf.h"
#include "util.h"

using namespace std;

namespace rr {

static const unsigned int NUM_X86_DEBUG_REGS = 8;
static const unsigned int NUM_X86_WATCHPOINTS = 4;

Task::Task(Session& session, pid_t _tid, pid_t _rec_tid, uint32_t serial,
           SupportedArch a)
    : scratch_ptr(),
      scratch_size(),
      // This will be initialized when the syscall buffer is.
      desched_fd_child(-1),
      // This will be initialized when the syscall buffer is.
      cloned_file_data_fd_child(-1),
      hpc(_tid, session.ticks_semantics()),
      tid(_tid),
      rec_tid(_rec_tid > 0 ? _rec_tid : _tid),
      syscallbuf_size(0),
      serial(serial),
      prname("???"),
      ticks(0),
      registers(a),
      how_last_execution_resumed(RESUME_CONT),
      last_resume_orig_cx(0),
      did_set_breakpoint_after_cpuid(false),
      is_stopped(false),
      seccomp_bpf_enabled(false),
      detected_unexpected_exit(false),
      registers_dirty(false),
      orig_syscallno_dirty(false),
      extra_registers(a),
      extra_registers_known(false),
      session_(&session),
      top_of_stack(),
      seen_ptrace_exit_event(false),
      handled_ptrace_exit_event(false),
      expecting_ptrace_interrupt_stop(0),
      was_reaped(false) {
  memset(&thread_locals, 0, sizeof(thread_locals));
}

void Task::detach() {
  LOG(debug) << "detaching from Task " << tid << " (rec:" << rec_tid << ")";

  fallible_ptrace(PTRACE_DETACH, nullptr, nullptr);

  // Not really, but there's also no reason to actually try to reap it,
  // since we detached.
  was_reaped = true;
}

void Task::reenable_cpuid_tsc() {
  AutoRemoteSyscalls remote(this);
  if (session().has_cpuid_faulting()) {
    remote.infallible_syscall(syscall_number_for_arch_prctl(arch()),
                          ARCH_SET_CPUID, 1);
  }
  remote.infallible_syscall(syscall_number_for_prctl(arch()),
                        PR_SET_TSC, PR_TSC_ENABLE);
}

bool Task::may_reap() {
  // Non thread-group-leaders may always be reaped
  if (tid != real_tgid()) {
    return true;
  }
  if (thread_group()->task_set().size() > 1) {
    return false;
  }
  return true;
}

void Task::reap() {
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

void Task::wait_exit() {
  siginfo_t info;
  LOG(debug) << "Waiting for exit of " << tid;
  /* We want to wait for the child to exit, but we don't actually
   * want to reap the task when it's dead. We could use WEXITED | WNOWAIT,
   * but that would hang if `t` is a thread-group-leader of a thread group
   * that has other still-running threads. Instead, we wait for WSTOPPED, but
   * we know that there is no possibility for the task to stop between now and
   * its exit, at which point the system call will return with -ECHILD.
   * There is one exception: If there was a simultaneous exec from another
   * thread, and this is the group leader, then this task may lose its pid
   * as soon as it enters the zombie state, causing `tid` to refer to the
   * newly-execed thread and us getting a PTRACE_EVENT_EXEC instead. To account
   * for this we add `| WNOWAIT` to prevent dequeing the event and simply take
   * it as an indication that the task has execed.
   */
  int ret = waitid(P_PID, tid, &info, WSTOPPED | WNOWAIT);
  if (ret == 0) {
    ASSERT(this, info.si_pid == tid) << "Expected " << tid << " got " << info.si_pid;
    if (WaitStatus(info).ptrace_event() == PTRACE_EVENT_EXIT) {
      // It's possible that the earlier exit event was synthetic, in which
      // case we're only now catching up to the real process exit. In that
      // case, just ask the process to actually exit. (TODO: We may want to
      // catch this earlier).
      return proceed_to_exit(true);
    }
    ASSERT(this, WaitStatus(info).ptrace_event() == PTRACE_EVENT_EXEC)
      << "Expected PTRACE_EVENT_EXEC, got " << WaitStatus(info);
    // The kernel will do the reaping for us in this case
    was_reaped = true;
  } else {
    ASSERT(this, ret == -1 && errno == ECHILD) << "Got ret=" << ret << " errno=" << errno;
  }
}

void Task::proceed_to_exit(bool wait) {
  LOG(debug) << "Advancing tid " << tid << " to exit";
  int ret = fallible_ptrace(PTRACE_CONT, nullptr, nullptr);
  ASSERT(this, ret == 0 || (ret == -1 && errno == ESRCH))
    << "Got ret=" << ret << " errno=" << errno;
  if (wait) {
    wait_exit();
  }
}

WaitStatus Task::kill() {
  if (already_reaped()) {
    return this->status();
  }
  /* This call is racy. There is basically three situations:
  * 1. By the time the kernel gets arround to delivering this signal,
  *    we were already in a PTRACE_EVENT_EXIT stop (e.g. due to an earlier
  *    fatal signal or group exit from a sibling task that the kernel
  *    didn't report to us yet), that we didn't observe yet (if we had, we
  *    would have removed the task from the task map already). In this case,
  *    this signal will advance from the PTRACE_EVENT_EXIT and put the child
  *    into hidden-zombie state, which the waitpid below will reap.
  * 2. The task was in a coredump wait. This situation essentially works the
  *    same as 1, but the final exit status will be some other fatal signal.
  * 3. Anything else basically. The signal will take priority and put us
  *    into the PTRACE_EVENT_EXIT stop, which the subsequent waitpid will
  *    then observe.
  */
  LOG(debug) << "Sending SIGKILL to " << tid;
  int ret = syscall(SYS_tgkill, real_tgid(), tid, SIGKILL);
  DEBUG_ASSERT(ret == 0);
  int raw_status = -1;
  int wait_ret = ::waitpid(tid, &raw_status, __WALL | WUNTRACED);
  WaitStatus status = WaitStatus(raw_status);
  LOG(debug) << " -> " << status;
  bool is_exit_event = status.ptrace_event() == PTRACE_EVENT_EXIT;
  DEBUG_ASSERT(wait_ret == tid &&
    (is_exit_event || status.type() == WaitStatus::FATAL_SIGNAL ||
      status.type() == WaitStatus::EXIT));
  did_kill();
  if (is_exit_event) {
    /* If this is the exit event, we can detach here and the task will
      * continue to zombie state for its parent to reap. If we're not in
      * the exit event, we already reaped it from the ptrace perspective,
      * which implicitly detached.
      */
    if (ptrace_if_alive(PTRACE_GETEVENTMSG, nullptr, &raw_status)) {
      status = WaitStatus(raw_status);
    } else {
      status = WaitStatus::for_fatal_sig(SIGKILL);
    }
    int ret = fallible_ptrace(PTRACE_DETACH, nullptr, nullptr);
    DEBUG_ASSERT(ret == 0 || (ret == -1 && errno == ESRCH));
    if (ret == -1) {
      /* It's possible for the above ptrace to fail with ESRCH. How?
      * It's the other side of the race described above. If an external
      * process issues an additional SIGKILL, we will advance from the
      * ptrace exit event and we might still be processing the exit, just
      * as the detach request comes in. To address this, we waitpid again,
      * which will reap/detach us from ptrace and frees the real parent to
      * do its reaping. */
      raw_status = 0;
      wait_ret = ::waitpid(tid, &raw_status, __WALL | WUNTRACED);
      status = WaitStatus(raw_status);
      LOG(debug) << " --> " << status;
      DEBUG_ASSERT(wait_ret == tid && status.fatal_sig() == SIGKILL);
    }
  } else {
    was_reaped = true;
  }
  return status;
}

Task::~Task() {
  ASSERT(this, seen_ptrace_exit_event);
  ASSERT(this, handled_ptrace_exit_event);
  ASSERT(this, syscallbuf_child.is_null());

  if (!session().is_recording() && !already_reaped()) {
    // Reap the zombie.
    int ret = waitpid(tid, NULL, __WALL);
    if (ret == -1) {
      ASSERT(this, errno == ECHILD || errno == ESRCH);
    } else {
      ASSERT(this, ret == tid);
    }
  }

  session().on_destroy(this);
  tg->erase_task(this);
  as->erase_task(this);
  fds->erase_task(this);

  LOG(debug) << "  dead";
}

void Task::finish_emulated_syscall() {
  // XXX verify that this can't be interrupted by a breakpoint trap
  Registers r = regs();

  // Passing RESUME_NO_TICKS here is not only a small performance optimization,
  // but also avoids counting an event if the instruction immediately following
  // a syscall instruction is a conditional branch.
  resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);

  set_regs(r);
  wait_status = WaitStatus();
}

void Task::dump(FILE* out) const {
  out = out ? out : stderr;
  stringstream ss;
  ss << wait_status;
  fprintf(out, "  %s(tid:%d rec_tid:%d status:0x%s)<%p>\n", prname.c_str(),
          tid, rec_tid, ss.str().c_str(), this);
  if (session().is_recording()) {
    // TODO pending events are currently only meaningful
    // during recording.  We should change that
    // eventually, to have more informative output.
    log_pending_events();
  }
}

std::string Task::proc_fd_path(int fd) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path) - 1, "/proc/%d/fd/%d", tid, fd);
  return path;
}

std::string Task::proc_stat_path() {
  char path[PATH_MAX];
  snprintf(path, sizeof(path) - 1, "/proc/%d/stat", tid);
  return path;
}

struct stat Task::stat_fd(int fd) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path) - 1, "/proc/%d/fd/%d", tid, fd);
  struct stat result;
  auto ret = ::stat(path, &result);
  ASSERT(this, ret == 0);
  return result;
}

struct stat Task::lstat_fd(int fd) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path) - 1, "/proc/%d/fd/%d", tid, fd);
  struct stat result;
  auto ret = ::lstat(path, &result);
  ASSERT(this, ret == 0);
  return result;
}

ScopedFd Task::open_fd(int fd, int flags) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path) - 1, "/proc/%d/fd/%d", tid, fd);
  return ScopedFd(path, flags);
}

string Task::file_name_of_fd(int fd) {
  char path[PATH_MAX];
  char procfd[40];
  snprintf(procfd, sizeof(procfd) - 1, "/proc/%d/fd/%d", tid, fd);
  ssize_t nbytes = readlink(procfd, path, sizeof(path) - 1);
  if (nbytes < 0) {
    path[0] = 0;
  } else {
    path[nbytes] = 0;
  }
  return path;
}

const siginfo_t& Task::get_siginfo() {
  DEBUG_ASSERT(stop_sig());
  return pending_siginfo;
}

/**
 * Must be idempotent.
 */
void Task::destroy_buffers(Task *as_task, Task *fd_task) {
  auto saved_syscallbuf_child = syscallbuf_child;
  // Clear syscallbuf_child now so nothing tries to use it while tearing
  // down buffers.
  syscallbuf_child = nullptr;
  if (as_task != nullptr) {
    AutoRemoteSyscalls remote(as_task);
    as_task->unmap_buffers_for(remote, this, saved_syscallbuf_child);
    if (as_task == fd_task) {
      as_task->close_buffers_for(remote, this, true);
    }
    goto done;
  }
  if (fd_task != nullptr) {
    AutoRemoteSyscalls remote(fd_task);
    fd_task->close_buffers_for(remote, this, true);
  }
done:
  scratch_ptr = nullptr;
  desched_fd_child = -1;
  cloned_file_data_fd_child = -1;
}

void Task::unmap_buffers_for(
    AutoRemoteSyscalls& remote, Task* other,
    remote_ptr<struct syscallbuf_hdr> saved_syscallbuf_child) {
  auto arch = remote.task()->arch();
  if (other->scratch_ptr) {
    remote.infallible_syscall(syscall_number_for_munmap(arch),
                              other->scratch_ptr, other->scratch_size);
    vm()->unmap(this, other->scratch_ptr, other->scratch_size);
  }
  if (!saved_syscallbuf_child.is_null()) {
    remote.infallible_syscall(syscall_number_for_munmap(arch),
                              saved_syscallbuf_child, other->syscallbuf_size);
    vm()->unmap(this, saved_syscallbuf_child, other->syscallbuf_size);
  }
}

void Task::did_kill()
{
  /* We may or may not have seen this event (see the note on race conditions
   * in Session.cc), but let's pretend that we did to make this task look like
   * other that we didn't kill ourselves
   */
  seen_ptrace_exit_event = true;
  handled_ptrace_exit_event = true;
  syscallbuf_child = nullptr;
  /* No need to unmap/close things in the child here - the kernel did that for
   * us when the child died. */
  scratch_ptr = nullptr;
  desched_fd_child = -1;
  cloned_file_data_fd_child = -1;
}

/**
 * Must be idempotent.
 */
void Task::close_buffers_for(AutoRemoteSyscalls& remote, Task* other, bool really_close) {
  auto arch = remote.task()->arch();
  if (other->desched_fd_child >= 0) {
    if (session().is_recording() && really_close) {
      remote.infallible_syscall(syscall_number_for_close(arch),
                                other->desched_fd_child);
    }
    fds->did_close(other->desched_fd_child);
  }
  if (other->cloned_file_data_fd_child >= 0) {
    if (really_close) {
      remote.infallible_syscall(syscall_number_for_close(arch),
                                other->cloned_file_data_fd_child);
    }
    fds->did_close(other->cloned_file_data_fd_child);
  }
}

void Task::emulate_jump(remote_code_ptr ip) {
  Registers r = regs();
  r.set_ip(ip);
  set_regs(r);
  ticks += PerfCounters::ticks_for_unconditional_indirect_branch(this);
}

bool Task::is_desched_event_syscall() {
  return is_ioctl_syscall(regs().original_syscallno(), arch()) &&
         desched_fd_child != -1 &&
         desched_fd_child == (int)regs().arg1_signed();
}

bool Task::is_ptrace_seccomp_event() const {
  int event = ptrace_event();
  return (PTRACE_EVENT_SECCOMP_OBSOLETE == event ||
          PTRACE_EVENT_SECCOMP == event);
}

template <typename Arch>
static vector<uint8_t> ptrace_get_regs_set(Task* t, const Registers& regs,
                                           size_t min_size) {
  auto iov = t->read_mem(remote_ptr<typename Arch::iovec>(regs.arg4()));
  ASSERT(t, iov.iov_len >= min_size)
      << "Should have been caught during prepare_ptrace";
  return t->read_mem(iov.iov_base.rptr().template cast<uint8_t>(), iov.iov_len);
}

static void process_shmdt(Task* t, remote_ptr<void> addr) {
  size_t size = t->vm()->get_shm_size(addr);
  t->vm()->remove_shm_size(addr);
  t->vm()->unmap(t, addr, size);
}

template <typename Arch>
static void ptrace_syscall_exit_legacy_arch(Task* t, Task* tracee, const Registers& regs)
{
  switch ((int)regs.orig_arg1_signed()) {
    case Arch::PTRACE_SETREGS: {
      auto data = t->read_mem(
          remote_ptr<typename Arch::user_regs_struct>(regs.arg4()));
      Registers r = tracee->regs();
      r.set_from_ptrace_for_arch(Arch::arch(), &data, sizeof(data));
      tracee->set_regs(r);
      break;
    }
    case Arch::PTRACE_SETFPREGS: {
      auto data = t->read_mem(
          remote_ptr<typename Arch::user_fpregs_struct>(regs.arg4()));
      auto r = tracee->extra_regs();
      r.set_user_fpregs_struct(t, Arch::arch(), &data, sizeof(data));
      tracee->set_extra_regs(r);
      break;
    }
    case Arch::PTRACE_SETFPXREGS: {
      auto data =
          t->read_mem(remote_ptr<X86Arch::user_fpxregs_struct>(regs.arg4()));
      auto r = tracee->extra_regs();
      r.set_user_fpxregs_struct(t, data);
      tracee->set_extra_regs(r);
      break;
    }
    case Arch::PTRACE_POKEUSR: {
      size_t addr = regs.arg3();
      typename Arch::unsigned_word data = regs.arg4();
      if (addr < sizeof(typename Arch::user_regs_struct)) {
        Registers r = tracee->regs();
        r.write_register_by_user_offset(addr, data);
        tracee->set_regs(r);
      } else if (addr >= offsetof(typename Arch::user, u_debugreg[0]) &&
                  addr < offsetof(typename Arch::user, u_debugreg[8])) {
        size_t regno =
            (addr - offsetof(typename Arch::user, u_debugreg[0])) /
            sizeof(data);
        tracee->set_x86_debug_reg(regno, data);
      }
      break;
    }
    default:
      break;
  }
}

template <>
void ptrace_syscall_exit_legacy_arch<ARM64Arch>(Task*, Task*, const Registers&)
{
  // Nothing to do - unimplemented on this architecture
  return;
}

template <typename Arch>
void Task::on_syscall_exit_arch(int syscallno, const Registers& regs) {
  session().accumulate_syscall_performed();

  if (regs.original_syscallno() == SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO) {
    return;
  }

  if (syscallno == session_->syscall_number_for_rrcall_mprotect_record()) {
    // When we record an rr replay of a tracee which does a syscallbuf'ed
    // `mprotect`, neither the replay nor its recording see the mprotect
    // syscall, since it's untraced during both recording and replay. rr
    // replay is notified of the syscall via the `mprotect_records`
    // mechanism; if it's being recorded, it forwards that notification to
    // the recorder by calling this syscall.
    pid_t tid = regs.orig_arg1();
    remote_ptr<void> addr = regs.arg2();
    size_t num_bytes = regs.arg3();
    int prot = regs.arg4_signed();
    Task* t = session().find_task(tid);
    ASSERT(this, t);
    return t->vm()->protect(t, addr, num_bytes, prot);
  }

  // mprotect can change the protection status of some mapped regions before
  // failing.
  // SYS_rrcall_mprotect_record always fails with ENOSYS, though we want to
  // note its usage here.
  if (regs.syscall_failed() && !is_mprotect_syscall(syscallno, regs.arch())) {
    return;
  }

  switch (syscallno) {
    case Arch::brk:
    case Arch::mmap:
    case Arch::mmap2:
    case Arch::mremap: {
      LOG(debug) << "(brk/mmap/mmap2/mremap will receive / has received direct "
                    "processing)";
      return;
    }

    case Arch::mprotect: {
      remote_ptr<void> addr = regs.orig_arg1();
      size_t num_bytes = regs.arg2();
      int prot = regs.arg3_signed();
      return vm()->protect(this, addr, num_bytes, prot);
    }
    case Arch::munmap: {
      remote_ptr<void> addr = regs.orig_arg1();
      size_t num_bytes = regs.arg2();
      return vm()->unmap(this, addr, num_bytes);
    }
    case Arch::shmdt:
      return process_shmdt(this, regs.orig_arg1());
    case Arch::madvise: {
      remote_ptr<void> addr = regs.orig_arg1();
      size_t num_bytes = regs.arg2();
      int advice = regs.arg3();
      return vm()->advise(this, addr, num_bytes, advice);
    }
    case Arch::ipc: {
      switch ((int)regs.orig_arg1_signed()) {
        case SHMDT:
          return process_shmdt(this, regs.arg5());
        default:
          break;
      }
      break;
    }

    case Arch::set_thread_area:
      set_thread_area(regs.orig_arg1());
      return;

    case Arch::prctl:
      switch ((int)regs.orig_arg1_signed()) {
        case PR_SET_SECCOMP:
          if (regs.arg2() == SECCOMP_MODE_FILTER && session().is_recording()) {
            seccomp_bpf_enabled = true;
          }
          break;
        case PR_SET_NAME: {
          update_prname(regs.arg2());
          break;
        }
      }
      return;

    case Arch::dup:
    case Arch::dup2:
    case Arch::dup3:
      fd_table()->did_dup(regs.orig_arg1(), regs.syscall_result());
      return;
    case Arch::fcntl64:
    case Arch::fcntl:
      if (regs.arg2() == Arch::DUPFD || regs.arg2() == Arch::DUPFD_CLOEXEC) {
        fd_table()->did_dup(regs.orig_arg1(), regs.syscall_result());
      }
      return;
    case Arch::close:
      fd_table()->did_close(regs.orig_arg1());
      return;

    case Arch::unshare:
      if (regs.orig_arg1() & CLONE_FILES) {
        fds->erase_task(this);
        fds = fds->clone();
        fds->insert_task(this);
        vm()->fd_tables_changed();
      }
      return;

    case Arch::pwrite64:
    case Arch::write: {
      int fd = (int)regs.orig_arg1_signed();
      vector<FileMonitor::Range> ranges;
      ssize_t amount = regs.syscall_result_signed();
      if (amount > 0) {
        ranges.push_back(FileMonitor::Range(regs.arg2(), amount));
      }
      FileMonitor::LazyOffset offset(this, regs, syscallno);
      fd_table()->did_write(this, fd, ranges, offset);
      return;
    }

    case Arch::pwritev:
    case Arch::writev: {
      int fd = (int)regs.orig_arg1_signed();
      vector<FileMonitor::Range> ranges;
      auto iovecs =
          read_mem(remote_ptr<typename Arch::iovec>(regs.arg2()), regs.arg3());
      ssize_t written = regs.syscall_result_signed();
      ASSERT(this, written >= 0);
      for (auto& v : iovecs) {
        ssize_t amount = min<ssize_t>(written, v.iov_len);
        if (amount > 0) {
          ranges.push_back(FileMonitor::Range(v.iov_base, amount));
          written -= amount;
        }
      }
      FileMonitor::LazyOffset offset(this, regs, syscallno);
      fd_table()->did_write(this, fd, ranges, offset);
      return;
    }

    case Arch::ptrace: {
      pid_t pid = (pid_t)regs.arg2_signed();
      Task* tracee = session().find_task(pid);
      switch ((int)regs.orig_arg1_signed()) {
        case PTRACE_SETREGSET: {
          switch ((int)regs.arg3()) {
            case NT_PRSTATUS: {
              auto set = ptrace_get_regs_set<Arch>(
                  this, regs, user_regs_struct_size(tracee->arch()));
              Registers r = tracee->regs();
              r.set_from_ptrace_for_arch(tracee->arch(), set.data(), set.size());
              tracee->set_regs(r);
              break;
            }
            case NT_PRFPREG: {
              auto set = ptrace_get_regs_set<Arch>(
                  this, regs, user_fpregs_struct_size(tracee->arch()));
              ExtraRegisters r = tracee->extra_regs();
              r.set_user_fpregs_struct(this, tracee->arch(), set.data(),
                                       set.size());
              tracee->set_extra_regs(r);
              break;
            }
            case NT_ARM_SYSTEM_CALL: {
              auto set = ptrace_get_regs_set<Arch>(
                  this, regs, sizeof(int));
              ASSERT(this, set.size() >= sizeof(int));
              int new_syscallno = *(int*)set.data();
              Registers r = tracee->regs();
              r.set_original_syscallno(new_syscallno);
              tracee->set_regs(r);
              break;
            }
            case NT_ARM_HW_WATCH:
            case NT_ARM_HW_BREAK: {
              auto set = ptrace_get_regs_set<Arch>(
                  this, regs, offsetof(ARM64Arch::user_hwdebug_state, dbg_regs[0]));
              ASSERT(this, set.size() >= sizeof(int));
              tracee->set_aarch64_debug_regs((int)regs.arg3(),
                (ARM64Arch::user_hwdebug_state*)set.data(),
                (set.size() - offsetof(ARM64Arch::user_hwdebug_state, dbg_regs[0]))/
                  2*sizeof(ARM64Arch::hw_bp));
              break;
            }
            case NT_X86_XSTATE: {
              switch (tracee->extra_regs().format()) {
                case ExtraRegisters::XSAVE: {
                  XSaveLayout layout;
                  ReplaySession* replay = session().as_replay();
                  if (replay) {
                    layout = xsave_layout_from_trace(
                        replay->trace_reader().cpuid_records());
                  } else {
                    layout = xsave_native_layout();
                  }
                  auto set = ptrace_get_regs_set<Arch>(this, regs, layout.full_size);
                  ExtraRegisters r;
                  bool ok =
                      r.set_to_raw_data(tracee->arch(), ExtraRegisters::XSAVE,
                                        set.data(), set.size(), layout);
                  ASSERT(this, ok) << "Invalid XSAVE data";
                  tracee->set_extra_regs(r);
                  break;
                }
                default:
                  ASSERT(this, false) << "Unknown ExtraRegisters format; "
                                         "Should have been caught during "
                                         "prepare_ptrace";
              }
              break;
            }
            default:
              ASSERT(this, false) << "Unknown regset type; Should have been "
                                     "caught during prepare_ptrace";
              break;
          }
          break;
        }
        case Arch::PTRACE_ARCH_PRCTL: {
          if (tracee->arch() != x86_64) {
            break;
          }
          int code = (int)regs.arg4();
          switch (code) {
            case ARCH_GET_FS:
            case ARCH_GET_GS:
              break;
            case ARCH_SET_FS:
            case ARCH_SET_GS: {
              Registers r = tracee->regs();
              if (regs.arg3() == 0) {
                // Work around a kernel bug in pre-4.7 kernels, where setting
                // the gs/fs base to 0 via PTRACE_REGSET did not work correctly.
                tracee->ptrace_if_alive(Arch::PTRACE_ARCH_PRCTL, regs.arg3(),
                                        (void*)(uintptr_t)regs.arg4());
              }
              if (code == ARCH_SET_FS) {
                r.set_fs_base(regs.arg3());
              } else {
                r.set_gs_base(regs.arg3());
              }
              tracee->set_regs(r);
              break;
            }
            default:
              ASSERT(tracee, 0) << "Should have detected this earlier";
          }
          break;
        }
        case Arch::PTRACE_SETREGS:
        case Arch::PTRACE_SETFPREGS:
        case Arch::PTRACE_SETFPXREGS:
        case Arch::PTRACE_POKEUSR: {
          ptrace_syscall_exit_legacy_arch<Arch>(this, tracee, regs);
        }
      }
      return;
    }
  }
}

void Task::on_syscall_exit(int syscallno, SupportedArch arch,
                           const Registers& regs) {
  with_converted_registers<void>(regs, arch, [&](const Registers& regs) {
    RR_ARCH_FUNCTION(on_syscall_exit_arch, arch, syscallno, regs);
  });
}

void Task::move_ip_before_breakpoint() {
  // TODO: assert that this is at a breakpoint trap.
  Registers r = regs();
  r.set_ip(r.ip().undo_executed_bkpt(arch()));
  set_regs(r);
}

void Task::enter_syscall() {
  bool need_ptrace_syscall_event = !seccomp_bpf_enabled ||
                                   session().syscall_seccomp_ordering() ==
                                       Session::SECCOMP_BEFORE_PTRACE_SYSCALL;
  bool need_seccomp_event = seccomp_bpf_enabled;
  while (need_ptrace_syscall_event || need_seccomp_event) {
    resume_execution(need_ptrace_syscall_event ? RESUME_SYSCALL : RESUME_CONT,
                     RESUME_WAIT, RESUME_NO_TICKS);
    if (is_ptrace_seccomp_event()) {
      ASSERT(this, need_seccomp_event);
      need_seccomp_event = false;
      continue;
    }
    ASSERT(this, !ptrace_event());
    if (session().is_recording() && wait_status.group_stop()) {
      static_cast<RecordTask*>(this)->stash_group_stop();
      continue;
    }
    if (!stop_sig()) {
      ASSERT(this, need_ptrace_syscall_event);
      need_ptrace_syscall_event = false;
      continue;
    }
    if (ReplaySession::is_ignored_signal(stop_sig()) &&
        session().is_replaying()) {
      continue;
    }
    ASSERT(this, session().is_recording() && !is_deterministic_signal(this))
        << " got unexpected signal " << signal_name(stop_sig());
    if (stop_sig() == session().as_record()->syscallbuf_desched_sig()) {
      continue;
    }
    static_cast<RecordTask*>(this)->stash_sig();
  }
  apply_syscall_entry_regs();
}

bool Task::exit_syscall() {
  // If PTRACE_SYSCALL_BEFORE_SECCOMP, we are inconsistent about
  // whether we process the syscall on the syscall entry trap or
  // on the seccomp trap. Detect if we are on the former and
  // just bring us forward to the seccomp trap.
  bool will_see_seccomp = seccomp_bpf_enabled &&
                          (session().syscall_seccomp_ordering() ==
                           Session::PTRACE_SYSCALL_BEFORE_SECCOMP) &&
                          !is_ptrace_seccomp_event();
  while (true) {
    resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);
    if (will_see_seccomp && is_ptrace_seccomp_event()) {
      will_see_seccomp = false;
      continue;
    }
    if (ptrace_event() == PTRACE_EVENT_EXIT) {
      return false;
    }
    ASSERT(this, !ptrace_event());
    if (!stop_sig()) {
      canonicalize_regs(arch());
      break;
    }
    if (ReplaySession::is_ignored_signal(stop_sig()) &&
        session().is_replaying()) {
      continue;
    }
    ASSERT(this, session().is_recording());
    static_cast<RecordTask*>(this)->stash_sig();
  }
  return true;
}

bool Task::exit_syscall_and_prepare_restart() {
  Registers r = regs();
  int syscallno = r.original_syscallno();
  LOG(debug) << "exit_syscall_and_prepare_restart from syscall "
             << rr::syscall_name(syscallno, r.arch());
  r.set_original_syscallno(syscall_number_for_gettid(r.arch()));
  set_regs(r);
  // This exits the hijacked SYS_gettid.  Now the tracee is
  // ready to do our bidding.
  if (!exit_syscall()) {
    // The tracee suddenly exited. To get this to replay correctly, we need to
    // make it look like we really entered the syscall. Then
    // handle_ptrace_exit_event will record something appropriate.
    r.set_original_syscallno(syscallno);
    r.set_syscall_result(-ENOSYS);
    set_regs(r);
    return false;
  }
  LOG(debug) << "exit_syscall_and_prepare_restart done";

  // Restore these regs to what they would have been just before
  // the tracee trapped at the syscall.
  r.set_original_syscallno(-1);
  r.set_syscallno(syscallno);
  r.set_ip(r.ip() - syscall_instruction_length(r.arch()));
  set_regs(r);
  return true;
}

static string prname_from_exe_image(const string& e) {
  size_t last_slash = e.rfind('/');
  return e.substr(last_slash == e.npos ? 0 : last_slash + 1);
}

#if defined(__i386__) || defined(__x86_64__)
#define AR_L (1 << 21)
static bool is_long_mode_segment(uint32_t segment) {
  uint32_t ar = 0;
  asm("lar %[segment], %[ar]" : [ar] "=r"(ar) : [segment] "r"(segment));
  return ar & AR_L;
}
#endif

void Task::post_exec(const string& exe_file) {
  Task* stopped_task_in_address_space = nullptr;
  bool other_task_in_address_space = false;
  for (Task* t : as->task_set()) {
    if (t != this) {
      other_task_in_address_space = true;
      if (t->is_stopped) {
        stopped_task_in_address_space = t;
        break;
      }
    }
  }
  if (stopped_task_in_address_space) {
    AutoRemoteSyscalls remote(stopped_task_in_address_space);
    unmap_buffers_for(remote, this, syscallbuf_child);
  } else if (other_task_in_address_space) {
    // We should clean up our syscallbuf/scratch but that's too hard since we
    // have no stopped task to use for that :-(.
    // (We can't clean up those buffers *before* the exec completes, because it
    // might fail in which case we shouldn't have cleaned them up.)
    // Just let the buffers leak. The AddressSpace will clean up our local
    // shared buffer when it's destroyed.
    LOG(warn) << "Intentionally leaking syscallbuf after exec for task " << tid;
  }

  session().post_exec();

  as->erase_task(this);
  fds->erase_task(this);

  extra_registers = ExtraRegisters(registers.arch());
  extra_registers_known = false;
  ExtraRegisters e = extra_regs();
  e.reset();
  set_extra_regs(e);

  syscallbuf_child = nullptr;
  syscallbuf_size = 0;
  scratch_ptr = nullptr;
  cloned_file_data_fd_child = -1;
  desched_fd_child = -1;
  preload_globals = nullptr;
  thread_group()->execed = true;

  thread_areas_.clear();
  memset(&thread_locals, 0, sizeof(thread_locals));

  as = session().create_vm(this, exe_file, as->uid().exec_count() + 1);
  // It's barely-documented, but Linux unshares the fd table on exec
  fds = fds->clone();
  fds->insert_task(this);
  prname = prname_from_exe_image(as->exe_image());
}

void Task::post_exec_syscall() {
  canonicalize_regs(arch());
  as->post_exec_syscall(this);

  if (session().has_cpuid_faulting()) {
    AutoRemoteSyscalls remote(this);
    remote.infallible_syscall(syscall_number_for_arch_prctl(arch()),
                              ARCH_SET_CPUID, 0);
  }
}

bool Task::execed() const { return tg->execed; }

void Task::flush_inconsistent_state() { ticks = 0; }

string Task::read_c_str(remote_ptr<char> child_addr, bool *ok) {
  remote_ptr<void> p = child_addr;
  string str;
  while (true) {
    // We're only guaranteed that [child_addr,
    // end_of_page) is mapped.
    remote_ptr<void> end_of_page = ceil_page_size(p + 1);
    ssize_t nbytes = end_of_page - p;
    std::unique_ptr<char[]> buf(new char[nbytes]);

    read_bytes_helper(p, nbytes, buf.get(), ok);
    if (ok && !*ok) {
      return "";
    }
    for (int i = 0; i < nbytes; ++i) {
      if ('\0' == buf[i]) {
        return str;
      }
      str += buf[i];
    }
    p = end_of_page;
  }
}

const Registers& Task::regs() const {
  ASSERT(this, is_stopped);
  return registers;
}

const ExtraRegisters* Task::extra_regs_fallible() {
  if (!extra_registers_known) {
#if defined(__i386__) || defined(__x86_64__)
    if (xsave_area_size() > 512) {
      LOG(debug) << "  (refreshing extra-register cache using XSAVE)";

      extra_registers.format_ = ExtraRegisters::XSAVE;
      extra_registers.data_.resize(xsave_area_size());
      struct iovec vec = { extra_registers.data_.data(),
                           extra_registers.data_.size() };
      if (fallible_ptrace(PTRACE_GETREGSET, NT_X86_XSTATE, &vec)) {
        return nullptr;
      }
      extra_registers.data_.resize(vec.iov_len);
      // The kernel may return less than the full XSTATE
      extra_registers.validate(this);
    } else {
#if defined(__i386__)
      LOG(debug) << "  (refreshing extra-register cache using FPXREGS)";

      extra_registers.format_ = ExtraRegisters::XSAVE;
      extra_registers.data_.resize(sizeof(user_fpxregs_struct));
      if (fallible_ptrace(PTRACE_GETFPXREGS, nullptr, extra_registers.data_.data())) {
        return nullptr;
      }
#elif defined(__x86_64__)
      // x86-64 that doesn't support XSAVE; apparently Xeon E5620 (Westmere)
      // is in this class.
      LOG(debug) << "  (refreshing extra-register cache using FPREGS)";

      extra_registers.format_ = ExtraRegisters::XSAVE;
      extra_registers.data_.resize(sizeof(user_fpregs_struct));
      if (fallible_ptrace(PTRACE_GETFPREGS, nullptr, extra_registers.data_.data())) {
        return nullptr;
      }
#endif
    }
#elif defined(__aarch64__)
    LOG(debug) << "  (refreshing extra-register cache using FPR)";

    extra_registers.format_ = ExtraRegisters::NT_FPR;
    extra_registers.data_.resize(sizeof(ARM64Arch::user_fpregs_struct));
    struct iovec vec = { extra_registers.data_.data(),
                          extra_registers.data_.size() };
    if (fallible_ptrace(PTRACE_GETREGSET, NT_PRFPREG, &vec)) {
      return nullptr;
    }
    extra_registers.data_.resize(vec.iov_len);
#else
#error need to define new extra_regs support
#endif
    extra_registers_known = true;
  }
  return &extra_registers;
}

const ExtraRegisters& Task::extra_regs() {
  if (!extra_regs_fallible()) {
    ASSERT(this, false) << "Can't find task for infallible extra_regs";
  }
  return extra_registers;
}

#if defined(__i386__) || defined(__x86_64__)
static ssize_t dr_user_word_offset(size_t i) {
  DEBUG_ASSERT(i < NUM_X86_DEBUG_REGS);
  return offsetof(struct user, u_debugreg[0]) + sizeof(void*) * i;
}

uintptr_t Task::get_debug_reg(size_t regno) {
  errno = 0;
  long result =
      fallible_ptrace(PTRACE_PEEKUSER, dr_user_word_offset(regno), nullptr);
  if (errno == ESRCH) {
    return 0;
  }
  return result;
}

bool Task::set_x86_debug_reg(size_t regno, uintptr_t value) {
  errno = 0;
  fallible_ptrace(PTRACE_POKEUSER, dr_user_word_offset(regno), (void*)value);
  return errno == ESRCH || errno == 0;
}

uintptr_t Task::x86_debug_status() {
  return fallible_ptrace(PTRACE_PEEKUSER, dr_user_word_offset(6), nullptr);
}
#else
#define FATAL_X86_ONLY() FATAL() << "Reached x86-only code path on non-x86 architecture";
uintptr_t Task::get_debug_reg(size_t) {
  FATAL_X86_ONLY();
  return 0;
}

bool Task::set_x86_debug_reg(size_t, uintptr_t) {
  FATAL_X86_ONLY();
  return false;
}

uintptr_t Task::x86_debug_status() {
  FATAL_X86_ONLY();
  return 0;
}
#endif

#if defined(__aarch64__)
bool Task::set_aarch64_debug_regs(int which, ARM64Arch::user_hwdebug_state *regs, size_t nregs) {
  errno = 0;
  struct iovec iov { .iov_base = regs, .iov_len = sizeof(*regs) - (16-nregs)*sizeof(ARM64Arch::hw_bp) };
  ASSERT(this, which == NT_ARM_HW_BREAK || which == NT_ARM_HW_WATCH);
  fallible_ptrace(PTRACE_SETREGSET, which, (void*)&iov);
  return errno == 0;
}
bool Task::get_aarch64_debug_regs(int which, ARM64Arch::user_hwdebug_state *regs) {
  errno = 0;
  struct iovec iov { .iov_base = regs, .iov_len = sizeof(*regs) };
  ASSERT(this, which == NT_ARM_HW_BREAK || which == NT_ARM_HW_WATCH);
  fallible_ptrace(PTRACE_GETREGSET, which, (void*)&iov);
  return errno == 0;
}
#else
bool Task::set_aarch64_debug_regs(int, ARM64Arch::user_hwdebug_state *, size_t) {
  FATAL() << "Reached aarch64 code path on non-aarch64 system";
  return false;
}
bool Task::get_aarch64_debug_regs(int, ARM64Arch::user_hwdebug_state *) {
  FATAL() << "Reached aarch64 code path on non-aarch64 system";
  return false;
}
#endif

void Task::set_x86_debug_status(uintptr_t status) {
  if (arch() == x86 || arch() == x86_64) {
    set_x86_debug_reg(6, status);
  }
}

static bool is_singlestep_resume(ResumeRequest request) {
  return request == RESUME_SINGLESTEP || request == RESUME_SYSEMU_SINGLESTEP;
}

TrapReasons Task::compute_trap_reasons() {
  ASSERT(this, stop_sig() == SIGTRAP);

  TrapReasons reasons;

  const siginfo_t& si = get_siginfo();
  if (arch() == x86 || arch() == x86_64) {
    uintptr_t status = x86_debug_status();
    reasons.singlestep = (status & DS_SINGLESTEP) != 0;
    if (!reasons.singlestep && is_singlestep_resume(how_last_execution_resumed)) {
      if (is_at_syscall_instruction(this, address_of_last_execution_resume) &&
          ip() ==
              address_of_last_execution_resume +
                  syscall_instruction_length(arch())) {
        // During replay we execute syscall instructions in certain cases, e.g.
        // mprotect with syscallbuf. The kernel does not set DS_SINGLESTEP when we
        // step over those instructions so we need to detect that here.
        reasons.singlestep = true;
      } else {
        TrappedInstruction ti =
          trapped_instruction_at(this, address_of_last_execution_resume);
        if (ti == TrappedInstruction::CPUID &&
            ip() == address_of_last_execution_resume +
                        trapped_instruction_len(TrappedInstruction::CPUID)) {
          // Likewise we emulate CPUID instructions and must forcibly detect that
          // here.
          reasons.singlestep = true;
          // This also takes care of the did_set_breakpoint_after_cpuid workaround case
        } else if (ti == TrappedInstruction::INT3 &&
            ip() == address_of_last_execution_resume +
                        trapped_instruction_len(TrappedInstruction::INT3)) {
          // INT3 instructions should also be turned into a singlestep here.
          reasons.singlestep = true;
        }
      }
    }

    // In VMWare Player 6.0.4 build-2249910, 32-bit Ubuntu x86 guest,
    // single-stepping does not trigger watchpoints :-(. So we have to
    // check watchpoints here. fast_forward also hides watchpoint changes.
    // Write-watchpoints will detect that their value has changed and trigger.
    // XXX Read/exec watchpoints can't be detected this way so they're still
    // broken in the above configuration :-(.
    if ((DS_WATCHPOINT_ANY | DS_SINGLESTEP) & status) {
      as->notify_watchpoint_fired(status, nullptr,
          is_singlestep_resume(how_last_execution_resumed)
              ? address_of_last_execution_resume : nullptr);
    }
    reasons.watchpoint =
        as->has_any_watchpoint_changes() || (DS_WATCHPOINT_ANY & status);
  } else if (arch() == aarch64) {
    reasons.watchpoint = false;
    reasons.singlestep = si.si_code == TRAP_TRACE;
    reasons.watchpoint = si.si_code == TRAP_HWBKPT;
    if (reasons.watchpoint) {
      as->notify_watchpoint_fired(0, remote_ptr<void>((uintptr_t)si.si_addr),
          is_singlestep_resume(how_last_execution_resumed)
              ? address_of_last_execution_resume : nullptr);
    }
  }

  // If we triggered a breakpoint, this would be the address of the breakpoint
  remote_code_ptr ip_at_breakpoint = ip().undo_executed_bkpt(arch());
  // Don't trust siginfo to report execution of a breakpoint if singlestep or
  // watchpoint triggered.
  if (reasons.singlestep) {
    reasons.breakpoint =
        as->is_breakpoint_instruction(this, address_of_last_execution_resume);
    if (reasons.breakpoint) {
      ASSERT(this, address_of_last_execution_resume == ip_at_breakpoint);
    }
  } else if (reasons.watchpoint) {
    // We didn't singlestep, so watchpoint state is completely accurate.
    // The only way the last instruction could have triggered a watchpoint
    // and be a breakpoint instruction is if an EXEC watchpoint fired
    // at the breakpoint address.
    reasons.breakpoint = as->has_exec_watchpoint_fired(ip_at_breakpoint) &&
                         as->is_breakpoint_instruction(this, ip_at_breakpoint);
  } else {
    ASSERT(this, SIGTRAP == si.si_signo) << " expected SIGTRAP, got " << si;
    reasons.breakpoint = is_kernel_trap(si.si_code);
    if (reasons.breakpoint) {
      ASSERT(this, as->is_breakpoint_instruction(this, ip_at_breakpoint))
          << " expected breakpoint at " << ip_at_breakpoint << ", got siginfo "
          << si;
    }
  }
  return reasons;
}

static void* preload_thread_locals_local_addr(AddressSpace& as) {
  if (!as.has_mapping(AddressSpace::preload_thread_locals_start())) {
    return nullptr;
  }
  // There might have been a mapping there, but not the one we expect (i.e.
  // the one shared with us for thread locals). In that case we behave as
  // if the mapping didn't exist at all.
  auto& mapping = as.mapping_of(AddressSpace::preload_thread_locals_start());
  if (mapping.flags & AddressSpace::Mapping::IS_THREAD_LOCALS) {
    DEBUG_ASSERT(mapping.local_addr);
    return mapping.local_addr;
  }
  return nullptr;
}

template <typename Arch> static void setup_preload_thread_locals_arch(Task* t) {
  void* local_addr = preload_thread_locals_local_addr(*t->vm());
  if (local_addr) {
    auto locals = reinterpret_cast<preload_thread_locals<Arch>*>(local_addr);
    static_assert(sizeof(*locals) <= PRELOAD_THREAD_LOCALS_SIZE,
                  "bad PRELOAD_THREAD_LOCALS_SIZE");
    locals->syscallbuf_stub_alt_stack = t->syscallbuf_alt_stack();
  }
}

void Task::setup_preload_thread_locals() {
  activate_preload_thread_locals();
  RR_ARCH_FUNCTION(setup_preload_thread_locals_arch, arch(), this);
}

const Task::ThreadLocals& Task::fetch_preload_thread_locals() {
  if (tuid() == as->thread_locals_tuid()) {
    void* local_addr = preload_thread_locals_local_addr(*as);
    if (local_addr) {
      memcpy(thread_locals, local_addr, PRELOAD_THREAD_LOCALS_SIZE);
      return thread_locals;
    }
    // The mapping might have been removed by crazy application code.
    // That's OK, assuming the preload library was removed too.
    memset(&thread_locals, 0, sizeof(thread_locals));
  }
  return thread_locals;
}

void Task::activate_preload_thread_locals() {
  // Switch thread-locals to the new task.
  if (tuid() != as->thread_locals_tuid()) {
    void* local_addr = preload_thread_locals_local_addr(*as);
    if (local_addr) {
      Task* t = session().find_task(as->thread_locals_tuid());
      if (t) {
        t->fetch_preload_thread_locals();
      }
      memcpy(local_addr, thread_locals, PRELOAD_THREAD_LOCALS_SIZE);
      as->set_thread_locals_tuid(tuid());
    }
  }
}

#if defined(__x86_64__) || defined(__i386__)
static bool cpu_has_KNL_string_singlestep_bug() {
  static bool has_quirk =
      ((cpuid(CPUID_GETFEATURES, 0).eax & 0xF0FF0) == 0x50670);
  return has_quirk;
}
#else
static bool cpu_has_KNL_string_singlestep_bug() {
  return false;
}
#endif

/*
 * The value of rcx above which the CPU doesn't properly handle singlestep for
 * string instructions. Right now, since only once CPU has this quirk, this
 * value is hardcoded, but could depend on the CPU architecture in the future.
 */
static int single_step_coalesce_cutoff() { return 16; }

void Task::work_around_KNL_string_singlestep_bug() {
  /* The extra cx >= cutoff check is just an optimization, to avoid the
     moderately expensive load from ip() if we can */
  if (!cpu_has_KNL_string_singlestep_bug()) {
    return;
  }
  uintptr_t cx = regs().cx();
  uintptr_t cutoff = single_step_coalesce_cutoff();
  if (cx > cutoff && at_x86_string_instruction(this)) {
    /* KNL has a quirk where single-stepping a string instruction can step up
      to 64 iterations. Work around this by fudging registers to force the
      processor to execute one iteration and one interation only. */
    LOG(debug) << "Working around KNL single-step hardware bug (cx=" << cx
              << ")";
    if (cx > cutoff) {
      last_resume_orig_cx = cx;
      Registers r = regs();
      /* An arbitrary value < cutoff would work fine here, except 1, since
        the last iteration of the loop behaves differently */
      r.set_cx(cutoff);
      set_regs(r);
    }
  }
}

void Task::resume_execution(ResumeRequest how, WaitRequest wait_how,
                            TicksRequest tick_period, int sig) {
  will_resume_execution(how, wait_how, tick_period, sig);

  if (tick_period != RESUME_NO_TICKS) {
    if (tick_period == RESUME_UNLIMITED_TICKS) {
      hpc.reset(0);
    } else {
      ASSERT(this, tick_period >= 0 && tick_period <= MAX_TICKS_REQUEST);
      hpc.reset(max<Ticks>(1, tick_period));
    }
    activate_preload_thread_locals();
  }

  LOG(debug) << "resuming execution of " << tid << " with "
             << ptrace_req_name<NativeArch>(how)
             << (sig ? string(", signal ") + signal_name(sig) : string())
             << " tick_period " << tick_period << " wait " << wait_how;
  set_x86_debug_status(0);

  if (is_singlestep_resume(how)) {
    work_around_KNL_string_singlestep_bug();
    if (is_x86ish(arch())) {
      singlestepping_instruction = trapped_instruction_at(this, ip());
      if (singlestepping_instruction == TrappedInstruction::CPUID) {
        // In KVM virtual machines (and maybe others), singlestepping over CPUID
        // executes the following instruction as well. Work around that.
        did_set_breakpoint_after_cpuid =
          vm()->add_breakpoint(ip() + trapped_instruction_len(singlestepping_instruction), BKPT_INTERNAL);
      }
    } else if (arch() == aarch64 && is_singlestep_resume(how_last_execution_resumed)) {
      // On aarch64, if the last execution was any sort of single step, then
      // resuming again with PTRACE_(SYSEMU_)SINGLESTEP will cause a debug fault
      // immediately before executing the next instruction in userspace
      // (essentially completing the singlestep that got "interrupted" by
      // trapping into the kernel). To prevent this, we must re-arm the
      // PSTATE.SS bit. (If the last resume was not a single step,
      // the kernel will apply this modification).
      if (!registers.aarch64_singlestep_flag()) {
        registers.set_aarch64_singlestep_flag();
        registers_dirty = true;
      }
    }
  }

  address_of_last_execution_resume = ip();
  how_last_execution_resumed = how;

  flush_regs();

  pid_t wait_ret = 0;
  if (session().is_recording()) {
    /* There's a nasty race where a stopped task gets woken up by a SIGKILL
     * and advances to the PTRACE_EXIT_EVENT ptrace-stop just before we
     * send a PTRACE_CONT. Our PTRACE_CONT will cause it to continue and exit,
     * which means we don't get a chance to clean up robust futexes etc.
     * Avoid that by doing a waitpid() here to see if it has exited.
     * This doesn't fully close the race since in theory we could be preempted
     * between the waitpid and the ptrace_if_alive, giving another task
     * a chance to SIGKILL our tracee and advance it to the PTRACE_EXIT_EVENT,
     * or just letting the tracee be scheduled to process its pending SIGKILL.
     */
    int raw_status = 0;
    wait_ret = waitpid(tid, &raw_status, WNOHANG | __WALL);
    ASSERT(this, 0 <= wait_ret)
        << "waitpid(" << tid << ", NOHANG) failed with " << wait_ret;
    WaitStatus status(raw_status);
    if (wait_ret == tid) {
      // In some (but not all) cases where the child was killed with SIGKILL,
      // we don't get PTRACE_EVENT_EXIT before it just exits, because a SIGKILL
      // arrived when the child was already in the PTRACE_EVENT_EXIT stop.
      // The status could be any exit or fatal-signal status, since this status
      // can reflect what caused the thread to exit before the SIGKILL arrived
      // and forced it out of the PTRACE_EVENT_EXIT stop.
      ASSERT(this,
             status.ptrace_event() == PTRACE_EVENT_EXIT ||
                 status.reaped())
          << "got " << status;
      did_waitpid(status);
    } else {
      ASSERT(this, 0 == wait_ret)
          << "waitpid(" << tid << ", NOHANG) failed with " << wait_ret;
    }
  }
  if (wait_ret > 0 || handled_ptrace_exit_event) {
    LOG(debug) << "Task " << tid << " exited unexpectedly";
    // wait() will see this and report the ptrace-exit event.
    detected_unexpected_exit = true;
  } else {
    ptrace_if_alive(how, nullptr, (void*)(uintptr_t)sig);
    is_stopped = false;
    extra_registers_known = false;
    if (RESUME_WAIT == wait_how) {
      wait();
    }
  }
}

void Task::set_regs(const Registers& regs) {
  ASSERT(this, is_stopped);
  if (registers.original_syscallno() != regs.original_syscallno()) {
    orig_syscallno_dirty = true;
  }
  bool changed = registers != regs;
  if (changed) {
    registers_dirty = true;
    registers = regs;
  }
}

void Task::flush_regs() {
  if (registers_dirty) {
    LOG(debug) << "Flushing registers for tid " << tid << " " << registers;
    auto ptrace_regs = registers.get_ptrace_iovec();
#if defined(__i386__) || defined(__x86_64__)
    if (ptrace_if_alive(PTRACE_SETREGSET, NT_PRSTATUS, &ptrace_regs)) {
      /* It's ok for flush regs to fail, e.g. if the task got killed underneath
       * us - we just need to remember not to trust any value we would load
       * from ptrace otherwise */
      registers_dirty = false;
      orig_syscallno_dirty = false;
    }
#elif defined(__aarch64__)
    struct iovec vec = { &ptrace_regs,
                          sizeof(ptrace_regs) };
    if (ptrace_if_alive(PTRACE_SETREGSET, NT_PRSTATUS, &vec)) {
      registers_dirty = false;
    }
#else
    #error "Unknown archietcture"
#endif
  }
#if defined(__i386__) || defined(__x86_64__)
  else {
    ASSERT(this, !orig_syscallno_dirty);
  }
#elif defined(__aarch64__)
  if (orig_syscallno_dirty) {
    uintptr_t syscall = registers.original_syscallno();
    struct iovec vec = { &syscall,
                          sizeof(syscall) };
    LOG(debug) << "Chaning syscall to " << syscall;
    if (ptrace_if_alive(PTRACE_SETREGSET, NT_ARM_SYSTEM_CALL, &vec)) {
      orig_syscallno_dirty = false;
    }
  }
#endif
}

void Task::set_extra_regs(const ExtraRegisters& regs) {
  ASSERT(this, !regs.empty()) << "Trying to set empty ExtraRegisters";
  ASSERT(this, regs.arch() == arch())
      << "Trying to set wrong arch ExtraRegisters";
  extra_registers = regs;
  extra_registers_known = true;

  switch (extra_registers.format()) {
    case ExtraRegisters::XSAVE: {
      if (xsave_area_size() > 512) {
        struct iovec vec = { extra_registers.data_.data(),
                             extra_registers.data_.size() };
        ptrace_if_alive(PTRACE_SETREGSET, NT_X86_XSTATE, &vec);
      } else {
#if defined(__i386__)
        ASSERT(this,
               extra_registers.data_.size() == sizeof(user_fpxregs_struct));
        ptrace_if_alive(PTRACE_SETFPXREGS, nullptr,
                        extra_registers.data_.data());
#elif defined(__x86_64__)
        ASSERT(this,
               extra_registers.data_.size() == sizeof(user_fpregs_struct));
        ptrace_if_alive(PTRACE_SETFPREGS, nullptr,
                        extra_registers.data_.data());
#endif
      }
      break;
    }
    case ExtraRegisters::NT_FPR: {
      struct iovec vec = { extra_registers.data_.data(),
                            extra_registers.data_.size() };
      ptrace_if_alive(PTRACE_SETREGSET, NT_PRFPREG, &vec);
      break;
    }
    default:
      ASSERT(this, false) << "Unexpected ExtraRegisters format";
  }
}

enum WatchBytesX86 {
  BYTES_1 = 0x00,
  BYTES_2 = 0x01,
  BYTES_4 = 0x03,
  BYTES_8 = 0x02
};
static WatchBytesX86 num_bytes_to_dr_len(size_t num_bytes) {
  switch (num_bytes) {
    case 1:
      return BYTES_1;
    case 2:
      return BYTES_2;
    case 4:
      return BYTES_4;
    case 8:
      return BYTES_8;
    default:
      FATAL() << "Unsupported breakpoint size " << num_bytes;
      return WatchBytesX86(-1); // not reached
  }
}

struct DebugControl {
  uintptr_t dr0_local : 1;
  uintptr_t dr0_global : 1;
  uintptr_t dr1_local : 1;
  uintptr_t dr1_global : 1;
  uintptr_t dr2_local : 1;
  uintptr_t dr2_global : 1;
  uintptr_t dr3_local : 1;
  uintptr_t dr3_global : 1;

  uintptr_t ignored : 8;

  WatchType dr0_type : 2;
  WatchBytesX86 dr0_len : 2;
  WatchType dr1_type : 2;
  WatchBytesX86 dr1_len : 2;
  WatchType dr2_type : 2;
  WatchBytesX86 dr2_len : 2;
  WatchType dr3_type : 2;
  WatchBytesX86 dr3_len : 2;

  void enable(size_t index, WatchBytesX86 size, WatchType type) {
    switch (index) {
#define CASE(_i)                                                  \
      case _i:                                                    \
        dr##_i##_local = 1;                                       \
        dr##_i##_global = 0;                                      \
        dr##_i##_type = type;                                     \
        dr##_i##_len = size;                                      \
        break
      CASE(0);
      CASE(1);
      CASE(2);
      CASE(3);
#undef CASE
      default:
        FATAL() << "Invalid index";
    }
  }
};

static_assert(sizeof(DebugControl) == sizeof(uintptr_t),
              "Can't pack DebugControl");

union PackedDebugControl {
  uintptr_t packed;
  DebugControl ctl;
};

static bool set_x86_debug_regs(Task *t, const Task::DebugRegs& regs) {
  // Reset the debug status since we're about to change the set
  // of programmed watchpoints.
  t->set_x86_debug_reg(6, 0);

  if (regs.size() > NUM_X86_WATCHPOINTS) {
    t->set_x86_debug_reg(7, 0);
    return false;
  }

  // Work around kernel bug https://bugzilla.kernel.org/show_bug.cgi?id=200965.
  // For every watchpoint we're going to use, enable it with size 1.
  // This will let us set the address freely without potentially triggering
  // the kernel bug which will reject an unaligned address if the watchpoint
  // is disabled but was non-size-1.
  PackedDebugControl dr7;
  dr7.packed = 0;
  for (size_t i = 0; i < regs.size(); ++i) {
    dr7.ctl.enable(i, BYTES_1, WATCH_EXEC);
  }
  t->set_x86_debug_reg(7, dr7.packed);

  size_t index = 0;
  for (auto reg : regs) {
    if (!t->set_x86_debug_reg(index, reg.addr.as_int())) {
      t->set_x86_debug_reg(7, 0);
      return false;
    }
    dr7.ctl.enable(index, num_bytes_to_dr_len(reg.num_bytes), reg.type);
    ++index;
  }
  return t->set_x86_debug_reg(7, dr7.packed);
}

template <typename Arch>
static bool set_debug_regs_arch(Task* t, const Task::DebugRegs& regs);
template <> bool set_debug_regs_arch<X86Arch>(Task* t, const Task::DebugRegs& regs) {
  return set_x86_debug_regs(t, regs);
}
template <> bool set_debug_regs_arch<X64Arch>(Task* t, const Task::DebugRegs& regs) {
  return set_x86_debug_regs(t, regs);
}

static void query_max_bp_wp(Task* t, ssize_t* max_bp, ssize_t* max_wp) {
  ARM64Arch::user_hwdebug_state bps;
  ARM64Arch::user_hwdebug_state wps;
  bool ok = t->get_aarch64_debug_regs(NT_ARM_HW_BREAK, &bps) &&
            t->get_aarch64_debug_regs(NT_ARM_HW_WATCH, &wps);
  ASSERT(t, ok);
  *max_bp = bps.dbg_info & 0xff;
  *max_wp = wps.dbg_info & 0xff;
}

template <> bool set_debug_regs_arch<ARM64Arch>(Task* t, const Task::DebugRegs& regs) {
  ARM64Arch::user_hwdebug_state bps;
  ARM64Arch::user_hwdebug_state wps;
  memset(&bps, 0, sizeof(bps));
  memset(&wps, 0, sizeof(wps));

  static ssize_t max_bp = -1;
  static ssize_t max_wp = -1;
  if (max_bp == -1) {
    query_max_bp_wp(t, &max_bp, &max_wp);
  }

  // Having at least one of each is architecturally guaranteed
  ASSERT(t, max_bp >= 1 && max_wp >= 1);

  ssize_t cur_bp = 0;
  ssize_t cur_wp = 0;
  for (auto reg : regs) {
    // GDB always splits these into nicely aligned platform chunks for us,
    // but let's be general and support unaligned registers also.
    size_t len = reg.num_bytes;
    remote_ptr<uint8_t> addr = reg.addr.cast<uint8_t>();
    while (len > 0) {
      ARM64Arch::hw_bp* bp = nullptr;
      if (reg.type == WATCH_EXEC) {
        if (cur_bp == max_bp) {
          return false;
        }
        bp = &bps.dbg_regs[cur_bp++];
      } else {
        if (cur_wp == max_wp) {
          return false;
        }
        bp = &wps.dbg_regs[cur_wp++];
      }
      ARM64Arch::hw_breakpoint_ctrl ctrl;
      memset(&ctrl, 0, sizeof(ctrl));
      switch (reg.type) {
        case WATCH_EXEC:
          ctrl.type = ARM_WATCH_EXEC;
          break;
        case WATCH_WRITE:
          ctrl.type = ARM_WATCH_WRITE;
          break;
        case WATCH_READWRITE:
          ctrl.type = ARM_WATCH_READWRITE;
          break;
      }
      ctrl.enabled = 1;
      ctrl.priv = ARM_PRIV_EL0;
      uintptr_t off = (uintptr_t)addr.as_int() % 8;
      size_t cur_bp_len = std::min(8-off, len);
      // This is a byte mask of which particular byte in the 8byte word at `addr`
      // to watch.
      uintptr_t mask = ((((uintptr_t)1) << cur_bp_len) - 1) << off;
      ASSERT(t, (mask & ~0xff) == 0);
      ctrl.length = mask;
      bp->addr = addr.as_int() - off;
      bp->ctrl = ctrl;
      len -= cur_bp_len;
      addr += cur_bp_len;
    }
  }

  // max_bp rather than cur_bp to make sure to clear out any unused slots
  return t->set_aarch64_debug_regs(NT_ARM_HW_BREAK, &bps, max_bp) &&
         t->set_aarch64_debug_regs(NT_ARM_HW_WATCH, &wps, max_wp);
}

bool Task::set_debug_regs(const DebugRegs& regs) {
  RR_ARCH_FUNCTION(set_debug_regs_arch, arch(), this, regs);
}

static void set_thread_area(std::vector<X86Arch::user_desc>& thread_areas_,
                            X86Arch::user_desc desc) {
  for (auto& t : thread_areas_) {
    if (t.entry_number == desc.entry_number) {
      t = desc;
      return;
    }
  }
  thread_areas_.push_back(desc);
}

void Task::set_thread_area(remote_ptr<X86Arch::user_desc> tls) {
  // We rely on the fact that user_desc is word-size-independent.
  DEBUG_ASSERT(arch() == x86 || arch() == x86_64);
  auto desc = read_mem(tls);
  rr::set_thread_area(thread_areas_, desc);
}

int Task::emulate_set_thread_area(int idx, X86Arch::user_desc desc) {
  DEBUG_ASSERT(arch() == x86 || arch() == x86_64);
  errno = 0;
  fallible_ptrace(NativeArch::PTRACE_SET_THREAD_AREA, idx, &desc);
  if (errno != 0) {
    return errno;
  }
  desc.entry_number = idx;
  rr::set_thread_area(thread_areas_, desc);
  return 0;
}

int Task::emulate_get_thread_area(int idx, X86Arch::user_desc& desc) {
  DEBUG_ASSERT(arch() == x86 || arch() == x86_64);
  LOG(debug) << "Emulating PTRACE_GET_THREAD_AREA";
  errno = 0;
  fallible_ptrace(NativeArch::PTRACE_GET_THREAD_AREA, idx, &desc);
  return errno;
}

pid_t Task::tgid() const { return tg->tgid; }

pid_t Task::real_tgid() const {
  // Unless we're recording, each task is in its own thread group
  return session().is_recording() ? tgid() : tid;
}

const string& Task::trace_dir() const {
  const TraceStream* trace = trace_stream();
  ASSERT(this, trace) << "Trace directory not available";
  return trace->dir();
}

uint32_t Task::trace_time() const {
  const TraceStream* trace = trace_stream();
  return trace ? trace->time() : 0;
}

void Task::update_prname(remote_ptr<void> child_addr) {
  char buf[16];
  // The null-terminated name might start within the last 16 bytes of a memory
  // mapping.
  ssize_t bytes = read_bytes_fallible(child_addr, sizeof(buf), buf);
  // If there was no readable data then this shouldn't be called
  ASSERT(this, bytes > 0);
  // Make sure the final byte is null if the string needed to be truncated
  buf[bytes - 1] = 0;
  prname = buf;
}

static bool is_signal_triggered_by_ptrace_interrupt(int group_stop_sig) {
  switch (group_stop_sig) {
    case SIGTRAP:
    // We sometimes see SIGSTOP at interrupts, though the
    // docs don't mention that.
    case SIGSTOP:
      return true;
    default:
      return false;
  }
}

// This function doesn't really need to do anything. The signal will cause
// waitpid to return EINTR and that's all we need.
static void handle_alarm_signal(__attribute__((unused)) int sig) {}

bool Task::wait_unexpected_exit() {
  if (detected_unexpected_exit) {
    LOG(debug) << "Unexpected (SIGKILL) exit was detected; reporting it now";
    did_waitpid(WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT));
    detected_unexpected_exit = false;
    return true;
  }
  return false;
}

void Task::wait(double interrupt_after_elapsed) {
  LOG(debug) << "going into blocking waitid(" << tid << ") ...";
  ASSERT(this, session().is_recording() || interrupt_after_elapsed == -1);

  if (wait_unexpected_exit()) {
    return;
  }

  WaitStatus status;
  bool sent_wait_interrupt = false;
  int ret;
  while (true) {
    if (interrupt_after_elapsed == 0 && !sent_wait_interrupt) {
      ptrace_if_alive(PTRACE_INTERRUPT, nullptr, nullptr);
      sent_wait_interrupt = true;
      expecting_ptrace_interrupt_stop = 2;
    }

    if (interrupt_after_elapsed > 0) {
      struct itimerval timer = { { 0, 0 },
                                 to_timeval(interrupt_after_elapsed) };
      setitimer(ITIMER_REAL, &timer, nullptr);
    }
    siginfo_t info;
    ret = waitid(P_PID, tid, &info, WSTOPPED);
    DEBUG_ASSERT(ret == 0 || ret == -1);
    if (ret == -1) {
      ret = -errno;
    }
    if (interrupt_after_elapsed > 0) {
      struct itimerval timer = { { 0, 0 }, { 0, 0 } };
      setitimer(ITIMER_REAL, &timer, nullptr);
      interrupt_after_elapsed = 0;
    }

    if (ret == 0) {
      status = WaitStatus(info);
      // waitpid was not interrupted by the alarm.
      break;
    } else {
      if (ret == -ECHILD) {
        /* The process died without us getting a PTRACE_EXIT_EVENT notification.
        * This is possible if the process receives a SIGKILL while in the exit
        * event stop, but before we were able to read the event notification.
        * We handle this situation by synthesizing an exit event, but otherwise
        * going about our regular business.
        */
        LOG(debug) << "Synthesizing PTRACE_EVENT_EXIT for zombie process " << tid;
        status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
        break;
      } else if (ret != -EINTR) {
        FATAL() << "Unexpected wait error " << -ret;
      }
      continue;
    }
  }

  if (sent_wait_interrupt) {
    LOG(warn) << "Forced to PTRACE_INTERRUPT tracee";
    if (!is_signal_triggered_by_ptrace_interrupt(status.group_stop())) {
      LOG(warn) << "  PTRACE_INTERRUPT raced with another event " << status;
    }
  }
  did_waitpid(status);
}

void Task::canonicalize_regs(SupportedArch syscall_arch) {
  ASSERT(this, is_stopped);

  if (registers.arch() == x86_64) {
    if (syscall_arch == x86) {
      // The int $0x80 compatibility handling clears r8-r11
      // (see arch/x86/entry/entry_64_compat.S). The sysenter compatibility
      // handling also clears r12-r15. However, to actually make such a syscall,
      // the user process would have to switch itself into compatibility mode,
      // which, though possible, does not appear to actually be done by any
      // real application (contrary to int $0x80, which is accessible from 64bit
      // mode as well).
      registers_dirty |= registers.set_r8(0x0);
      registers_dirty |= registers.set_r9(0x0);
      registers_dirty |= registers.set_r10(0x0);
      registers_dirty |= registers.set_r11(0x0);
    } else {
      // x86-64 'syscall' instruction copies RFLAGS to R11 on syscall entry.
      // If we single-stepped into the syscall instruction, the TF flag will be
      // set in R11. We don't want the value in R11 to depend on whether we
      // were single-stepping during record or replay, possibly causing
      // divergence.
      // This doesn't matter when exiting a sigreturn syscall, since it
      // restores the original flags.
      // For untraced syscalls, the untraced-syscall entry point code (see
      // write_rr_page) does this itself.
      // We tried just clearing %r11, but that caused hangs in
      // Ubuntu/Debian kernels.
      // Making this match the flags makes this operation idempotent, which is
      // helpful.
      registers_dirty |= registers.set_r11(0x246);
      // x86-64 'syscall' instruction copies return address to RCX on syscall
      // entry. rr-related kernel activity normally sets RCX to -1 at some point
      // during syscall execution, but apparently in some (unknown) situations
      // probably involving untraced syscalls, that doesn't happen. To avoid
      // potential issues, forcibly replace RCX with -1 always.
      // This doesn't matter (and we should not do this) when exiting a
      // sigreturn syscall, since it will restore the original RCX and we don't
      // want to clobber that.
      // For untraced syscalls, the untraced-syscall entry point code (see
      // write_rr_page) does this itself.
      registers_dirty |= registers.set_cx((intptr_t)-1);
    }
    // On kernel 3.13.0-68-generic #111-Ubuntu SMP we have observed a failed
    // execve() clearing all flags during recording. During replay we emulate
    // the exec so this wouldn't happen. Just reset all flags so everything's
    // consistent.
    // 0x246 is ZF+PF+IF+reserved, the result clearing a register using
    // "xor reg, reg".
    registers_dirty |= registers.set_flags(0x246);
  } else if (registers.arch() == x86) {
    // The x86 SYSENTER handling in Linux modifies EBP and EFLAGS on entry.
    // EBP is the potential sixth syscall parameter, stored on the user stack.
    // The EFLAGS changes are described here:
    // http://linux-kernel.2935.n7.nabble.com/ia32-sysenter-target-does-not-preserve-EFLAGS-td1074164.html
    // In a VMWare guest, the modifications to EFLAGS appear to be
    // nondeterministic. Cover that up by setting EFLAGS to reasonable values
    // now.
    registers_dirty |= registers.set_flags(0x246);
  }
}

bool Task::read_aarch64_tls_register(uintptr_t *result) {
  struct iovec vec = { result, sizeof(*result) };
  return ptrace_if_alive(PTRACE_GETREGSET, NT_ARM_TLS, &vec);
}

void Task::set_aarch64_tls_register(uintptr_t val) {
  struct iovec vec = { &val, sizeof(val) };
  bool ok = ptrace_if_alive(PTRACE_SETREGSET, NT_ARM_TLS, &vec);
  ASSERT(this, ok);
}

void Task::did_waitpid(WaitStatus status) {
  LOG(debug) << "  Task " << tid << " changed status to " << status;

  // After PTRACE_INTERRUPT, any next two stops may be a group stop caused by
  // that PTRACE_INTERRUPT (or neither may be). This is because PTRACE_INTERRUPT
  // generally lets other stops win (and thus doesn't inject it's own stop), but
  // if the other stop was already done processing, even we didn't see it yet,
  // the stop will still be queued, so we could see the other stop and then the
  // PTRACE_INTERRUPT group stop.
  // When we issue PTRACE_INTERRUPT, we this set this counter to 2, and here
  // we decrement it on every stop such that while this counter is positive,
  // any group-stop could be one induced by PTRACE_INTERRUPT
  bool siginfo_overriden = false;
  if (expecting_ptrace_interrupt_stop > 0) {
    expecting_ptrace_interrupt_stop--;
    if (is_signal_triggered_by_ptrace_interrupt(status.group_stop())) {
      // Assume this was PTRACE_INTERRUPT and thus treat this as
      // TIME_SLICE_SIGNAL instead.
      if (session().is_recording()) {
        // Force this timeslice to end
        session().as_record()->scheduler().expire_timeslice();
      }
      status = WaitStatus::for_stop_sig(PerfCounters::TIME_SLICE_SIGNAL);
      memset(&pending_siginfo, 0, sizeof(pending_siginfo));
      pending_siginfo.si_signo = PerfCounters::TIME_SLICE_SIGNAL;
      pending_siginfo.si_fd = hpc.ticks_interrupt_fd();
      pending_siginfo.si_code = POLL_IN;
      siginfo_overriden = true;
      expecting_ptrace_interrupt_stop = 0;
    }
  }

  if (!siginfo_overriden && status.stop_sig()) {
    if (!ptrace_if_alive(PTRACE_GETSIGINFO, nullptr, &pending_siginfo)) {
      LOG(debug) << "Unexpected process death getting siginfo for " << tid;
      status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
    }
  }

  intptr_t original_syscallno = registers.original_syscallno();
  LOG(debug) << "  (refreshing register cache)";

  if (status.reaped()) {
    was_reaped = true;
    if (handled_ptrace_exit_event) {
      LOG(debug) << "Reaped task late " << tid;
      // We did not reap this task when it exited, likely because it was a
      // thread group leader blocked on the exit of the other members of
      // its thread group. This has now reaped the task, so all we need to do
      // here is get out quickly and the higher-level function should go ahead
      // and delete us.
      is_stopped = true;
      wait_status = status;
      return;
    }
    LOG(debug) << "Unexpected process reap for " << tid;
    /* Mark buffers as having been destroyed. We missed our chance
     * to destroy them normally in handle_ptrace_exit_event.
     * XXX: We could try to find some tasks here to unmap our buffers, but it
     *      seems hardly worth it.
     */
    destroy_buffers(nullptr, nullptr);
    status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
  } else {
    // An unstable exit can cause a task to exit without us having run it, in
    // which case we might have pending register changes for it that are now
    // irrelevant. In that case we just throw away our register changes and use
    // whatever the kernel now has.
    if (status.ptrace_event() != PTRACE_EVENT_EXIT) {
      ASSERT(this, !registers_dirty) << "Registers shouldn't already be dirty (status is " << status << ")";
    }
    // If the task was not stopped, we don't need to read the registers.
    // In fact if we didn't start the thread, we may not have flushed dirty
    // registers but still received a PTRACE_EVENT_EXIT, in which case the
    // task's register values are not what they should be.
    if (!is_stopped && !registers_dirty) {
      LOG(debug) << "Requesting registers from tracee " << tid;
      NativeArch::user_regs_struct ptrace_regs;

#if defined(__i386__) || defined(__x86_64__)
      if (ptrace_if_alive(PTRACE_GETREGS, nullptr, &ptrace_regs)) {
        registers.set_from_ptrace(ptrace_regs);
        // Check the architecture of the task by looking at the
        // cs segment register and checking if that segment is a long mode segment
        // (Linux always uses GDT entries for this, which are globally the same).
        SupportedArch a = is_long_mode_segment(registers.cs()) ? x86_64 : x86;
        if (a != registers.arch()) {
          registers.set_arch(a);
          registers.set_from_ptrace(ptrace_regs);
        }
      }
#elif defined(__aarch64__)
      struct iovec vec = { &ptrace_regs,
                          sizeof(ptrace_regs) };
      if (ptrace_if_alive(PTRACE_GETREGSET, NT_PRSTATUS, &vec)) {
        registers.set_from_ptrace(ptrace_regs);
      }
#else
#error detect architecture here
#endif
      else {
        LOG(debug) << "Unexpected process death for " << tid;
        status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
      }
    }
  }

  is_stopped = true;
  wait_status = status;
  Ticks more_ticks = hpc.read_ticks(this);
  // We stop counting here because there may be things we want to do to the
  // tracee that would otherwise generate ticks.
  hpc.stop_counting();
  session().accumulate_ticks_processed(more_ticks);
  ticks += more_ticks;

  if (status.ptrace_event() == PTRACE_EVENT_EXIT) {
    ASSERT(this, !handled_ptrace_exit_event);
    seen_ptrace_exit_event = true;
    if (already_reaped()) {
      // NB: It's possible for us to have already reaped in the
      // "Unexpected process reap" case above. If that's happened, there's
      // nothing more to do here.
      handled_ptrace_exit_event = true;
    }
  } else {
    if (arch() == x86 || arch() == x86_64) {
      // Clear the single step flag in case we got here by taking a signal
      // after asking for a single step. We want to avoid taking that single
      // step after the signal resumes, so the singlestep flag needs to be
      // cleared. On aarch64, the kernel does this for us.
      if (registers.x86_singlestep_flag()) {
        registers.clear_x86_singlestep_flag();
        registers_dirty = true;
      }

      if (last_resume_orig_cx != 0) {
        uintptr_t new_cx = registers.cx();
        /* Un-fudge registers, if we fudged them to work around the KNL hardware
          quirk */
        unsigned cutoff = single_step_coalesce_cutoff();
        ASSERT(this, new_cx == cutoff - 1 || new_cx == cutoff);
        registers.set_cx(last_resume_orig_cx - cutoff + new_cx);
        registers_dirty = true;
      }
      last_resume_orig_cx = 0;
    }

    if (did_set_breakpoint_after_cpuid) {
      remote_code_ptr bkpt_addr =
        address_of_last_execution_resume + trapped_instruction_len(singlestepping_instruction);
      if (ip().undo_executed_bkpt(arch()) == bkpt_addr) {
        Registers r = regs();
        r.set_ip(bkpt_addr);
        set_regs(r);
      }
      vm()->remove_breakpoint(bkpt_addr, BKPT_INTERNAL);
      did_set_breakpoint_after_cpuid = false;
    }
    if ((singlestepping_instruction == TrappedInstruction::PUSHF ||
         singlestepping_instruction == TrappedInstruction::PUSHF16) &&
        ip() == address_of_last_execution_resume +
          trapped_instruction_len(singlestepping_instruction)) {
      // We singlestepped through a pushf. Clear TF bit on stack.
      auto sp = regs().sp().cast<uint16_t>();
      // If this address is invalid then we should have segfaulted instead of
      // retiring the instruction!
      uint16_t val = read_mem(sp);
      write_mem(sp, (uint16_t)(val & ~X86_TF_FLAG));
    }
    singlestepping_instruction = TrappedInstruction::NONE;

    // We might have singlestepped at the resumption address and just exited
    // the kernel without executing the breakpoint at that address.
    // The kernel usually (always?) singlesteps an extra instruction when
    // we do this with PTRACE_SYSEMU_SINGLESTEP, but rr's ptrace emulation
    // doesn't and it's kind of a kernel bug.
    if (as->get_breakpoint_type_at_addr(address_of_last_execution_resume) !=
            BKPT_NONE &&
        stop_sig() == SIGTRAP && !ptrace_event() &&
        ip().undo_executed_bkpt(arch()) == address_of_last_execution_resume) {
      ASSERT(this, more_ticks == 0);
      // When we resume execution and immediately hit a breakpoint, the original
      // syscall number can be reset to -1. Undo that, so that the register
      // state matches the state we'd be in if we hadn't resumed. ReplayTimeline
      // depends on resume-at-a-breakpoint being a noop.
      registers.set_original_syscallno(original_syscallno);
      registers_dirty = true;
    }

    // If we're in the rr page,  we may have just returned from an untraced
    // syscall there and while in the rr page registers need to be consistent
    // between record and replay. During replay most untraced syscalls are
    // replaced with "xor eax,eax" (right after a "movq -1, %rcx") so
    // rcx is always -1, but during recording it sometimes isn't after we've
    // done a real syscall.
    if (is_in_rr_page()) {
      // N.B.: Cross architecture syscalls don't go through the rr page, so we
      // know what the architecture is.
      canonicalize_regs(arch());
    }
  }

  did_wait();
}

bool Task::try_wait() {
  if (wait_unexpected_exit()) {
    return true;
  }

  // Check if there is a status change for us
  WaitStatus status;
  siginfo_t info;
  memset(&info, 0, sizeof(siginfo_t));
  int ret = waitid(P_PID, tid, &info, WSTOPPED | WNOHANG);
  ASSERT(this, 0 == ret || (-1 == ret && errno == ECHILD)) <<
    "waitid(" << tid << ", NOHANG) failed with "
                         << ret;
  LOG(debug) << "waitpid(" << tid << ", NOHANG) returns " << ret;
  if (ret == 0 && info.si_pid == 0) {
    return false;
  }
  if (ret == 0) {
    status = WaitStatus(info);
  } else if (ret == -1) {
    DEBUG_ASSERT(errno == ECHILD);
    // Either we died unexpectedly or we were in exec and changed the tid.
    // Try to differentiate the two situations by seeing if there is an exit
    // notification ready for us to de-queue, in which case we synthesize an
    // exit event (but don't actually reap the task, instead leaving that
    // for the generic cleanup code).
    int ret = waitid(P_PID, tid, &info, WEXITED | WNOWAIT | WNOHANG);
    if (ret == 0 && info.si_pid == tid) {
      LOG(debug) << "Synthesizing PTRACE_EVENT_EXIT for zombie process in try_wait " << tid;
      status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
    } else {
      DEBUG_ASSERT(ret == -1 && errno == ECHILD);
      return false;
    }
  }
  did_waitpid(status);
  return true;
}

template <typename Arch>
static void set_tls_from_clone_arch(Task* t, remote_ptr<void> tls) {
  if (Arch::clone_tls_type == Arch::UserDescPointer) {
    t->set_thread_area(tls.cast<X86Arch::user_desc>());
  }
}

static void set_tls_from_clone(Task* t, remote_ptr<void> tls) {
  RR_ARCH_FUNCTION(set_tls_from_clone_arch, t->arch(), t, tls);
}

template <typename Arch>
static void setup_preload_thread_locals_from_clone_arch(Task* t, Task* origin) {
  void* local_addr = preload_thread_locals_local_addr(*t->vm());
  if (local_addr) {
    t->activate_preload_thread_locals();
    auto locals = reinterpret_cast<preload_thread_locals<Arch>*>(local_addr);
    auto origin_locals = reinterpret_cast<const preload_thread_locals<Arch>*>(
        origin->fetch_preload_thread_locals());
    locals->alt_stack_nesting_level = origin_locals->alt_stack_nesting_level;
    // clone() syscalls set the child stack pointer, so the child is no
    // longer in the syscallbuf code even if the parent was.
  }
}

void Task::setup_preload_thread_locals_from_clone(Task* origin) {
  RR_ARCH_FUNCTION(setup_preload_thread_locals_from_clone_arch, this->arch(), this, origin);
}

Task* Task::clone(CloneReason reason, int flags, remote_ptr<void> stack,
                  remote_ptr<void> tls, remote_ptr<int>, pid_t new_tid,
                  pid_t new_rec_tid, uint32_t new_serial,
                  Session* other_session,
                  FdTable::shr_ptr new_fds,
                  ThreadGroup::shr_ptr new_tg) {
  Session* new_task_session = &session();
  if (other_session) {
    ASSERT(this, reason != TRACEE_CLONE);
    new_task_session = other_session;
  } else {
    ASSERT(this, reason == TRACEE_CLONE);
  }
  Task* t =
      new_task_session->new_task(new_tid, new_rec_tid, new_serial, arch());

  if (CLONE_SHARE_VM & flags) {
    t->as = as;
    if (!stack.is_null()) {
      remote_ptr<void> last_stack_byte = stack - 1;
      if (t->as->has_mapping(last_stack_byte)) {
        auto mapping = t->as->mapping_of(last_stack_byte);
        if (!mapping.recorded_map.is_heap()) {
          const KernelMapping& m = mapping.map;
          LOG(debug) << "mapping stack for " << new_tid << " at " << m;
          t->as->map(t, m.start(), m.size(), m.prot(), m.flags(),
                     m.file_offset_bytes(), "[stack]", m.device(), m.inode());
        }
      }
    }
  } else {
    t->as = new_task_session->clone(t, as);
  }

  t->syscallbuf_size = syscallbuf_size;
  t->preload_globals = preload_globals;
  t->seccomp_bpf_enabled = seccomp_bpf_enabled;

  // FdTable is either shared or copied, so the contents of
  // syscallbuf_fds_disabled_child are still valid.
  if (CLONE_SHARE_FILES & flags) {
    ASSERT(this, !new_fds);
    t->fds = fds;
  } else if (new_fds) {
    t->fds = new_fds;
  } else {
    t->fds = fds->clone();
  }
  t->fds->insert_task(t);

  t->top_of_stack = stack;
  // Clone children, both thread and fork, inherit the parent
  // prname.
  t->prname = prname;

  // wait() before trying to do anything that might need to
  // use ptrace to access memory
  t->wait();

  t->post_wait_clone(this, flags);
  if (CLONE_SHARE_THREAD_GROUP & flags) {
    ASSERT(this, !new_tg);
    t->tg = tg;
  } else {
    if (new_tg) {
      t->tg = new_tg;
    } else {
      t->tg = new_task_session->clone(t, tg);
    }
  }
  t->tg->insert_task(t);

  t->open_mem_fd_if_needed();
  t->thread_areas_ = thread_areas_;
  if (CLONE_SET_TLS & flags) {
    set_tls_from_clone(t, tls);
  }

  t->as->insert_task(t);

  if (reason == TRACEE_CLONE) {
    if (!(CLONE_SHARE_VM & flags)) {
      // Unmap syscallbuf and scratch for tasks running the original address
      // space.
      AutoRemoteSyscalls remote(t);
      for (Task* tt : as->task_set()) {
        // Leak the scratch buffer for the task we cloned from. We need to do
        // this because we may be using part of it for the syscallbuf stack
        // and unmapping it now would cause a crash in the new task.
        if (tt != this) {
          t->unmap_buffers_for(remote, tt, tt->syscallbuf_child);
        }
      }
      as->did_fork_into(t);
    }

    // `t` doesn't have a syscallbuf and `t->desched_fd_child`/
    // `t->cloned_file_data_fd_child` are both -1.
    if (session().is_replaying()) {
      // `t` is not really sharing our fd table, in fact our real fd table
      // is only used by this task, so it only contains our syscallbuf fds (if any),
      // not the fds for any other task. So, only really-close the fds for 'this'.
      // We still need to update t's `fds` table to indicate that those fds were
      // closed during recording, though, otherwise we may get FileMonitor
      // collisions.
      AutoRemoteSyscalls remote(t);
      for (Task* tt : fds->task_set()) {
        t->close_buffers_for(remote, tt, tt == this);
      }
    } else if (CLONE_SHARE_FILES & flags) {
      // `t` is sharing our fd table, so it should not close anything.
    } else {
      // Close syscallbuf fds for all tasks using the original fd table.
      AutoRemoteSyscalls remote(t);
      for (Task* tt : fds->task_set()) {
        t->close_buffers_for(remote, tt, true);
      }
    }
  }

  t->post_vm_clone(reason, flags, this);

  return t;
}

bool Task::post_vm_clone(CloneReason reason, int flags, Task* origin) {
  bool created_preload_thread_locals_mapping = false;
  if (!(CLONE_SHARE_VM & flags)) {
    created_preload_thread_locals_mapping = this->as->post_vm_clone(this);
  }
  this->as->fd_tables_changed();

  if (reason == TRACEE_CLONE) {
    setup_preload_thread_locals_from_clone(origin);
  }

  return created_preload_thread_locals_mapping;
}

Task* Task::os_fork_into(Session* session, FdTable::shr_ptr new_fds) {
  AutoRemoteSyscalls remote(this, AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS);
  Task* child =
      os_clone(Task::SESSION_CLONE_LEADER, session, remote, rec_tid, serial,
               // Most likely, we'll be setting up a
               // CLEARTID futex.  That's not done
               // here, but rather later in
               // |copy_state()|.
               //
               // We also don't use any of the SETTID
               // flags because that earlier work will
               // be copied by fork()ing the address
               // space.
               SIGCHLD,
               move(new_fds));
  // When we forked ourselves, the child inherited the setup we
  // did to make the clone() call.  So we have to "finish" the
  // remote calls (i.e. undo fudged state) in the child too,
  // even though we never made any syscalls there.
  remote.restore_state_to(child);
  return child;
}

Task* Task::os_clone_into(const CapturedState& state,
                          AutoRemoteSyscalls& remote,
                          const ClonedFdTables& cloned_fd_tables,
                          ThreadGroup::shr_ptr new_tg) {
  auto fdtable_entry = cloned_fd_tables.find(state.fdtable_identity);
  DEBUG_ASSERT(fdtable_entry != cloned_fd_tables.end() &&
               "All captured fd tables should be in cloned_fd_tables");
  return os_clone(Task::SESSION_CLONE_NONLEADER, &remote.task()->session(),
                  remote, state.rec_tid, state.serial,
                  // We don't actually /need/ to specify the
                  // SIGHAND/SYSVMEM flags because those things
                  // are emulated in the tracee.  But we use the
                  // same flags as glibc to be on the safe side
                  // wrt kernel bugs.
                  //
                  // We don't pass CLONE_SETTLS here *only*
                  // because we'll do it later in
                  // |copy_state()|.
                  //
                  // See |os_fork_into()| above for discussion
                  // of the CTID flags.
                  (CLONE_VM | CLONE_FS | CLONE_SIGHAND |
                   CLONE_SYSVSEM),
                  fdtable_entry->second,
                  move(new_tg),
                  state.top_of_stack);
}

template <typename Arch>
static void copy_tls_arch(const Task::CapturedState& state,
                          AutoRemoteSyscalls& remote) {
  if (Arch::clone_tls_type == Arch::UserDescPointer) {
    for (const auto& t : state.thread_areas) {
      AutoRestoreMem remote_tls(remote, (const uint8_t*)&t, sizeof(t));
      LOG(debug) << "    setting tls " << remote_tls.get();
      remote.infallible_syscall(
          syscall_number_for_set_thread_area(remote.arch()),
          remote_tls.get().as_int());
    }
  } else if (Arch::arch() == aarch64) {
    remote.task()->set_aarch64_tls_register(state.tls_register);
  }
}

static void copy_tls(const Task::CapturedState& state,
                     AutoRemoteSyscalls& remote) {
  RR_ARCH_FUNCTION(copy_tls_arch, remote.arch(), state, remote);
}

static int64_t fdinfo_field(Task* t, int fd, const char* field, bool must_exist) {
  char buf[1024];
  sprintf(buf, "/proc/%d/fdinfo/%d", t->tid, fd);
  ScopedFd info(buf, O_RDONLY);
  if (must_exist) {
    ASSERT(t, info.is_open()) << "Can't open " << buf;
  } else if (!info.is_open()) {
    return -1;
  }
  ssize_t bytes = read(info, buf, sizeof(buf) - 1);
  ASSERT(t, bytes > 0);
  buf[bytes] = 0;

  char* p = buf;
  size_t field_len = strlen(field);
  while (*p) {
    if (strncmp(p, field, field_len) == 0) {
      char* end;
      long long int r = strtoll(p + field_len, &end, 10);
      ASSERT(t, *end == 0 || *end == '\n');
      return r;
    }
    while (*p) {
      if (*p == '\n') {
        ++p;
        break;
      }
      ++p;
    }
  }
  return -1;
}

int64_t Task::fd_offset(int fd) {
  return fdinfo_field(this, fd, "pos:", true);
}

pid_t Task::pid_of_pidfd(int fd) {
  return fdinfo_field(this, fd, "Pid:", false);
}

Task::CapturedState Task::capture_state() {
  CapturedState state;
  state.rec_tid = rec_tid;
  state.fdtable_identity = uintptr_t(fds.get());
  state.serial = serial;
  state.tguid = thread_group()->tguid();
  state.regs = regs();
  state.extra_regs = extra_regs();
  state.prname = prname;
  if (arch() == aarch64) {
    bool ok = read_aarch64_tls_register(&state.tls_register);
    ASSERT(this, ok);
  }
  state.thread_areas = thread_areas_;
  state.desched_fd_child = desched_fd_child;
  state.cloned_file_data_fd_child = cloned_file_data_fd_child;
  state.cloned_file_data_fname = cloned_file_data_fname;
  state.cloned_file_data_offset =
      cloned_file_data_fd_child >= 0
          ? fd_offset(cloned_file_data_fd_child)
          : 0;
  memcpy(&state.thread_locals, fetch_preload_thread_locals(),
         PRELOAD_THREAD_LOCALS_SIZE);
  state.syscallbuf_child = syscallbuf_child;
  state.syscallbuf_size = syscallbuf_size;
  state.preload_globals = preload_globals;
  state.scratch_ptr = scratch_ptr;
  state.scratch_size = scratch_size;
  state.wait_status = wait_status;
  state.ticks = ticks;
  state.top_of_stack = top_of_stack;
  return state;
}

void Task::copy_state(const CapturedState& state) {
  set_regs(state.regs);
  set_extra_regs(state.extra_regs);
  {
    AutoRemoteSyscalls remote(this);
    {
      char prname[17];
      strncpy(prname, state.prname.c_str(), sizeof(prname));
      prname[16] = 0;
      AutoRestoreMem remote_prname(remote, (const uint8_t*)prname, 16);
      LOG(debug) << "    setting name to " << prname;
      remote.infallible_syscall(syscall_number_for_prctl(arch()), PR_SET_NAME,
                                remote_prname.get().as_int());
      update_prname(remote_prname.get());
    }

    copy_tls(state, remote);
    thread_areas_ = state.thread_areas;
    syscallbuf_size = state.syscallbuf_size;

    ASSERT(this, !syscallbuf_child)
        << "Syscallbuf should not already be initialized in clone";
    if (!state.syscallbuf_child.is_null()) {
      // All these fields are preserved by the fork.
      desched_fd_child = state.desched_fd_child;
      cloned_file_data_fd_child = state.cloned_file_data_fd_child;
      cloned_file_data_fname = state.cloned_file_data_fname;
      if (cloned_file_data_fd_child >= 0) {
        ScopedFd fd(cloned_file_data_fname.c_str(), session().as_record() ?
          O_RDWR : O_RDONLY);
        remote.infallible_send_fd_dup(fd, cloned_file_data_fd_child);
        remote.infallible_lseek_syscall(
            cloned_file_data_fd_child, state.cloned_file_data_offset, SEEK_SET);
      }
      syscallbuf_child = state.syscallbuf_child;
    }
  }
  preload_globals = state.preload_globals;
  ASSERT(this, as->thread_locals_tuid() != tuid());
  memcpy(&thread_locals, &state.thread_locals, PRELOAD_THREAD_LOCALS_SIZE);
  // The scratch buffer (for now) is merely a private mapping in
  // the remote task.  The CoW copy made by fork()'ing the
  // address space has the semantics we want.  It's not used in
  // replay anyway.
  scratch_ptr = state.scratch_ptr;
  scratch_size = state.scratch_size;

  // Whatever |from|'s last wait status was is what ours would
  // have been.
  wait_status = state.wait_status;

  ticks = state.ticks;
}

remote_ptr<const struct syscallbuf_record> Task::next_syscallbuf_record() {
  return ((syscallbuf_child + 1).cast<uint8_t>() +
          read_mem(REMOTE_PTR_FIELD(syscallbuf_child, num_rec_bytes)))
      .cast<const struct syscallbuf_record>();
}

long Task::stored_record_size(
    remote_ptr<const struct syscallbuf_record> record) {
  return ::stored_record_size(read_mem(REMOTE_PTR_FIELD(record, size)));
}

long Task::fallible_ptrace(int request, remote_ptr<void> addr, void* data) {
  return ptrace(__ptrace_request(request), tid, addr, data);
}

bool Task::open_mem_fd() {
  // Use ptrace to read/write during open_mem_fd
  as->set_mem_fd(ScopedFd());

  if (!is_stopped) {
    LOG(warn) << "Can't retrieve mem fd for " << tid <<
      "; process not stopped, racing with exec?";
    return false;
  }

  /**
   * We're expecting that either we or the child can read the mem fd.
   * It's possible for both to not be the case (us on certain kernel
   * configurations, the child after it did a setuid).
   */
  char pid_path[PATH_MAX];
  sprintf(pid_path, "/proc/%d", tid);
  ScopedFd dir_fd(pid_path, O_PATH);
  if (dir_fd < 0) {
    LOG(info) << "Can't retrieve mem fd for " << tid << "; process no longer exists??";
    return false;
  }

  ScopedFd fd = ScopedFd::openat(dir_fd, "mem", O_RDWR | O_CLOEXEC);
  if (!fd.is_open()) {
    LOG(debug) << "Falling back to the remote fd dance";
    AutoRemoteSyscalls remote(this);
    int remote_mem_dir_fd = remote.send_fd(dir_fd);
    if (remote_mem_dir_fd < 0) {
      LOG(info) << "Can't retrieve mem fd for " << tid << "; process is exiting?";
      return false;
    }

    char mem[] = "mem";
    // If the remote dies, any of these can fail. That's ok, we'll just
    // find that the fd wasn't successfully opened.
    AutoRestoreMem remote_path(remote, mem, sizeof(mem));
    int remote_mem_fd = remote.syscall(syscall_number_for_openat(arch()),
                        remote_mem_dir_fd, remote_path.get(), O_RDWR);
    fd = remote.retrieve_fd(remote_mem_fd);
    remote.syscall(syscall_number_for_close(arch()), remote_mem_fd);
    remote.syscall(syscall_number_for_close(arch()), remote_mem_dir_fd);
  }

  if (!fd.is_open()) {
    LOG(info) << "Can't retrieve mem fd for " << tid << "; process no longer exists?";
    return false;
  }
  as->set_mem_fd(move(fd));
  return true;
}

void Task::open_mem_fd_if_needed() {
  if (!as->mem_fd().is_open()) {
    open_mem_fd();
  }
}

KernelMapping Task::init_syscall_buffer(AutoRemoteSyscalls& remote,
                                        remote_ptr<void> map_hint) {
  char name[50];
  sprintf(name, "syscallbuf.%d", rec_tid);
  KernelMapping km =
      Session::create_shared_mmap(remote, syscallbuf_size, map_hint, name);
  auto& m = remote.task()->vm()->mapping_of(km.start());
  remote.task()->vm()->mapping_flags_of(km.start()) |=
      AddressSpace::Mapping::IS_SYSCALLBUF;

  ASSERT(this, !syscallbuf_child)
      << "Should not already have syscallbuf initialized!";

  syscallbuf_child = km.start().cast<struct syscallbuf_hdr>();

  // No entries to begin with.
  memset(m.local_addr, 0, sizeof(struct syscallbuf_hdr));

  return km;
}

void Task::set_syscallbuf_locked(bool locked) {
  if (!syscallbuf_child) {
    return;
  }
  remote_ptr<uint8_t> remote_addr = REMOTE_PTR_FIELD(syscallbuf_child, locked);
  uint8_t locked_before = read_mem(remote_addr);
  uint8_t new_locked = locked ? (locked_before | SYSCALLBUF_LOCKED_TRACER)
                              : (locked_before & ~SYSCALLBUF_LOCKED_TRACER);
  if (new_locked != locked_before) {
    write_mem(remote_addr, new_locked);
  }
}

void Task::reset_syscallbuf() {
  if (!syscallbuf_child) {
    return;
  }

  ASSERT(this,
         !is_in_untraced_syscall() ||
             0 == (SYSCALLBUF_LOCKED_TRACEE &
                   read_mem(REMOTE_PTR_FIELD(syscallbuf_child, locked))));

  // Memset is easiest to do by using the local mapping which should always
  // exist for the syscallbuf
  uint32_t num_rec =
      read_mem(REMOTE_PTR_FIELD(syscallbuf_child, num_rec_bytes));
  uint8_t* ptr = as->local_mapping(syscallbuf_child + 1, num_rec);
  DEBUG_ASSERT(ptr != nullptr);
  memset(ptr, 0, num_rec);
  write_mem(REMOTE_PTR_FIELD(syscallbuf_child, num_rec_bytes), (uint32_t)0);
  write_mem(REMOTE_PTR_FIELD(syscallbuf_child, mprotect_record_count),
            (uint32_t)0);
  write_mem(REMOTE_PTR_FIELD(syscallbuf_child, mprotect_record_count_completed),
            (uint32_t)0);
  write_mem(REMOTE_PTR_FIELD(syscallbuf_child, blocked_sigs_generation),
            (uint32_t)0);
}

ssize_t Task::read_bytes_ptrace(remote_ptr<void> addr, ssize_t buf_size,
                                void* buf) {
  ssize_t nread = 0;
  // ptrace operates on the word size of the host, so we really do want
  // to use sizes of host types here.
  uintptr_t word_size = sizeof(long);
  errno = 0;
  // Only read aligned words. This ensures we can always read the last
  // byte before an unmapped region.
  while (nread < buf_size) {
    uintptr_t start = addr.as_int() + nread;
    uintptr_t start_word = start & ~(word_size - 1);
    uintptr_t end_word = start_word + word_size;
    uintptr_t length = std::min(end_word - start, uintptr_t(buf_size - nread));

    long v = fallible_ptrace(PTRACE_PEEKDATA, start_word, nullptr);
    if (errno) {
      break;
    }
    memcpy(static_cast<uint8_t*>(buf) + nread,
           reinterpret_cast<uint8_t*>(&v) + (start - start_word), length);
    nread += length;
  }

  return nread;
}

ssize_t Task::write_bytes_ptrace(remote_ptr<void> addr, ssize_t buf_size,
                                 const void* buf) {
  ssize_t nwritten = 0;
  // ptrace operates on the word size of the host, so we really do want
  // to use sizes of host types here.
  uintptr_t word_size = sizeof(long);
  errno = 0;
  // Only write aligned words. This ensures we can always write the last
  // byte before an unmapped region.
  while (nwritten < buf_size) {
    uintptr_t start = addr.as_int() + nwritten;
    uintptr_t start_word = start & ~(word_size - 1);
    uintptr_t end_word = start_word + word_size;
    uintptr_t length =
        std::min(end_word - start, uintptr_t(buf_size - nwritten));

    long v;
    if (length < word_size) {
      v = fallible_ptrace(PTRACE_PEEKDATA, start_word, nullptr);
      if (errno) {
        break;
      }
    }
    memcpy(reinterpret_cast<uint8_t*>(&v) + (start - start_word),
           static_cast<const uint8_t*>(buf) + nwritten, length);
    fallible_ptrace(PTRACE_POKEDATA, start_word, reinterpret_cast<void*>(v));
    nwritten += length;
  }

  return nwritten;
}

ssize_t Task::read_bytes_fallible(remote_ptr<void> addr, ssize_t buf_size,
                                  void* buf) {
  ASSERT_ACTIONS(this, buf_size >= 0, << "Invalid buf_size " << buf_size);
  if (0 == buf_size) {
    return 0;
  }

  if (uint8_t* local_addr = as->local_mapping(addr, buf_size)) {
    memcpy(buf, local_addr, buf_size);
    return buf_size;
  }

  if (!as->mem_fd().is_open()) {
    return read_bytes_ptrace(addr, buf_size, static_cast<uint8_t*>(buf));
  }

  ssize_t all_read = 0;
  while (all_read < buf_size) {
    errno = 0;
    ssize_t nread = pread64(as->mem_fd(), static_cast<uint8_t*>(buf) + all_read,
                            buf_size - all_read, addr.as_int() + all_read);
    // We open the mem_fd just after being notified of
    // exec(), when the Task is created.  Trying to read from that
    // fd seems to return 0 with errno 0.  Reopening the mem fd
    // allows the pwrite to succeed.  It seems that the first mem
    // fd we open, very early in exec, refers to the address space
    // before the exec and the second mem fd refers to the address
    // space after exec.
    if (0 == nread && 0 == all_read && 0 == errno) {
      if (!open_mem_fd()) {
        return 0;
      }
      continue;
    }
    if (nread <= 0) {
      if (all_read > 0) {
        // We did successfully read some data, so return success and ignore
        // any error.
        errno = 0;
        return all_read;
      }
      return nread;
    }
    // We read some data. We should try again in case we get short reads.
    all_read += nread;
  }
  return all_read;
}

void Task::read_bytes_helper(remote_ptr<void> addr, ssize_t buf_size, void* buf,
                             bool* ok) {
  // pread64 etc can't handle addresses that appear to be negative ...
  // like [vsyscall].
  ssize_t nread = read_bytes_fallible(addr, buf_size, buf);
  if (nread != buf_size) {
    if (ok) {
      *ok = false;
    } else {
      ASSERT(this, false) << "Should have read " << buf_size << " bytes from "
                          << addr << ", but only read " << nread;
    }
  }
}

/**
 * This function exists to work around
 * https://bugzilla.kernel.org/show_bug.cgi?id=99101.
 * On some kernels pwrite() to /proc/.../mem fails when writing to a region
 * that's PROT_NONE.
 * Also, writing through MAP_SHARED readonly mappings fails (even if the
 * file was opened read-write originally), so we handle that here too.
 */
static ssize_t safe_pwrite64(Task* t, const void* buf, ssize_t buf_size,
                             remote_ptr<void> addr) {
  vector<KernelMapping> mappings_to_fix;
  for (const auto& m :
       t->vm()->maps_containing_or_after(floor_page_size(addr))) {
    if (m.map.start() >= ceil_page_size(addr + buf_size)) {
      break;
    }
    if (m.map.prot() & PROT_WRITE) {
      continue;
    }
    if (!(m.map.prot() & PROT_READ) || (m.map.flags() & MAP_SHARED)) {
      mappings_to_fix.push_back(m.map);
    }
  };

  if (mappings_to_fix.empty()) {
    return pwrite_all_fallible(t->vm()->mem_fd(), buf, buf_size, addr.as_int());
  }

  AutoRemoteSyscalls remote(t);
  int mprotect_syscallno = syscall_number_for_mprotect(t->arch());
  for (auto& m : mappings_to_fix) {
    remote.infallible_syscall(mprotect_syscallno, m.start(), m.size(),
                              m.prot() | PROT_WRITE);
  }
  ssize_t nwritten = pwrite_all_fallible(t->vm()->mem_fd(), buf, buf_size, addr.as_int());
  for (auto& m : mappings_to_fix) {
    remote.infallible_syscall(mprotect_syscallno, m.start(), m.size(),
                              m.prot());
  }
  return nwritten;
}

void Task::write_bytes_helper(remote_ptr<void> addr, ssize_t buf_size,
                              const void* buf, bool* ok, uint32_t flags) {
  ASSERT(this, buf_size >= 0) << "Invalid buf_size " << buf_size;
  if (0 == buf_size) {
    return;
  }

  if (uint8_t* local_addr = as->local_mapping(addr, buf_size)) {
    memcpy(local_addr, buf, buf_size);
    return;
  }

  if (!as->mem_fd().is_open()) {
    ssize_t nwritten =
        write_bytes_ptrace(addr, buf_size, static_cast<const uint8_t*>(buf));
    if (nwritten > 0) {
      vm()->notify_written(addr, nwritten, flags);
    }
    if (ok && nwritten < buf_size) {
      *ok = false;
    }
    return;
  }

  errno = 0;
  ssize_t nwritten = safe_pwrite64(this, buf, buf_size, addr.as_int());
  // See comment in read_bytes_helper().
  if (0 == nwritten && 0 == errno) {
    open_mem_fd();
    return write_bytes_helper(addr, buf_size, buf, ok, flags);
  }
  if (errno == EPERM) {
    FATAL() << "Can't write to /proc/" << tid << "/mem\n"
            << "Maybe you need to disable grsecurity MPROTECT with:\n"
            << "  setfattr -n user.pax.flags -v 'emr' <executable>";
  }
  if (ok) {
    if (nwritten < buf_size) {
      *ok = false;
    }
  } else {
    ASSERT(this, nwritten == buf_size)
        << "Should have written " << buf_size << " bytes to " << addr
        << ", but only wrote " << nwritten;
  }
  if (nwritten > 0) {
    vm()->notify_written(addr, nwritten, flags);
  }
}

uint64_t Task::write_ranges(const vector<FileMonitor::Range>& ranges,
                            void* data, size_t size) {
  uint8_t* p = static_cast<uint8_t*>(data);
  size_t s = size;
  size_t result = 0;
  for (auto& r : ranges) {
    size_t bytes = min(s, r.length);
    write_bytes_helper(r.data, bytes, p);
    s -= bytes;
    result += bytes;
    if (s == 0) {
      break;
    }
  }
  return result;
}

const TraceStream* Task::trace_stream() const {
  if (session().as_record()) {
    return &session().as_record()->trace_writer();
  }
  if (session().as_replay()) {
    return &session().as_replay()->trace_reader();
  }
  return nullptr;
}

void Task::xptrace(int request, remote_ptr<void> addr, void* data) {
  errno = 0;
  fallible_ptrace(request, addr, data);
  ASSERT(this, !errno) << "ptrace(" << ptrace_req_name<NativeArch>(request) << ", " << tid
                       << ", addr=" << addr << ", data=" << data
                       << ") failed with errno " << errno;
}

bool Task::ptrace_if_alive(int request, remote_ptr<void> addr, void* data) {
  errno = 0;
  fallible_ptrace(request, addr, data);
  if (errno == ESRCH) {
    LOG(debug) << "ptrace_if_alive tid " << tid << " was not alive";
    return false;
  }
  ASSERT(this, !errno) << "ptrace(" << ptrace_req_name<NativeArch>(request) << ", " << tid
                       << ", addr=" << addr << ", data=" << data
                       << ") failed with errno " << errno;
  return true;
}

SupportedArch Task::detect_syscall_arch() {
  SupportedArch syscall_arch;
  bool ok = get_syscall_instruction_arch(
      this, regs().ip().decrement_by_syscall_insn_length(arch()),
      &syscall_arch);
  ASSERT(this, ok);
  return syscall_arch;
}

bool Task::clone_syscall_is_complete(pid_t* new_pid,
                                     SupportedArch syscall_arch) {
  int event = ptrace_event();
  if (PTRACE_EVENT_CLONE == event || PTRACE_EVENT_FORK == event ||
      PTRACE_EVENT_VFORK == event) {
    *new_pid = get_ptrace_eventmsg<pid_t>();
    return true;
  }
  ASSERT(this, !event) << "Unexpected ptrace event "
                       << ptrace_event_name(event);

  // EAGAIN can happen here due to fork failing under load. The caller must
  // handle this.
  // XXX ENOSYS shouldn't happen here.
  intptr_t result = regs().syscall_result_signed();
  ASSERT(this,
         regs().syscall_may_restart() || -ENOSYS == result ||
             -EAGAIN == result || -ENOMEM == result)
      << "Unexpected task status " << status() << " ("
      << syscall_name(regs().original_syscallno(), syscall_arch)
      << " syscall errno: " << errno_name(-result) << ")";
  return false;
}

template <typename Arch> static void do_preload_init_arch(Task* t) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<Arch>>(t->regs().arg1()));

  for (Task* tt : t->vm()->task_set()) {
    tt->preload_globals = params.globals.rptr();
  }

  t->write_mem(REMOTE_PTR_FIELD(t->preload_globals, in_replay),
               (unsigned char)t->session().is_replaying());
}

static void do_preload_init(Task* t) {
  RR_ARCH_FUNCTION(do_preload_init_arch, t->arch(), t);
}

void Task::at_preload_init() {
  as->at_preload_init(this);
  do_preload_init(this);

  fd_table()->init_syscallbuf_fds_disabled(this);
}

template <typename Arch>
static long perform_remote_clone_arch(
    AutoRemoteSyscalls& remote, unsigned base_flags, remote_ptr<void> stack,
    remote_ptr<int> ptid, remote_ptr<void> tls, remote_ptr<int> ctid) {
  switch (Arch::clone_parameter_ordering) {
    case Arch::FlagsStackParentTLSChild:
      return remote.syscall(Arch::clone, base_flags, stack, ptid.as_int(),
                            tls.as_int(), ctid.as_int());
    case Arch::FlagsStackParentChildTLS:
      return remote.syscall(Arch::clone, base_flags, stack, ptid.as_int(),
                            ctid.as_int(), tls.as_int());
  }
}

static long perform_remote_clone(AutoRemoteSyscalls& remote,
                                 unsigned base_flags, remote_ptr<void> stack,
                                 remote_ptr<int> ptid, remote_ptr<void> tls,
                                 remote_ptr<int> ctid) {
  RR_ARCH_FUNCTION(perform_remote_clone_arch, remote.arch(), remote, base_flags,
                   stack, ptid, tls, ctid);
}

/*static*/ Task* Task::os_clone(CloneReason reason, Session* session,
                                AutoRemoteSyscalls& remote, pid_t rec_child_tid,
                                uint32_t new_serial, unsigned base_flags,
                                FdTable::shr_ptr new_fds,
                                ThreadGroup::shr_ptr new_tg,
                                remote_ptr<void> stack, remote_ptr<int> ptid,
                                remote_ptr<void> tls, remote_ptr<int> ctid) {
  long ret;
  do {
    ret = perform_remote_clone(remote, base_flags, stack, ptid, tls, ctid);
  } while (ret == -EAGAIN);
  ASSERT(remote.task(), ret >= 0)
      << "remote clone failed with errno " << errno_name(-ret);

  Task* child = remote.task()->clone(
      reason, clone_flags_to_task_flags(base_flags), stack, tls, ctid,
      remote.new_tid(), rec_child_tid, new_serial, session, move(new_fds),
      move(new_tg));
  return child;
}

static void setup_fd_table(Task* t, FdTable& fds, int tracee_socket_fd_number) {
  fds.add_monitor(t, STDOUT_FILENO, new StdioMonitor(STDOUT_FILENO));
  fds.add_monitor(t, STDERR_FILENO, new StdioMonitor(STDERR_FILENO));
  fds.add_monitor(t, RR_MAGIC_SAVE_DATA_FD, new MagicSaveDataMonitor());
  fds.add_monitor(t, tracee_socket_fd_number, new PreserveFileMonitor());
}

static void spawned_child_fatal_error(const ScopedFd& err_fd,
                                      const char* format, ...) {
  va_list args;
  va_start(args, format);
  char* buf;
  if (vasprintf(&buf, format, args) < 0) {
    exit(1);
  }

  char* buf2;
  if (asprintf(&buf2, "%s (%s)", buf, errno_name(errno).c_str()) < 0) {
    exit(1);
  }
  write_all(err_fd, buf2, strlen(buf2));
  _exit(1);
}

static void disable_tsc(int err_fd) {
  /* Trap to the rr process if a 'rdtsc' instruction is issued.
   * That allows rr to record the tsc and replay it
   * deterministically. */
  if (0 > prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0)) {
    spawned_child_fatal_error(err_fd, "error setting up prctl");
  }
}

template <typename Arch> void set_up_process_arch(int err_fd);
template <> void set_up_process_arch<X86Arch>(int err_fd) { disable_tsc(err_fd); }
template <> void set_up_process_arch<X64Arch>(int err_fd) { disable_tsc(err_fd); }
template <> void set_up_process_arch<ARM64Arch>(int) {}

void set_up_process_arch(SupportedArch arch, int err_fd) {
  RR_ARCH_FUNCTION(set_up_process_arch, arch, err_fd);
}

/**
 * Prepare this process and its ancestors for recording/replay by
 * preventing direct access to sources of nondeterminism, and ensuring
 * that rr bugs don't adversely affect the underlying system.
 */
static void set_up_process(Session& session, const ScopedFd& err_fd,
                           const ScopedFd& sock_fd, int sock_fd_number) {
  /* TODO tracees can probably undo some of the setup below
   * ... */

  restore_initial_resource_limits();

  /* CLOEXEC so that the original fd here will be closed by the exec that's
   * about to happen.
   */
  int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (0 > fd) {
    spawned_child_fatal_error(err_fd, "error opening /dev/null");
  }
  if (RR_MAGIC_SAVE_DATA_FD != dup2(fd, RR_MAGIC_SAVE_DATA_FD)) {
    spawned_child_fatal_error(err_fd, "error duping to RR_MAGIC_SAVE_DATA_FD");
  }

  if (sock_fd_number != dup2(sock_fd, sock_fd_number)) {
    spawned_child_fatal_error(err_fd,
                              "error duping to RR_RESERVED_SOCKET_FD");
  }

  if (session.is_replaying()) {
    // This task and all its descendants should silently reap any terminating
    // children.
    if (SIG_ERR == signal(SIGCHLD, SIG_IGN)) {
      spawned_child_fatal_error(err_fd, "error doing signal()");
    }

    // If the rr process dies, prevent runaway tracee processes
    // from dragging down the underlying system.
    //
    // TODO: this isn't inherited across fork().
    if (0 > prctl(PR_SET_PDEATHSIG, SIGKILL)) {
      spawned_child_fatal_error(err_fd, "Couldn't set parent-death signal");
    }

    // Put the replaying processes into their own session. This will stop
    // signals being sent to these processes by the terminal --- in particular
    // SIGTSTP/SIGINT/SIGWINCH.
    setsid();
  }

  /* Do any architecture specific setup, such as disabling non-deterministic
     instructions */
  set_up_process_arch(NativeArch::arch(), err_fd);

  /* If we're in setuid_sudo mode, we have CAP_SYS_ADMIN, so we don't need to
     set NO_NEW_PRIVS here in order to install the seccomp filter later. In,
     emulate any potentially privileged, operations, so we might as well set
     no_new_privs */
  if (!session.is_recording() || !has_effective_caps(1 << CAP_SYS_ADMIN)) {
    if (0 > prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
      spawned_child_fatal_error(
          err_fd,
          "prctl(NO_NEW_PRIVS) failed, SECCOMP_FILTER is not available: your "
          "kernel is too old. Use `record -n` to disable the filter.");
    }
  }
}

static SeccompFilter<struct sock_filter> create_seccomp_filter() {
  SeccompFilter<struct sock_filter> f;
  for (auto& e : AddressSpace::rr_page_syscalls()) {
    if (e.traced == AddressSpace::UNTRACED) {
      auto ip = AddressSpace::rr_page_syscall_exit_point(e.traced, e.privileged,
                                                         e.enabled,
                                                         NativeArch::arch());
      f.allow_syscalls_from_callsite(ip);
    }
  }
  f.trace();
  return f;
}

/**
 * This is called (and must be called) in the tracee after rr has taken
 * ptrace control. Otherwise, once we've installed the seccomp filter,
 * things go wrong because we have no ptracer and the seccomp filter demands
 * one.
 */
static void set_up_seccomp_filter(const struct sock_fprog& prog, int err_fd) {
  /* Note: the filter is installed only for record. This call
   * will be emulated (not passed to the kernel) in the replay. */
  if (0 > prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (uintptr_t)&prog, 0, 0)) {
    spawned_child_fatal_error(
        err_fd, "prctl(SECCOMP) failed, SECCOMP_FILTER is not available: your "
                "kernel is too old.");
  }
  /* anything that happens from this point on gets filtered! */
}

static void run_initial_child(Session& session, const ScopedFd& error_fd,
                              const ScopedFd& sock_fd, int sock_fd_number,
                              const char* exe_path_cstr,
                              char* const argv_array[],
                              char* const envp_array[],
                              const struct sock_fprog& seccomp_prog) {
  pid_t pid = getpid();

  set_up_process(session, error_fd, sock_fd, sock_fd_number);
  // The preceding code must run before sending SIGSTOP here,
  // since after SIGSTOP replay emulates almost all syscalls, but
  // we need the above syscalls to run "for real".

  // Signal to tracer that we're configured.
  ::kill(pid, SIGSTOP);

  // This code must run after rr has taken ptrace control.
  set_up_seccomp_filter(seccomp_prog, error_fd);

  // We do a small amount of dummy work here to retire
  // some branches in order to ensure that the ticks value is
  // non-zero.  The tracer can then check the ticks value
  // at the first ptrace-trap to see if it seems to be
  // working.
  int start = random() % 5;
  int num_its = start + 5;
  int sum = 0;
  for (int i = start; i < num_its; ++i) {
    sum += i;
  }
  syscall(SYS_write, -1, &sum, sizeof(sum));

  CPUIDBugDetector::run_detection_code();

  execve(exe_path_cstr, argv_array, envp_array);

  switch (errno) {
    case ENOENT:
      spawned_child_fatal_error(
          error_fd, "execve failed: '%s' (or interpreter) not found",
          exe_path_cstr);
      break;
    default:
      spawned_child_fatal_error(error_fd, "execve of '%s' failed",
                                exe_path_cstr);
      break;
  }
  // Never returns!
}

/*static*/ Task* Task::spawn(Session& session, ScopedFd& error_fd,
                             ScopedFd* sock_fd_out,
                             ScopedFd* sock_fd_receiver_out,
                             int* tracee_socket_fd_number_out,
                             const std::string& exe_path,
                             const std::vector<std::string>& argv,
                             const std::vector<std::string>& envp,
                             pid_t rec_tid) {
  DEBUG_ASSERT(session.tasks().size() == 0);

  int sockets[2];
  long ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets);
  if (ret < 0) {
    FATAL() << "socketpair failed";
  }
  *sock_fd_out = ScopedFd(sockets[0]);
  *sock_fd_receiver_out = ScopedFd(sockets[1]);

  // Find a usable FD number to dup to in the child. RR_RESERVED_SOCKET_FD
  // might already be used by an outer rr.
  int fd_number = RR_RESERVED_SOCKET_FD;
  // We assume no other thread is mucking with this part of the fd address space.
  while (true) {
    ret = fcntl(fd_number, F_GETFD);
    if (ret < 0) {
      if (errno != EBADF) {
        FATAL() << "Error checking fd";
      }
      break;
    }
    ++fd_number;
  }
  *tracee_socket_fd_number_out = fd_number;

  pid_t tid;
  // After fork() in a multithreaded program, the child can safely call only
  // async-signal-safe functions, and malloc is not one of them (breaks e.g.
  // with tcmalloc).
  // Doing the allocations before the fork duplicates the allocations, but
  // prevents errors.
  StringVectorToCharArray argv_array(argv);
  StringVectorToCharArray envp_array(envp);
  SeccompFilter<struct sock_filter> filter = create_seccomp_filter();
  struct sock_fprog prog = {(unsigned short)filter.filters.size(),
                            filter.filters.data()};
  do {
    tid = fork();
    // fork() can fail with EAGAIN due to temporary load issues. In such
    // cases, retry the fork().
  } while (0 > tid && errno == EAGAIN);

  if (0 == tid) {
    run_initial_child(session, error_fd, *sock_fd_receiver_out, fd_number, exe_path.c_str(),
                      argv_array.get(), envp_array.get(), prog);
    // run_initial_child never returns
  }

  if (0 > tid) {
    FATAL() << "Failed to fork";
  }

  // Make sure the child has the only reference to this side of the pipe.
  error_fd.close();

  // Sync with the child process.
  // We minimize the code we run between fork()ing and PTRACE_SEIZE, because
  // any abnormal exit of the rr process will leave the child paused and
  // parented by the init process, i.e. effectively leaked. After PTRACE_SEIZE
  // with PTRACE_O_EXITKILL, the tracee will die if rr dies.
  intptr_t options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                     PTRACE_O_TRACECLONE;
  if (!Flags::get().disable_ptrace_exit_events) {
    options |= PTRACE_O_TRACEEXIT;
  }
  if (session.is_recording()) {
    options |= PTRACE_O_TRACEVFORK | PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEEXEC;
  }

  ret =
      ptrace((__ptrace_request)PTRACE_SEIZE, tid, nullptr, (void*)(options | PTRACE_O_EXITKILL));
  if (ret < 0 && errno == EINVAL) {
    // PTRACE_O_EXITKILL was added in kernel 3.8, and we only need
    // it for more robust cleanup, so tolerate not having it.
    ret = ptrace((__ptrace_request)PTRACE_SEIZE, tid, nullptr, (void*)options);
  }
  if (ret) {
    // Note that although the tracee may have died due to some fatal error,
    // we haven't reaped its exit code so there's no danger of killing
    // (or PTRACE_SEIZEing) the wrong process.
    int tmp_errno = errno;
    ::kill(tid, SIGKILL);
    errno = tmp_errno;

    string hint;
    if (errno == EPERM) {
      hint = "; child probably died before reaching SIGSTOP\n"
             "Child's message: " +
             session.read_spawned_task_error();
    }
    FATAL() << "PTRACE_SEIZE failed for tid " << tid << hint;
  }

  Task* t = session.new_task(tid, rec_tid, session.next_task_serial(),
                             NativeArch::arch());
  auto tg = session.create_initial_tg(t);
  t->tg.swap(tg);
  auto as = session.create_vm(t);
  t->as.swap(as);
  t->fds = FdTable::create(t);
  setup_fd_table(t, *t->fds, fd_number);

  // Install signal handler here, so that when creating the first RecordTask
  // it sees the exact same signal state in the parent as will be in the child.
  struct sigaction sa;
  sa.sa_handler = handle_alarm_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0; // No SA_RESTART, so waitpid() will be interrupted
  sigaction(SIGALRM, &sa, nullptr);

  t->wait();
  if (t->ptrace_event() == PTRACE_EVENT_EXIT) {
    t->proceed_to_exit();
    FATAL() << "Tracee died before reaching SIGSTOP\n"
               "Child's message: "
            << session.read_spawned_task_error();
  }
  // SIGSTOP can be reported as a signal-stop or group-stop depending on
  // whether PTRACE_SEIZE happened before or after it was delivered.
  if (SIGSTOP != t->status().stop_sig() &&
      SIGSTOP != t->status().group_stop()) {
    WaitStatus failed_status = t->status();
    t->kill();
    FATAL() << "Unexpected stop " << failed_status
            << "\nChild's message: "
            << session.read_spawned_task_error();
  }

  t->clear_wait_status();
  t->open_mem_fd();
  return t;
}

void* Task::preload_thread_locals() {
  return preload_thread_locals_local_addr(*as);
}

static bool file_was_deleted(string s) {
  static const char deleted[] = " (deleted)";
  ssize_t find_deleted = s.size() - (sizeof(deleted) - 1);
  return s.find(deleted) == size_t(find_deleted);
}

static void create_mapping(Task *t, AutoRemoteSyscalls &remote, const KernelMapping &km) {
  string real_file_name;
  dev_t device = KernelMapping::NO_DEVICE;
  ino_t inode = KernelMapping::NO_INODE;
  if (km.is_real_device() && !file_was_deleted(km.fsname())) {
    struct stat real_file; string real_file_name;
    remote.finish_direct_mmap(km.start(), km.size(), km.prot(), km.flags(),
      km.fsname(), O_RDONLY, km.file_offset_bytes()/page_size(),
      real_file, real_file_name);
  } else {
    remote.infallible_mmap_syscall(km.start(), km.size(), km.prot(),
                                  km.flags() | MAP_FIXED | MAP_ANONYMOUS, -1,
                                  0);
  }
  t->vm()->map(t, km.start(), km.size(), km.prot(), km.flags(), km.file_offset_bytes(),
               real_file_name, device, inode, nullptr, &km);
}

static void apply_mm_map(AutoRemoteSyscalls& remote, const struct prctl_mm_map& map)
{
  AutoRestoreMem remote_mm_map(remote, (const uint8_t*)&map, sizeof(map));
  remote.infallible_syscall(syscall_number_for_prctl(remote.task()->arch()), PR_SET_MM,
                            PR_SET_MM_MAP, remote_mm_map.get().as_int(),
                            sizeof(map));
}

static void copy_mem_mapping(Task* from, Task* to, const KernelMapping& km) {
  vector<char> buf;
  buf.resize(km.size());
  ssize_t bytes = from->read_bytes_fallible(km.start(), km.size(), buf.data());
  // There can be mappings of files where the mapping starts beyond the end-of-file
  // so no bytes will be read.
  if (bytes > 0) {
    // We may have a short read here if there are beyond-end-of-mapped-file pages
    // in the mapping.
    bool ok = true;
    to->write_bytes_helper(km.start(), bytes, buf.data(), &ok);
    ASSERT(to, ok);
  }
}

static void move_vdso_mapping(AutoRemoteSyscalls &remote, const KernelMapping &km) {
  for (const auto& m : remote.task()->vm()->maps()) {
    if  (m.map.is_vdso() && m.map.start() != km.start()) {
      LOG(debug) << "Moving VDSO for " << remote.task()->tid;
      /* Remap VDSO to the address that is used in the target process,
         before it gets unmapped.
         Otherwise the kernel seems to put the address of the original
         VDSO __kernel_rt_sigreturn function as return address on the stack.
         This might not affect x86_64 because there __restore_rt
         located in libpthread.so.0 is used. */
      remote.infallible_syscall(syscall_number_for_mremap(remote.arch()), m.map.start(), m.map.size(),
                                m.map.size(), MREMAP_MAYMOVE | MREMAP_FIXED, km.start());
      remote.task()->vm()->remap(remote.task(), m.map.start(), m.map.size(), km.start(), m.map.size());
    }
  }
}

void Task::dup_from(Task *other) {
  std::vector<KernelMapping> mappings;
  KernelMapping stack_mapping;
  bool found_stack = false;
  KernelMapping vdso_mapping;
  bool found_vdso = false;
  for (KernelMapIterator it(other); !it.at_end(); ++it) {
    auto km = it.current();
    if (km.is_stack()) {
      stack_mapping = km;
      found_stack = true;
    } else {
      mappings.push_back(km);
    }
    if (km.is_vdso()) {
      found_vdso = true;
      vdso_mapping = km;
    }
  }
  ASSERT(this, found_stack);
  // Copy address space
  LOG(debug) << "Mapping rr page for " << tid;
  {
    AutoRemoteSyscalls remote(this);
    this->vm()->map_rr_page(remote);
  }
  {
    AutoRemoteSyscalls remote(this, AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS);
    if (found_vdso) {
      move_vdso_mapping(remote, vdso_mapping);
    }
    LOG(debug) << "Unmapping memory for " << tid;
    // TODO: Only do this if the rr page isn't already mapped
    this->vm()->unmap_all_but_rr_page(remote);
    LOG(debug) << "Creating stack mapping " << stack_mapping << " for " << tid;
    create_mapping(this, remote, stack_mapping);
    LOG(debug) << "Copying stack into " << tid;
    copy_mem_mapping(other, this, stack_mapping);
  }
  {
    AutoRemoteSyscalls remote_this(this);
    for (auto &km : mappings) {
      if (km.start() == vm()->rr_page_start() || km.is_vsyscall()) {
        continue;
      }
      LOG(debug) << "Creating mapping " << km << " for " << tid;
      create_mapping(this, remote_this, km);
      LOG(debug) << "Copying mapping into " << tid;
      // XXX: If this maps a file, recreate it as such
      copy_mem_mapping(other, this, km);
    }
    AutoRemoteSyscalls remote_other(other);
    std::vector<int> all_fds = read_all_proc_fds(other->tid);
    for (int fd : all_fds) {
      if (fd == session().tracee_fd_number()) {
        continue;
      }
      ScopedFd here = remote_other.retrieve_fd(fd);
      int remote_fd_flags = remote_other.infallible_syscall(
        syscall_number_for_fcntl(this->arch()), fd, F_GETFD);
      int remote_fd = remote_this.send_fd(here);
      if (remote_fd != fd) {
        remote_this.infallible_syscall(syscall_number_for_dup2(this->arch()), remote_fd, fd);
        remote_this.infallible_syscall(syscall_number_for_close(this->arch()), remote_fd);
      }
      remote_other.infallible_syscall(
        syscall_number_for_fcntl(this->arch()),
        fd, F_SETFD, remote_fd_flags);
    }
    string path = ".";
    AutoRestoreMem child_path(remote_other, path.c_str());
    long child_fd =
      remote_other.syscall(syscall_number_for_openat(other->arch()), AT_FDCWD,
                     child_path.get(), O_RDONLY);
    ASSERT(other, child_fd != -1);
    {
      ScopedFd fd = remote_other.retrieve_fd(child_fd);
      remote_other.syscall(syscall_number_for_close(other->arch()), child_fd);
      child_fd = remote_this.send_fd(fd);
      remote_this.syscall(syscall_number_for_fchdir(this->arch()), child_fd);
      remote_this.syscall(syscall_number_for_close(this->arch()), child_fd);
    }
    struct prctl_mm_map map;
    memset(&map, 0, sizeof(prctl_mm_map));

    other->vm()->read_mm_map(other, &map);
    apply_mm_map(remote_this, map);
  }
  copy_state(other->capture_state());
}

/**
 * Proceeds until the next system call, which is being executed.
 */
static void __ptrace_cont(Task* t, ResumeRequest resume_how,
                          SupportedArch syscall_arch, int expect_syscallno,
                          int expect_syscallno2 = -1, pid_t new_tid = -1) {
  t->resume_execution(resume_how, RESUME_NONBLOCKING, RESUME_NO_TICKS);
  while (true) {
    if (t->wait_unexpected_exit()) {
      break;
    }
    int raw_status;
    // Do our own waitpid instead of calling Task::wait() so we can detect and
    // handle tid changes due to off-main-thread execve.
    // When we're expecting a tid change, we can't pass a tid here because we
    // don't know which tid to wait for.
    // Passing the original tid seems to cause a hang in some kernels
    // (e.g. 4.10.0-19-generic) if the tid change races with our waitpid
    int ret = waitpid(new_tid >= 0 ? -1 : t->tid, &raw_status, __WALL);
    ASSERT(t, ret >= 0);
    ASSERT(t, ret == (new_tid >= 0 ? new_tid : t->tid));
    if (new_tid >= 0) {
      t->hpc.set_tid(new_tid);
      t->tid = new_tid;
    }
    t->did_waitpid(WaitStatus(raw_status));

    if (ReplaySession::is_ignored_signal(t->status().stop_sig())) {
      t->resume_execution(resume_how, RESUME_NONBLOCKING, RESUME_NO_TICKS);
    } else {
      break;
    }
  }

  ASSERT(t, !t->stop_sig())
      << "Expected no pending signal, but got " << t->stop_sig();

  /* check if we are synchronized with the trace -- should never fail */
  int current_syscall = t->regs().original_syscallno();
  ASSERT(t,
         current_syscall == expect_syscallno ||
             current_syscall == expect_syscallno2)
      << "Should be at " << syscall_name(expect_syscallno, syscall_arch)
      << ", but instead at " << syscall_name(current_syscall, syscall_arch);
}

void Task::did_handle_ptrace_exit_event() {
  ASSERT(this, seen_ptrace_exit_event);
  ASSERT(this, !handled_ptrace_exit_event);
  handled_ptrace_exit_event = true;
}

void Task::os_exec_stub(SupportedArch exec_arch)
{
  std::string stub_filename = find_exec_stub(exec_arch);
  // Setup memory and registers for the execve call. We may not have to save
  // the old values since they're going to be wiped out by execve. We can
  // determine this by checking if this address space has any tasks with a
  // different tgid.
  Task* memory_task = this;
  for (auto task : vm()->task_set()) {
    if (task->tgid() != tgid()) {
      memory_task = task;
      break;
    }
  }

  // Old data if required
  std::vector<uint8_t> saved_data;

  // Set up everything
  Registers regs = this->regs();
  regs.set_ip(vm()->traced_syscall_ip());
  remote_ptr<void> remote_mem = floor_page_size(regs.sp());

  // Determine how much memory we'll need
  size_t filename_size = stub_filename.size() + 1;
  size_t total_size = filename_size + sizeof(size_t);
  if (memory_task != this) {
    saved_data = read_mem(remote_mem.cast<uint8_t>(), total_size);
  }

  // We write a zero word in the host size, not t's size, but that's OK,
  // since the host size must be bigger than t's size.
  // We pass no argv or envp, so exec params 2 and 3 just point to the NULL
  // word.
  write_mem(remote_mem.cast<size_t>(), size_t(0));
  regs.set_arg2(remote_mem);
  regs.set_arg3(remote_mem);
  remote_ptr<void> filename_addr = remote_mem + sizeof(size_t);
  write_bytes_helper(filename_addr, filename_size, stub_filename.c_str());
  regs.set_arg1(filename_addr);
  /* The original_syscallno is execve in the old architecture. The kernel does
   * not update the original_syscallno when the architecture changes across
   * an exec.
   * We're using the dedicated traced-syscall IP so its arch is t's arch.
   */
  int expect_syscallno = syscall_number_for_execve(arch());
  regs.set_syscallno(expect_syscallno);
  regs.set_original_syscallno(expect_syscallno);
  set_regs(regs);

  LOG(debug) << "Beginning execve" << this->regs();
  enter_syscall();
  ASSERT(this, !stop_sig()) << "Stub exec failed on entry";
  /* Complete the syscall. The tid of the task will be the thread-group-leader
   * tid, no matter what tid it was before.
   */
  pid_t tgid = real_tgid();
  __ptrace_cont(this, RESUME_SYSCALL, arch(), expect_syscallno,
                syscall_number_for_execve(exec_arch),
                tgid == tid ? -1 : tgid);
  LOG(debug) << this->status() << " " << this->regs();
  if (this->regs().syscall_result()) {
    errno = -this->regs().syscall_result();
    if (access(stub_filename.c_str(), 0) == -1 && errno == ENOENT &&
        exec_arch == x86) {
      FATAL() << "Cannot find exec stub " << stub_filename
              << " to replay this 32-bit process; you probably built rr with "
                 "disable32bit";
    }
    errno = -this->regs().syscall_result();
    ASSERT(this, false) << "Exec of stub " << stub_filename << " failed";
  }

  // Restore any memory if required. We need to do this through memory_task,
  // since the new task is now on the new address space. Do it now because
  // later we may try to unmap this task's syscallbuf.
  if (memory_task != this) {
    memory_task->write_mem(remote_mem.cast<uint8_t>(), saved_data.data(),
                           saved_data.size());
  }
}

void Task::apply_syscall_entry_regs()
{
  if (arch() == aarch64) {
    registers.set_original_syscallno(registers.syscallno());
    registers.set_orig_arg1(registers.arg1());
    // Don't update registers_dirty here, because these registers are not part
    // of the ptrace state tracked by that flag.
  }
}

void Task::tgkill(int sig) {
  LOG(debug) << "Sending " << sig << " to tid " << tid;
  ASSERT(this, 0 == syscall(SYS_tgkill, real_tgid(), tid, sig));
}

void Task::move_to_signal_stop()
{
  LOG(debug) << "    maybe not in signal-stop (status " << status()
             << "); doing tgkill(SYSCALLBUF_DESCHED_SIGNAL)";
  // Always send SYSCALLBUF_DESCHED_SIGNAL because other signals (except
  // TIME_SLICE_SIGNAL) will be blocked by
  // RecordTask::will_resume_execution().
  // During record make sure to use the syscallbuf desched sig.
  // During replay, it doesn't really matter, since we don't apply
  // the signal mask to the replay task.
  int sig = SIGPWR;
  if (session().is_recording()) {
    sig = session().as_record()->syscallbuf_desched_sig();
  }
  this->tgkill(sig);
  /* Now singlestep the task until we're in a signal-stop for the signal
   * we've just sent. We must absorb and forget that signal here since we
   * don't want it delivered to the task for real.
   */
  auto old_ip = ip();
  do {
    resume_execution(RESUME_SINGLESTEP, RESUME_WAIT, RESUME_NO_TICKS);
    ASSERT(this, old_ip == ip())
        << "Singlestep actually advanced when we "
        << "just expected a signal; was at " << old_ip << " now at "
        << ip() << " with status " << status();
    // Ignore any pending TIME_SLICE_SIGNALs and continue until we get our
    // SYSCALLBUF_DESCHED_SIGNAL.
  } while (stop_sig() == PerfCounters::TIME_SLICE_SIGNAL);
}

}
