/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Task.h"

#include <asm/prctl.h>
#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <linux/net.h>
#include <linux/perf_event.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#include <limits>
#include <set>
#include <sstream>

#include <rr/rr.h>

#include "preload/preload_interface.h"

#include "AutoRemoteSyscalls.h"
#include "CPUIDBugDetector.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "kernel_supplement.h"
#include "log.h"
#include "MagicSaveDataMonitor.h"
#include "PreserveFileMonitor.h"
#include "RecordSession.h"
#include "record_signal.h"
#include "RecordTask.h"
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "seccomp-bpf.h"
#include "StdioMonitor.h"
#include "StringVectorToCharArray.h"
#include "util.h"

using namespace std;

namespace rr {

static const unsigned int NUM_X86_DEBUG_REGS = 8;
static const unsigned int NUM_X86_WATCHPOINTS = 4;

Task::Task(Session& session, pid_t _tid, pid_t _rec_tid, uint32_t serial,
           SupportedArch a)
    : unstable(false),
      stable_exit(false),
      thread_locals_initialized(false),
      scratch_ptr(),
      scratch_size(),
      // This will be initialized when the syscall buffer is.
      desched_fd_child(-1),
      // This will be initialized when the syscall buffer is.
      cloned_file_data_fd_child(-1),
      hpc(_tid),
      tid(_tid),
      rec_tid(_rec_tid > 0 ? _rec_tid : _tid),
      syscallbuf_hdr(),
      syscallbuf_size(0),
      num_syscallbuf_bytes(0),
      stopping_breakpoint_table_entry_size(0),
      serial(serial),
      prname("???"),
      ticks(0),
      registers(a),
      is_stopped(false),
      detected_unexpected_exit(false),
      extra_registers(a),
      extra_registers_known(false),
      session_(&session),
      top_of_stack(),
      seen_ptrace_exit_event(false) {}

void Task::destroy() {
  LOG(debug) << "task " << tid << " (rec:" << rec_tid << ") is dying ...";

  // child_mem_fd needs to be valid since we won't be able to open
  // it for futex_wait after we've detached.
  ASSERT(this, as->mem_fd().is_open());

  fallible_ptrace(PTRACE_DETACH, nullptr, nullptr);

  // Subclasses can do something in their destructors after we've detached
  delete this;
}

Task::~Task() {
  if (unstable) {
    LOG(warn) << tid << " is unstable; not blocking on its termination";
    // This will probably leak a zombie process for rr's lifetime.
  } else {
    ASSERT(this, seen_ptrace_exit_event);

    if (tg->task_set().empty() && !session().is_recording()) {
      // Reap the zombie.
      int ret = waitpid(tg->real_tgid, NULL, __WALL);
      if (ret == -1) {
        ASSERT(this, errno == ECHILD || errno == ESRCH);
      } else {
        ASSERT(this, ret == tg->real_tgid);
      }
    }
  }

  destroy_local_buffers();

  session().on_destroy(this);
  tg->erase_task(this);
  as->erase_task(this);
  fds->erase_task(this);

  LOG(debug) << "  dead";
}

void Task::finish_emulated_syscall() {
  // We need to execute something to get us out of a SYSEMU syscall-stop into a
  // signal-stop. SINGLESTEP/SYSEMU_SINGLESTEP works, but sometimes executes
  // instruction after the syscall as well, so we need to be able to undo that.

  // XXX verify that this can't be interrupted by a breakpoint trap
  Registers r = regs();
  remote_code_ptr ip = r.ip();
  bool known_idempotent_insn_after_syscall =
      (is_in_traced_syscall() || is_in_untraced_syscall());

  // We're about to single-step the tracee at its $ip just past
  // the syscall insn, then back up the $ip to where it started.
  // This is problematic because it will execute the insn at the
  // current $ip twice.  If that insns isn't idempotent, then
  // replay will create side effects that diverge from
  // recording.
  //
  // To prevent that, we insert a breakpoint trap at the current
  // $ip.  We can execute that without creating side effects.
  // After the single-step, we remove the breakpoint, which
  // restores the original insn at the $ip.
  //
  // Syscalls made from the syscallbuf are known to execute an
  // idempotent insn after the syscall trap (restore register
  // from stack), so we don't have to pay this expense.
  if (!known_idempotent_insn_after_syscall) {
    bool ok = vm()->add_breakpoint(ip, BKPT_INTERNAL);
    ASSERT(this, ok) << "Can't add breakpoint???";
  }
  // Passing RESUME_NO_TICKS here is not only a small performance optimization,
  // but also avoids counting an event if the instruction immediately following
  // a syscall instruction is a conditional branch.
  resume_execution(RESUME_SYSEMU_SINGLESTEP, RESUME_WAIT, RESUME_NO_TICKS);

  if (!known_idempotent_insn_after_syscall) {
    // The breakpoint should raise SIGTRAP, but we can also see
    // any of the host of replay-ignored signals.
    ASSERT(this, (stop_sig() == SIGTRAP ||
                  ReplaySession::is_ignored_signal(stop_sig())))
        << "PENDING SIG IS " << signal_name(stop_sig());
    vm()->remove_breakpoint(ip, BKPT_INTERNAL);
  }
  set_regs(r);
  wait_status = WaitStatus();
}

void Task::dump(FILE* out) const {
  out = out ? out : stderr;
  stringstream ss;
  ss << wait_status;
  fprintf(out, "  %s(tid:%d rec_tid:%d status:0x%s%s)<%p>\n", prname.c_str(),
          tid, rec_tid, ss.str().c_str(), unstable ? " UNSTABLE" : "", this);
  if (session().is_recording()) {
    // TODO pending events are currently only meaningful
    // during recording.  We should change that
    // eventually, to have more informative output.
    log_pending_events();
  }
}

struct stat Task::stat_fd(int fd) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path) - 1, "/proc/%d/fd/%d", tid, fd);
  struct stat result;
  auto ret = ::stat(path, &result);
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
  snprintf(path, sizeof(path) - 1, "/proc/%d/fd/%d", tid, fd);
  ssize_t nbytes = readlink(path, path, sizeof(path) - 1);
  if (nbytes < 0) {
    path[0] = 0;
  } else {
    path[nbytes] = 0;
  }
  return path;
}

const siginfo_t& Task::get_siginfo() {
  assert(stop_sig());
  return pending_siginfo;
}

TraceReader& Task::trace_reader() {
  return session().as_replay()->trace_reader();
}

TraceWriter& Task::trace_writer() {
  return session().as_record()->trace_writer();
}

void Task::destroy_buffers() {
  AutoRemoteSyscalls remote(this);
  remote.infallible_syscall(syscall_number_for_munmap(arch()), scratch_ptr,
                            scratch_size);
  vm()->unmap(scratch_ptr, scratch_size);
  if (!syscallbuf_child.is_null()) {
    remote.infallible_syscall(syscall_number_for_munmap(arch()),
                              syscallbuf_child, num_syscallbuf_bytes);
    vm()->unmap(syscallbuf_child, num_syscallbuf_bytes);
    if (desched_fd_child >= 0) {
      if (session().is_recording()) {
        remote.infallible_syscall(syscall_number_for_close(arch()),
                                  desched_fd_child);
      }
      fds->did_close(desched_fd_child);
    }
    if (cloned_file_data_fd_child >= 0) {
      remote.infallible_syscall(syscall_number_for_close(arch()),
                                cloned_file_data_fd_child);
      fds->did_close(cloned_file_data_fd_child);
    }
  }
}

bool Task::is_desched_event_syscall() {
  return is_ioctl_syscall(regs().original_syscallno(), arch()) &&
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

template <typename Arch>
static off_t get_io_offset_arch(int syscallno, const Registers& regs) {
  switch (syscallno) {
    case Arch::pwrite64:
    case Arch::pwritev:
    case Arch::pread64:
    case Arch::preadv:
      if (sizeof(typename Arch::unsigned_word) == 4) {
        return regs.arg4_signed() | (off_t(regs.arg5_signed()) << 32);
      }
      return regs.arg4_signed();
    default:
      return -1;
  }
}

off_t Task::get_io_offset(int syscallno, const Registers& regs) {
  RR_ARCH_FUNCTION(get_io_offset_arch, arch(), syscallno, regs);
}

template <typename Arch>
void Task::on_syscall_exit_arch(int syscallno, const Registers& regs) {
  session().accumulate_syscall_performed();

  // mprotect can change the protection status of some mapped regions before
  // failing.
  if (regs.syscall_failed() && !is_mprotect_syscall(syscallno, arch())) {
    return;
  }

  switch (syscallno) {
    case Arch::brk:
    case Arch::mmap:
    case Arch::mmap2: {
      LOG(debug)
          << "(brk/mmap/mmap2 will receive / has received direct processing)";
      return;
    }
    case Arch::mprotect: {
      remote_ptr<void> addr = regs.arg1();
      size_t num_bytes = regs.arg2();
      int prot = regs.arg3_signed();
      return vm()->protect(addr, num_bytes, prot);
    }
    case Arch::mremap: {
      remote_ptr<void> old_addr = regs.arg1();
      size_t old_num_bytes = regs.arg2();
      remote_ptr<void> new_addr = regs.syscall_result();
      size_t new_num_bytes = regs.arg3();
      return vm()->remap(old_addr, old_num_bytes, new_addr, new_num_bytes);
    }
    case Arch::munmap: {
      remote_ptr<void> addr = regs.arg1();
      size_t num_bytes = regs.arg2();
      return vm()->unmap(addr, num_bytes);
    }
    case Arch::shmdt: {
      remote_ptr<void> addr = regs.arg1();
      auto mapping = vm()->mapping_of(addr);
      ASSERT(this, mapping.map.start() == addr);
      return vm()->unmap(addr, mapping.map.end() - addr);
    }
    case Arch::madvise: {
      remote_ptr<void> addr = regs.arg1();
      size_t num_bytes = regs.arg2();
      int advice = regs.arg3();
      return vm()->advise(addr, num_bytes, advice);
    }
    case Arch::ipc: {
      switch ((int)regs.arg1_signed()) {
        case SHMDT: {
          remote_ptr<void> addr = regs.arg5();
          auto mapping = vm()->mapping_of(addr);
          ASSERT(this, mapping.map.start() == addr);
          return vm()->unmap(addr, mapping.map.end() - addr);
        }
        default:
          break;
      }
      break;
    }

    case Arch::set_thread_area:
      set_thread_area(regs.arg1());
      // Assume any set_thread_area sets up TLS
      thread_locals_initialized = true;
      return;

    case Arch::arch_prctl:
      switch ((int)regs.arg1_signed()) {
        case ARCH_SET_FS:
          thread_locals_initialized = true;
          break;
      }
      return;

    case Arch::prctl:
      switch ((int)regs.arg1_signed()) {
        case PR_SET_NAME: {
          update_prname(regs.arg2());
          break;
        }
      }
      return;

    case Arch::dup:
    case Arch::dup2:
    case Arch::dup3:
      fd_table()->did_dup(regs.arg1(), regs.syscall_result());
      return;
    case Arch::fcntl64:
    case Arch::fcntl:
      if (regs.arg2() == Arch::DUPFD || regs.arg2() == Arch::DUPFD_CLOEXEC) {
        fd_table()->did_dup(regs.arg1(), regs.syscall_result());
      }
      return;
    case Arch::close:
      fd_table()->did_close(regs.arg1());
      return;

    case Arch::unshare:
      if (regs.arg1() & CLONE_FILES) {
        fds->erase_task(this);
        fds = fds->clone(this);
      }
      return;

    case Arch::pwrite64:
    case Arch::write: {
      int fd = (int)regs.arg1_signed();
      vector<FileMonitor::Range> ranges;
      ssize_t amount = regs.syscall_result_signed();
      if (amount > 0) {
        ranges.push_back(FileMonitor::Range(regs.arg2(), amount));
      }
      fd_table()->did_write(this, fd, ranges,
                            get_io_offset_arch<Arch>(syscallno, regs));
      return;
    }

    case Arch::pwritev:
    case Arch::writev: {
      int fd = (int)regs.arg1_signed();
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
      fd_table()->did_write(this, fd, ranges,
                            get_io_offset_arch<Arch>(syscallno, regs));
      return;
    }

    case Arch::ptrace: {
      pid_t pid = (pid_t)regs.arg2_signed();
      Task* tracee = session().find_task(pid);
      switch ((int)regs.arg1_signed()) {
        case PTRACE_SETREGS: {
          auto data = read_mem(
              remote_ptr<typename Arch::user_regs_struct>(regs.arg4()));
          Registers r = tracee->regs();
          r.set_from_ptrace_for_arch(Arch::arch(), &data, sizeof(data));
          tracee->set_regs(r);
          break;
        }
        case PTRACE_SETFPREGS: {
          auto data = read_mem(
              remote_ptr<typename Arch::user_fpregs_struct>(regs.arg4()));
          auto r = extra_regs();
          r.set_user_fpregs_struct(Arch::arch(), &data, sizeof(data));
          set_extra_regs(r);
          break;
        }
        case PTRACE_SETFPXREGS: {
          auto data =
              read_mem(remote_ptr<X86Arch::user_fpxregs_struct>(regs.arg4()));
          auto r = extra_regs();
          r.set_user_fpxregs_struct(data);
          set_extra_regs(r);
          break;
        }
        case PTRACE_SETREGSET: {
          switch ((int)regs.arg3()) {
            case NT_PRSTATUS: {
              auto set = ptrace_get_regs_set<Arch>(
                  this, regs, sizeof(typename Arch::user_regs_struct));
              Registers r = tracee->regs();
              r.set_from_ptrace_for_arch(Arch::arch(), set.data(), set.size());
              tracee->set_regs(r);
              break;
            }
            case NT_FPREGSET: {
              auto set = ptrace_get_regs_set<Arch>(
                  this, regs, sizeof(typename Arch::user_fpregs_struct));
              ExtraRegisters r = tracee->extra_regs();
              r.set_user_fpregs_struct(Arch::arch(), set.data(), set.size());
              tracee->set_extra_regs(r);
              break;
            }
            case NT_X86_XSTATE: {
              switch (tracee->extra_regs().format()) {
                case ExtraRegisters::XSAVE: {
                  auto set = ptrace_get_regs_set<Arch>(
                      this, regs, tracee->extra_regs().data_size());
                  ExtraRegisters r;
                  r.set_to_raw_data(tracee->arch(), ExtraRegisters::XSAVE, set);
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
        case PTRACE_POKEUSER: {
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
            tracee->set_debug_reg(regno, data);
          }
          break;
        }
      }
      return;
    }
  }
}

void Task::on_syscall_exit(int syscallno, const Registers& regs) {
  RR_ARCH_FUNCTION(on_syscall_exit_arch, arch(), syscallno, regs)
}

void Task::move_ip_before_breakpoint() {
  // TODO: assert that this is at a breakpoint trap.
  Registers r = regs();
  r.set_ip(r.ip().decrement_by_bkpt_insn_length(arch()));
  set_regs(r);
}

void Task::advance_syscall() {
  while (true) {
    resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);
    if (is_ptrace_seccomp_event()) {
      continue;
    }
    ASSERT(this, !ptrace_event());
    if (!stop_sig()) {
      break;
    }
    if (ReplaySession::is_ignored_signal(stop_sig()) &&
        session().is_replaying()) {
      continue;
    }
    ASSERT(this, session().is_recording());
    static_cast<RecordTask*>(this)->stash_sig();
  }
}

void Task::exit_syscall_and_prepare_restart() {
  Registers r = regs();
  int syscallno = r.original_syscallno();
  r.set_original_syscallno(syscall_number_for_gettid(r.arch()));
  set_regs(r);
  // This exits the hijacked SYS_gettid.  Now the tracee is
  // ready to do our bidding.
  advance_syscall();

  // Restore these regs to what they would have been just before
  // the tracee trapped at the syscall.
  r.set_original_syscallno(-1);
  r.set_syscallno(syscallno);
  r.set_ip(r.ip() - syscall_instruction_length(r.arch()));
  set_regs(r);
}

static string prname_from_exe_image(const string& e) {
  size_t last_slash = e.rfind('/');
  return e.substr(last_slash == e.npos ? 0 : last_slash + 1);
}

void Task::post_exec(SupportedArch a, const string& exe_file) {
  /* We just saw a successful exec(), so from now on we know
   * that the address space layout for the replay tasks will
   * (should!) be the same as for the recorded tasks.  So we can
   * start validating registers at events. */
  session().post_exec();

  as->erase_task(this);
  fds->erase_task(this);

  registers.set_arch(a);
  extra_registers = ExtraRegisters(a);
  extra_registers_known = false;
  struct user_regs_struct ptrace_regs;
  ptrace_if_alive(PTRACE_GETREGS, nullptr, &ptrace_regs);
  registers.set_from_ptrace(ptrace_regs);
  // Change syscall number to execve *for the new arch*. If we don't do this,
  // and the arch changes, then the syscall number for execve in the old arch/
  // is treated as the syscall we're executing in the new arch, with hilarious
  // results.
  registers.set_original_syscallno(syscall_number_for_execve(arch()));
  set_regs(registers);

  syscallbuf_child = nullptr;
  cloned_file_data_fd_child = -1;
  desched_fd_child = -1;
  preload_globals = nullptr;
  thread_locals_initialized = false;

  thread_areas_.clear();

  as = session().create_vm(this, exe_file, as->uid().exec_count() + 1);
  // It's barely-documented, but Linux unshares the fd table on exec
  fds = fds->clone(this);
  prname = prname_from_exe_image(as->exe_image());
}

void Task::post_exec_syscall(TraceTaskEvent& event) {
  as->post_exec_syscall(this);
  fds->update_for_cloexec(this, event);
}

void Task::flush_inconsistent_state() { ticks = 0; }

string Task::read_c_str(remote_ptr<char> child_addr) {
  // XXX handle invalid C strings
  remote_ptr<void> p = child_addr;
  string str;
  while (true) {
    // We're only guaranteed that [child_addr,
    // end_of_page) is mapped.
    remote_ptr<void> end_of_page = ceil_page_size(p + 1);
    ssize_t nbytes = end_of_page - p;
    char buf[nbytes];

    read_bytes_helper(p, nbytes, buf);
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

// 0 means XSAVE not detected
static unsigned int xsave_area_size = 0;
static bool xsave_initialized = false;

static void init_xsave() {
  if (xsave_initialized) {
    return;
  }
  xsave_initialized = true;

  unsigned int eax, ecx, edx;
  cpuid(CPUID_GETFEATURES, 0, &eax, &ecx, &edx);
  if (!(ecx & (1 << 26))) {
    // XSAVE not present
    return;
  }

  // We'll use the largest possible area all the time
  // even when it might not be needed. Simpler that way.
  cpuid(CPUID_GETXSAVE, 0, &eax, &ecx, &edx);
  xsave_area_size = ecx;
}

const ExtraRegisters& Task::extra_regs() {
  if (!extra_registers_known) {
    init_xsave();
    if (xsave_area_size) {
      LOG(debug) << "  (refreshing extra-register cache using XSAVE)";

      extra_registers.format_ = ExtraRegisters::XSAVE;
      extra_registers.data_.resize(xsave_area_size);
      struct iovec vec = { extra_registers.data_.data(),
                           extra_registers.data_.size() };
      xptrace(PTRACE_GETREGSET, NT_X86_XSTATE, &vec);
      ASSERT(this, vec.iov_len == xsave_area_size)
          << "Didn't get enough register data; expected " << xsave_area_size
          << " but got " << vec.iov_len;
    } else {
#if defined(__i386__)
      LOG(debug) << "  (refreshing extra-register cache using FPXREGS)";

      extra_registers.format_ = ExtraRegisters::XSAVE;
      extra_registers.data_.resize(sizeof(user_fpxregs_struct));
      xptrace(PTRACE_GETFPXREGS, nullptr, extra_registers.data_.data());
#elif defined(__x86_64__)
      // x86-64 that doesn't support XSAVE; apparently Xeon E5620 (Westmere)
      // is in this class.
      LOG(debug) << "  (refreshing extra-register cache using FPREGS)";

      extra_registers.format_ = ExtraRegisters::XSAVE;
      extra_registers.data_.resize(sizeof(user_fpregs_struct));
      xptrace(PTRACE_GETFPREGS, nullptr, extra_registers.data_.data());
#else
#error need to define new extra_regs support
#endif
    }

    extra_registers_known = true;
  }
  return extra_registers;
}

static ssize_t dr_user_word_offset(size_t i) {
  assert(i < NUM_X86_DEBUG_REGS);
  return offsetof(struct user, u_debugreg[0]) + sizeof(void*) * i;
}

uintptr_t Task::debug_status() {
  return fallible_ptrace(PTRACE_PEEKUSER, dr_user_word_offset(6), nullptr);
}

void Task::set_debug_status(uintptr_t status) {
  fallible_ptrace(PTRACE_POKEUSER, dr_user_word_offset(6), (void*)status);
}

TrapReasons Task::compute_trap_reasons() {
  ASSERT(this, stop_sig() == SIGTRAP);
  TrapReasons reasons;
  uintptr_t status = debug_status();

  // XXX singlestepping over a syscall instruction doesn't trigger
  // DS_SINGLESTEP. But we don't do that in ReplaySession or DiversionSession
  // ... hopefully?
  reasons.singlestep = (status & DS_SINGLESTEP) != 0;

  // In VMWare Player 6.0.4 build-2249910, 32-bit Ubuntu x86 guest,
  // single-stepping does not trigger watchpoints :-(. So we have to
  // check watchpoints here. fast_forward also hides watchpoint changes.
  // Write-watchpoints will detect that their value has changed and trigger.
  // XXX Read/exec watchpoints can't be detected this way so they're still
  // broken in the above configuration :-(.
  if ((DS_WATCHPOINT_ANY | DS_SINGLESTEP) & status) {
    as->notify_watchpoint_fired(status);
  }
  reasons.watchpoint =
      as->has_any_watchpoint_changes() || (DS_WATCHPOINT_ANY & status);

  // If we triggered a breakpoint, this would be the address of the breakpoint
  remote_code_ptr ip_at_breakpoint = ip().decrement_by_bkpt_insn_length(arch());
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
    const siginfo_t& si = get_siginfo();
    ASSERT(this, SIGTRAP == si.si_signo);
    /* XXX unable to find docs on which of these "should" be
     * right.  The SI_KERNEL code is seen in the int3 test, so we
     * at least need to handle that. */
    reasons.breakpoint = SI_KERNEL == si.si_code || TRAP_BRKPT == si.si_code;
    if (reasons.breakpoint) {
      ASSERT(this, as->is_breakpoint_instruction(this, ip_at_breakpoint));
    }
  }
  return reasons;
}

static const Property<bool, AddressSpace> thread_locals_initialized_property;

void Task::resume_execution(ResumeRequest how, WaitRequest wait_how,
                            TicksRequest tick_period, int sig) {
  // Treat a RESUME_NO_TICKS tick_period as a very large but finite number.
  // Always resetting here, and always to a nonzero number, improves
  // consistency between recording and replay and hopefully
  // makes counting bugs behave similarly between recording and
  // replay.
  // Accumulate any unknown stuff in tick_count().
  if (tick_period != RESUME_NO_TICKS) {
    hpc.reset(tick_period == RESUME_UNLIMITED_TICKS
                  ? 0xffffffff
                  : max<Ticks>(1, tick_period));
    // Ensure preload_globals.thread_locals_initialized is up to date. Avoid
    // unnecessary writes by caching last written value per-AddressSpace.
    if (preload_globals) {
      bool* prop = thread_locals_initialized_property.get(*as);
      if (!prop || *prop != thread_locals_initialized) {
        write_mem(REMOTE_PTR_FIELD(preload_globals, thread_locals_initialized),
                  (unsigned char)thread_locals_initialized);
        if (!prop) {
          prop = &thread_locals_initialized_property.create(*as);
        }
        *prop = thread_locals_initialized;
      }
    }
  }

  LOG(debug) << "resuming execution of " << tid << " with "
             << ptrace_req_name(how)
             << (sig ? string(", signal ") + signal_name(sig) : string());
  address_of_last_execution_resume = ip();
  set_debug_status(0);

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
    wait_ret = waitpid(tid, &raw_status, WNOHANG | __WALL | WSTOPPED);
    ASSERT(this, 0 <= wait_ret) << "waitpid(" << tid << ", NOHANG) failed with "
                                << wait_ret;
    WaitStatus status(raw_status);
    if (wait_ret == tid) {
      ASSERT(this, status.ptrace_event() == PTRACE_EVENT_EXIT);
    } else {
      ASSERT(this, 0 == wait_ret) << "waitpid(" << tid
                                  << ", NOHANG) failed with " << wait_ret;
    }
  }
  if (wait_ret == tid) {
    // wait() will see this and report the ptrace-exit event.
    detected_unexpected_exit = true;
  } else {
    ptrace_if_alive(how, nullptr, (void*)(uintptr_t)sig);
  }

  is_stopped = false;
  extra_registers_known = false;
  if (RESUME_WAIT == wait_how) {
    wait();
  }
}

void Task::set_regs(const Registers& regs) {
  ASSERT(this, is_stopped);
  registers = regs;
  auto ptrace_regs = registers.get_ptrace();
  ptrace_if_alive(PTRACE_SETREGS, nullptr, &ptrace_regs);
}

void Task::set_extra_regs(const ExtraRegisters& regs) {
  ASSERT(this, !regs.empty()) << "Trying to set empty ExtraRegisters";
  extra_registers = regs;
  extra_registers_known = true;

  init_xsave();

  switch (extra_registers.format()) {
    case ExtraRegisters::XSAVE: {
      if (xsave_area_size) {
        struct iovec vec = { extra_registers.data_.data(),
                             extra_registers.data_.size() };
        ptrace_if_alive(PTRACE_SETREGSET, NT_X86_XSTATE, &vec);
      } else {
#if defined(__i386__)
        ptrace_if_alive(PTRACE_SETFPXREGS, nullptr,
                        extra_registers.data_.data());
#elif defined(__x86_64__)
        ptrace_if_alive(PTRACE_SETFPREGS, nullptr,
                        extra_registers.data_.data());
#else
#error Unsupported architecture
#endif
      }
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

bool Task::set_debug_regs(const DebugRegs& regs) {
  struct DebugControl {
    uintptr_t packed() { return *(uintptr_t*)this; }

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
  } dr7;
  memset(&dr7, 0, sizeof(dr7));
  static_assert(sizeof(DebugControl) == sizeof(uintptr_t),
                "Can't pack DebugControl");

  // Reset the debug status since we're about to change the set
  // of programmed watchpoints.
  ptrace_if_alive(PTRACE_POKEUSER, dr_user_word_offset(6), 0);
  // Ensure that we clear the programmed watchpoints in case
  // enabling one of them fails.  We guarantee atomicity to the
  // caller.
  ptrace_if_alive(PTRACE_POKEUSER, dr_user_word_offset(7), 0);
  if (regs.size() > NUM_X86_WATCHPOINTS) {
    return false;
  }

  size_t dr = 0;
  for (auto reg : regs) {
    if (fallible_ptrace(PTRACE_POKEUSER, dr_user_word_offset(dr),
                        (void*)reg.addr.as_int())) {
      return false;
    }
    switch (dr++) {
#define CASE_ENABLE_DR(_dr7, _i, _reg)                                         \
  case _i:                                                                     \
    _dr7.dr##_i##_local = 1;                                                   \
    _dr7.dr##_i##_type = _reg.type;                                            \
    _dr7.dr##_i##_len = num_bytes_to_dr_len(_reg.num_bytes);                   \
    break
      CASE_ENABLE_DR(dr7, 0, reg);
      CASE_ENABLE_DR(dr7, 1, reg);
      CASE_ENABLE_DR(dr7, 2, reg);
      CASE_ENABLE_DR(dr7, 3, reg);
#undef CASE_ENABLE_DR
      default:
        FATAL() << "There's no debug register " << dr;
    }
  }
  return 0 == fallible_ptrace(PTRACE_POKEUSER, dr_user_word_offset(7),
                              (void*)dr7.packed());
}

uintptr_t Task::get_debug_reg(size_t regno) {
  errno = 0;
  auto result =
      fallible_ptrace(PTRACE_PEEKUSER, dr_user_word_offset(regno), nullptr);
  if (errno == ESRCH) {
    return 0;
  }
  return result;
}

void Task::set_debug_reg(size_t regno, uintptr_t value) {
  fallible_ptrace(PTRACE_POKEUSER, dr_user_word_offset(regno), (void*)value);
}

void Task::set_thread_area(remote_ptr<struct user_desc> tls) {
  // We rely on the fact that user_desc is word-size-independent.
  auto desc = read_mem(tls);
  for (auto& t : thread_areas_) {
    if (t.entry_number == desc.entry_number) {
      t = desc;
      return;
    }
  }
  thread_areas_.push_back(desc);
}

pid_t Task::tgid() const { return tg->tgid; }

pid_t Task::real_tgid() const { return tg->real_tgid; }

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
  struct prname_buf {
    char chars[16];
  };
  auto name = read_mem(child_addr.cast<prname_buf>());
  name.chars[sizeof(name.chars) - 1] = '\0';
  prname = name.chars;
}

static bool is_zombie_process(pid_t pid) {
  char buf[1000];
  sprintf(buf, "/proc/%d/status", pid);
  FILE* f = fopen(buf, "r");
  if (!f) {
    // Something went terribly wrong. Just say it's a zombie
    // so we treat it as dead.
    return true;
  }
  static const char state_keyword[] = "State:";
  while (fgets(buf, sizeof(buf), f)) {
    if (strncmp(buf, state_keyword, sizeof(state_keyword) - 1) == 0) {
      fclose(f);

      char* b = buf + sizeof(state_keyword) - 1;
      while (*b == ' ' || *b == '\t') {
        ++b;
      }
      return *b == 'Z';
    }
  }
  fclose(f);
  // Something went terribly wrong. Just say it's a zombie
  // so we treat it as dead.
  return true;
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

static struct timeval to_timeval(double t) {
  struct timeval v;
  v.tv_sec = (time_t)floor(t);
  v.tv_usec = (int)floor((t - v.tv_sec) * 1000000);
  return v;
}

void Task::wait(double interrupt_after_elapsed) {
  LOG(debug) << "going into blocking waitpid(" << tid << ") ...";
  ASSERT(this, !unstable) << "Don't wait for unstable tasks";
  ASSERT(this, session().is_recording() || interrupt_after_elapsed == 0);

  if (detected_unexpected_exit) {
    LOG(debug) << "Unexpected (SIGKILL) exit was detected; reporting it now";
    did_waitpid(WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT));
    detected_unexpected_exit = false;
    return;
  }

  WaitStatus status;
  bool sent_wait_interrupt = false;
  pid_t ret;
  while (true) {
    if (interrupt_after_elapsed) {
      struct itimerval timer = { { 0, 0 },
                                 to_timeval(interrupt_after_elapsed) };
      setitimer(ITIMER_REAL, &timer, nullptr);
    }
    int raw_status = 0;
    ret = waitpid(tid, &raw_status, __WALL);
    status = WaitStatus(raw_status);
    if (interrupt_after_elapsed) {
      struct itimerval timer = { { 0, 0 }, { 0, 0 } };
      setitimer(ITIMER_REAL, &timer, nullptr);
    }
    if (ret >= 0 || errno != EINTR) {
      // waitpid was not interrupted by the alarm.
      break;
    }

    if (is_zombie_process(tg->real_tgid)) {
      // The process is dead. We must stop waiting on it now
      // or we might never make progress.
      // XXX it's not clear why the waitpid() syscall
      // doesn't return immediately in this case, but in
      // some cases it doesn't return normally at all!

      // Fake a PTRACE_EVENT_EXIT for this task.
      status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
      ret = tid;
      // XXX could this leave unreaped zombies lying around?
      break;
    }

    if (!sent_wait_interrupt && interrupt_after_elapsed) {
      ptrace_if_alive(PTRACE_INTERRUPT, nullptr, nullptr);
      sent_wait_interrupt = true;
    }
  }

  if (ret >= 0 && status.exit_code() >= 0) {
    // Unexpected non-stopping exit code returned in wait_status.
    // This shouldn't happen; a PTRACE_EXIT_EVENT for this task
    // should be observed first, and then we would kill the task
    // before wait()ing again, so we'd only see the exit
    // code in detach_and_reap. But somehow we see it here in
    // grandchild_threads and async_kill_with_threads tests (and
    // maybe others), when a PTRACE_EXIT_EVENT has not been sent.
    // Verify that we have not actually seen a PTRACE_EXIT_EVENT.
    ASSERT(this, !seen_ptrace_exit_event) << "A PTRACE_EXIT_EVENT was observed "
                                             "for this task, but somehow "
                                             "forgotten";

    // Turn this into a PTRACE_EXIT_EVENT.
    status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
  }

  LOG(debug) << "  waitpid(" << tid << ") returns " << ret << "; status "
             << status;
  ASSERT(this, tid == ret) << "waitpid(" << tid << ") failed with " << ret;

  // If some other ptrace-stop happened to race with our
  // PTRACE_INTERRUPT, then let the other event win.  We only
  // want to interrupt tracees stuck running in userspace.
  // We convert the ptrace-stop to a reschedule signal.
  if (sent_wait_interrupt &&
      is_signal_triggered_by_ptrace_interrupt(status.group_stop())) {
    LOG(warn) << "Forced to PTRACE_INTERRUPT tracee";
    // Force this timeslice to end
    if (session().is_recording()) {
      session().as_record()->scheduler().expire_timeslice();
    }
    status = WaitStatus::for_stop_sig(PerfCounters::TIME_SLICE_SIGNAL);
    siginfo_t si;
    memset(&si, 0, sizeof(si));
    si.si_signo = PerfCounters::TIME_SLICE_SIGNAL;
    si.si_fd = hpc.ticks_fd();
    si.si_code = POLL_IN;
    did_waitpid(status, &si);
    return;
  }

  if (sent_wait_interrupt) {
    LOG(warn) << "  PTRACE_INTERRUPT raced with another event " << status;
  }
  did_waitpid(status);
}

static bool is_in_non_sigreturn_exit_syscall(Task* t) {
  if (!t->status().is_syscall()) {
    return false;
  }
  if (t->session().is_recording()) {
    auto rt = static_cast<RecordTask*>(t);
    return !rt->ev().is_syscall_event() ||
           !is_sigreturn(rt->ev().Syscall().number, t->arch());
  }
  return true;
}

/**
 * Call this when we've trapped in a syscall (entry or exit) in the kernel,
 * to normalize registers.
 */
static void fixup_syscall_registers(Registers& registers) {
  if (registers.arch() == x86_64) {
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
    registers.set_r11(0x246);
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
    registers.set_cx((intptr_t)-1);
    // On kernel 3.13.0-68-generic #111-Ubuntu SMP we have observed a failed
    // execve() clearing all flags during recording. During replay we emulate
    // the exec so this wouldn't happen. Just reset all flags so everything's
    // consistent.
    // 0x246 is ZF+PF+IF+reserved, the result clearing a register using
    // "xor reg, reg".
    registers.set_flags(0x246);
  } else if (registers.arch() == x86) {
    // The x86 SYSENTER handling in Linux modifies EBP and EFLAGS on entry.
    // EBP is the potential sixth syscall parameter, stored on the user stack.
    // The EFLAGS changes are described here:
    // http://linux-kernel.2935.n7.nabble.com/ia32-sysenter-target-does-not-preserve-EFLAGS-td1074164.html
    // In a VMWare guest, the modifications to EFLAGS appear to be
    // nondeterministic. Cover that up by setting EFLAGS to reasonable values
    // now.
    registers.set_flags(0x246);
  }
}

void Task::emulate_syscall_entry(const Registers& regs) {
  Registers r = regs;
  fixup_syscall_registers(r);
  set_regs(r);
}

void Task::did_waitpid(WaitStatus status, siginfo_t* override_siginfo) {
  Ticks more_ticks = hpc.read_ticks();
  // Stop PerfCounters ASAP to reduce the possibility that due to bugs or
  // whatever they pick up something spurious later.
  hpc.stop();
  ticks += more_ticks;
  session().accumulate_ticks_processed(more_ticks);

  LOG(debug) << "  (refreshing register cache)";
  intptr_t original_syscallno = registers.original_syscallno();
  // Skip reading registers in a PTRACE_EVENT_EXEC, since
  // we may not know the correct architecture.
  bool did_read_regs = false;
  if (status.ptrace_event() != PTRACE_EVENT_EXEC) {
    struct user_regs_struct ptrace_regs;
    if (ptrace_if_alive(PTRACE_GETREGS, nullptr, &ptrace_regs)) {
      registers.set_from_ptrace(ptrace_regs);
      did_read_regs = true;
    } else {
      LOG(debug) << "Unexpected process death for " << tid;
      status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
    }
  }
  if (status.stop_sig()) {
    if (override_siginfo) {
      pending_siginfo = *override_siginfo;
    } else {
      if (!ptrace_if_alive(PTRACE_GETSIGINFO, nullptr, &pending_siginfo)) {
        LOG(debug) << "Unexpected process death for " << tid;
        status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
      }
    }
  }

  is_stopped = true;
  wait_status = status;
  if (ptrace_event() == PTRACE_EVENT_EXIT) {
    seen_ptrace_exit_event = true;
  }

  bool need_to_set_regs = false;
  if (registers.singlestep_flag()) {
    registers.clear_singlestep_flag();
    need_to_set_regs = true;
  }

  // We might have singlestepped at the resumption address and just exited
  // the kernel without executing the breakpoint at that address.
  // The kernel usually (always?) singlesteps an extra instruction when
  // we do this with PTRACE_SYSEMU_SINGLESTEP, but rr's ptrace emulation doesn't
  // and it's kind of a kernel bug.
  if (as->get_breakpoint_type_at_addr(address_of_last_execution_resume) !=
          BKPT_NONE &&
      stop_sig() == SIGTRAP && !ptrace_event() &&
      ip() ==
          address_of_last_execution_resume.increment_by_bkpt_insn_length(
              arch())) {
    ASSERT(this, more_ticks == 0);
    // When we resume execution and immediately hit a breakpoint, the original
    // syscall number can be reset to -1. Undo that, so that the register
    // state matches the state we'd be in if we hadn't resumed. ReplayTimeline
    // depends on resume-at-a-breakpoint being a noop.
    registers.set_original_syscallno(original_syscallno);
    need_to_set_regs = true;
  }

  // When exiting a syscall, we need to normalize nondeterministic registers.
  // We also need to do this when we receive a signal in the rr page, since
  // we may have just returned from an untraced syscall there and while in the
  // rr page registers need to be consistent between record and replay.
  // During replay most untraced syscalls are replaced with "xor eax,eax" so
  // rcx is always -1, but during recording it sometimes isn't after we've
  // done a real syscall.
  if (is_in_non_sigreturn_exit_syscall(this) || is_in_rr_page()) {
    fixup_syscall_registers(registers);
    need_to_set_regs = true;
  }
  if (need_to_set_regs && did_read_regs) {
    // If we couldn't read registers, don't fix them up!
    set_regs(registers);
  }
}

bool Task::try_wait() {
  int raw_status = 0;
  pid_t ret = waitpid(tid, &raw_status, WNOHANG | __WALL | WSTOPPED);
  ASSERT(this, 0 <= ret) << "waitpid(" << tid << ", NOHANG) failed with "
                         << ret;
  LOG(debug) << "waitpid(" << tid << ", NOHANG) returns " << ret << ", status "
             << WaitStatus(raw_status);
  if (ret == tid) {
    did_waitpid(WaitStatus(raw_status));
    return true;
  }
  return false;
}

template <typename Arch>
static void set_thread_area_from_clone_arch(Task* t, remote_ptr<void> tls) {
  if (Arch::clone_tls_type == Arch::UserDescPointer) {
    t->set_thread_area(tls.cast<struct user_desc>());
  }
}

static void set_thread_area_from_clone(Task* t, remote_ptr<void> tls) {
  RR_ARCH_FUNCTION(set_thread_area_from_clone_arch, t->arch(), t, tls);
}

Task* Task::clone(int flags, remote_ptr<void> stack, remote_ptr<void> tls,
                  remote_ptr<int>, pid_t new_tid, pid_t new_rec_tid,
                  uint32_t new_serial, Session* other_session) {
  auto& sess = other_session ? *other_session : session();
  Task* t = sess.new_task(new_tid, new_rec_tid, new_serial, arch());

  if (CLONE_SHARE_TASK_GROUP & flags) {
    t->tg = tg;
  } else {
    t->tg = sess.clone(t, tg);
  }
  t->tg->insert_task(t);
  if (CLONE_SHARE_VM & flags) {
    t->as = as;
    if (!stack.is_null()) {
      remote_ptr<void> last_stack_byte = stack - 1;
      if (t->as->has_mapping(last_stack_byte)) {
        auto mapping = t->as->mapping_of(last_stack_byte);
        if (!mapping.recorded_map.is_heap()) {
          const KernelMapping& m = mapping.map;
          LOG(debug) << "mapping stack for " << new_tid << " at " << m;
          t->as->map(m.start(), m.size(), m.prot(), m.flags(),
                     m.file_offset_bytes(), "[stack]", m.device(), m.inode());
        }
      }
    }
  } else {
    t->as = sess.clone(t, as);
  }

  t->syscallbuf_size = syscallbuf_size;
  t->stopping_breakpoint_table = stopping_breakpoint_table;
  t->stopping_breakpoint_table_entry_size =
      stopping_breakpoint_table_entry_size;
  t->preload_globals = preload_globals;

  // FdTable is either shared or copied, so the contents of
  // syscallbuf_fds_disabled_child are still valid.
  if (CLONE_SHARE_FILES & flags) {
    t->fds = fds;
    t->fds->insert_task(t);
  } else {
    t->fds = fds->clone(t);
  }

  t->top_of_stack = stack;
  // Clone children, both thread and fork, inherit the parent
  // prname.
  t->prname = prname;

  // wait() before trying to do anything that might need to
  // use ptrace to access memory
  t->wait();

  t->open_mem_fd_if_needed();
  t->thread_areas_ = thread_areas_;
  // When cloning a task in the same session, the new task's thread-locals
  // are not initialized ... unless CLONE_SET_TLS is set.
  if (other_session) {
    t->thread_locals_initialized = thread_locals_initialized;
  }
  if (CLONE_SET_TLS & flags) {
    set_thread_area_from_clone(t, tls);
    t->thread_locals_initialized = true;
  }

  t->as->insert_task(t);

  if (!(CLONE_SHARE_VM & flags) && &session() == &t->session()) {
    as->did_fork_into(t);

    if (!syscallbuf_child.is_null()) {
      AutoRemoteSyscalls remote(t);
      // Unshare the syscallbuf memory so when we lock it below, we don't
      // also lock it in the task we cloned from!
      int prot = PROT_READ | PROT_WRITE;
      int flags = MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS;
      remote.infallible_mmap_syscall(syscallbuf_child, num_syscallbuf_bytes,
                                     prot, flags, -1, 0);
      t->vm()->map(syscallbuf_child, num_syscallbuf_bytes, prot, flags, 0,
                   string(), KernelMapping::NO_DEVICE, KernelMapping::NO_INODE);

      // Mark the clone's syscallbuf as locked. This will prevent the
      // clone using syscallbuf until the clone reinitializes the
      // the buffer via its pthread_atfork handler. Otherwise the clone may
      // log syscalls to its copy of the syscallbuf and we won't know about
      // them since we don't have it mapped.
      // In some cases (e.g. vfork(), or raw SYS_fork syscall) the
      // pthread_atfork handler will never run. Syscallbuf will be permanently
      // disabled but that's OK, those cases are rare (and in the case of vfork,
      // tracees should immediately exit or exec anyway).
      t->write_mem(REMOTE_PTR_FIELD(syscallbuf_child, locked), uint8_t(1));

      if (CLONE_SHARE_FILES & flags) {
        // Clear our desched_fd_child so that we don't try to close it.
        // It should only be closed in |this|.
        t->desched_fd_child = -1;
        t->cloned_file_data_fd_child = -1;
      }
    }
  }

  return t;
}

Task* Task::os_fork_into(Session* session) {
  AutoRemoteSyscalls remote(this);
  Task* child = os_clone(this, session, remote, rec_tid, serial,
                         // Most likely, we'll be setting up a
                         // CLEARTID futex.  That's not done
                         // here, but rather later in
                         // |copy_state()|.
                         //
                         // We also don't use any of the SETTID
                         // flags because that earlier work will
                         // be copied by fork()ing the address
                         // space.
                         SIGCHLD);
  // When we forked ourselves, the child inherited the setup we
  // did to make the clone() call.  So we have to "finish" the
  // remote calls (i.e. undo fudged state) in the child too,
  // even though we never made any syscalls there.
  remote.restore_state_to(child);
  return child;
}

Task* Task::os_clone_into(const CapturedState& state, Task* task_leader,
                          AutoRemoteSyscalls& remote) {
  return os_clone(task_leader, &task_leader->session(), remote, state.rec_tid,
                  state.serial,
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
                  (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                   CLONE_THREAD | CLONE_SYSVSEM),
                  state.top_of_stack);
}

template <typename Arch>
static void copy_tls_arch(const Task::CapturedState& state,
                          AutoRemoteSyscalls& remote) {
  if (Arch::clone_tls_type == Arch::UserDescPointer) {
    for (const struct user_desc& t : state.thread_areas) {
      AutoRestoreMem remote_tls(remote, (const uint8_t*)&t, sizeof(t));
      LOG(debug) << "    setting tls " << remote_tls.get();
      remote.infallible_syscall(
          syscall_number_for_set_thread_area(remote.arch()),
          remote_tls.get().as_int());
    }
  }
}

static void copy_tls(const Task::CapturedState& state,
                     AutoRemoteSyscalls& remote) {
  RR_ARCH_FUNCTION(copy_tls_arch, remote.arch(), state, remote);
}

static int64_t get_fd_offset(Task* t, int fd) {
  char buf[PATH_MAX];
  sprintf(buf, "/proc/%d/fdinfo/%d", t->tid, fd);
  ScopedFd info(buf, O_RDONLY);
  ASSERT(t, info.is_open()) << "Can't open " << buf;
  ssize_t bytes = read(info, buf, sizeof(buf) - 1);
  ASSERT(t, bytes > 0);
  buf[bytes] = 0;

  char* p = buf;
  while (*p) {
    if (strncmp(p, "pos:", 4) == 0) {
      char* end;
      long long int r = strtoll(p + 4, &end, 10);
      ASSERT(t, *end == 0 || *end == '\n');
      return r;
    }
    while (*p && *p != '\n') {
      ++p;
    }
  }
  return -1;
}

Task::CapturedState Task::capture_state() {
  CapturedState state;
  state.rec_tid = rec_tid;
  state.serial = serial;
  state.regs = regs();
  state.extra_regs = extra_regs();
  state.prname = prname;
  state.thread_areas = thread_areas_;
  state.num_syscallbuf_bytes = num_syscallbuf_bytes;
  state.desched_fd_child = desched_fd_child;
  state.cloned_file_data_fd_child = cloned_file_data_fd_child;
  state.cloned_file_data_offset =
      cloned_file_data_fd_child >= 0
          ? get_fd_offset(this, cloned_file_data_fd_child)
          : 0;
  state.syscallbuf_child = syscallbuf_child;
  state.syscallbuf_size = syscallbuf_size;
  if (syscallbuf_hdr) {
    size_t data_size = syscallbuf_data_size();
    if (syscallbuf_hdr->locked) {
      // There may be an incomplete syscall record after num_rec_bytes that
      // we need to capture here. We don't know how big that record is,
      // so just record the entire buffer. This should not be common.
      data_size = num_syscallbuf_bytes;
    }
    state.syscallbuf_hdr.resize(data_size);
    memcpy(state.syscallbuf_hdr.data(), syscallbuf_hdr,
           state.syscallbuf_hdr.size());
  }
  state.preload_globals = preload_globals;
  state.scratch_ptr = scratch_ptr;
  state.scratch_size = scratch_size;
  state.wait_status = wait_status;
  state.ticks = ticks;
  state.top_of_stack = top_of_stack;
  state.thread_locals_initialized = thread_locals_initialized;
  return state;
}

void Task::copy_state(const CapturedState& state) {
  set_regs(state.regs);
  set_extra_regs(state.extra_regs);
  {
    AutoRemoteSyscalls remote(this);
    {
      char prname[16];
      strncpy(prname, state.prname.c_str(), sizeof(prname));
      AutoRestoreMem remote_prname(remote, (const uint8_t*)prname,
                                   sizeof(prname));
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
      num_syscallbuf_bytes = state.num_syscallbuf_bytes;
      desched_fd_child = state.desched_fd_child;
      cloned_file_data_fd_child = state.cloned_file_data_fd_child;
      if (cloned_file_data_fd_child >= 0) {
        remote.infallible_lseek_syscall(
            cloned_file_data_fd_child, state.cloned_file_data_offset, SEEK_SET);
      }

      // The syscallbuf is mapped as a shared
      // segment between rr and the tracee.  So we
      // have to unmap it, create a copy, and then
      // re-map the copy in rr and the tracee.
      init_syscall_buffer(remote, state.syscallbuf_child);
      ASSERT(this, state.syscallbuf_child == syscallbuf_child);
      // Ensure the copied syscallbuf has the same contents
      // as the old one, for consistency checking.
      memcpy(syscallbuf_hdr, state.syscallbuf_hdr.data(),
             state.syscallbuf_hdr.size());
    }
  }
  preload_globals = state.preload_globals;
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

  thread_locals_initialized = state.thread_locals_initialized;
}

void Task::destroy_local_buffers() {
  munmap(syscallbuf_hdr, num_syscallbuf_bytes);
}

long Task::fallible_ptrace(int request, remote_ptr<void> addr, void* data) {
  return ptrace(__ptrace_request(request), tid, addr, data);
}

void Task::open_mem_fd() {
  // Use ptrace to read/write during open_mem_fd
  as->set_mem_fd(ScopedFd());

  // We could try opening /proc/<pid>/mem directly first and
  // only do this dance if that fails. But it's simpler to
  // always take this path, and gives better test coverage.
  static const char path[] = "/proc/self/mem";

  AutoRemoteSyscalls remote(this);
  long remote_fd;
  {
    AutoRestoreMem remote_path(remote, (const uint8_t*)path, sizeof(path));
    // skip leading '/' since we want the path to be relative to the root fd
    remote_fd = remote.infallible_syscall(syscall_number_for_openat(arch()),
                                          RR_RESERVED_ROOT_DIR_FD,
                                          remote_path.get() + 1, O_RDWR);
  }

  as->set_mem_fd(remote.retrieve_fd(remote_fd));
  ASSERT(this, as->mem_fd().is_open());

  remote.infallible_syscall(syscall_number_for_close(arch()), remote_fd);
}

void Task::open_mem_fd_if_needed() {
  if (!as->mem_fd().is_open()) {
    open_mem_fd();
  }
}

void Task::init_syscall_buffer(AutoRemoteSyscalls& remote,
                               remote_ptr<void> map_hint) {
  static int nonce = 0;
  // Create the segment we'll share with the tracee.
  char path[PATH_MAX];
  snprintf(path, sizeof(path) - 1, SYSCALLBUF_SHMEM_PATH_PREFIX "%d-%d", tid,
           nonce++);

  // Let the child create the shmem block and then send the fd back to us.
  // This lets us avoid having to make the file world-writeable so that
  // the child can read it when it's in a different user namespace (which
  // would be a security hole, letting other users abuse rr users).
  int child_shmem_fd;
  {
    AutoRestoreMem child_path(remote, path);
    // skip leading '/' since we want the path to be relative to the root fd
    child_shmem_fd = remote.infallible_syscall(
        syscall_number_for_openat(arch()), RR_RESERVED_ROOT_DIR_FD,
        child_path.get() + 1, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  }

  /* Remove the fs name so that we don't have to worry about
   * cleaning up this segment in error conditions. */
  unlink(path);

  ScopedFd shmem_fd = remote.retrieve_fd(child_shmem_fd);
  resize_shmem_segment(shmem_fd, syscallbuf_size);
  LOG(debug) << "created shmem segment " << path;

  // Map the segment in ours and the tracee's address spaces.
  void* map_addr;
  num_syscallbuf_bytes = syscallbuf_size;
  int prot = PROT_READ | PROT_WRITE;
  int flags = MAP_SHARED;
  if ((void*)-1 == (map_addr = mmap(nullptr, num_syscallbuf_bytes, prot, flags,
                                    shmem_fd, 0))) {
    FATAL() << "Failed to mmap shmem region";
  }
  if (!map_hint.is_null()) {
    flags |= MAP_FIXED;
  }
  remote_ptr<void> child_map_addr = remote.infallible_mmap_syscall(
      map_hint, num_syscallbuf_bytes, prot, flags, child_shmem_fd, 0);

  ASSERT(this, !syscallbuf_child)
      << "Should not already have syscallbuf initialized!";
  syscallbuf_child = child_map_addr.cast<struct syscallbuf_hdr>();
  syscallbuf_hdr = (struct syscallbuf_hdr*)map_addr;
  // No entries to begin with.
  memset(syscallbuf_hdr, 0, sizeof(*syscallbuf_hdr));

  struct stat st;
  ASSERT(this, 0 == ::fstat(shmem_fd, &st));
  vm()->map(child_map_addr, num_syscallbuf_bytes, prot, flags, 0, path,
            st.st_dev, st.st_ino);

  shmem_fd.close();
  remote.infallible_syscall(syscall_number_for_close(arch()), child_shmem_fd);
}

void Task::reset_syscallbuf() {
  uint8_t* ptr = (uint8_t*)(syscallbuf_hdr + 1);
  memset(ptr, 0, syscallbuf_hdr->num_rec_bytes);
  syscallbuf_hdr->num_rec_bytes = 0;
  syscallbuf_hdr->mprotect_record_count = 0;
  syscallbuf_hdr->mprotect_record_count_completed = 0;
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
  ASSERT(this, buf_size >= 0) << "Invalid buf_size " << buf_size;
  if (0 == buf_size) {
    return 0;
  }

  if (!as->mem_fd().is_open()) {
    return read_bytes_ptrace(addr, buf_size, buf);
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
    // fd we open, very early in exec, refers to some resource
    // that's different than the one we see after reopening the
    // fd, after exec.
    if (0 == nread && 0 == all_read && 0 == errno) {
      open_mem_fd();
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

bool Task::try_replace_pages(remote_ptr<void> addr, ssize_t buf_size,
                             const void* buf) {
  // Check that there are private-mapping pages covering the destination area.
  // The pages must all have the same prot and flags.
  uintptr_t page_size = sysconf(_SC_PAGESIZE);
  uintptr_t page_start = addr.as_int() & ~(page_size - 1);
  uintptr_t page_end =
      (addr.as_int() + buf_size + page_size - 1) & ~(page_size - 1);
  int all_prot, all_flags;
  for (uintptr_t p = page_start; p < page_end; p += page_size) {
    const KernelMapping& m = as->mapping_of(p).map;
    if (p > page_start) {
      if (all_prot != m.prot() || all_flags != m.flags()) {
        return false;
      }
    } else {
      all_prot = m.prot();
      all_flags = m.flags();
    }
  }
  if (!(all_flags & MAP_PRIVATE)) {
    return false;
  }

  auto cur = read_mem(remote_ptr<uint8_t>(page_start), page_end - page_start);

  // XXX share this with AddressSpace.cc
  char path[] = "/tmp/rr-replaced-pages-XXXXXX";
  ScopedFd fd(mkstemp(path));
  ASSERT(this, fd.is_open());
  ssize_t nwritten = write(fd, cur.data(), cur.size());
  ASSERT(this, nwritten == (ssize_t)cur.size());
  nwritten = pwrite(fd, buf, buf_size, addr.as_int() - page_start);
  ASSERT(this, nwritten == buf_size);

  AutoRemoteSyscalls remote(this);
  SupportedArch a = arch();
  AutoRestoreMem child_path(remote, reinterpret_cast<uint8_t*>(path),
                            sizeof(path));
  // skip leading '/' since we want the path to be relative to the root fd
  int child_fd = remote.infallible_syscall(syscall_number_for_openat(a),
                                           RR_RESERVED_ROOT_DIR_FD,
                                           child_path.get() + 1, O_RDWR);
  ASSERT(this, child_fd >= 0);

  // Just map the new file right over the top of existing pages
  remote.infallible_mmap_syscall(page_start, cur.size(), all_prot,
                                 all_flags | MAP_FIXED, child_fd, 0);

  remote.infallible_syscall(syscall_number_for_close(a), child_fd);

  unlink(path);
  return true;
}

/**
 * This function exists to work around
 * https://bugzilla.kernel.org/show_bug.cgi?id=99101.
 * On some kernels pwrite() to /proc/.../mem fails when writing to a region
 * that's PROT_NONE.
 */
static ssize_t safe_pwrite64(Task* t, const void* buf, ssize_t buf_size,
                             remote_ptr<void> addr) {
  vector<KernelMapping> mappings_to_fix;
  for (auto m : t->vm()->maps_starting_at(floor_page_size(addr))) {
    if (m.map.start() >= ceil_page_size(addr + buf_size)) {
      break;
    }
    if (!(m.map.prot() & (PROT_READ | PROT_WRITE))) {
      mappings_to_fix.push_back(m.map);
    }
  };

  if (mappings_to_fix.empty()) {
    return pwrite64(t->vm()->mem_fd(), buf, buf_size, addr.as_int());
  }

  AutoRemoteSyscalls remote(t);
  int mprotect_syscallno = syscall_number_for_mprotect(t->arch());
  for (auto& m : mappings_to_fix) {
    remote.infallible_syscall(mprotect_syscallno, m.start(), m.size(),
                              m.prot() | PROT_WRITE);
  }
  ssize_t nwritten = pwrite64(t->vm()->mem_fd(), buf, buf_size, addr.as_int());
  for (auto& m : mappings_to_fix) {
    remote.infallible_syscall(mprotect_syscallno, m.start(), m.size(),
                              m.prot());
  }
  return nwritten;
}

void Task::write_bytes_helper(remote_ptr<void> addr, ssize_t buf_size,
                              const void* buf, bool* ok) {
  ASSERT(this, buf_size >= 0) << "Invalid buf_size " << buf_size;
  if (0 == buf_size) {
    return;
  }

  if (!as->mem_fd().is_open()) {
    ssize_t nwritten = write_bytes_ptrace(addr, buf_size, buf);
    if (nwritten > 0) {
      vm()->notify_written(addr, nwritten);
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
    return write_bytes_helper(addr, buf_size, buf, ok);
  }
  if (errno == EPERM && try_replace_pages(addr, buf_size, buf)) {
    // Maybe a PaX kernel and we're trying to write to an executable page.
    vm()->notify_written(addr, buf_size);
    return;
  }
  if (ok) {
    if (nwritten < buf_size) {
      *ok = false;
    }
  } else {
    ASSERT(this, nwritten == buf_size) << "Should have written " << buf_size
                                       << " bytes to " << addr
                                       << ", but only wrote " << nwritten;
  }
  if (nwritten > 0) {
    vm()->notify_written(addr, nwritten);
  }
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
  ASSERT(this, !errno) << "ptrace(" << ptrace_req_name(request) << ", " << tid
                       << ", addr=" << addr << ", data=" << data
                       << ") failed with errno " << errno;
}

bool Task::ptrace_if_alive(int request, remote_ptr<void> addr, void* data) {
  errno = 0;
  fallible_ptrace(request, addr, data);
  if (errno == ESRCH) {
    return false;
  }
  ASSERT(this, !errno) << "ptrace(" << ptrace_req_name(request) << ", " << tid
                       << ", addr=" << addr << ", data=" << data
                       << ") failed with errno " << errno;
  return true;
}

bool Task::clone_syscall_is_complete() {
  int event = ptrace_event();
  if (PTRACE_EVENT_CLONE == event || PTRACE_EVENT_FORK == event) {
    return true;
  }
  ASSERT(this, !event) << "Unexpected ptrace event "
                       << ptrace_event_name(event);

  // EAGAIN can happen here due to fork failing under load. The caller must
  // handle this.
  // XXX ENOSYS shouldn't happen here.
  intptr_t result = regs().syscall_result_signed();
  ASSERT(this, regs().syscall_may_restart() || -ENOSYS == result ||
                   -EAGAIN == result || -ENOMEM == result)
      << "Unexpected task status " << status() << " ("
      << syscall_name(regs().original_syscallno())
      << " syscall errno: " << errno_name(-result) << ")";
  return false;
}

template <typename Arch> static void do_preload_init_arch(Task* t) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<Arch> >(t->regs().arg1()));

  t->preload_globals = params.globals.rptr();

  t->stopping_breakpoint_table = params.breakpoint_table.rptr().as_int();
  t->stopping_breakpoint_table_entry_size = params.breakpoint_table_entry_size;

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
static void perform_remote_clone_arch(
    AutoRemoteSyscalls& remote, unsigned base_flags, remote_ptr<void> stack,
    remote_ptr<int> ptid, remote_ptr<void> tls, remote_ptr<int> ctid) {
  switch (Arch::clone_parameter_ordering) {
    case Arch::FlagsStackParentTLSChild:
      remote.syscall(Arch::clone, base_flags, stack, ptid.as_int(),
                     tls.as_int(), ctid.as_int());
      break;
    case Arch::FlagsStackParentChildTLS:
      remote.syscall(Arch::clone, base_flags, stack, ptid.as_int(),
                     ctid.as_int(), tls.as_int());
      break;
  }
}

static void perform_remote_clone(Task* parent, AutoRemoteSyscalls& remote,
                                 unsigned base_flags, remote_ptr<void> stack,
                                 remote_ptr<int> ptid, remote_ptr<void> tls,
                                 remote_ptr<int> ctid) {
  RR_ARCH_FUNCTION(perform_remote_clone_arch, parent->arch(), remote,
                   base_flags, stack, ptid, tls, ctid);
}

/*static*/ Task* Task::os_clone(Task* parent, Session* session,
                                AutoRemoteSyscalls& remote, pid_t rec_child_tid,
                                uint32_t new_serial, unsigned base_flags,
                                remote_ptr<void> stack, remote_ptr<int> ptid,
                                remote_ptr<void> tls, remote_ptr<int> ctid) {
  perform_remote_clone(parent, remote, base_flags, stack, ptid, tls, ctid);
  while (!parent->clone_syscall_is_complete()) {
    // clone syscalls can fail with EAGAIN due to temporary load issues.
    // Just retry the system call until it succeeds.
    if (parent->regs().syscall_result_signed() == -EAGAIN) {
      perform_remote_clone(parent, remote, base_flags, stack, ptid, tls, ctid);
    } else {
      // XXX account for ReplaySession::is_ignored_signal?
      parent->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);
    }
  }
  pid_t new_tid = parent->get_ptrace_eventmsg<pid_t>();

  parent->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);
  Task* child =
      parent->clone(clone_flags_to_task_flags(base_flags), stack, tls, ctid,
                    new_tid, rec_child_tid, new_serial, session);
  return child;
}

static void setup_fd_table(FdTable& fds) {
  fds.add_monitor(STDOUT_FILENO, new StdioMonitor(STDOUT_FILENO));
  fds.add_monitor(STDERR_FILENO, new StdioMonitor(STDERR_FILENO));
  fds.add_monitor(RR_MAGIC_SAVE_DATA_FD, new MagicSaveDataMonitor());
  fds.add_monitor(RR_RESERVED_ROOT_DIR_FD, new PreserveFileMonitor());
}

static void set_cpu_affinity(int cpu) {
  assert(cpu >= 0);

  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(cpu, &mask);
  if (0 > sched_setaffinity(0, sizeof(mask), &mask)) {
    FATAL() << "Couldn't bind to CPU " << cpu;
  }
}

static void spawned_child_fatal_error(const ScopedFd& err_fd,
                                      const char* format, ...) {
  va_list args;
  va_start(args, format);
  char* buf;
  vasprintf(&buf, format, args);

  char* buf2;
  asprintf(&buf2, "%s (%s)", buf, errno_name(errno).c_str());
  write(err_fd, buf2, strlen(buf2));
  _exit(1);
}

/**
 * Prepare this process and its ancestors for recording/replay by
 * preventing direct access to sources of nondeterminism, and ensuring
 * that rr bugs don't adversely affect the underlying system.
 */
static void set_up_process(Session& session, const ScopedFd& err_fd) {
  /* TODO tracees can probably undo some of the setup below
   * ... */

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

  // If we're running under rr then don't try to set up RR_RESERVED_ROOT_DIR_FD;
  // it should already be correct (unless someone chrooted in between,
  // which would be crazy ... though we could fix it by dynamically
  // assigning RR_RESERVED_ROOT_DIR_FD.)
  if (!running_under_rr()) {
    /* CLOEXEC so that the original fd here will be closed by the exec that's
     * about to happen.
     */
    fd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (0 > fd) {
      spawned_child_fatal_error(err_fd, "error opening root directory");
    }
    if (RR_RESERVED_ROOT_DIR_FD != dup2(fd, RR_RESERVED_ROOT_DIR_FD)) {
      spawned_child_fatal_error(err_fd,
                                "error duping to RR_RESERVED_ROOT_DIR_FD");
    }
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

  /* Trap to the rr process if a 'rdtsc' instruction is issued.
   * That allows rr to record the tsc and replay it
   * deterministically. */
  if (0 > prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0)) {
    spawned_child_fatal_error(err_fd, "error setting up prctl");
  }

  if (0 > prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    spawned_child_fatal_error(
        err_fd,
        "prctl(NO_NEW_PRIVS) failed, SECCOMP_FILTER is not available: your "
        "kernel is too old. Use `record -n` to disable the filter.");
  }
}

/**
 * This is called (and must be called) in the tracee after rr has taken
 * ptrace control. Otherwise, once we've installed the seccomp filter,
 * things go wrong because we have no ptracer and the seccomp filter demands
 * one.
 */
static void set_up_seccomp_filter(Session& session, int err_fd) {
  SeccompFilter<struct sock_filter> f;
  if (session.is_recording() && session.as_record()->use_syscall_buffer()) {
    for (auto& e : AddressSpace::rr_page_syscalls()) {
      if (e.traced == AddressSpace::UNTRACED) {
        auto ip = AddressSpace::rr_page_syscall_exit_point(
            e.traced, e.privileged, e.enabled);
        f.allow_syscalls_from_callsite(ip);
      }
    }
    f.trace();
  } else {
    // Use a dummy filter that always generates ptrace traps. Supplying this
    // dummy filter makes ptrace-event behavior consistent whether or not
    // we enable syscall buffering, and more importantly, consistent whether
    // or not the tracee installs its own seccomp filter.
    f.trace();
  }

  struct sock_fprog prog = { (unsigned short)f.filters.size(),
                             f.filters.data() };

  /* Note: the filter is installed only for record. This call
   * will be emulated in the replay */
  if (0 > prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (uintptr_t)&prog, 0, 0)) {
    spawned_child_fatal_error(
        err_fd, "prctl(SECCOMP) failed, SECCOMP_FILTER is not available: your "
                "kernel is too old.");
  }
  /* anything that happens from this point on gets filtered! */
}

static void run_initial_child(Session& session, const ScopedFd& error_fd,
                              const TraceStream& trace) {
  // Set current working directory to the cwd used during
  // recording. The main effect of this is to resolve relative
  // paths in the following execvpe correctly during replay.
  chdir(trace.initial_cwd().c_str());
  set_up_process(session, error_fd);
  // The preceding code must run before sending SIGSTOP here,
  // since after SIGSTOP replay emulates almost all syscalls, but
  // we need the above syscalls to run "for real".

  // Signal to tracer that we're configured.
  ::kill(getpid(), SIGSTOP);

  // This code must run after rr has taken ptrace control.
  set_up_seccomp_filter(session, error_fd);

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

  const char* exe = trace.initial_exe().c_str();
  execvpe(exe, StringVectorToCharArray(trace.initial_argv()).get(),
          StringVectorToCharArray(trace.initial_envp()).get());
  // That failed. Try executing the file directly.
  execve(exe, StringVectorToCharArray(trace.initial_argv()).get(),
         StringVectorToCharArray(trace.initial_envp()).get());

  switch (errno) {
    case ENOENT:
      spawned_child_fatal_error(
          error_fd, "execve failed: '%s' (or interpreter) not found", exe);
      break;
    default:
      spawned_child_fatal_error(error_fd, "execve of '%s' failed", exe);
      break;
  }
  // Never returns!
}

/*static*/ Task* Task::spawn(Session& session, const ScopedFd& error_fd,
                             const TraceStream& trace, pid_t rec_tid) {
  assert(session.tasks().size() == 0);

  if (trace.bound_to_cpu() >= 0) {
    // Set CPU affinity now, after we've created any helper threads
    // (so they aren't affected), but before we create any
    // tracees (so they are all affected).
    // Note that we're binding rr itself to the same CPU as the
    // tracees, since this seems to help performance.
    set_cpu_affinity(trace.bound_to_cpu());
  }

  pid_t tid;
  do {
    tid = fork();
    // fork() can fail with EAGAIN due to temporary load issues. In such
    // cases, retry the fork().
  } while (0 > tid && errno == EAGAIN);

  if (0 == tid) {
    run_initial_child(session, error_fd, trace);
    // run_initial_child never returns
  }

  if (0 > tid) {
    FATAL() << "Failed to fork";
  }

  struct sigaction sa;
  sa.sa_handler = handle_alarm_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0; // No SA_RESTART, so waitpid() will be interrupted
  sigaction(SIGALRM, &sa, nullptr);

  // Sync with the child process.
  // We minimize the code we run between fork()ing and PTRACE_SEIZE, because
  // any abnormal exit of the rr process will leave the child paused and
  // parented by the init process, i.e. effectively leaked. After PTRACE_SEIZE
  // with PTRACE_O_EXITKILL, the tracee will die if rr dies.
  intptr_t options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                     PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT;
  if (session.is_recording()) {
    options |= PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEEXEC;
  }

  long ret =
      ptrace(PTRACE_SEIZE, tid, nullptr, (void*)(options | PTRACE_O_EXITKILL));
  if (ret < 0 && errno == EINVAL) {
    // PTRACE_O_EXITKILL was added in kernel 3.8, and we only need
    // it for more robust cleanup, so tolerate not having it.
    ret = ptrace(PTRACE_SEIZE, tid, nullptr, (void*)options);
  }
  if (ret) {
    // Note that although the tracee may have died due to some fatal error,
    // we haven't reaped its exit code so there's no danger of killing
    // (or PTRACE_SEIZEing) the wrong process.
    int tmp_errno = errno;
    kill(tid, SIGKILL);
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
  auto tg = session.create_tg(t);
  t->tg.swap(tg);
  auto as = session.create_vm(t, trace.initial_exe());
  t->as.swap(as);
  t->fds = FdTable::create(t);
  setup_fd_table(*t->fds);

  t->wait();
  if (t->ptrace_event() == PTRACE_EVENT_EXIT) {
    FATAL() << "Tracee died before reaching SIGSTOP\n"
               "Child's message: "
            << session.read_spawned_task_error();
  }
  // SIGSTOP can be reported as a signal-stop or group-stop depending on
  // whether PTRACE_SEIZE happened before or after it was delivered.
  if (SIGSTOP != t->status().stop_sig() &&
      SIGSTOP != t->status().group_stop()) {
    FATAL() << "Unexpected stop " << t->status() << "\n"
                                                    "Child's message: "
            << session.read_spawned_task_error();
  }

  t->clear_wait_status();
  t->open_mem_fd();
  return t;
}

string Task::syscall_name(int syscall) const {
  return rr::syscall_name(syscall, arch());
} // namespace rr
}
