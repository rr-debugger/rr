/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "AutoRemoteSyscalls.h"

#include <limits.h>
#include <linux/net.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "rr/rr.h"

#include "RecordTask.h"
#include "ReplaySession.h"
#include "Session.h"
#include "Task.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

/**
 * The ABI of the socketcall syscall is a nightmare; the first arg to
 * the kernel is the sub-operation, and the second argument is a
 * pointer to the args.  The args depend on the sub-op.
 */
template <typename Arch> struct socketcall_args {
  typename Arch::signed_long args[3];
} __attribute__((packed));

void AutoRestoreMem::init(const void* mem, ssize_t num_bytes) {
  ASSERT(remote.task(),
         remote.enable_mem_params() == AutoRemoteSyscalls::ENABLE_MEMORY_PARAMS)
      << "Memory parameters were disabled";

  len = num_bytes;
  saved_sp = remote.regs().sp();

  remote.regs().set_sp(remote.regs().sp() - len);
  remote.task()->set_regs(remote.regs());
  addr = remote.regs().sp();

  data.resize(len);
  remote.task()->read_bytes_helper(addr, len, data.data());

  if (mem) {
    remote.task()->write_bytes_helper(addr, len, mem);
  }
}

AutoRestoreMem::~AutoRestoreMem() {
  DEBUG_ASSERT(saved_sp == remote.regs().sp() + len);

  remote.task()->write_bytes_helper(addr, len, data.data());

  remote.regs().set_sp(remote.regs().sp() + len);
  remote.task()->set_regs(remote.regs());
}

static bool is_SIGTRAP_default_and_unblocked(Task* t) {
  if (!t->session().is_recording()) {
    return true;
  }
  RecordTask* rt = static_cast<RecordTask*>(t);
  return rt->sig_disposition(SIGTRAP) == SIGNAL_DEFAULT &&
         !rt->is_sig_blocked(SIGTRAP);
}

AutoRemoteSyscalls::AutoRemoteSyscalls(Task* t,
                                       MemParamsEnabled enable_mem_params)
    : t(t),
      initial_regs(t->regs()),
      initial_ip(t->ip()),
      initial_sp(t->regs().sp()),
      restore_wait_status(t->status()),
      new_tid_(-1),
      scratch_mem_was_mapped(false),
      use_singlestep_path(false),
      enable_mem_params_(enable_mem_params) {
  // We support two paths for syscalls:
  // -- a fast path using a privileged untraced syscall and PTRACE_SINGLESTEP.
  // This only requires a single task-wait.
  // -- a slower path using a privileged traced syscall and PTRACE_SYSCALL/
  // PTRACE_CONT via Task::enter_syscall(). This requires 2 or 3 task-waits
  // depending on whether the seccomp event fires before the syscall-entry
  // event.
  // Use the slow path when running under rr, because the rr recording us
  // needs to see and trace these tracee syscalls, and if they're untraced by
  // us they're also untraced by the outer rr.
  // Use the slow path if SIGTRAP is blocked or ignored because otherwise
  // the PTRACE_SINGLESTEP will cause the kernel to unblock it.
  setup_path(t->vm()->has_rr_page() && !running_under_rr() &&
             is_SIGTRAP_default_and_unblocked(t));
  if (enable_mem_params == ENABLE_MEMORY_PARAMS) {
    maybe_fix_stack_pointer();
  }
}

void AutoRemoteSyscalls::setup_path(bool enable_singlestep_path) {
  if (!replaced_bytes.empty()) {
    t->write_mem(remote_ptr<uint8_t>(initial_regs.ip().to_data_ptr<uint8_t>()),
                 replaced_bytes.data(), replaced_bytes.size());
  }

  remote_code_ptr syscall_ip;
  use_singlestep_path = enable_singlestep_path;
  if (enable_singlestep_path) {
    syscall_ip = AddressSpace::rr_page_syscall_entry_point(
        AddressSpace::UNTRACED, AddressSpace::PRIVILEGED,
        AddressSpace::RECORDING_AND_REPLAY, t->arch());
    use_singlestep_path = true;
  } else {
    syscall_ip = t->vm()->traced_syscall_ip();
  }
  initial_regs.set_ip(syscall_ip);

  // We need to make sure to clear any breakpoints or other alterations of
  // the syscall instruction we're using. Note that the tracee may have set its
  // own breakpoints or otherwise modified the instruction, so suspending our
  // own breakpoint is insufficient.
  std::vector<uint8_t> syscall = rr::syscall_instruction(t->arch());
  replaced_bytes =
      t->read_mem(initial_regs.ip().to_data_ptr<uint8_t>(), syscall.size());
  if (replaced_bytes == syscall) {
    replaced_bytes.clear();
  } else {
    t->write_mem(initial_regs.ip().to_data_ptr<uint8_t>(), syscall.data(),
                 syscall.size());
  }
}

static bool is_usable_area(const KernelMapping& km) {
  return (km.prot() & (PROT_READ | PROT_WRITE)) == (PROT_READ | PROT_WRITE) &&
         (km.flags() & MAP_PRIVATE);
}

void AutoRemoteSyscalls::maybe_fix_stack_pointer() {
  if (!t->session().done_initial_exec()) {
    return;
  }

  remote_ptr<void> last_stack_byte = t->regs().sp() - 1;
  if (t->vm()->has_mapping(last_stack_byte)) {
    auto m = t->vm()->mapping_of(last_stack_byte);
    if (is_usable_area(m.map) && m.map.start() + 2048 <= t->regs().sp()) {
      // 'sp' is in a stack region and there's plenty of space there. No need
      // to fix anything.
      return;
    }
  }

  MemoryRange found_stack;
  for (const auto& m : t->vm()->maps()) {
    if (is_usable_area(m.map)) {
      found_stack = m.map;
      break;
    }
  };

  if (found_stack.start().is_null()) {
    AutoRemoteSyscalls remote(t, DISABLE_MEMORY_PARAMS);
    found_stack =
        MemoryRange(remote.infallible_mmap_syscall(
                        remote_ptr<void>(), 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
                    4096);
    scratch_mem_was_mapped = true;
  }

  fixed_sp = found_stack.end();
  DEBUG_ASSERT(!fixed_sp.is_null());
  initial_regs.set_sp(fixed_sp);
}

AutoRemoteSyscalls::~AutoRemoteSyscalls() { restore_state_to(t); }

void AutoRemoteSyscalls::restore_state_to(Task* t) {
  // Unmap our scatch region if required
  if (scratch_mem_was_mapped) {
    AutoRemoteSyscalls remote(t, DISABLE_MEMORY_PARAMS);
    remote.infallible_syscall(syscall_number_for_munmap(arch()),
                              fixed_sp - 4096, 4096);
  }
  if (!replaced_bytes.empty()) {
    t->write_mem(remote_ptr<uint8_t>(initial_regs.ip().to_data_ptr<uint8_t>()),
                 replaced_bytes.data(), replaced_bytes.size());
  }
  auto regs = initial_regs;
  regs.set_ip(initial_ip);
  regs.set_sp(initial_sp);
  // Restore stomped registers.
  t->set_regs(regs);
  t->set_status(restore_wait_status);
}

static bool ignore_signal(Task* t) {
  int sig = t->stop_sig();
  if (!sig) {
    return false;
  }
  if (t->session().is_replaying()) {
    if (ReplaySession::is_ignored_signal(sig)) {
      return true;
    }
  } else if (t->session().is_recording()) {
    if (sig != SYSCALLBUF_DESCHED_SIGNAL) {
      static_cast<RecordTask*>(t)->stash_sig();
    }
    return true;
  }
  ASSERT(t, false) << "Unexpected signal " << signal_name(sig);
  return false;
}

long AutoRemoteSyscalls::syscall_base(int syscallno, Registers& callregs) {
  LOG(debug) << "syscall " << syscall_name(syscallno, t->arch());

  if ((int)callregs.arg1() == SIGTRAP && use_singlestep_path &&
      (is_sigaction_syscall(syscallno, t->arch()) ||
       is_rt_sigaction_syscall(syscallno, t->arch()) ||
       is_signal_syscall(syscallno, t->arch()))) {
    // Don't use the fast path if we're about to set up a signal handler
    // for SIGTRAP!
    LOG(debug) << "Disabling singlestep path due to SIGTRAP sigaction";
    setup_path(false);
    callregs.set_ip(initial_regs.ip());
  }

  callregs.set_syscallno(syscallno);
  t->set_regs(callregs);

  if (use_singlestep_path) {
    while (true) {
      t->resume_execution(RESUME_SINGLESTEP, RESUME_WAIT, RESUME_NO_TICKS);
      LOG(debug) << "Used singlestep path; status=" << t->status();
      // When a PTRACE_EVENT_EXIT is returned we don't update registers
      if (t->ip() != callregs.ip()) {
        // We entered the syscall, so stop now
        break;
      }
      if (ignore_signal(t)) {
        // We were interrupted by a signal before we even entered the syscall
        continue;
      }
      ASSERT(t, false) << "Unexpected status " << t->status();
    }
  } else {
    t->enter_syscall();
    LOG(debug) << "Used enter_syscall; status=" << t->status();
    // proceed to syscall exit
    t->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);
    LOG(debug) << "syscall exit status=" << t->status();
  }
  while (true) {
    // If the syscall caused the task to exit, just stop now with that status.
    if (t->ptrace_event() == PTRACE_EVENT_EXIT) {
      restore_wait_status = t->status();
      break;
    }
    if (t->status().is_syscall() ||
        (t->stop_sig() == SIGTRAP &&
         is_kernel_trap(t->get_siginfo().si_code))) {
      // If we got a SIGTRAP then we assume that's our singlestep and we're
      // done.
      break;
    }
    if (is_clone_syscall(syscallno, t->arch()) &&
        t->clone_syscall_is_complete(&new_tid_, t->arch())) {
      t->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);
      LOG(debug) << "got clone event; new status=" << t->status();
      continue;
    }
    if (ignore_signal(t)) {
      if (t->regs().syscall_may_restart()) {
        t->enter_syscall();
        LOG(debug) << "signal ignored; restarting syscall, status="
                   << t->status();
        t->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);
        LOG(debug) << "syscall exit status=" << t->status();
        continue;
      }
      LOG(debug) << "signal ignored";
      // We have been notified of a signal after a non-interruptible syscall
      // completed. Don't continue, we're done here.
      break;
    }
    ASSERT(t, false) << "Unexpected status " << t->status();
    break;
  }

  LOG(debug) << "done, result=" << t->regs().syscall_result();
  return t->regs().syscall_result();
}

SupportedArch AutoRemoteSyscalls::arch() const { return t->arch(); }

template <typename Arch>
static void write_socketcall_args(Task* t, remote_ptr<void> remote_mem,
                                  typename Arch::signed_long arg1,
                                  typename Arch::signed_long arg2,
                                  typename Arch::signed_long arg3) {
  socketcall_args<Arch> sc_args = { { arg1, arg2, arg3 } };
  t->write_mem(remote_mem.cast<socketcall_args<Arch>>(), sc_args);
}

static size_t align_size(size_t size) {
  static int align_amount = sizeof(uintptr_t);
  return (size + align_amount - 1) & ~(align_amount - 1);
}

static remote_ptr<void> allocate(remote_ptr<void>* buf_end,
                                 const AutoRestoreMem& remote_buf,
                                 size_t size) {
  remote_ptr<void> r = *buf_end;
  *buf_end += align_size(size);
  if (size_t(*buf_end - remote_buf.get()) > remote_buf.size()) {
    FATAL() << "overflow";
  }
  return r;
}

template <typename T>
static remote_ptr<T> allocate(remote_ptr<void>* buf_end,
                              const AutoRestoreMem& remote_buf) {
  return allocate(buf_end, remote_buf, sizeof(T)).cast<T>();
}

static int create_bind_and_listen_socket(const char* path) {
  struct sockaddr_un addr;
  int listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (listen_sock < 0) {
    FATAL() << "Failed to create listen socket";
  }

  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
  addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
  if (::bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr))) {
    FATAL() << "Failed to bind listen socket";
  }

  if (chmod(path, 0666)) {
    FATAL() << "Failed to make listening socket world-writeable";
  }

  if (listen(listen_sock, 1)) {
    FATAL() << "Failed to mark listening for listen socket";
  }

  return listen_sock;
}

template <typename Arch>
static int child_create_socket(AutoRemoteSyscalls& remote,
                               remote_ptr<socketcall_args<Arch>> sc_args) {
  int child_sock;
  if (sc_args.is_null()) {
    child_sock =
        remote.infallible_syscall(Arch::socket, AF_UNIX, SOCK_STREAM, 0);
  } else {
    write_socketcall_args<Arch>(remote.task(), sc_args, AF_UNIX, SOCK_STREAM,
                                0);
    child_sock =
        remote.infallible_syscall(Arch::socketcall, SYS_SOCKET, sc_args);
  }
  return child_sock;
}

struct TemporaryProcMounter {
  TemporaryProcMounter(Task* tracee)
    : tracee(tracee)
    , helper_pid(-1) {}
  Task* tracee;
  pid_t helper_pid;
  ScopedFd rr_to_helper_write;

  void mount() {
    int pipe_fds_tmp[2];
    int ret = pipe(pipe_fds_tmp);
    ASSERT(tracee, ret >= 0);
    ScopedFd rr_to_helper_read(pipe_fds_tmp[0]);
    rr_to_helper_write = ScopedFd(pipe_fds_tmp[1]);
    ret = pipe(pipe_fds_tmp);
    ASSERT(tracee, ret >= 0);
    ScopedFd helper_to_rr_read(pipe_fds_tmp[0]);
    ScopedFd helper_to_rr_write(pipe_fds_tmp[1]);

    pid_t child = fork();
    if (!child) {
      rr_to_helper_write.close();
      helper_to_rr_read.close();
      run_child(rr_to_helper_read, helper_to_rr_write);
    }
    rr_to_helper_read.close();
    helper_to_rr_write.close();
    helper_pid = child;
    char ch;
    ret = read(helper_to_rr_read, &ch, 1);
    ASSERT(tracee, ret == 1);
  }

  void run_child(ScopedFd& rr_to_helper_read, ScopedFd& helper_to_rr_write) {
    char buf[40];

    // Obtain fds for the user, pid and mount namespaces of the tracee.
    sprintf(buf, "/proc/%d/ns/user", tracee->tid);
    ScopedFd user_namespace_fd(buf, O_RDONLY);
    ASSERT(tracee, user_namespace_fd.is_open());

    sprintf(buf, "/proc/%d/ns/mnt", tracee->tid);
    ScopedFd mount_namespace_fd(buf, O_RDONLY);
    ASSERT(tracee, mount_namespace_fd.is_open());

    sprintf(buf, "/proc/%d/ns/pid", tracee->tid);
    ScopedFd pid_namespace_fd(buf, O_RDONLY);
    ASSERT(tracee, pid_namespace_fd.is_open());

    // Now chdir to the root directory of the tracee.
    // This will let us mount /proc in the right place.
    // Do this before switching mount namespaces since the tracee may have
    // unmounted the initial /proc mount in its namespace.
    sprintf(buf, "/proc/%d/root", tracee->tid);
    ScopedFd root_fd(buf, O_PATH);
    ASSERT(tracee, root_fd.is_open());

    // Enter the user namespace of the tracee so we get all the capabilities
    // we need.
    int ret = setns(user_namespace_fd, CLONE_NEWUSER);
    // If the tracee hasn't changed user namespaces but /proc isn't mounted
    // then the tracee must have CAP_SYS_ADMIN, and therefore so must our
    // process, so tolerate this.
    ASSERT(tracee, ret >= 0 || errno == EINVAL);
    // Enter the pid namespace of the tracee.
    ret = setns(pid_namespace_fd, CLONE_NEWPID);
    // We might get EINVAL if the pid namespace hasn't changed.
    ASSERT(tracee, ret >= 0 || errno == EINVAL);
    // Now enter the mount namespace of the tracee so we can mount procfs
    // and the tracee will see it.
    ret = setns(mount_namespace_fd, CLONE_NEWNS);
    ASSERT(tracee, ret >= 0);
    // Entering the mount namespace causes our current working directory
    // to reset to the root if we changed it to root_fd earlier. I can't
    // figure out why. So, chdir now.
    ret = fchdir(root_fd);
    ASSERT(tracee, ret >= 0);

    ret = umask(0);
    ASSERT(tracee, ret >= 0);
    // In theory creating this directory could fail if the root directory
    // for the tracee has been made non-writeable to us. That shouldn't
    // happen in practice. If it does we should be able to mount proc
    // somewhere else.
    ret = mkdir("proc", 0777);
    ASSERT(tracee, ret >= 0);

    // Fork to obtain a child which is in the desired PID namespace
    pid_t child = fork();
    if (!child) {
      // This can't race with other mount syscalls in the tracee namespace
      // because we don't allow context switching during tracee mount().
      // This can't race with tracee root directory traversal because we don't
      // allow context switching during tracee getdents().
      // This can't race with tracee reading /proc/<tid>/mounts because /proc
      // is not already mounted. In theory a tracee could mount procfs elsewhere
      // and be reading mounts that way ... but too bad.
      ret = ::mount("dummy", "proc", "proc", 0, NULL);
      ASSERT(tracee, ret >= 0);
      exit(0);
    }
    int status;
    ret = waitpid(child, &status, 0);
    ASSERT(tracee, ret == child);
    ASSERT(tracee, WIFEXITED(status) && WEXITSTATUS(status) == 0);

    // Signal that procfs has been mounted
    ret = write(helper_to_rr_write, "y", 1);
    ASSERT(tracee, ret == 1);
    // Wait for the signal that the procfs is no longer needed
    char ch;
    ret = read(rr_to_helper_read, &ch, 1);
    ASSERT(tracee, ret == 1);
    // Perform the unmount
    ret = umount("proc");
    ASSERT(tracee, ret >= 0);
    ret = rmdir("proc");
    ASSERT(tracee, ret >= 0);
    exit(0);
  }

  ~TemporaryProcMounter() {
    if (helper_pid < 0) {
      return;
    }
    int ret = write(rr_to_helper_write, "x", 1);
    ASSERT(tracee, ret == 1);
    int status;
    waitpid(helper_pid, &status, 0);
    ASSERT(tracee, WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
};

static bool kernel_supports_thread_self() {
  static bool supported = access("/proc/thread-self", F_OK) >= 0;
  return supported;
}

template <typename Arch>
static void child_connect_socket(AutoRemoteSyscalls& remote,
                                 AutoRestoreMem& remote_buf,
                                 remote_ptr<socketcall_args<Arch>> sc_args,
                                 remote_ptr<void> buf_end, int child_sock,
                                 const char* path) {
  TemporaryProcMounter mounter(remote.task());
  typename Arch::sockaddr_un addr;
  memset(&addr, 0, sizeof(addr)); // Make valgrind happy.
  addr.sun_family = AF_UNIX;

  char buf[80];
  Task* t = remote.task();
  // See if there's a procfs mounted that our tracee can use.
  sprintf(buf, "/proc/%d/root/proc", t->tid);
  int ret = access(buf, F_OK);
  if (ret < 0) {
    ASSERT(remote.task(), errno == ENOENT);
    mounter.mount();
  }
  // It's possible that the tracee created a non-procfs file/dir at /proc.
  // That would be pathological so we're going to ignore it.

  // Find the path for the tracee task in the procfs it can see under /proc.
  // We can't use "/proc/self" because the process main thread might have
  // exited and "/proc/self" is broken in that case.
  // "thread-self" requires Linux 3.17. Keep supporting 3.11 to some extent.
  if (kernel_supports_thread_self()) {
    sprintf(addr.sun_path, "/proc/thread-self/fd/%d", RR_RESERVED_ROOT_DIR_FD);
  } else {
    if (t->tid != t->own_namespace_tid()) {
      LOG(warn) << "Child thread in own pid namespace; assuming its /proc"
                << " is in the same namespace";
      // This will normally be true, since it's somewhat broken for a task
      // to find a procfs under /proc that's mounted for a different PID
      // namespace.
    }
    sprintf(addr.sun_path, "/proc/%d/fd/%d", t->own_namespace_tid(),
            RR_RESERVED_ROOT_DIR_FD);
  }

  if (strlen(addr.sun_path) + strlen(path) >= sizeof(addr.sun_path)) {
    FATAL() << "Paths " << addr.sun_path << " " << path
            << " too long, cannot connect child";
  }
  strcat(addr.sun_path, path);

  auto remote_addr = allocate<typename Arch::sockaddr_un>(&buf_end, remote_buf);
  remote.task()->write_mem(remote_addr, addr);
  if (sc_args.is_null()) {
    ret = remote.syscall(Arch::connect, child_sock, remote_addr, sizeof(addr));
  } else {
    write_socketcall_args<Arch>(remote.task(), sc_args, child_sock,
                                remote_addr.as_int(), sizeof(addr));
    ret = remote.syscall(Arch::socketcall, SYS_CONNECT, sc_args);
  }
  ASSERT(remote.task(), ret == 0)
      << "Failed to connect child socket " << addr.sun_path
      << " err=" << errno_name(-ret);
}

template <typename Arch>
static long child_sendmsg(AutoRemoteSyscalls& remote,
                          AutoRestoreMem& remote_buf,
                          remote_ptr<socketcall_args<Arch>> sc_args,
                          remote_ptr<void> buf_end, int child_sock, int fd) {
  char cmsgbuf[Arch::cmsg_space(sizeof(fd))];
  memset(cmsgbuf, 0, sizeof(cmsgbuf));
  // Pull the puppet strings to have the child send its fd
  // to us.  Similarly to above, we DONT_WAIT on the
  // call to finish, since it's likely not defined whether the
  // sendmsg() may block on our recvmsg()ing what the tracee
  // sent us (in which case we would deadlock with the tracee).
  // We call sendmsg on child socket, but first we have to prepare a lot of
  // data.
  auto remote_msg = allocate<typename Arch::msghdr>(&buf_end, remote_buf);
  auto remote_msgdata = allocate<typename Arch::iovec>(&buf_end, remote_buf);
  auto remote_cmsgbuf = allocate(&buf_end, remote_buf, sizeof(cmsgbuf));

  // Unfortunately we need to send at least one byte of data in our
  // message for it to work
  typename Arch::iovec msgdata;
  msgdata.iov_base = remote_msg; // doesn't matter much, we ignore the data
  msgdata.iov_len = 1;
  remote.task()->write_mem(remote_msgdata, msgdata);

  typename Arch::msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_control = remote_cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);
  msg.msg_iov = remote_msgdata;
  msg.msg_iovlen = 1;
  remote.task()->write_mem(remote_msg, msg);

  auto cmsg = reinterpret_cast<typename Arch::cmsghdr*>(cmsgbuf);
  cmsg->cmsg_len = Arch::cmsg_len(sizeof(fd));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  *static_cast<int*>(Arch::cmsg_data(cmsg)) = fd;
  remote.task()->write_bytes_helper(remote_cmsgbuf, sizeof(cmsgbuf), &cmsgbuf);

  if (sc_args.is_null()) {
    return remote.syscall(Arch::sendmsg, child_sock, remote_msg, 0);
  } else {
    write_socketcall_args<Arch>(remote.task(), sc_args, child_sock,
                                remote_msg.as_int(), 0);
    return remote.syscall(Arch::socketcall, SYS_SENDMSG, sc_args);
  }
}

static int recvmsg_socket(int sock) {
  char received_data;
  struct iovec msgdata;
  msgdata.iov_base = &received_data;
  msgdata.iov_len = 1;

  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);
  msg.msg_iov = &msgdata;
  msg.msg_iovlen = 1;

  if (0 > recvmsg(sock, &msg, 0)) {
    FATAL() << "Failed to receive fd";
  }

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  DEBUG_ASSERT(cmsg && cmsg->cmsg_level == SOL_SOCKET &&
               cmsg->cmsg_type == SCM_RIGHTS);
  int our_fd = *(int*)CMSG_DATA(cmsg);
  DEBUG_ASSERT(our_fd >= 0);
  return our_fd;
}

template <typename T> static size_t reserve() { return align_size(sizeof(T)); }

static void* do_accept(void* p) {
  int fd = intptr_t(p);
  int sock = accept(fd, nullptr, nullptr);
  return (void*)intptr_t(sock);
}

template <typename Arch> ScopedFd AutoRemoteSyscalls::retrieve_fd_arch(int fd) {
  size_t data_length = std::max(reserve<typename Arch::sockaddr_un>(),
                                reserve<typename Arch::msghdr>() +
                                    align_size(Arch::cmsg_space(sizeof(fd))) +
                                    reserve<typename Arch::iovec>());
  if (has_socketcall_syscall(Arch::arch())) {
    data_length += reserve<socketcall_args<Arch>>();
  }
  AutoRestoreMem remote_buf(*this, nullptr, data_length);

  remote_ptr<void> sc_args_end = remote_buf.get();
  remote_ptr<socketcall_args<Arch>> sc_args;
  if (has_socketcall_syscall(Arch::arch())) {
    sc_args = allocate<socketcall_args<Arch>>(&sc_args_end, remote_buf);
  }

  char path[PATH_MAX];
  snprintf(path, sizeof(path) - 1, "%s/rr-tracee-fd-transfer-%d-%ld", tmp_dir(),
           t->tid, random());
  path[sizeof(path) - 1] = 0;

  int listen_sock = create_bind_and_listen_socket(path);
  int child_sock = child_create_socket(*this, sc_args);

  // There's a tricky potential deadlock here. We need to puppet the tracee's
  // connect() syscall and at the same time accept() it from our process; the
  // tracee's connect() cannot complete until our accept() has happened.
  // We could launch the tracee connect() syscall and then do a blocking
  // accept() here before waiting for the connect() to complete, but then there
  // is a risk that a rogue signal could interrupt the tracee's connect(),
  // putting it in a ptrace-stop which we never detect because our accept()
  // never finishes.
  // A simple safe way to avoid the deadlock is to create our own temporary
  // thread to do the accept(). That lets us treat the connect() call like
  // any other blocking tracee AutoRemoteSyscall. If this were to become a
  // performance problem, the best solution would probably to be to keep a
  // dedicated accept-thread around.

  pthread_t accept_thread;
  int ret = pthread_create(&accept_thread, nullptr, do_accept,
                           (void*)intptr_t(listen_sock));
  ASSERT(t, ret >= 0) << "Cannot create helper thread";

  child_connect_socket(
      *this, remote_buf, sc_args, sc_args_end, child_sock, path);

  void* thread_ret;
  ret = pthread_join(accept_thread, &thread_ret);
  ASSERT(t, ret == 0) << "Cannot join helper thread";
  int sock = intptr_t(thread_ret);
  ASSERT(t, sock >= 0) << "Failed to create parent socket";

  // Verify that the child's PID is correct. This is a world-writeable socket
  // so anyone could connect, and this check is vital.
  struct ucred cred;
  cred.pid = -1;
  socklen_t credlen = sizeof(cred);
  if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &credlen) < 0) {
    ASSERT(t, false) << "Failed SO_PEERCRED";
  }
  ASSERT(t, credlen == sizeof(cred));
  if (cred.pid != t->real_tgid()) {
    FATAL() << "Some other process connected to our socket!!!";
  }

  // Listening socket not needed anymore
  close(listen_sock);
  unlink(path);
  long child_syscall_result =
      child_sendmsg(*this, remote_buf, sc_args, sc_args_end, child_sock, fd);
  ASSERT(t, child_syscall_result > 0) << "Failed to sendmsg() in tracee; err="
                                      << errno_name(-child_syscall_result);
  // Child may be waiting on our recvmsg().
  int our_fd = recvmsg_socket(sock);

  child_syscall_result = infallible_syscall(Arch::close, child_sock);
  ret = close(sock);
  ASSERT(t, ret == 0) << "Failed to close parent socket";

  return ScopedFd(our_fd);
}

ScopedFd AutoRemoteSyscalls::retrieve_fd(int fd) {
  RR_ARCH_FUNCTION(retrieve_fd_arch, arch(), fd);
}

remote_ptr<void> AutoRemoteSyscalls::infallible_mmap_syscall(
    remote_ptr<void> addr, size_t length, int prot, int flags, int child_fd,
    uint64_t offset_pages) {
  // The first syscall argument is called "arg 1", so
  // our syscall-arg-index template parameter starts
  // with "1".
  remote_ptr<void> ret =
      has_mmap2_syscall(arch())
          ? infallible_syscall_ptr(syscall_number_for_mmap2(arch()), addr,
                                   length, prot, flags, child_fd,
                                   (off_t)offset_pages)
          : infallible_syscall_ptr(syscall_number_for_mmap(arch()), addr,
                                   length, prot, flags, child_fd,
                                   offset_pages * page_size());
  if (flags & MAP_FIXED) {
    ASSERT(t, addr == ret) << "MAP_FIXED at " << addr << " but got " << ret;
  }
  return ret;
}

int64_t AutoRemoteSyscalls::infallible_lseek_syscall(int fd, int64_t offset,
                                                     int whence) {
  switch (arch()) {
    case x86: {
      AutoRestoreMem mem(*this, &offset, sizeof(int64_t));
      infallible_syscall(syscall_number_for__llseek(arch()), fd, offset >> 32,
                         offset, mem.get(), whence);
      return t->read_mem(mem.get().cast<int64_t>());
    }
    case x86_64:
      return infallible_syscall(syscall_number_for_lseek(arch()), fd, offset,
                                whence);
    default:
      ASSERT(t, false) << "Unknown arch";
      return -1;
  }
}

void AutoRemoteSyscalls::check_syscall_result(long ret, int syscallno) {
  if (-4096 < ret && ret < 0) {
    string extra_msg;
    if (is_open_syscall(syscallno, arch())) {
      extra_msg = " opening " + t->read_c_str(t->regs().arg1());
    } else if (is_openat_syscall(syscallno, arch())) {
      extra_msg = " opening " + t->read_c_str(t->regs().arg2());
    }
    ASSERT(t, false) << "Syscall " << syscall_name(syscallno, arch())
                     << " failed with errno " << errno_name(-ret) << extra_msg;
  }
}

} // namespace rr
