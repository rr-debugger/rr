/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "AutoRemoteSyscalls.h"

#include <limits.h>
#include <linux/net.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "rr/rr.h"

#include "ReplaySession.h"
#include "Session.h"
#include "Task.h"
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
  ASSERT(remote.task(), !remote.regs().sp().is_null())
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
  assert(saved_sp == remote.regs().sp() + len);

  remote.task()->write_bytes_helper(addr, len, data.data());

  remote.regs().set_sp(remote.regs().sp() + len);
  remote.task()->set_regs(remote.regs());
}

AutoRemoteSyscalls::AutoRemoteSyscalls(Task* t,
                                       MemParamsEnabled enable_mem_params)
    : t(t),
      initial_regs(t->regs()),
      initial_ip(t->ip()),
      initial_sp(t->regs().sp()),
      pending_syscallno(-1) {
  // We could use privilged_traced_syscall_ip() here, but we don't actually
  // need privileges because tracee seccomp filters are modified to only
  // produce PTRACE_SECCOMP_EVENTs that we ignore. And before the rr page is
  // loaded, the privileged_traced_syscall_ip is not available.
  initial_regs.set_ip(t->vm()->traced_syscall_ip());
  if (enable_mem_params == ENABLE_MEMORY_PARAMS) {
    maybe_fix_stack_pointer();
  } else {
    initial_regs.set_sp(remote_ptr<void>());
  }
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
  for (auto m : t->vm()->maps()) {
    if (is_usable_area(m.map)) {
      found_stack = m.map;
      break;
    }
  };
  ASSERT(t, !found_stack.start().is_null()) << "No stack area found";

  initial_regs.set_sp(found_stack.end());
}

AutoRemoteSyscalls::~AutoRemoteSyscalls() { restore_state_to(t); }

void AutoRemoteSyscalls::restore_state_to(Task* t) {
  if (!replaced_bytes.empty()) {
    t->write_mem(remote_ptr<uint8_t>(
                     t->vm()->traced_syscall_ip().to_data_ptr<uint8_t>()),
                 replaced_bytes.data(), replaced_bytes.size());
  }
  initial_regs.set_ip(initial_ip);
  initial_regs.set_sp(initial_sp);
  // Restore stomped registers.
  t->set_regs(initial_regs);
}

void AutoRemoteSyscalls::syscall_helper(SyscallWaiting wait, int syscallno,
                                        Registers& callregs) {
  callregs.set_syscallno(syscallno);
  t->set_regs(callregs);

  t->advance_syscall();

  ASSERT(t, t->regs().ip() - callregs.ip() ==
                syscall_instruction_length(t->arch()))
      << "Should have advanced ip by one syscall_insn";

  ASSERT(t, t->regs().original_syscallno() == syscallno)
      << "Should be entering " << t->syscall_name(syscallno)
      << ", but instead at " << t->syscall_name(t->regs().original_syscallno());

  // Start running the syscall.
  pending_syscallno = syscallno;
  t->resume_execution(RESUME_SYSCALL, RESUME_NONBLOCKING, RESUME_NO_TICKS);
  if (WAIT == wait) {
    wait_syscall(syscallno);
  }
}

void AutoRemoteSyscalls::wait_syscall(int syscallno) {
  ASSERT(t, pending_syscallno == syscallno || syscallno < 0);

  // Wait for syscall-exit trap (or PTRACE_EVENT_* trap).
  t->wait();
  pending_syscallno = -1;

  ASSERT(t, t->regs().original_syscallno() == syscallno || syscallno < 0)
      << "Should be entering " << t->syscall_name(syscallno)
      << ", but instead at " << t->syscall_name(t->regs().original_syscallno());
}

SupportedArch AutoRemoteSyscalls::arch() const { return t->arch(); }

template <typename Arch>
static void write_socketcall_args(Task* t, remote_ptr<void> remote_mem,
                                  typename Arch::signed_long arg1,
                                  typename Arch::signed_long arg2,
                                  typename Arch::signed_long arg3) {
  socketcall_args<Arch> sc_args = { { arg1, arg2, arg3 } };
  t->write_mem(remote_mem.cast<socketcall_args<Arch> >(), sc_args);
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
  assert(size_t(*buf_end - remote_buf.get()) <= remote_buf.size());
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
                               remote_ptr<socketcall_args<Arch> > sc_args) {
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

template <typename Arch>
static void child_connect_socket(AutoRemoteSyscalls& remote,
                                 AutoRestoreMem& remote_buf,
                                 remote_ptr<socketcall_args<Arch> > sc_args,
                                 remote_ptr<void> buf_end, int child_sock,
                                 const char* path, int* cwd_fd) {
  typename Arch::sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  assert(strlen(path) < sizeof(addr.sun_path));
  // Skip leading '/' since we're going to access this relative to the root
  assert(path[0] == '/');
  strcpy(addr.sun_path, path + 1);

  auto tmp_buf_end = buf_end;
  auto remote_dot = allocate(&tmp_buf_end, remote_buf, 2);
  remote.task()->write_mem(remote_dot.cast<char>(), ".", 2);
  // This may fail because the tracee has done a setuid and is no longer
  // able to access its own CWD. There doesn't seem to be a way to save
  // and restore the CWD in this situation --- and connectat() doesn't exist yet
  // so we have no way to avoid having to set the CWD if we're in a chrooted
  // environment. We'll hack around such a failure later by putting the child
  // into a new directory that it can't access.
  *cwd_fd = remote.syscall(syscall_number_for_open(Arch::arch()), remote_dot,
                           O_PATH | O_DIRECTORY);
  ASSERT(remote.task(), *cwd_fd >= 0 || *cwd_fd == -EACCES);
  remote.infallible_syscall(Arch::fchdir, RR_RESERVED_ROOT_DIR_FD);

  auto remote_addr = allocate<typename Arch::sockaddr_un>(&buf_end, remote_buf);
  remote.task()->write_mem(remote_addr, addr);
  Registers callregs = remote.regs();
  int remote_syscall;
  if (sc_args.is_null()) {
    callregs.set_arg1(child_sock);
    callregs.set_arg2(remote_addr);
    callregs.set_arg3(sizeof(addr));
    remote_syscall = Arch::connect;
  } else {
    write_socketcall_args<Arch>(remote.task(), sc_args, child_sock,
                                remote_addr.as_int(), sizeof(addr));
    callregs.set_arg1(SYS_CONNECT);
    callregs.set_arg2(sc_args);
    remote_syscall = Arch::socketcall;
  }
  remote.syscall_helper(AutoRemoteSyscalls::DONT_WAIT, remote_syscall,
                        callregs);
}

template <typename Arch>
static void restore_cwd(AutoRemoteSyscalls& remote, int cwd_fd) {
  if (cwd_fd >= 0) {
    remote.infallible_syscall(Arch::fchdir, cwd_fd);
    remote.infallible_syscall(Arch::close, cwd_fd);
  } else {
    // We can't get back to the original directory. (Note that we may not
    // be able to access it ourselves from outside the tracee, if it's in a
    // mount namespace created by the tracee.)
    // Fake it by making a world-accessible directory, chdir the tracee into it,
    // then make it inaccessible.
    char path[PATH_MAX];
    sprintf(path, "/tmp/rr-tracee-fd-inaccessible-dir-%d-%ld",
            remote.task()->tid, random());
    int ret = mkdir(path, 0777);
    ASSERT(remote.task(), ret >= 0);
    AutoRestoreMem mem(remote, path);
    remote.infallible_syscall(Arch::chdir, mem.get());
    ret = chmod(path, 0000);
    ASSERT(remote.task(), ret >= 0);
    ret = rmdir(path);
    ASSERT(remote.task(), ret >= 0);
  }
}

template <typename Arch>
static void child_sendmsg(AutoRemoteSyscalls& remote,
                          AutoRestoreMem& remote_buf,
                          remote_ptr<socketcall_args<Arch> > sc_args,
                          remote_ptr<void> buf_end, int child_sock, int fd) {
  char cmsgbuf[Arch::cmsg_space(sizeof(fd))];
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

  Registers callregs = remote.regs();
  int remote_syscall;
  if (sc_args.is_null()) {
    callregs.set_arg1(child_sock);
    callregs.set_arg2(remote_msg);
    callregs.set_arg3(0);
    remote_syscall = Arch::sendmsg;
  } else {
    write_socketcall_args<Arch>(remote.task(), sc_args, child_sock,
                                remote_msg.as_int(), 0);
    callregs.set_arg1(SYS_SENDMSG);
    callregs.set_arg2(sc_args);
    remote_syscall = Arch::socketcall;
  }
  remote.syscall_helper(AutoRemoteSyscalls::DONT_WAIT, remote_syscall,
                        callregs);
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
  assert(cmsg && cmsg->cmsg_level == SOL_SOCKET &&
         cmsg->cmsg_type == SCM_RIGHTS);
  int our_fd = *(int*)CMSG_DATA(cmsg);
  assert(our_fd >= 0);
  return our_fd;
}

template <typename T> static size_t reserve() { return align_size(sizeof(T)); }

template <typename Arch> ScopedFd AutoRemoteSyscalls::retrieve_fd_arch(int fd) {
  size_t data_length = std::max(reserve<typename Arch::sockaddr_un>(),
                                reserve<typename Arch::msghdr>() +
                                    align_size(Arch::cmsg_space(sizeof(fd))) +
                                    reserve<typename Arch::iovec>());
  if (has_socketcall_syscall(Arch::arch())) {
    data_length += reserve<socketcall_args<Arch> >();
  }
  AutoRestoreMem remote_buf(*this, nullptr, data_length);

  remote_ptr<void> sc_args_end = remote_buf.get();
  remote_ptr<socketcall_args<Arch> > sc_args;
  if (has_socketcall_syscall(Arch::arch())) {
    sc_args = allocate<socketcall_args<Arch> >(&sc_args_end, remote_buf);
  }

  char path[PATH_MAX];
  sprintf(path, "/tmp/rr-tracee-fd-transfer-%d-%ld", t->tid, random());

  int listen_sock = create_bind_and_listen_socket(path);
  int child_sock = child_create_socket(*this, sc_args);
  int cwd_fd;
  child_connect_socket(*this, remote_buf, sc_args, sc_args_end, child_sock,
                       path, &cwd_fd);
  // Now the child is waiting for us to accept it.
  int sock = accept(listen_sock, nullptr, nullptr);
  if (sock < 0) {
    FATAL() << "Failed to create parent socket";
  }

  // Verify that the child's PID is correct. This is a world-writeable socket
  // so anyone could connect, and this check is vital.
  struct ucred cred;
  cred.pid = -1;
  socklen_t credlen = sizeof(cred);
  if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &credlen) < 0) {
    FATAL() << "Failed SO_PEERCRED";
  }
  ASSERT(t, credlen == sizeof(cred));
  if (cred.pid != task()->real_tgid()) {
    FATAL() << "Some other process connected to our socket!!!";
  }

  // Complete child's connect() syscall
  wait_syscall();
  int child_syscall_result = t->regs().syscall_result_signed();
  if (child_syscall_result) {
    FATAL() << "Failed to connect() in tracee; err="
            << errno_name(-child_syscall_result);
  }
  restore_cwd<Arch>(*this, cwd_fd);

  // Listening socket not needed anymore
  close(listen_sock);
  unlink(path);
  child_sendmsg(*this, remote_buf, sc_args, sc_args_end, child_sock, fd);
  wait_syscall();
  child_syscall_result = t->regs().syscall_result_signed();
  if (0 >= child_syscall_result) {
    FATAL() << "Failed to sendmsg() in tracee; err="
            << errno_name(-child_syscall_result);
  }
  // Child may be waiting on our recvmsg().
  int our_fd = recvmsg_socket(sock);

  child_syscall_result = infallible_syscall(Arch::close, child_sock);
  if (0 > close(sock)) {
    FATAL() << "Failed to close parent socket";
  }

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
      ASSERT(task(), false) << "Unknown arch";
      return -1;
  }
}

void AutoRemoteSyscalls::check_syscall_result(int syscallno) {
  long ret = t->regs().syscall_result_signed();
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
