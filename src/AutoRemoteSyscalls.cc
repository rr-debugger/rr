/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "RemoteSyscalls"

#include "AutoRemoteSyscalls.h"

#include "log.h"
#include "task.h"
#include "util.h"

using namespace rr;

void AutoRestoreMem::init(const uint8_t* mem, ssize_t num_bytes) {
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
  assert(saved_sp.as_int() == remote.regs().sp() + len);

  remote.task()->write_bytes_helper(addr, len, data.data());

  remote.regs().set_sp(remote.regs().sp() + len);
  remote.task()->set_regs(remote.regs());
}

AutoRemoteSyscalls::AutoRemoteSyscalls(Task* t)
    : t(t),
      initial_regs(t->regs()),
      initial_ip(t->ip()),
      pending_syscallno(-1) {
  static_assert(sizeof(code_buffer) >= sizeof(X86Arch::syscall_insn),
                "syscall_insn is too large for buffer");
  static_assert(sizeof(code_buffer) >= sizeof(X64Arch::syscall_insn),
                "syscall_insn is too large for buffer");

  // Inject syscall instruction, saving previous insn (fragment)
  // at $ip.
  t->read_bytes(initial_ip, code_buffer);
  if (t->arch() == x86) {
    t->write_bytes(initial_ip, X86Arch::syscall_insn);
  } else {
    assert(t->arch() == x86_64);
    t->write_bytes(initial_ip, X64Arch::syscall_insn);
  }
}

AutoRemoteSyscalls::~AutoRemoteSyscalls() { restore_state_to(t); }

void AutoRemoteSyscalls::restore_state_to(Task* t) {
  // Restore stomped insn (fragment).
  t->write_bytes(initial_ip, code_buffer);
  // Restore stomped registers.
  t->set_regs(initial_regs);
}

// TODO de-dup
static void advance_syscall(Task* t) {
  do {
    t->cont_syscall();
  } while (t->is_ptrace_seccomp_event() || SIGCHLD == t->pending_sig());
  assert(t->ptrace_event() == 0);
}

long AutoRemoteSyscalls::syscall_helper(SyscallWaiting wait, int syscallno,
                                        Registers& callregs) {
  callregs.set_syscallno(syscallno);
  t->set_regs(callregs);

  advance_syscall(t);

  ASSERT(t, t->regs().ip() - callregs.ip() == sizeof(X86Arch::syscall_insn))
      << "Should have advanced ip by one syscall_insn";

  ASSERT(t, t->regs().original_syscallno() == syscallno)
      << "Should be entering " << t->syscallname(syscallno)
      << ", but instead at " << t->syscallname(t->regs().original_syscallno());

  // Start running the syscall.
  pending_syscallno = syscallno;
  t->cont_syscall_nonblocking();
  if (WAIT == wait) {
    return wait_syscall(syscallno);
  }
  return 0;
}

long AutoRemoteSyscalls::wait_syscall(int syscallno) {
  ASSERT(t, pending_syscallno == syscallno);

  // Wait for syscall-exit trap.
  t->wait();
  pending_syscallno = -1;

  ASSERT(t, t->regs().original_syscallno() == syscallno)
      << "Should be entering " << t->syscallname(syscallno)
      << ", but instead at " << t->syscallname(t->regs().original_syscallno());

  return t->regs().syscall_result_signed();
}

SupportedArch AutoRemoteSyscalls::arch() const { return t->arch(); }

static void write_socketcall_args(Task* t,
                                  remote_ptr<struct socketcall_args> remote_mem,
                                  long arg1, long arg2, long arg3) {
  struct socketcall_args sc_args = { { arg1, arg2, arg3 } };
  t->write_mem(remote_mem, sc_args);
}

static size_t align_size(size_t size) {
  static int align_amount = 8;
  return (size + align_amount) & ~(align_amount - 1);
}

ScopedFd AutoRemoteSyscalls::retrieve_fd(int fd) {
  struct sockaddr_un socket_addr;
  struct msghdr msg;
  // Unfortunately we need to send at least one byte of data in our
  // message for it to work
  struct iovec msgdata;
  char received_data;
  char cmsgbuf[CMSG_SPACE(sizeof(fd))];
  int data_length =
      align_size(sizeof(struct socketcall_args)) +
      std::max(align_size(sizeof(socket_addr)),
               align_size(sizeof(msg)) + align_size(sizeof(cmsgbuf)) +
                   align_size(sizeof(msgdata)));
  AutoRestoreMem remote_socketcall_args_holder(*this, nullptr, data_length);
  auto remote_socketcall_args = remote_socketcall_args_holder.get();
  bool using_socketcall = has_socketcall_syscall(arch());

  memset(&socket_addr, 0, sizeof(socket_addr));
  socket_addr.sun_family = AF_UNIX;
  snprintf(socket_addr.sun_path, sizeof(socket_addr.sun_path) - 1,
           "/tmp/rr-tracee-fd-transfer-%d", t->tid);

  int listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (listen_sock < 0) {
    FATAL() << "Failed to create listen socket";
  }
  if (::bind(listen_sock, (struct sockaddr*)&socket_addr,
             sizeof(socket_addr))) {
    FATAL() << "Failed to bind listen socket";
  }
  if (listen(listen_sock, 1)) {
    FATAL() << "Failed to mark listening for listen socket";
  }

  int child_sock;
  if (using_socketcall) {
    write_socketcall_args(t,
                          remote_socketcall_args.cast<struct socketcall_args>(),
                          AF_UNIX, SOCK_STREAM, 0);
    child_sock = syscall(syscall_number_for_socketcall(arch()), SYS_SOCKET,
                         remote_socketcall_args);
  } else {
    child_sock =
        syscall(syscall_number_for_socket(arch()), AF_UNIX, SOCK_STREAM, 0);
  }
  if (child_sock < 0) {
    FATAL() << "Failed to create child socket";
  }

  auto remote_sockaddr =
      (remote_socketcall_args + align_size(sizeof(struct socketcall_args)))
          .cast<struct sockaddr_un>();
  t->write_mem(remote_sockaddr, socket_addr);
  Registers callregs = initial_regs;
  int remote_syscall;
  if (using_socketcall) {
    write_socketcall_args(
        t, remote_socketcall_args.cast<struct socketcall_args>(), child_sock,
        remote_sockaddr.as_int(), sizeof(socket_addr));
    callregs.set_arg1(SYS_CONNECT);
    callregs.set_arg2(remote_socketcall_args);
    remote_syscall = syscall_number_for_socketcall(arch());
  } else {
    callregs.set_arg1(child_sock);
    callregs.set_arg2(remote_sockaddr);
    callregs.set_arg3(sizeof(socket_addr));
    remote_syscall = syscall_number_for_connect(arch());
  }
  syscall_helper(DONT_WAIT, remote_syscall, callregs);
  // Now the child is waiting for us to accept it.

  int sock = accept(listen_sock, nullptr, nullptr);
  if (sock < 0) {
    FATAL() << "Failed to create parent socket";
  }
  int child_ret = wait_syscall(remote_syscall);
  if (child_ret) {
    FATAL() << "Failed to connect() in tracee";
  }
  // Listening socket not needed anymore
  close(listen_sock);
  unlink(socket_addr.sun_path);

  // Pull the puppet strings to have the child send its fd
  // to us.  Similarly to above, we DONT_WAIT on the
  // call to finish, since it's likely not defined whether the
  // sendmsg() may block on our recvmsg()ing what the tracee
  // sent us (in which case we would deadlock with the tracee).
  auto remote_msg =
      remote_socketcall_args + align_size(sizeof(struct socketcall_args));
  auto remote_msgdata = remote_msg + align_size(sizeof(msg));
  auto remote_cmsgbuf = remote_msgdata + align_size(sizeof(msgdata));
  // XXX should be using Arch::iovec
  msgdata.iov_base =
      (void*)remote_msg.as_int(); // doesn't matter much, we ignore the data
  msgdata.iov_len = 1;
  t->write_mem(remote_msgdata.cast<struct iovec>(), msgdata);
  memset(&msg, 0, sizeof(msg));
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);
  msg.msg_iov = reinterpret_cast<struct iovec*>(remote_msgdata.as_int());
  msg.msg_iovlen = 1;
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  *(int*)CMSG_DATA(cmsg) = fd;
  t->write_bytes_helper(remote_cmsgbuf, sizeof(cmsgbuf), &cmsgbuf);
  msg.msg_control = (void*)remote_cmsgbuf.as_int();
  t->write_mem(remote_msg.cast<struct msghdr>(), msg);
  callregs = initial_regs;
  if (using_socketcall) {
    write_socketcall_args(t,
                          remote_socketcall_args.cast<struct socketcall_args>(),
                          child_sock, remote_msg.as_int(), 0);
    callregs.set_arg1(SYS_SENDMSG);
    callregs.set_arg2(remote_socketcall_args);
    remote_syscall = syscall_number_for_socketcall(arch());
  } else {
    callregs.set_arg1(child_sock);
    callregs.set_arg2(remote_msg);
    callregs.set_arg3(0);
    remote_syscall = syscall_number_for_sendmsg(arch());
  }
  syscall_helper(DONT_WAIT, remote_syscall, callregs);
  // Child may be waiting on our recvmsg().

  // Our 'msg' struct is mostly already OK.
  msg.msg_control = cmsgbuf;
  msgdata.iov_base = &received_data;
  msg.msg_iov = &msgdata;
  if (0 > recvmsg(sock, &msg, 0)) {
    FATAL() << "Failed to receive fd";
  }
  cmsg = CMSG_FIRSTHDR(&msg);
  assert(cmsg && cmsg->cmsg_level == SOL_SOCKET &&
         cmsg->cmsg_type == SCM_RIGHTS);
  int our_fd = *(int*)CMSG_DATA(cmsg);
  assert(our_fd >= 0);

  if (0 >= wait_syscall(remote_syscall)) {
    FATAL() << "Failed to sendmsg() in tracee";
  }

  syscall(syscall_number_for_close(arch()), child_sock);
  close(sock);

  return ScopedFd(our_fd);
}
