/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "RemoteSyscalls"

#include "AutoRemoteSyscalls.h"

#include "log.h"
#include "task.h"
#include "util.h"

using namespace rr;
using namespace std;

/**
 * The ABI of the socketcall syscall is a nightmare; the first arg to
 * the kernel is the sub-operation, and the second argument is a
 * pointer to the args.  The args depend on the sub-op.
 */
template <typename Arch> struct socketcall_args {
  typename Arch::signed_long args[3];
} __attribute__((packed));

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
  // Inject syscall instruction, saving previous insn (fragment)
  // at $ip.
  vector<uint8_t> syscall_insn = syscall_instruction(t->arch());
  code_buffer = t->read_mem(initial_ip, syscall_insn.size());
  t->write_mem(initial_ip, syscall_insn.data(), syscall_insn.size());
}

AutoRemoteSyscalls::~AutoRemoteSyscalls() { restore_state_to(t); }

void AutoRemoteSyscalls::restore_state_to(Task* t) {
  // Restore stomped insn (fragment).
  t->write_mem(initial_ip, code_buffer.data(), code_buffer.size());
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

  ASSERT(t, t->regs().ip() - callregs.ip() ==
                syscall_instruction_length(t->arch()))
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
  ASSERT(t, pending_syscallno == syscallno || syscallno < 0);

  // Wait for syscall-exit trap.
  t->wait();
  pending_syscallno = -1;

  ASSERT(t, t->regs().original_syscallno() == syscallno || syscallno < 0)
      << "Should be entering " << t->syscallname(syscallno)
      << ", but instead at " << t->syscallname(t->regs().original_syscallno());

  return t->regs().syscall_result_signed();
}

SupportedArch AutoRemoteSyscalls::arch() const { return t->arch(); }

template <typename Arch>
static void write_socketcall_args(Task* t, remote_ptr<void> remote_mem,
                                  long arg1, long arg2, long arg3) {
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
  int listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (listen_sock < 0) {
    FATAL() << "Failed to create listen socket";
  }

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
  addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
  if (::bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr))) {
    FATAL() << "Failed to bind listen socket";
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
    child_sock = remote.syscall(syscall_number_for_socket(Arch::arch()),
                                AF_UNIX, SOCK_STREAM, 0);
  } else {
    write_socketcall_args<Arch>(remote.task(), sc_args, AF_UNIX, SOCK_STREAM,
                                0);
    child_sock = remote.syscall(syscall_number_for_socketcall(Arch::arch()),
                                SYS_SOCKET, sc_args);
  }
  if (child_sock < 0) {
    FATAL() << "Failed to create child socket";
  }
  return child_sock;
}

template <typename Arch>
static void child_connect_socket(AutoRemoteSyscalls& remote,
                                 AutoRestoreMem& remote_buf,
                                 remote_ptr<socketcall_args<Arch> > sc_args,
                                 remote_ptr<void> buf_end, int child_sock,
                                 const char* path) {
  typename Arch::sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  assert(strlen(path) < sizeof(addr.sun_path));
  strcpy(addr.sun_path, path);

  auto remote_addr = allocate<typename Arch::sockaddr_un>(&buf_end, remote_buf);
  remote.task()->write_mem(remote_addr, addr);
  Registers callregs = remote.regs();
  int remote_syscall;
  if (sc_args.is_null()) {
    callregs.set_arg1(child_sock);
    callregs.set_arg2(remote_addr);
    callregs.set_arg3(sizeof(addr));
    remote_syscall = syscall_number_for_connect(Arch::arch());
  } else {
    write_socketcall_args<Arch>(remote.task(), sc_args, child_sock,
                                remote_addr.as_int(), sizeof(addr));
    callregs.set_arg1(SYS_CONNECT);
    callregs.set_arg2(sc_args);
    remote_syscall = syscall_number_for_socketcall(Arch::arch());
  }
  remote.syscall_helper(AutoRemoteSyscalls::DONT_WAIT, remote_syscall,
                        callregs);
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
    remote_syscall = syscall_number_for_sendmsg(Arch::arch());
  } else {
    write_socketcall_args<Arch>(remote.task(), sc_args, child_sock,
                                remote_msg.as_int(), 0);
    callregs.set_arg1(SYS_SENDMSG);
    callregs.set_arg2(sc_args);
    remote_syscall = syscall_number_for_socketcall(Arch::arch());
  }
  remote.syscall_helper(AutoRemoteSyscalls::DONT_WAIT, remote_syscall,
                        callregs);
}

static int recvmsg_socket(int sock) {
  char cmsgbuf[CMSG_SPACE(sizeof(int))];

  char received_data;
  struct iovec msgdata;
  msgdata.iov_base = &received_data;
  msgdata.iov_len = 1;

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

  char path[] = "/tmp/rr-tracee-fd-transfer-XXXXXXXXXX";
  sprintf(path, "/tmp/rr-tracee-fd-transfer-%d", t->tid);

  int listen_sock = create_bind_and_listen_socket(path);
  int child_sock = child_create_socket(*this, sc_args);
  child_connect_socket(*this, remote_buf, sc_args, sc_args_end, child_sock,
                       path);
  // Now the child is waiting for us to accept it.
  int sock = accept(listen_sock, nullptr, nullptr);
  if (sock < 0) {
    FATAL() << "Failed to create parent socket";
  }
  // Complete child's connect() syscall
  if (wait_syscall()) {
    FATAL() << "Failed to connect() in tracee";
  }
  // Listening socket not needed anymore
  close(listen_sock);
  unlink(path);
  child_sendmsg(*this, remote_buf, sc_args, sc_args_end, child_sock, fd);
  // Child may be waiting on our recvmsg().
  int our_fd = recvmsg_socket(sock);
  if (0 >= wait_syscall()) {
    FATAL() << "Failed to sendmsg() in tracee";
  }

  syscall(syscall_number_for_close(Arch::arch()), child_sock);
  close(sock);

  return ScopedFd(our_fd);
}

ScopedFd AutoRemoteSyscalls::retrieve_fd(int fd) {
  RR_ARCH_FUNCTION(retrieve_fd_arch, arch(), fd);
}
