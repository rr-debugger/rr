/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "ProcessSyscallRec"

#include "record_syscall.h"

#include <arpa/inet.h>
#include <asm/ldt.h>
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ethtool.h>
#include <linux/futex.h>
#include <linux/if.h>
#include <linux/ipc.h>
#include <linux/msg.h>
#include <linux/net.h>
#include <linux/prctl.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/sockios.h>
#include <linux/wireless.h>
#include <poll.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/quota.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <termios.h>

#include <limits>
#include <utility>

#include <rr/rr.h>

#include "preload/syscall_buffer.h"

#include "AutoRemoteSyscalls.h"
#include "drm.h"
#include "Flags.h"
#include "kernel_abi.h"
#include "log.h"
#include "recorder.h" // for terminate_recording()
#include "recorder_sched.h"
#include "RecordSession.h"
#include "syscalls.h"
#include "task.h"
#include "TraceStream.h"
#include "util.h"

using namespace std;
using namespace rr;

template <typename Arch>
static void rec_before_record_syscall_entry_arch(Task* t, int syscallno) {
  if (Arch::write != syscallno) {
    return;
  }
  int fd = t->regs().arg1_signed();
  if (RR_MAGIC_SAVE_DATA_FD != fd) {
    return;
  }
  remote_ptr<void> buf = t->regs().arg2();
  size_t len = t->regs().arg3();

  ASSERT(t, buf) << "Can't save a null buffer";

  t->record_remote(buf, len);
}

void rec_before_record_syscall_entry(Task* t, int syscallno) {
  RR_ARCH_FUNCTION(rec_before_record_syscall_entry_arch, t->arch(), t,
                   syscallno)
}

/**
 * Read the socketcall args pushed by |t| as part of the syscall in
 * |regs| into the |args| outparam.  Also store the address of the
 * socketcall args into |*argsp|.
 */
template <typename T>
static T read_socketcall_args(Task* t, remote_ptr<void>* argsp) {
  remote_ptr<T> p = t->regs().arg2();
  T args = t->read_mem(p);
  *argsp = p;
  return args;
}

/**
 * Erase any scratch pointer initialization done for |t| and leave
 * the state bits ready to be initialized again.
 */
static void reset_scratch_pointers(Task* t) {
  assert(t->ev().type() == EV_SYSCALL);

  while (!t->ev().Syscall().saved_args.empty()) {
    t->ev().Syscall().saved_args.pop();
  }
  t->ev().Syscall().tmp_data_ptr = t->scratch_ptr;
  t->ev().Syscall().tmp_data_num_bytes = -1;
}

/**
 * Record a tracee argument pointer that (most likely) was replaced by
 * a pointer into scratch memory.  |argp| can have any value,
 * including NULL.  It must be fetched by calling |pop_arg_ptr()|
 * during processing syscall results, and in reverse order of calls to
 * |push*()|.
 */
static void push_arg_ptr(Task* t, remote_ptr<void> argp) {
  t->ev().Syscall().saved_args.push(argp);
}

/**
 * Reset scratch state for |t|, because scratch can't be used for
 * |event|.  Log a warning as well.
 */
static Switchable abort_scratch(Task* t, const char* event) {
  int num_bytes = t->ev().Syscall().tmp_data_num_bytes;

  assert(t->ev().Syscall().tmp_data_ptr == t->scratch_ptr);

  if (0 > num_bytes) {
    LOG(warn) << "`" << event << "' requires scratch buffers, but that's not "
                                 "implemented.  Disabling context switching: "
                                 "deadlock may follow.";
  } else {
    LOG(warn)
        << "`" << event << "' needed a scratch buffer of size " << num_bytes
        << ", but only " << t->scratch_size
        << " was available.  Disabling context switching: deadlock may follow.";
  }
  reset_scratch_pointers(t);
  return PREVENT_SWITCH; /* don't allow context-switching */
}

/**
 * Return nonzero if the scratch state initialized for |t| fits
 * within the allocated region (and didn't overflow), zero otherwise.
 */
static int can_use_scratch(Task* t, remote_ptr<void> scratch_end) {
  remote_ptr<void> scratch_start = t->scratch_ptr;

  assert(t->ev().Syscall().tmp_data_ptr == t->scratch_ptr);

  t->ev().Syscall().tmp_data_num_bytes = scratch_end - scratch_start;
  return 0 <= t->ev().Syscall().tmp_data_num_bytes &&
         t->ev().Syscall().tmp_data_num_bytes <= t->scratch_size;
}

template <typename T>
static remote_ptr<T> allocate_scratch(remote_ptr<void>* scratch) {
  remote_ptr<T> p = scratch->cast<T>();
  *scratch = p + 1;
  return p;
}

/**
 * Return ALLOW_SWITCH if it's OK to context-switch away from |t| for its
 * ipc call.  If so, prepare any required scratch buffers for |t|.
 */
template <typename Arch>
static Switchable prepare_ipc(Task* t, bool need_scratch_setup) {
  int call = t->regs().arg1_signed();
  remote_ptr<void> scratch =
      need_scratch_setup ? t->ev().Syscall().tmp_data_ptr : remote_ptr<void>();

  assert(!t->desched_rec());

  switch (call) {
    case MSGRCV: {
      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }
      size_t msgsize = t->regs().arg3();
      remote_ptr<typename Arch::ipc_kludge_args> child_kludge =
          t->regs().arg5();
      auto kludge = t->read_mem(child_kludge);

      push_arg_ptr(t, kludge.msgbuf);
      kludge.msgbuf = scratch;
      scratch += msgsize;
      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, "msgrcv");
      }
      t->write_mem(child_kludge, kludge);
      return ALLOW_SWITCH;
    }
    case MSGSND:
      return ALLOW_SWITCH;
    default:
      return PREVENT_SWITCH;
  }
}

/**
 * Read the msg_iov array from |msg| into |iovs|, which must be sized
 * appropriately.  Return the total number of bytes comprising |iovs|.
 */
template <typename Arch>
static ssize_t read_iovs(Task* t, const typename Arch::msghdr& msg,
                         typename Arch::iovec* iovs) {
  size_t num_iov_bytes = msg.msg_iovlen * sizeof(*iovs);
  t->read_bytes_helper(msg.msg_iov, num_iov_bytes, (uint8_t*)iovs);
  return num_iov_bytes;
}

/**
 * Reserve scratch on T for all pointer members of msghdr and update the scratch
 * pointer passed in. Return TRUE if there's no scratch overflow.
 */
template <typename Arch>
static bool reserve_scratch_for_msghdr(Task* t, typename Arch::msghdr* msg,
                                       remote_ptr<void>* scratch) {
  auto tmpmsg = *msg;
  // reserve space
  remote_ptr<void> scratch_tmp = *scratch;
  if (msg->msg_name) {
    tmpmsg.msg_name = scratch_tmp;
    scratch_tmp += msg->msg_namelen;
  }

  typename Arch::iovec iovs[msg->msg_iovlen];
  ssize_t num_iov_bytes = read_iovs<Arch>(t, *msg, iovs);
  tmpmsg.msg_iov = scratch_tmp.cast<typename Arch::iovec>();
  scratch_tmp += num_iov_bytes;

  typename Arch::iovec tmpiovs[msg->msg_iovlen];
  memcpy(tmpiovs, iovs, num_iov_bytes);
  for (size_t i = 0; i < msg->msg_iovlen; ++i) {
    auto& tmpiov = tmpiovs[i];
    tmpiov.iov_base = scratch_tmp;
    scratch_tmp += tmpiov.iov_len;
  }

  if (msg->msg_control) {
    tmpmsg.msg_control = scratch_tmp;
    scratch_tmp += msg->msg_controllen;
  }

  // check scratch
  *scratch = scratch_tmp;
  if (!can_use_scratch(t, *scratch)) {
    abort_scratch(t, "recvfrom");
    return false;
  }

  // update child mem
  if (msg->msg_control) {
    t->remote_memcpy(tmpmsg.msg_control, msg->msg_control,
                     tmpmsg.msg_controllen);
  }
  *msg = tmpmsg; // update original msghdr
  t->write_bytes_helper(msg->msg_iov, num_iov_bytes, (const uint8_t*)tmpiovs);
  for (size_t i = 0; i < msg->msg_iovlen; ++i) {
    auto& iov = iovs[i];
    auto& tmpiov = tmpiovs[i];
    t->remote_memcpy(tmpiov.iov_base, iov.iov_base, tmpiov.iov_len);
  }
  return true;
}

/**
 * Reserve scratch on T for struct mmsghdr *msgvec.
 * Return TRUE if there's no scratch overflow.
 */
template <typename Arch>
static bool reserve_scratch_for_msgvec(
    Task* t, unsigned int vlen, remote_ptr<typename Arch::mmsghdr> pmsgvec,
    remote_ptr<void>* scratch) {
  typename Arch::mmsghdr msgvec[vlen];
  t->read_bytes_helper(pmsgvec, sizeof(msgvec), msgvec);

  // Reserve scratch for struct mmsghdr *msgvec
  auto tmpmsgvec = scratch->cast<typename Arch::mmsghdr>();
  *scratch += sizeof(msgvec);

  // Reserve scratch for child pointers of struct msghdr
  for (unsigned int i = 0; i < vlen; ++i) {
    if (!reserve_scratch_for_msghdr<Arch>(t, &(msgvec[i].msg_hdr), scratch)) {
      return false;
    }
  }

  // Write back the modified msgvec
  t->write_bytes_helper(tmpmsgvec, sizeof(msgvec), msgvec);
  return true;
}

/**
 * Initialize any necessary state to execute the socketcall that |t|
 * is stopped at, for example replacing tracee args with pointers into
 * scratch memory if necessary.
 */
template <typename Arch>
static Switchable prepare_socketcall(Task* t, bool need_scratch_setup) {
  remote_ptr<void> scratch =
      need_scratch_setup ? t->ev().Syscall().tmp_data_ptr : remote_ptr<void>();
  Registers r = t->regs();

  assert(!t->desched_rec());

  /* int socketcall(int call, unsigned long *args) {
   *   long a[6];
   *   copy_from_user(a,args);
   *   sys_recv(a0, (void __user *)a1, a[2], a[3]);
   * }
   *
   *  (from http://lxr.linux.no/#linux+v3.6.3/net/socket.c#L2354)
   */
  switch (r.arg1_signed()) {
    /* ssize_t recv([int sockfd, void *buf, size_t len, int flags]) */
    case SYS_RECV: {
      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }
      remote_ptr<void> argsp;
      auto args = read_socketcall_args<typename Arch::recv_args>(t, &argsp);
      /* The socketcall args are passed on the stack and
       * pointed at by arg2.  We need to set up scratch
       * buffer space for |buf|, but we also have to
       * overwrite that pointer in the socketcall args on
       * the stack.  So what we do is copy the socketcall
       * args to our scratch space, replace the |buf| arg
       * there with a pointer to the scratch region just
       * /after/ the socketcall args, and then hand the
       * scratch pointer to the kernel. */
      /* The socketcall arg pointer. */
      push_arg_ptr(t, argsp);
      auto tmpargsp = allocate_scratch<typename Arch::recv_args>(&scratch);
      r.set_arg2(tmpargsp);
      /* The |buf| pointer. */
      push_arg_ptr(t, args.buf);
      args.buf = scratch;
      scratch += args.len;
      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, "recv");
      }

      t->write_mem(tmpargsp, args);
      t->set_regs(r);
      return ALLOW_SWITCH;
    }

    /* int accept([int sockfd, struct sockaddr *addr, socklen_t *addrlen]) */
    case SYS_ACCEPT: {
      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }
      remote_ptr<typename Arch::accept_args> argsp = r.arg2();
      auto args = t->read_mem(argsp);
      auto addrlen = t->read_mem(args.addrlen.rptr());

      // We use the same basic scheme here as for RECV
      // above.  For accept() though, there are two
      // (in)outparams: |addr| and |addrlen|.  |*addrlen| is
      // the total size of |addr|, so we reserve that much
      // space for it.  |*addrlen| is set to the size of the
      // returned sockaddr, so we reserve space for
      // |addrlen| too.

      // Reserve space for scratch socketcall args.
      push_arg_ptr(t, argsp);
      auto tmpargsp = allocate_scratch<typename Arch::accept_args>(&scratch);
      r.set_arg2(tmpargsp);

      push_arg_ptr(t, args.addrlen);
      args.addrlen = allocate_scratch<typename Arch::socklen_t>(&scratch);

      push_arg_ptr(t, args.addr);
      args.addr = scratch.cast<typename Arch::sockaddr>();
      scratch += addrlen;
      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, "accept");
      }

      t->write_mem(tmpargsp, args);
      t->write_mem(args.addrlen.rptr(), addrlen);
      t->set_regs(r);
      return ALLOW_SWITCH;
    }

    /* int accept4([int sockfd, struct sockaddr *addr, socklen_t *addrlen, int
     * flags]) */
    case SYS_ACCEPT4: {
      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }
      remote_ptr<typename Arch::accept4_args> argsp = r.arg2();
      auto args = t->read_mem(argsp);
      auto addrlen = t->read_mem(args._.addrlen.rptr());

      // We use the same basic scheme here as for RECV
      // above.  For accept() though, there are two
      // (in)outparams: |addr| and |addrlen|.  |*addrlen| is
      // the total size of |addr|, so we reserve that much
      // space for it.  |*addrlen| is set to the size of the
      // returned sockaddr, so we reserve space for
      // |addrlen| too.

      // Reserve space for scratch socketcall args.
      push_arg_ptr(t, argsp);
      auto tmpargsp = allocate_scratch<typename Arch::accept4_args>(&scratch);
      r.set_arg2(tmpargsp);

      push_arg_ptr(t, args._.addrlen);
      args._.addrlen = allocate_scratch<typename Arch::socklen_t>(&scratch);

      push_arg_ptr(t, args._.addr);
      args._.addr = allocate_scratch<typename Arch::sockaddr>(&scratch);

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, "accept");
      }

      t->write_mem(tmpargsp, args);
      t->write_mem(args._.addrlen.rptr(), addrlen);
      t->set_regs(r);
      return ALLOW_SWITCH;
    }

    case SYS_RECVFROM: {
      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }
      remote_ptr<typename Arch::recvfrom_args> argsp = r.arg2();
      auto args = t->read_mem(argsp);

      // Reserve space for scratch socketcall args.
      push_arg_ptr(t, argsp);
      auto tmpargsp = allocate_scratch<typename Arch::recvfrom_args>(&scratch);
      r.set_arg2(tmpargsp);

      push_arg_ptr(t, args.buf);
      args.buf = scratch;
      scratch += args.len;

      typename Arch::socklen_t addrlen;
      if (args.src_addr) {
        addrlen = t->read_mem(args.addrlen.rptr());

        push_arg_ptr(t, args.addrlen);
        args.addrlen = allocate_scratch<typename Arch::socklen_t>(&scratch);

        push_arg_ptr(t, args.src_addr);
        args.src_addr = scratch.cast<typename Arch::sockaddr>();
        scratch += addrlen;
      } else {
        push_arg_ptr(t, nullptr);
        push_arg_ptr(t, nullptr);
      }
      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, "recvfrom");
      }

      t->write_mem(tmpargsp, args);
      if (args.addrlen) {
        t->write_mem(args.addrlen.rptr(), addrlen);
      }
      t->set_regs(r);
      return ALLOW_SWITCH;
    }
    case SYS_RECVMSG: {
      remote_ptr<typename Arch::recvmsg_args> argsp = r.arg2();
      auto args = t->read_mem(argsp);
      if (args.flags & MSG_DONTWAIT) {
        return PREVENT_SWITCH;
      }
      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }
      auto msg = t->read_mem(args.msg.rptr());

      // Reserve scratch for the arg
      push_arg_ptr(t, argsp);
      auto tmpargsp = allocate_scratch<typename Arch::recvmsg_args>(&scratch);
      r.set_arg2(tmpargsp);

      // Reserve scratch for the struct msghdr
      auto scratch_msg = allocate_scratch<typename Arch::msghdr>(&scratch);

      // Reserve scratch for the child pointers of struct msghdr
      if (reserve_scratch_for_msghdr<Arch>(t, &msg, &scratch)) {
        t->write_mem(scratch_msg, msg);
      } else {
        return PREVENT_SWITCH;
      }

      args.msg = scratch_msg;
      t->write_mem(tmpargsp, args);
      t->set_regs(r);

      return ALLOW_SWITCH;
    }
    case SYS_SENDMSG: {
      remote_ptr<typename Arch::recvmsg_args> argsp = r.arg2();
      auto args = t->read_mem(argsp);
      return (args.flags & MSG_DONTWAIT) ? PREVENT_SWITCH : ALLOW_SWITCH;
    }
    case SYS_SENDMMSG: {
      remote_ptr<typename Arch::sendmmsg_args> argsp = r.arg2();
      auto args = t->read_mem(argsp);
      return (args.flags & MSG_DONTWAIT) ? PREVENT_SWITCH : ALLOW_SWITCH;
    }
    case SYS_RECVMMSG: {
      remote_ptr<typename Arch::recvmmsg_args> argsp = r.arg2();
      auto args = t->read_mem(argsp);

      if (args.flags & MSG_DONTWAIT) {
        return PREVENT_SWITCH;
      }
      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }

      // Reserve scratch for the arg
      push_arg_ptr(t, argsp);
      auto tmpargsp = allocate_scratch<typename Arch::recvmmsg_args>(&scratch);
      r.set_arg2(tmpargsp);

      // Update msgvec pointer of tmp arg
      auto poldmsgvec = args.msgvec.rptr();
      args.msgvec = scratch.cast<typename Arch::mmsghdr>();
      t->write_mem(tmpargsp, args);

      if (reserve_scratch_for_msgvec<Arch>(t, args.vlen, poldmsgvec,
                                           &scratch)) {
        t->set_regs(r);
        return ALLOW_SWITCH;
      } else {
        return PREVENT_SWITCH;
      }
    }
    default:
      return PREVENT_SWITCH;
  }
}

static const int RR_KCMP_FILE = 0;

template <typename Arch> static bool is_stdio_fd(Task* t, int fd) {
  int pid = getpid();

  int r = syscall(Arch::kcmp, pid, t->rec_tid, RR_KCMP_FILE, STDOUT_FILENO, fd);
  if (r < 0 && errno == ENOSYS) {
    return fd == STDOUT_FILENO || fd == STDERR_FILENO;
  }
  if (r == 0) {
    return true;
  }
  if (r < 0 && errno == EBADF) {
    // Tracees may try to write to invalid fds.
    return false;
  }
  ASSERT(t, r >= 0) << "kcmp failed";

  r = syscall(Arch::kcmp, pid, t->rec_tid, RR_KCMP_FILE, STDERR_FILENO, fd);
  if (r == 0) {
    return true;
  }
  if (r < 0 && errno == EBADF) {
    // Tracees may try to write to invalid fds.
    return false;
  }
  ASSERT(t, r >= 0) << "kcmp failed";

  return false;
}

/**
 * |t| was descheduled while in a buffered syscall.  We don't want
 * to use scratch memory for the call, because the syscallbuf itself
 * is serving that purpose.  More importantly, we *can't* set up
 * scratch for |t|, because it's already in the syscall.  So this
 * function sets things up so that the *syscallbuf* memory that |t|
 * is using as ~scratch will be recorded, so that it can be replayed.
 *
 * Returns ALLOW_SWITCH if the syscall should be interruptible, PREVENT_SWITCH
 *otherwise.
 */
template <typename Arch>
static Switchable set_up_scratch_for_syscallbuf(Task* t, int syscallno) {
  const struct syscallbuf_record* rec = t->desched_rec();

  assert(rec);
  ASSERT(t, syscallno == rec->syscallno) << "Syscallbuf records syscall "
                                         << t->syscallname(rec->syscallno)
                                         << ", but expecting "
                                         << t->syscallname(syscallno);

  reset_scratch_pointers(t);
  t->ev().Syscall().tmp_data_ptr =
      t->syscallbuf_child + (rec->extra_data - (uint8_t*)t->syscallbuf_hdr);
  /* |rec->size| is the entire record including extra data; we
   * just care about the extra data here. */
  t->ev().Syscall().tmp_data_num_bytes = rec->size - sizeof(*rec);

  switch (syscallno) {
    case Arch::write:
    case Arch::writev:
      return is_stdio_fd<Arch>(t, (int)t->regs().arg1_signed()) ? PREVENT_SWITCH
                                                                : ALLOW_SWITCH;
    default:
      return ALLOW_SWITCH;
  }
}

static bool exec_file_supported(const string& filename) {
#if defined(__i386__)
  /* All this function does is reject 64-bit ELF binaries. Everything
     else we (optimistically) indicate support for. Missing or corrupt
     files will cause execve to fail normally. When we support 64-bit,
     this entire function can be removed. */
  ScopedFd fd(filename.c_str(), O_RDONLY);
  if (fd < 0) {
    return true;
  }
  char header[5];
  bool ok = true;
  if (read(fd, header, sizeof(header)) == sizeof(header)) {
    if (header[0] == ELFMAG0 && header[1] == ELFMAG1 && header[2] == ELFMAG2 &&
        header[3] == ELFMAG3 && header[4] == ELFCLASS64) {
      ok = false;
    }
  }
  return ok;
#elif defined(__x86_64__)
  // We support 32-bit and 64-bit binaries.
  return true;
#else
#error unknown architecture
#endif
}

template <typename Arch> static Switchable rec_prepare_syscall_arch(Task* t) {
  int syscallno = t->ev().Syscall().number;
  /* If we are called again due to a restart_syscall, we musn't
   * redirect to scratch again as we will lose the original
   * addresses values. */
  bool restart = (syscallno == Arch::restart_syscall);
  remote_ptr<void> scratch = nullptr;

  if (t->desched_rec()) {
    return set_up_scratch_for_syscallbuf<Arch>(t, syscallno);
  }

  /* For syscall params that may need scratch memory, they
   * *will* need scratch memory if |need_scratch_setup| is
   * false.  They *don't* need scratch memory if we're
   * restarting a syscall, since if that's the case we've
   * already set it up. */
  bool need_scratch_setup = !restart;
  if (need_scratch_setup) {
    /* Don't stomp scratch pointers that were set up for
     * the restarted syscall.
     *
     * TODO: but, we'll stomp if we reenter through a
     * signal handler ... */
    reset_scratch_pointers(t);
    scratch = t->ev().Syscall().tmp_data_ptr;
  }

  if (syscallno < 0) {
    // Invalid syscall. Don't let it accidentally match a
    // syscall number below that's for an undefined syscall.
    return PREVENT_SWITCH;
  }

  switch (syscallno) {
    case Arch::splice: {
      Registers r = t->regs();
      remote_ptr<loff_t> off_in = r.arg2();
      remote_ptr<loff_t> off_out = r.arg4();

      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }

      push_arg_ptr(t, off_in);
      if (!off_in.is_null()) {
        auto off_in2 = allocate_scratch<loff_t>(&scratch);
        t->remote_memcpy(off_in2, off_in);
        r.set_arg2(off_in2);
      }
      push_arg_ptr(t, off_out);
      if (!off_out.is_null()) {
        auto off_out2 = allocate_scratch<loff_t>(&scratch);
        t->remote_memcpy(off_out2, off_out);
        r.set_arg4(off_out2);
      }
      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }

      t->set_regs(r);
      return ALLOW_SWITCH;
    }

    case Arch::sendfile64: {
      Registers r = t->regs();
      remote_ptr<loff_t> offset = r.arg3();

      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }

      push_arg_ptr(t, offset);
      if (!offset.is_null()) {
        auto offset2 = allocate_scratch<loff_t>(&scratch);
        t->remote_memcpy(offset2, offset);
        r.set_arg3(offset2);
      }
      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }

      t->set_regs(r);
      return ALLOW_SWITCH;
    }

    case Arch::clone: {
      unsigned long flags = t->regs().arg1();
      push_arg_ptr(t, flags);
      if (flags & CLONE_UNTRACED) {
        Registers r = t->regs();
        // We can't let tracees clone untraced tasks,
        // because they can create nondeterminism that
        // we can't replay.  So unset the UNTRACED bit
        // and then cover our tracks on exit from
        // clone().
        r.set_arg1(flags & ~CLONE_UNTRACED);
        t->set_regs(r);
      }
      return PREVENT_SWITCH;
    }

    case Arch::exit:
      t->stable_exit = true;
      if (t->task_group()->task_set().size() == 1) {
        t->task_group()->exit_code = (int)t->regs().arg1();
      }
      destroy_buffers(t);
      return PREVENT_SWITCH;

    case Arch::exit_group:
      if (t->task_group()->task_set().size() == 1) {
        t->stable_exit = true;
      }
      t->task_group()->exit_code = (int)t->regs().arg1();
      return PREVENT_SWITCH;

    case Arch::execve: {
      t->pre_exec();

      Registers r = t->regs();
      string raw_filename = t->read_c_str(r.arg1());
      // We can't use push_arg_ptr/pop_arg_ptr to save and restore
      // arg1 because execs get special ptrace events that clobber
      // the trace event for this system call.
      t->exec_saved_arg1 = r.arg1();
      uintptr_t end = r.arg1() + raw_filename.length();
      if (!exec_file_supported(t->exec_file())) {
        // Force exec to fail with ENOENT by advancing arg1 to
        // the null byte
        r.set_arg1(end);
        t->set_regs(r);
      }
      return PREVENT_SWITCH;
    }

    case Arch::fcntl64:
      switch ((int)t->regs().arg2_signed()) {
        case F_SETLKW:
#if F_SETLKW64 != F_SETLKW
        case F_SETLKW64:
#endif
          // SETLKW blocks, but doesn't write any
          // outparam data to the |struct flock|
          // argument, so no need for scratch.
          return ALLOW_SWITCH;
        default:
          return PREVENT_SWITCH;
      }

    /* int futex(int *uaddr, int op, int val, const struct timespec *timeout,
     * int *uaddr2, int val3); */
    case Arch::futex:
      switch ((int)t->regs().arg2_signed() & FUTEX_CMD_MASK) {
        case FUTEX_WAIT:
        case FUTEX_WAIT_BITSET:
          return ALLOW_SWITCH;
        default:
          return PREVENT_SWITCH;
      }

    case Arch::ipc:
      return prepare_ipc<Arch>(t, need_scratch_setup);

    case Arch::socketcall:
      return prepare_socketcall<Arch>(t, need_scratch_setup);

    case Arch::_newselect:
      return ALLOW_SWITCH;

    /* ssize_t read(int fd, void *buf, size_t count); */
    case Arch::read: {
      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }
      Registers r = t->regs();

      push_arg_ptr(t, r.arg2());
      r.set_arg2(scratch);
      scratch += (size_t)r.arg3();

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }

      t->set_regs(r);
      return ALLOW_SWITCH;
    }

    case Arch::write:
    case Arch::writev: {
      int fd = (int)t->regs().arg1_signed();
      maybe_mark_stdio_write(t, fd);
      // Tracee writes to rr's stdout/stderr are echoed during replay.
      // We want to ensure that these writes are replayed in the same
      // order as they were performed during recording. If we treat
      // those writes as interruptible, we can get into a difficult
      // situation: we start the system call, it gets interrupted,
      // we switch to another thread that starts its own write, and
      // at that point we don't know which order the kernel will
      // actually perform the writes in.
      // We work around this problem by making writes to rr's
      // stdout/stderr non-interruptible. This theoretically
      // introduces the possibility of deadlock between rr's
      // tracee and some external program reading rr's output
      // via a pipe ... but that seems unlikely to bite in practice.
      return is_stdio_fd<Arch>(t, fd) ? PREVENT_SWITCH : ALLOW_SWITCH;
      // Note that the determination of whether fd maps to rr's
      // stdout/stderr is exact, using kcmp, whereas our decision
      // to echo is currently based on the simple heuristic of
      // whether fd is STDOUT_FILENO/STDERR_FILENO (which can be
      // wrong due to those fds being dup'ed, redirected, etc).
      // We could use kcmp for the echo decision too, except
      // when writes are buffered by syscallbuf it gets rather
      // complex. A better solution is probably for the replayer
      // to track metadata for each tracee fd, tracking whether the
      // fd points to rr's stdout/stderr.
    }

    /* pid_t waitpid(pid_t pid, int *status, int options); */
    /* pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
     */
    case Arch::waitpid:
    case Arch::wait4: {
      Registers r = t->regs();
      remote_ptr<int> status = r.arg2();
      remote_ptr<typename Arch::rusage> rusage =
          (Arch::wait4 == syscallno) ? r.arg4() : (uintptr_t)0;

      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }
      push_arg_ptr(t, status);
      if (!status.is_null()) {
        r.set_arg2(scratch);
        scratch += status.referent_size();
      }
      push_arg_ptr(t, rusage);
      if (!rusage.is_null()) {
        r.set_arg4(scratch);
        scratch += rusage.referent_size();
      }

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }

      t->set_regs(r);
      return ALLOW_SWITCH;
    }

    case Arch::waitid: {
      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }

      Registers r = t->regs();
      remote_ptr<typename Arch::siginfo_t> infop = r.arg3();
      push_arg_ptr(t, infop);
      if (!infop.is_null()) {
        r.set_arg3(scratch);
        scratch += infop.referent_size();
      }

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }

      t->set_regs(r);
      return ALLOW_SWITCH;
    }

    case Arch::pause:
      return ALLOW_SWITCH;

    /* int poll(struct pollfd *fds, nfds_t nfds, int timeout) */
    /* int ppoll(struct pollfd *fds, nfds_t nfds,
     *           const struct timespec *timeout_ts,
     *           const sigset_t *sigmask); */
    case Arch::poll:
    case Arch::ppoll: {
      Registers r = t->regs();
      remote_ptr<typename Arch::pollfd> fds = r.arg1();
      auto fds2 = scratch.cast<typename Arch::pollfd>();
      nfds_t nfds = r.arg2();

      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }
      /* XXX fds can be NULL, right? */
      push_arg_ptr(t, fds);
      r.set_arg1(fds2);
      scratch += nfds * fds.referent_size();

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }
      /* |fds| is an inout param, so we need to copy over
       * the source data. */
      t->remote_memcpy(fds2, fds, nfds * fds.referent_size());
      t->set_regs(r);
      return ALLOW_SWITCH;
    }

    /* int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned
     * long arg4, unsigned long arg5); */
    case Arch::prctl: {
      /* TODO: many of these prctls are not blocking. */
      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }
      Registers r = t->regs();
      switch ((int)r.arg1_signed()) {
        case PR_GET_ENDIAN:
        case PR_GET_FPEMU:
        case PR_GET_FPEXC:
        case PR_GET_PDEATHSIG:
        case PR_GET_TSC:
        case PR_GET_UNALIGN: {
          remote_ptr<int> outparam = r.arg2();

          push_arg_ptr(t, outparam);
          r.set_arg2(scratch);
          scratch += outparam.referent_size();

          if (!can_use_scratch(t, scratch)) {
            return abort_scratch(t, t->syscallname(syscallno));
          }

          t->set_regs(r);
          return ALLOW_SWITCH;
        }
        case PR_GET_NAME:
        case PR_SET_NAME:
          return PREVENT_SWITCH;

        default:
          /* TODO: there are many more prctls with
           * outparams ... */
          return ALLOW_SWITCH;
      }
      FATAL() << "Not reached";
    }

    case Arch::_sysctl: {
      auto sysctl_args = t->read_mem(
          remote_ptr<typename Arch::__sysctl_args>(t->regs().arg1()));
      push_arg_ptr(t, sysctl_args.oldval);
      push_arg_ptr(t, sysctl_args.oldlenp);
      return PREVENT_SWITCH;
    }

    /* int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int
     * timeout); */
    case Arch::epoll_wait: {
      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }

      Registers r = t->regs();
      remote_ptr<typename Arch::epoll_event> events = r.arg2();
      int maxevents = r.arg3_signed();

      push_arg_ptr(t, events);
      r.set_arg2(scratch);
      scratch += maxevents * events.referent_size();

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }

      /* (Unlike poll(), the |events| param is a pure
       * outparam, no copy-over needed.) */
      t->set_regs(r);
      return ALLOW_SWITCH;
    }

    case Arch::ptrace:
      fprintf(
          stderr,
          "\n"
          "rr: internal recorder error:\n"
          "  ptrace() is not yet supported.  We need to go deeper.\n"
          "\n"
          "  Your trace is being synced and will be available for replay when\n"
          "  this process exits.\n");
      terminate_recording(t);
      FATAL() << "Not reached";
      return PREVENT_SWITCH;

    case Arch::epoll_pwait:
      FATAL() << "Unhandled syscall " << t->syscallname(syscallno);
      return ALLOW_SWITCH;

    /* The following two syscalls enable context switching not for
     * liveness/correctness reasons, but rather because if we
     * didn't context-switch away, rr might end up busy-waiting
     * needlessly.  In addition, albeit far less likely, the
     * client program may have carefully optimized its own context
     * switching and we should take the hint. */

    /* int nanosleep(const struct timespec *req, struct timespec *rem); */
    case Arch::nanosleep: {
      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }

      Registers r = t->regs();
      remote_ptr<typename Arch::timespec> rem = r.arg2();
      push_arg_ptr(t, rem);
      if (!rem.is_null()) {
        r.set_arg2(scratch);
        scratch += rem.referent_size();
      }

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }

      t->set_regs(r);
      return ALLOW_SWITCH;
    }

    case Arch::sched_yield:
      // Force |t| to be context-switched if another thread
      // of equal or higher priority is available.  We set
      // the counter to INT_MAX / 2 because various other
      // irrelevant events intervening between now and
      // scheduling may increment t's event counter, and we
      // don't want it to overflow.
      t->succ_event_counter = numeric_limits<int>::max() / 2;
      // We're just pretending that t is blocked.  The next
      // time its scheduling slot opens up, it's OK to
      // blocking-waitpid on t to see its status change.
      t->pseudo_blocked = true;
      t->session().schedule_one_round_robin(t);
      return ALLOW_SWITCH;

    case Arch::recvmmsg: {
      Registers r = t->regs();

      if ((unsigned int)r.arg4() & MSG_DONTWAIT) {
        return PREVENT_SWITCH;
      }
      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }

      remote_ptr<typename Arch::mmsghdr> poldmsgvec = r.arg2();
      push_arg_ptr(t, r.arg2());
      r.set_arg2(scratch);

      if (reserve_scratch_for_msgvec<Arch>(t, r.arg3(), poldmsgvec, &scratch)) {
        t->set_regs(r);
        return ALLOW_SWITCH;
      } else {
        return PREVENT_SWITCH;
      }
    }
    case Arch::rt_sigtimedwait: {
      if (!need_scratch_setup) {
        return ALLOW_SWITCH;
      }
      Registers r = t->regs();
      remote_ptr<typename Arch::siginfo_t> info = r.arg2();
      push_arg_ptr(t, info);
      if (!info.is_null()) {
        r.set_arg2(scratch);
        // TODO: is this size arch-dependent?
        scratch += info.referent_size();
      }

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }
      t->set_regs(r);
      return ALLOW_SWITCH;
    }
    case Arch::rt_sigsuspend:
    case Arch::sigsuspend:
      return ALLOW_SWITCH;

    case Arch::sendmmsg: {
      Registers r = t->regs();
      unsigned flags = (unsigned int)r.arg4();
      return (flags & MSG_DONTWAIT) ? PREVENT_SWITCH : ALLOW_SWITCH;
    }

    case Arch::sched_setaffinity: {
      // Ignore all sched_setaffinity syscalls. They might interfere
      // with our own affinity settings.
      Registers r = t->regs();
      push_arg_ptr(t, r.arg1());
      // Set arg1 to an invalid PID to ensure this syscall is ignored.
      r.set_arg1(-1);
      t->set_regs(r);
      return PREVENT_SWITCH;
    }

    default:
      return PREVENT_SWITCH;
  }
}

Switchable rec_prepare_syscall(Task* t) {
  RR_ARCH_FUNCTION(rec_prepare_syscall_arch, t->arch(), t)
}

/**
 * Write a trace data record that when replayed will be a no-op.  This
 * is used to avoid having special cases in replay code for failed
 * syscalls, e.g.
 */
static void record_noop_data(Task* t) { t->record_local(nullptr, 0, nullptr); }

template <typename Arch> static void rec_prepare_restart_syscall_arch(Task* t) {
  int syscallno = t->ev().Syscall().number;
  switch (syscallno) {
    case Arch::nanosleep: {
      /* Hopefully uniquely among syscalls, nanosleep()
       * requires writing to its remaining-time outparam
       * *only if* the syscall fails with -EINTR.  When a
       * nanosleep() is interrupted by a signal, we don't
       * know a priori whether it's going to be eventually
       * restarted or not.  (Not easily, anyway.)  So we
       * don't know whether it will eventually return -EINTR
       * and would need the outparam written.  To resolve
       * that, we do what the kernel does, and update the
       * outparam at the -ERESTART_RESTART interruption
       * regardless. */
      auto rem =
          t->ev().Syscall().saved_args.top().cast<typename Arch::timespec>();
      remote_ptr<typename Arch::timespec> rem2 = t->regs().arg2();

      if (!rem.is_null()) {
        t->remote_memcpy(rem, rem2);
        t->record_remote(rem);
      } else {
        record_noop_data(t);
      }
      /* If the nanosleep does indeed restart, then we'll
       * write the outparam twice.  *yawn*. */
      return;
    }
    default:
      return;
  }
}

void rec_prepare_restart_syscall(Task* t) {
  RR_ARCH_FUNCTION(rec_prepare_restart_syscall_arch, t->arch(), t)
}

template <typename Arch> static void init_scratch_memory(Task* t) {
  const int scratch_size = 512 * page_size();
  size_t sz = scratch_size;
  // The PROT_EXEC looks scary, and it is, but it's to prevent
  // this region from being coalesced with another anonymous
  // segment mapped just after this one.  If we named this
  // segment, we could remove this hack.
  int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  int fd = -1;
  // NB: we don't need to adjust this in the remote syscall below because
  // 0 == (0 >> PAGE_SIZE).
  off64_t offset_pages = 0;
  {
    /* initialize the scratchpad for blocking system calls */
    AutoRemoteSyscalls remote(t);
    t->scratch_ptr = remote.syscall(
        has_mmap2_syscall(Arch::arch()) ? Arch::mmap2 : Arch::mmap,
        0, sz, prot, flags, fd, offset_pages);
    t->scratch_size = scratch_size;
  }
  // record this mmap for the replay
  Registers r = t->regs();
  uintptr_t saved_result = r.syscall_result();
  r.set_syscall_result(t->scratch_ptr);
  t->set_regs(r);

  char filename[PATH_MAX];
  sprintf(filename, "scratch for thread %d", t->tid);
  struct stat stat;
  memset(&stat, 0, sizeof(stat));
  TraceMappedRegion file(string(filename), stat, t->scratch_ptr,
                         t->scratch_ptr + scratch_size);
  t->trace_writer().write_mapped_region(file);

  r.set_syscall_result(saved_result);
  t->set_regs(r);

  t->vm()->map(t->scratch_ptr, sz, prot, flags, page_size() * offset_pages,
               MappableResource::scratch(t->rec_tid));
}

/**
 * Return nonzero if tracee pointers were saved while preparing for
 * the syscall |t->ev|.
 */
static bool has_saved_arg_ptrs(Task* t) {
  return !t->ev().Syscall().saved_args.empty();
}

/**
 * Return the replaced tracee argument pointer saved by the matching
 * call to |push_arg_ptr()|.
 */
template <typename T> static remote_ptr<T> pop_arg_ptr(Task* t) {
  assert(!t->ev().Syscall().saved_args.empty());
  auto arg = t->ev().Syscall().saved_args.top();
  t->ev().Syscall().saved_args.pop();
  return arg.cast<T>();
}

enum AllowSlack {
  /**
   * Require that all saved scratch data was consumed.
   */
  NO_SLACK = 0,
  /**
   * Allow some saved scratch data to remain unconsumed,
   * for example if a buffer wasn't filled entirely.
   */
  ALLOW_SLACK = 1
};

/**
 * Read the scratch data written by the kernel in the syscall and
 * provide an iterator to read through it.
 */
class AutoRestoreScratch {
public:
  AutoRestoreScratch(Task* t, AllowSlack slack = NO_SLACK)
      : t(t), iter(nullptr), slack(slack) {
    remote_ptr<void> scratch = t->ev().Syscall().tmp_data_ptr;
    ssize_t num_bytes = t->ev().Syscall().tmp_data_num_bytes;
    if (num_bytes < 0) {
      // Scratch was not used
      return;
    }

    data.resize(num_bytes);
    t->read_bytes_helper(scratch, num_bytes, data.data());
    iter = data.data();
  }
  /**
   * Finish the sequence of operations and check that no mistakes were made.
   */
  ~AutoRestoreScratch() {
    if (!iter) {
      return;
    }

    ssize_t consumed = iter - data.data();
    ssize_t diff = t->ev().Syscall().tmp_data_num_bytes - consumed;

    assert(t->ev().Syscall().tmp_data_ptr == t->scratch_ptr);
    ASSERT(t, !diff || (slack && diff > 0))
        << "Saved " << t->ev().Syscall().tmp_data_num_bytes
        << " bytes of scratch memory but consumed " << consumed;
    if (slack) {
      LOG(debug) << "Left " << diff << " bytes unconsumed in scratch";
    }
    ASSERT(t, t->ev().Syscall().saved_args.empty())
        << "Under-consumed saved arg pointers";
  }

  bool scratch_used() { return iter; }

  /**
   * Write |count| values of type T to |child_addr|.
   * Record the written data so that it can be restored during replay.
   */
  template <typename T>
  void restore_and_record_args(remote_ptr<T> child_addr, size_t count) {
    ASSERT(t, scratch_used());
    size_t num_bytes = count * sizeof(T);
    t->write_bytes_helper(child_addr, num_bytes, iter);
    t->record_local(child_addr, num_bytes, iter);
    iter += num_bytes;
  }

  void restore_and_record_arg_buf(remote_ptr<void> child_addr, size_t bytes) {
    restore_and_record_args(child_addr.cast<uint8_t>(), bytes);
  }

  template <typename T>
  void restore_and_record_arg(remote_ptr<T> child_addr, T* value = nullptr) {
    if (value) {
      memcpy(value, iter, sizeof(T));
    }
    restore_and_record_args(child_addr, 1);
  }

  template <typename T> void read_arg(T* value) {
    ASSERT(t, scratch_used());
    memcpy(value, iter, sizeof(T));
    iter += sizeof(T);
  }

private:
  Task* t;
  vector<uint8_t> data;
  uint8_t* iter;
  AllowSlack slack;
};

// We have |keys_length| instead of using array_length(keys) to work
// around a gcc bug.
template <typename Arch>
struct elf_auxv_ordering {
  static const unsigned int keys[];
  static const size_t keys_length;
};

template<> const unsigned int elf_auxv_ordering<X86Arch>::keys[] = {
  AT_SYSINFO, AT_SYSINFO_EHDR, AT_HWCAP, AT_PAGESZ, AT_CLKTCK, AT_PHDR,
  AT_PHENT,   AT_PHNUM,        AT_BASE,  AT_FLAGS,  AT_ENTRY,  AT_UID,
  AT_EUID,    AT_GID,          AT_EGID,  AT_SECURE
};
template<> const size_t elf_auxv_ordering<X86Arch>::keys_length = array_length(keys);

template<> const unsigned int elf_auxv_ordering<X64Arch>::keys[] = {
  AT_SYSINFO_EHDR, AT_HWCAP, AT_PAGESZ, AT_CLKTCK, AT_PHDR,
  AT_PHENT,        AT_PHNUM, AT_BASE,   AT_FLAGS,  AT_ENTRY,
  AT_UID,          AT_EUID,  AT_GID,    AT_EGID,   AT_SECURE,
};
template<> const size_t elf_auxv_ordering<X64Arch>::keys_length = array_length(keys);

template <typename Arch> static void process_execve(Task* t) {
  Registers r = t->regs();
  if (r.syscall_failed()) {
    if (r.arg1() != t->exec_saved_arg1) {
      LOG(warn)
          << "Blocked attempt to execve 64-bit image (not yet supported by rr)";
      // Restore arg1, which we clobbered.
      r.set_arg1(t->exec_saved_arg1);
      t->set_regs(r);
    }
    return;
  }

  // XXX what does this signifiy?
  if (r.arg1() != 0) {
    return;
  }

  t->session().after_exec();
  t->post_exec();

  remote_ptr<typename Arch::signed_word> stack_ptr = t->regs().sp();

  /* start_stack points to argc - iterate over argv pointers */

  /* FIXME: there are special cases, like when recording gcc,
   *        where the stack pointer does not point to argc. For example,
   *        it may point to &argc.
   */
  // long* argc = (long*)t->read_word((uint8_t*)stack_ptr);
  // stack_ptr += *argc + 1;
  auto argc = t->read_mem(stack_ptr);
  stack_ptr += argc + 1;

  // unsigned long* null_ptr = read_child_data(t, sizeof(void*), stack_ptr);
  // assert(*null_ptr == 0);
  auto null_ptr = t->read_mem(stack_ptr);
  assert(null_ptr == 0);
  stack_ptr++;

  /* should now point to envp (pointer to environment strings) */
  while (0 != t->read_mem(stack_ptr)) {
    stack_ptr++;
  }
  stack_ptr++;
  /* should now point to ELF Auxiliary Table */

  struct ElfEntry {
    typename Arch::unsigned_word key;
    typename Arch::unsigned_word value;
  };
  union {
    ElfEntry entries[elf_auxv_ordering<Arch>::keys_length];
    uint8_t bytes[sizeof(entries)];
  } table;
  t->read_bytes(stack_ptr, table.bytes);
  stack_ptr += 2 * array_length(elf_auxv_ordering<Arch>::keys);

  for (size_t i = 0; i < array_length(elf_auxv_ordering<Arch>::keys); ++i) {
    auto expected_field = elf_auxv_ordering<Arch>::keys[i];
    const ElfEntry& entry = table.entries[i];
    ASSERT(t, expected_field == entry.key)
        << "Elf aux entry " << i << " should be " << HEX(expected_field)
        << ", but is " << HEX(entry.key);
  }

  auto at_random = t->read_mem(stack_ptr);
  stack_ptr++;
  ASSERT(t, AT_RANDOM == at_random) << "ELF item should be " << HEX(AT_RANDOM)
                                    << ", but is " << HEX(at_random);

  remote_ptr<void> rand_addr = t->read_mem(stack_ptr);
  // XXX where does the magic number come from?
  t->record_remote(rand_addr, 16);

  init_scratch_memory<Arch>(t);
}

static void record_ioctl_data(Task* t, ssize_t num_bytes) {
  remote_ptr<void> param = t->regs().arg3();
  t->record_remote(param, num_bytes);
}

/**
 * Record.the page above the top of |t|'s stack.  The SIOC* ioctls
 * have been observed to write beyond the end of tracees' stacks, as
 * if they had allocated scratch space for themselves.  All we can do
 * for now is try to record the scratch data.
 */
static void record_scratch_stack_page(Task* t) {
  t->record_remote(t->sp() - page_size(), page_size());
}

template <typename Arch> static void process_ioctl(Task* t, int request) {
  int type = _IOC_TYPE(request);
  int nr = _IOC_NR(request);
  int dir = _IOC_DIR(request);
  int size = _IOC_SIZE(request);
  remote_ptr<void> param = t->regs().arg3();

  LOG(debug) << "handling ioctl(" << HEX(request) << "): type:" << HEX(type)
             << " nr:" << HEX(nr) << " dir:" << HEX(dir) << " size:" << size;

  ASSERT(t, !t->is_desched_event_syscall())
      << "Failed to skip past desched ioctl()";

  /* Some ioctl()s are irregular and don't follow the _IOC()
   * conventions.  Special case them here. */
  switch (request) {
    case SIOCETHTOOL: {
      auto ifr = t->read_mem(param.cast<typename Arch::ifreq>());

      record_scratch_stack_page(t);
      t->record_remote(ifr.ifr_ifru.ifru_data,
                       sizeof(typename Arch::ethtool_cmd));
      return;
    }
    case SIOCGIFCONF: {
      auto ifconf = t->read_mem(param.cast<typename Arch::ifconf>());

      record_scratch_stack_page(t);
      t->record_local(param, sizeof(ifconf), &ifconf);
      t->record_remote(ifconf.ifc_ifcu.ifcu_buf, ifconf.ifc_len);
      return;
    }
    case SIOCGIFADDR:
    case SIOCGIFFLAGS:
    case SIOCGIFINDEX:
    case SIOCGIFMTU:
    case SIOCGIFNAME:
      record_scratch_stack_page(t);
      return record_ioctl_data(t, sizeof(typename Arch::ifreq));

    case SIOCGIWRATE:
      // SIOCGIWRATE hasn't been observed to write beyond
      // tracees' stacks, but we record a stack page here
      // just in case the behavior is driver-dependent.
      record_scratch_stack_page(t);
      return record_ioctl_data(t, sizeof(typename Arch::iwreq));

    case TCGETS:
      return record_ioctl_data(t, sizeof(typename Arch::termios));
    case TIOCINQ:
      return record_ioctl_data(t, sizeof(int));
    case TIOCGWINSZ:
      return record_ioctl_data(t, sizeof(typename Arch::winsize));
  }

  /* In ioctl language, "_IOC_WRITE" means "outparam".  Both
   * READ and WRITE can be set for inout params. */
  if (!(_IOC_WRITE & dir)) {
    /* If the kernel isn't going to write any data back to
     * us, we hope and pray that the result of the ioctl
     * (observable to the tracee) is deterministic. */
    LOG(debug) << "  (deterministic ioctl, nothing to do)";
    return;
  }

  /* The following are thought to be "regular" ioctls, the
   * processing of which is only known to (observably) write to
   * the bytes in the structure passed to the kernel.  So all we
   * need is to record |size| bytes.*/
  switch (request) {
    /* TODO: what are the 0x46 ioctls? */
    case 0xc020462b:
    case 0xc048464d:
    case 0xc0204637:
    case 0xc0304627:
      FATAL() << "Unknown 0x46-series ioctl nr " << HEX(nr);
      break; /* not reached */

    /* The following are ioctls for the linux Direct Rendering
     * Manager (DRM).  The ioctl "type" is 0x64 (100, or ASCII 'd'
     * as they docs helpfully declare it :/).  The ioctl numbers
     * are allocated as follows
     *
     *  [0x00, 0x40) -- generic commands
     *  [0x40, 0xa0) -- device-specific commands
     *  [0xa0, 0xff) -- more generic commands
     *
     * Chasing down unknown ioctls is somewhat annoying in this
     * scheme, but here's an example: request "0xc0406481".  "0xc"
     * means it's a read/write ioctl, and "0x0040" is the size of
     * the payload.  The actual ioctl request is "0x6481".
     *
     * As we saw above, "0x64" is the DRM type.  So now we need to
     * see what command "0x81" is.  It's in the
     * device-specific-command space, so we can start by
     * subtracting "0x40" to get a command "0x41".  Then
     *
     *  $ cd
     *  $ grep -rn 0x41 *
     *  nouveau_drm.h:200:#define DRM_NOUVEAU_GEM_PUSHBUF        0x41
     *
     * Well that was lucky!  So the command is
     * DRM_NOUVEAU_GEM_PUSHBUF, and the parameters etc can be
     * tracked down from that.
     */

    /* TODO: At least one of these ioctl()s, most likely
     * NOUVEAU_GEM_NEW, opens a file behind rr's back on behalf of
     * the callee.  That wreaks havoc later on in execution, so we
     * disable the whole lot for now until rr can handle that
     * behavior (by recording access to shmem segments). */
    case DRM_IOCTL_VERSION:
    case DRM_IOCTL_NOUVEAU_GEM_NEW:
    case DRM_IOCTL_NOUVEAU_GEM_PUSHBUF:
      FATAL() << "Intentionally unhandled DRM(0x64) ioctl nr " << HEX(nr);
      break;

    case DRM_IOCTL_GET_MAGIC:
    case DRM_IOCTL_RADEON_INFO:
    case DRM_IOCTL_I915_GEM_PWRITE:
    case DRM_IOCTL_GEM_OPEN:
    case DRM_IOCTL_I915_GEM_MMAP:
    case DRM_IOCTL_RADEON_GEM_CREATE:
    case DRM_IOCTL_RADEON_GEM_GET_TILING:
      FATAL() << "Not-understood DRM(0x64) ioctl nr " << HEX(nr);
      break; /* not reached */

    case 0x4010644d:
    case 0xc0186441:
    case 0x80086447:
    case 0xc0306449:
    case 0xc030644b:
      FATAL() << "Unknown DRM(0x64) ioctl nr " << HEX(nr);
      break; /* not reached */

    default:
      t->regs().print_register_file(stderr);
      ASSERT(t, false) << "Unknown ioctl(" << HEX(request)
                       << "): type:" << HEX(type) << " nr:" << HEX(nr)
                       << " dir:" << HEX(dir) << " size:" << size
                       << " addr:" << HEX(t->regs().arg3());
  }
}

static int get_ipc_command(int raw_cmd) { return raw_cmd & ~IPC_64; }

template <typename Arch> static void process_msgctl(Task* t, int cmd,
                                                    remote_ptr<void> buf) {
  ssize_t buf_size;
  switch(cmd) {
    case IPC_STAT:
    case MSG_STAT:
      buf_size = sizeof(typename Arch::msqid64_ds);
      break;
    case IPC_INFO:
    case MSG_INFO:
      buf_size = sizeof(typename Arch::msginfo);
      break;
    default:
      buf_size = 0;
      break;
  }
  t->record_remote(buf, buf_size);
}

template <typename Arch> static void process_ipc(Task* t, int call) {
  LOG(debug) << "ipc call: " << call;

  switch (call) {
    case MSGCTL: {
      int cmd = get_ipc_command((int)t->regs().arg3_signed());
      remote_ptr<void> buf = t->regs().arg5();
      process_msgctl<Arch>(t, cmd, buf);
      return;
    }
    case MSGRCV: {
      // The |msgsize| arg is only the size of message
      // payload; there's also a |msgtype| tag set just
      // before the payload.
      size_t buf_size = sizeof(long) + t->regs().arg3();
      remote_ptr<typename Arch::ipc_kludge_args> child_kludge =
          t->regs().arg5();
      auto kludge = t->read_mem(child_kludge);
      if (has_saved_arg_ptrs(t)) {
        remote_ptr<void> src = kludge.msgbuf;
        remote_ptr<void> dst = pop_arg_ptr<void>(t);

        kludge.msgbuf = dst;
        t->write_mem(child_kludge, kludge);

        t->remote_memcpy(dst, src, buf_size);
      }
      t->record_remote(kludge.msgbuf, buf_size);
      return;
    }
    case MSGGET:
    case MSGSND:
      return;
    default:
      FATAL() << "Unhandled IPC call " << call;
  }
}

static void process_mmap(Task* t, int syscallno, size_t length, int prot,
                         int flags, int fd, off_t offset_pages) {
  size_t size = ceil_page_size(length);
  off64_t offset = offset_pages * 4096;

  if (t->regs().syscall_failed()) {
    // We purely emulate failed mmaps.
    return;
  }
  remote_ptr<void> addr = t->regs().syscall_result();
  if (flags & MAP_ANONYMOUS) {
    // Anonymous mappings are by definition not
    // backed by any file-like object, and are
    // initialized to zero, so there's no
    // nondeterminism to record.
    // assert(!(flags & MAP_UNINITIALIZED));
    t->vm()->map(addr, size, prot, flags, 0, MappableResource::anonymous());
    return;
  }

  ASSERT(t, fd >= 0) << "Valid fd required for file mapping";
  assert(!(flags & MAP_GROWSDOWN));

  // TODO: save a reflink copy of the resource to the
  // trace directory as |fs/[st_dev].[st_inode]|.  Then
  // we wouldn't have to care about looking up a name
  // for the resource.
  char filename[PATH_MAX];
  struct stat stat;
  if (!t->fdstat(fd, &stat, filename, sizeof(filename))) {
    FATAL() << "Failed to fdstat " << fd;
  }
  bool copied =
      should_copy_mmap_region(filename, &stat, prot, flags, WARN_DEFAULT);

  if (copied) {
    off64_t end = (off64_t)stat.st_size - offset;
    t->record_remote(addr, min(end, (off64_t)size));
  }

  TraceMappedRegion file(filename, stat, addr, addr + size, copied);
  t->trace_writer().write_mapped_region(file);

  if (strstr(filename, SYSCALLBUF_LIB_FILENAME) && (prot & PROT_EXEC)) {
    t->syscallbuf_lib_start = file.start();
    t->syscallbuf_lib_end = file.end();
  }

  t->vm()->map(addr, size, prot, flags, offset,
               MappableResource(FileId(stat), filename));
}

/*
 * Restore all data of msghdr from src* to dst* (all child pointers) and
 * record child memory where the pointer members point for replay
 */
template <typename Arch>
static void record_and_restore_msghdr(Task* t,
                                      remote_ptr<typename Arch::msghdr> dst,
                                      remote_ptr<typename Arch::msghdr> src) {
  auto msg = t->read_mem(dst);
  auto tmpmsg = t->read_mem(src);

  msg.msg_namelen = tmpmsg.msg_namelen;
  msg.msg_flags = tmpmsg.msg_flags;
  msg.msg_controllen = tmpmsg.msg_controllen;
  t->write_mem(dst, msg);
  t->record_local(dst, &msg);

  if (msg.msg_name) {
    t->remote_memcpy(msg.msg_name, tmpmsg.msg_name, tmpmsg.msg_namelen);
  }
  t->record_remote(msg.msg_name, msg.msg_namelen);

  ASSERT(t, msg.msg_iovlen == tmpmsg.msg_iovlen)
      << "Scratch msg should have " << msg.msg_iovlen << " iovs, but has "
      << tmpmsg.msg_iovlen;
  typename Arch::iovec iovs[msg.msg_iovlen];
  read_iovs<Arch>(t, msg, iovs);
  typename Arch::iovec tmpiovs[tmpmsg.msg_iovlen];
  read_iovs<Arch>(t, tmpmsg, tmpiovs);
  for (size_t i = 0; i < msg.msg_iovlen; ++i) {
    auto iov = &iovs[i];
    auto& tmpiov = tmpiovs[i];
    t->remote_memcpy(iov->iov_base, tmpiov.iov_base, tmpiov.iov_len);
    iov->iov_len = tmpiov.iov_len;

    t->record_remote(iov->iov_base, iov->iov_len);
  }

  if (msg.msg_control) {
    t->remote_memcpy(msg.msg_control, tmpmsg.msg_control, msg.msg_controllen);
  }
  t->record_remote(msg.msg_control, msg.msg_controllen);
}

/**
 * Record all the data needed to restore the |struct msghdr| pointed
 * at in |t|'s address space by |child_msghdr|.
 */
template <typename Arch>
static void record_struct_msghdr(
    Task* t, remote_ptr<typename Arch::msghdr> child_msghdr) {
  auto msg = t->read_mem(child_msghdr);

  // Record the entire struct, because some of the direct fields
  // are written as inoutparams.
  t->record_local(child_msghdr, &msg);
  t->record_remote(msg.msg_name, msg.msg_namelen);

  // Read all the inout iovecs in one shot.
  typename Arch::iovec iovs[msg.msg_iovlen];
  t->read_bytes_helper(msg.msg_iov.rptr(), msg.msg_iovlen * sizeof(iovs[0]),
                       (uint8_t*)iovs);
  for (size_t i = 0; i < msg.msg_iovlen; ++i) {
    auto iov = &iovs[i];
    t->record_remote(iov->iov_base.rptr(), iov->iov_len);
  }

  t->record_remote(msg.msg_control.rptr(), msg.msg_controllen);
}

/** Like record_struct_msghdr(), but records mmsghdr. */
template <typename Arch>
static void record_struct_mmsghdr(
    Task* t, remote_ptr<typename Arch::mmsghdr> child_mmsghdr) {
  /* struct mmsghdr has an inline struct msghdr as its first
   * field, so it's OK to make this "cast". */
  record_struct_msghdr<Arch>(t, REMOTE_PTR_FIELD(child_mmsghdr, msg_hdr));
  /* We additionally have to record the outparam number of
   * received bytes. */
  t->record_remote(REMOTE_PTR_FIELD(child_mmsghdr, msg_len));
}

/*
 * Restore all data of msgvec from pnewmsg to poldmsg and
 * record child memory where the pointer members point for replay
 */
template <typename Arch>
static void record_and_restore_msgvec(
    Task* t, bool has_saved_arg_ptrs, int nmmsgs,
    remote_ptr<typename Arch::mmsghdr> pnewmsg,
    remote_ptr<typename Arch::mmsghdr> poldmsg) {
  if (!has_saved_arg_ptrs) {
    for (int i = 0; i < nmmsgs; ++i) {
      record_struct_mmsghdr<Arch>(t, pnewmsg + i);
    }
    return;
  }

  for (int i = 0; i < nmmsgs; ++i) {
    auto old = t->read_mem(poldmsg + i);
    auto tmp = t->read_mem(pnewmsg + i);

    old.msg_len = tmp.msg_len;
    t->write_mem(poldmsg + i, old);

    // record the msghdr part of mmsghdr
    record_and_restore_msghdr<Arch>(t, REMOTE_PTR_FIELD(poldmsg + i, msg_hdr),
                                    REMOTE_PTR_FIELD(pnewmsg + i, msg_hdr));
    // record mmsghdr.msg_len
    t->record_local(REMOTE_PTR_FIELD(poldmsg + i, msg_len), &old.msg_len);
  }
}

/*
 * Record msg_len of each element of msgvec
 * */
template <typename Arch>
static void record_each_msglen(Task* t, int nmmsgs,
                               remote_ptr<typename Arch::mmsghdr> msgvec) {
  /* Record the outparam msg_len fields. */
  for (int i = 0; i < nmmsgs; ++i, ++msgvec) {
    t->record_remote(REMOTE_PTR_FIELD(msgvec, msg_len));
  }
}

template <typename Arch>
static void process_socketcall(Task* t, int call, remote_ptr<void> base_addr) {
  LOG(debug) << "socket call: " << call;

  switch (call) {
    /* int socket(int domain, int type, int protocol); */
    case SYS_SOCKET:
    /* int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
     */
    case SYS_CONNECT:
    /* int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen); */
    case SYS_BIND:
    /* int listen(int sockfd, int backlog) */
    case SYS_LISTEN:
    /* ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) */
    case SYS_SENDMSG:
    /* ssize_t send(int sockfd, const void *buf, size_t len, int flags) */
    case SYS_SEND:
    /* ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const
     * struct sockaddr *dest_addr, socklen_t addrlen); */
    case SYS_SENDTO:
    /* int setsockopt(int sockfd, int level, int optname, const void *optval,
     * socklen_t optlen); */
    case SYS_SETSOCKOPT:
    /* int shutdown(int socket, int how) */
    case SYS_SHUTDOWN:
      return;

    /* int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
     */
    case SYS_GETPEERNAME:
    /* int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
     */
    case SYS_GETSOCKNAME: {
      auto args =
          t->read_mem(base_addr.cast<typename Arch::getsockname_args>());
      auto len = t->read_mem(args.addrlen.rptr());
      t->record_remote(args.addrlen.rptr());
      t->record_remote(args.addr, len);
      return;
    }

    /* ssize_t recv(int sockfd, void *buf, size_t len, int flags)
     * implemented by:
     * int socketcall(int call, unsigned long *args) {
     *   long a[6];
     *   copy_from_user(a,args);
     *   sys_recv(a0, (void __user *)a1, a[2], a[3]);
     * }
     */
    case SYS_RECV: {
      AutoRestoreScratch restore_scratch(t, ALLOW_SLACK);
      remote_ptr<void> buf;
      remote_ptr<void> argsp;
      typename Arch::recv_args args;
      ssize_t nrecvd = t->regs().syscall_result_signed();
      if (has_saved_arg_ptrs(t)) {
        buf = pop_arg_ptr<void>(t);
        argsp = pop_arg_ptr<void>(t);
        /* We don't need to record the fudging of the
         * socketcall arguments, because we won't
         * replay that. */
        restore_scratch.read_arg(&args);
      } else {
        remote_ptr<void> argsp;
        args = read_socketcall_args<typename Arch::recv_args>(t, &argsp);
        buf = args.buf;
      }

      /* Restore |buf| contents. */
      if (0 < nrecvd) {
        if (restore_scratch.scratch_used()) {
          restore_scratch.restore_and_record_arg_buf(buf, nrecvd);
        } else {
          t->record_remote(buf, nrecvd);
        }
      } else {
        record_noop_data(t);
      }

      if (restore_scratch.scratch_used()) {
        Registers r = t->regs();
        /* Restore the pointer to the original args. */
        r.set_arg2(argsp);
        t->set_regs(r);
      }
      return;
    }
    case SYS_RECVFROM: {
      auto args = t->read_mem(base_addr.cast<typename Arch::recvfrom_args>());

      ssize_t recvdlen = t->regs().syscall_result_signed();
      if (has_saved_arg_ptrs(t)) {
        auto src_addrp = pop_arg_ptr<typename Arch::sockaddr>(t);
        auto addrlenp = pop_arg_ptr<typename Arch::socklen_t>(t);
        auto buf = pop_arg_ptr<void>(t);
        auto argsp = pop_arg_ptr<void>(t);

        if (recvdlen > 0) {
          t->remote_memcpy(buf, args.buf, recvdlen);
        }
        args.buf = buf;

        if (!src_addrp.is_null()) {
          auto addrlen = t->read_mem(args.addrlen.rptr());
          t->remote_memcpy(src_addrp, args.src_addr, addrlen);
          t->write_mem(addrlenp, addrlen);
          args.src_addr = src_addrp;
          args.addrlen = addrlenp;
        }
        Registers r = t->regs();
        r.set_arg2(argsp);
        t->set_regs(r);
      }

      if (recvdlen > 0) {
        t->record_remote(args.buf, recvdlen);
      } else {
        record_noop_data(t);
      }
      if (args.src_addr) {
        auto addrlen = t->read_mem(args.addrlen.rptr());
        t->record_remote(args.addrlen.rptr());
        t->record_remote(args.src_addr.rptr(), addrlen);
      } else {
        record_noop_data(t);
        record_noop_data(t);
      }
      return;
    }
    /* ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags); */
    case SYS_RECVMSG: {
      Registers r = t->regs();
      remote_ptr<typename Arch::recvmsg_args> tmpargsp = r.arg2();
      auto tmpargs = t->read_mem(tmpargsp);
      if (!has_saved_arg_ptrs(t)) {
        return record_struct_msghdr<Arch>(t, tmpargs.msg);
      }

      auto argsp = pop_arg_ptr<typename Arch::recvmsg_args>(t);
      auto args = t->read_mem(argsp);

      record_and_restore_msghdr<Arch>(t, args.msg, tmpargs.msg);

      r.set_arg2(argsp);
      t->set_regs(r);
      return;
    }

    /*
     *  int getsockopt(int sockfd, int level, int optname, const void *optval,
     * socklen_t* optlen);
     */
    case SYS_GETSOCKOPT: {
      auto args = t->read_mem(base_addr.cast<typename Arch::getsockopt_args>());
      auto optlen = t->read_mem(args.optlen.rptr());
      t->record_remote(args.optlen.rptr());
      t->record_remote(args.optval, optlen);
      return;
    }

    /*
     *  int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
     *  int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int
     *flags);
     *
     * Note: The returned address is truncated if the buffer
     * provided is too small; in this case, addrlen will return a
     * value greater than was supplied to the call.
     *
     * For now we record the size of bytes that is returned by the
     * system call. We check in the replayer, if the buffer was
     * actually too small and throw an error there.
     */
    case SYS_ACCEPT:
    case SYS_ACCEPT4: {
      Registers r = t->regs();
      auto addrp = pop_arg_ptr<typename Arch::sockaddr>(t);
      auto addrlenp = pop_arg_ptr<typename Arch::socklen_t>(t);
      auto orig_argsp = pop_arg_ptr<void>(t);

      AutoRestoreScratch restore_scratch(t, ALLOW_SLACK);
      // Consume the scratch args.
      if (SYS_ACCEPT == call) {
        typename Arch::accept_args args;
        restore_scratch.read_arg(&args);
      } else {
        typename Arch::accept4_args args;
        restore_scratch.read_arg(&args);
      }
      typename Arch::socklen_t addrlen;
      restore_scratch.restore_and_record_arg(addrlenp, &addrlen);
      restore_scratch.restore_and_record_arg_buf(addrp, addrlen);

      /* Restore the pointer to the original args. */
      r.set_arg2(orig_argsp);
      t->set_regs(r);
      return;
    }

    /* int socketpair(int domain, int type, int protocol, int sv[2]);
     *
     * values returned in sv
     */
    case SYS_SOCKETPAIR: {
      auto args = t->read_mem(base_addr.cast<typename Arch::socketpair_args>());
      t->record_remote(args.sv, 2 * args.sv.referent_size());
      return;
    }

    /* int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
     *              unsigned int flags, struct timespec *timeout);*/
    case SYS_RECVMMSG: {
      Registers r = t->regs();
      int nmmsgs = r.syscall_result_signed();

      remote_ptr<typename Arch::recvmmsg_args> tmpargsp = r.arg2();
      auto tmpargs = t->read_mem(tmpargsp);

      typename Arch::recvmmsg_args args;
      bool has_saved_ptr = has_saved_arg_ptrs(t);
      if (has_saved_ptr) {
        auto argsp = pop_arg_ptr<typename Arch::recvmmsg_args>(t);
        args = t->read_mem(argsp);
        r.set_arg2(argsp);
        t->set_regs(r);
      }

      record_and_restore_msgvec<Arch>(t, has_saved_ptr, nmmsgs, tmpargs.msgvec,
                                      args.msgvec);
      return;
    }

    /* int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
    *              unsigned int flags);*/
    case SYS_SENDMMSG: {
      remote_ptr<typename Arch::sendmmsg_args> argsp = t->regs().arg2();
      auto args = t->read_mem(argsp);
      record_each_msglen<Arch>(t, t->regs().syscall_result_signed(),
                               args.msgvec);
      return;
    }

    default:
      FATAL() << "Unknown socketcall " << call;
  }
}

template <typename Arch>
static void before_syscall_exit(Task* t, int syscallno) {
  t->maybe_update_vm(syscallno, SYSCALL_EXIT);

  switch (syscallno) {
    case Arch::setpriority: {
      // The syscall might have failed due to insufficient
      // permissions (e.g. while trying to decrease the nice value
      // while not root).
      // We'll choose to honor the new value anyway since we'd like
      // to be able to test configurations where a child thread
      // has a lower nice value than its parent, which requires
      // lowering the child's nice value.
      if ((int)t->regs().arg1_signed() == PRIO_PROCESS) {
        Task* target =
            (int)t->regs().arg2_signed()
                ? t->session().find_task((int)t->regs().arg2_signed())
                : t;
        if (target) {
          LOG(debug) << "Setting nice value for tid " << t->tid << " to "
                     << t->regs().arg3();
          target->set_priority((int)t->regs().arg3_signed());
        }
      }
      return;
    }
    case Arch::set_robust_list:
      t->set_robust_list(t->regs().arg1(), (size_t)t->regs().arg2());
      return;

    case Arch::set_thread_area:
      t->set_thread_area(t->regs().arg1());
      return;

    case Arch::set_tid_address:
      t->set_tid_addr(t->regs().arg1());
      return;

    case Arch::sigaction:
    case Arch::rt_sigaction:
      // TODO: SYS_signal
      t->update_sigaction(t->regs());
      return;

    case Arch::sigprocmask:
    case Arch::rt_sigprocmask:
      t->update_sigmask(t->regs());
      return;
  }
}

static void check_syscall_rejected(Task* t) {
  // Invalid syscalls return -ENOSYS. Assume any such
  // result means the syscall was completely ignored by the
  // kernel so it's OK for us to not do anything special.
  // Other results mean we probably need to understand this
  // syscall, but we don't.
  if (t->regs().syscall_result_signed() != -ENOSYS) {
    t->regs().print_register_file(stderr);
    int syscallno = t->ev().Syscall().number;
    FATAL() << "Unhandled syscall " << t->syscallname(syscallno) << "("
            << syscallno << ") returned " << t->regs().syscall_result_signed();
  }
}

template <typename Arch> static void rec_process_syscall_arch(Task* t) {
  int syscallno = t->ev().Syscall().number;

  LOG(debug) << t->tid << ": processing: " << t->ev()
             << " -- time: " << t->trace_time();

  before_syscall_exit<Arch>(t, syscallno);

  if (const struct syscallbuf_record* rec = t->desched_rec()) {
    assert(t->ev().Syscall().tmp_data_ptr != t->scratch_ptr);

    t->record_local(t->ev().Syscall().tmp_data_ptr,
                    t->ev().Syscall().tmp_data_num_bytes,
                    (uint8_t*)rec->extra_data);
    return;
  }

  if (syscallno < 0) {
    check_syscall_rejected(t);
    return;
  }

  switch (syscallno) {

// All the regular syscalls are handled here.
#include "SyscallRecordCase.generated"

    case Arch::clone: {
      long new_tid = t->regs().syscall_result_signed();
      Task* new_task = t->session().find_task(new_tid);
      uintptr_t flags = pop_arg_ptr<void>(t).as_int();

      if (flags & CLONE_UNTRACED) {
        Registers r = t->regs();
        r.set_arg1(flags);
        t->set_regs(r);
      }

      if (new_tid < 0)
        break;

      new_task->push_event(SyscallEvent(syscallno));

      /* record child id here */
      new_task->record_remote(
          remote_ptr<typename Arch::pid_t>(t->regs().arg3()));
      new_task->record_remote(
          remote_ptr<typename Arch::pid_t>(t->regs().arg4()));

      new_task->record_remote(
          remote_ptr<typename Arch::user_desc>(new_task->regs().arg5()));
      new_task->record_remote(
          remote_ptr<typename Arch::pid_t>(new_task->regs().arg3()));
      new_task->record_remote(
          remote_ptr<typename Arch::pid_t>(new_task->regs().arg4()));

      new_task->pop_syscall();

      init_scratch_memory<Arch>(new_task);
      // The new tracee just "finished" a clone that was
      // started by its parent.  It has no pending events,
      // so it can be context-switched out.
      new_task->switchable = ALLOW_SWITCH;

      break;
    }
    case Arch::epoll_wait: {
      AutoRestoreScratch restore_scratch(t);
      auto events = pop_arg_ptr<typename Arch::epoll_event>(t);
      int maxevents = t->regs().arg3_signed();
      if (!events.is_null()) {
        restore_scratch.restore_and_record_args(events, maxevents);
        Registers r = t->regs();
        r.set_arg2(events);
        t->set_regs(r);
      } else {
        record_noop_data(t);
      }
      break;
    }
    case Arch::execve:
      process_execve<Arch>(t);
      break;

    case Arch::fcntl:
    case Arch::fcntl64: {
      int cmd = t->regs().arg2_signed();
      switch (cmd) {
        case Arch::DUPFD:
        case Arch::GETFD:
        case Arch::GETFL:
        case Arch::SETFL:
        case Arch::SETFD:
        case Arch::SETOWN:
        case Arch::SETOWN_EX:
        case Arch::SETSIG:
          break;

        case Arch::GETLK:
          t->record_remote(remote_ptr<typename Arch::flock>(t->regs().arg3()));
          break;

        case Arch::SETLK:
        case Arch::SETLKW:
          break;

        case Arch::GETLK64:
          // flock and flock64 better be different on 32-bit architectures, but
          // on 64-bit architectures, it's OK if they're the same.
          static_assert(
              sizeof(typename Arch::flock) < sizeof(typename Arch::flock64) ||
                  Arch::elfclass == ELFCLASS64,
              "struct flock64 not declared differently from struct flock");
          t->record_remote(
              remote_ptr<typename Arch::flock64>(t->regs().arg3()));
          break;

        case Arch::SETLK64:
        case Arch::SETLKW64:
          break;

        case Arch::GETOWN_EX:
          t->record_remote(
              remote_ptr<typename Arch::f_owner_ex>(t->regs().arg3()));
          break;

        default:
          FATAL() << "Unknown fcntl " << cmd;
      }
      break;
    }
    case Arch::futex: {
      t->record_remote(remote_ptr<int>(t->regs().arg1()));
      int op = (int)t->regs().arg2_signed() & FUTEX_CMD_MASK;

      switch (op) {

        case FUTEX_WAKE:
        case FUTEX_WAIT_BITSET:
        case FUTEX_WAIT:
          break;

        case FUTEX_CMP_REQUEUE:
        case FUTEX_WAKE_OP:
          t->record_remote(remote_ptr<int>(t->regs().arg5()));
          break;

        default:
          FATAL() << "Unknown futex op " << op;
      }

      break;
    }
    case Arch::getxattr:
    case Arch::lgetxattr:
    case Arch::fgetxattr: {
      ssize_t len = t->regs().syscall_result_signed();
      if (len > 0) {
        remote_ptr<void> value = t->regs().arg3();
        t->record_remote(value, len);
      } else {
        record_noop_data(t);
      }
      break;
    }
    case Arch::ioctl:
      process_ioctl<Arch>(t, (int)t->regs().arg2_signed());
      break;

    case Arch::msgctl:
      process_msgctl<Arch>(t, (int)t->regs().arg2_signed(),
                           t->regs().arg3());
      break;

    case Arch::ipc:
      process_ipc<Arch>(t, (unsigned int)t->regs().arg1());
      break;

    case Arch::mmap:
      switch (Arch::mmap_semantics) {
        case Arch::StructArguments: {
          auto args =
            t->read_mem(remote_ptr<typename Arch::mmap_args>(t->regs().arg1()));
          process_mmap(t, syscallno, args.len, args.prot, args.flags, args.fd,
                       args.offset / 4096);
          break;
        }
        case Arch::RegisterArguments:
          process_mmap(t, syscallno, (size_t)t->regs().arg2(),
                       (int)t->regs().arg3_signed(), (int)t->regs().arg4_signed(),
                       (int)t->regs().arg5_signed(),
                       (off_t)t->regs().arg6_signed());
          break;
      }
      break;
    case Arch::mmap2:
      process_mmap(t, syscallno, (size_t)t->regs().arg2(),
                   (int)t->regs().arg3_signed(), (int)t->regs().arg4_signed(),
                   (int)t->regs().arg5_signed(),
                   (off_t)t->regs().arg6_signed());
      break;

    case Arch::nanosleep: {
      AutoRestoreScratch restore_scratch(t, ALLOW_SLACK);
      auto rem = pop_arg_ptr<typename Arch::timespec>(t);

      if (!rem.is_null()) {
        Registers r = t->regs();
        /* If the sleep completes, the kernel doesn't
         * write back to the remaining-time
         * argument. */
        if (0 == (int)r.syscall_result_signed()) {
          record_noop_data(t);
        } else {
          /* TODO: where are we supposed to
           * write back these args?  We don't
           * see an EINTR return from
           * nanosleep() when it's interrupted
           * by a user-handled signal. */
          restore_scratch.restore_and_record_arg(rem);
        }
        r.set_arg2(rem);
        t->set_regs(r);
      }
      break;
    }
    case Arch::open: {
      string pathname = t->read_c_str(remote_ptr<void>(t->regs().arg1()));
      if (is_blacklisted_filename(pathname.c_str())) {
        /* NB: the file will still be open in the
         * process's file table, but let's hope this
         * gross hack dies before we have to worry
         * about that. */
        LOG(warn) << "Cowardly refusing to open " << pathname;
        Registers r = t->regs();
        r.set_syscall_result(-ENOENT);
        t->set_regs(r);
      }
      break;
    }
    case Arch::poll:
    case Arch::ppoll: {
      AutoRestoreScratch restore_scratch(t);
      auto fds = pop_arg_ptr<typename Arch::pollfd>(t);
      size_t nfds = t->regs().arg2();

      restore_scratch.restore_and_record_args(fds, nfds);
      Registers r = t->regs();
      r.set_arg1(fds);
      t->set_regs(r);
      break;
    }
    case Arch::prctl: {
      int size;
      switch ((int)t->regs().arg1_signed()) {
        /* See rec_prepare_syscall() for how these
         * sizes are determined. */
        case PR_GET_ENDIAN:
        case PR_GET_FPEMU:
        case PR_GET_FPEXC:
        case PR_GET_PDEATHSIG:
        case PR_GET_TSC:
        case PR_GET_UNALIGN:
          size = sizeof(int);
          break;

        case PR_SET_NAME:
          t->update_prname(t->regs().arg2());
        // fall through
        case PR_GET_NAME:
          // We actually execute these during replay, so
          // no need to save any data.
          size = 0;
          break;

        default:
          size = 0;
          break;
      }
      if (size > 0) {
        AutoRestoreScratch restore_scratch(t);
        auto arg = pop_arg_ptr<void>(t);

        restore_scratch.restore_and_record_arg_buf(arg, size);
        Registers r = t->regs();
        r.set_arg2(arg);
        t->set_regs(r);
      } else {
        record_noop_data(t);
      }
      break;
    }
    case Arch::quotactl: {
      int cmd = (int)t->regs().arg1_signed() & SUBCMDMASK;
      remote_ptr<void> addr = t->regs().arg4();
      switch (cmd) {
        case Q_GETQUOTA:
          t->record_remote(addr.cast<typename Arch::dqblk>());
          break;
        case Q_GETINFO:
          t->record_remote(addr.cast<typename Arch::dqinfo>());
          break;
        case Q_GETFMT:
          t->record_remote(addr, 4 /*FIXME: magic number*/);
          break;
        case Q_SETQUOTA:
          FATAL() << "Trying to set disk quota usage, this may interfere with "
                     "rr recording";
        // not reached
        default:
          // TODO: some of these may need to be
          // recorded ...
          break;
      }
      break;
    }
    case Arch::read: {
      AutoRestoreScratch restore_scratch(t, ALLOW_SLACK);
      remote_ptr<void> buf;

      ssize_t nread = t->regs().syscall_result_signed();
      if (has_saved_arg_ptrs(t)) {
        buf = pop_arg_ptr<void>(t);
      } else {
        buf = t->regs().arg2();
      }

      if (nread > 0) {
        if (restore_scratch.scratch_used()) {
          restore_scratch.restore_and_record_arg_buf(buf, nread);
        } else {
          t->record_remote(buf, nread);
        }
      } else {
        record_noop_data(t);
      }

      if (restore_scratch.scratch_used()) {
        Registers r = t->regs();
        r.set_arg2(buf);
        t->set_regs(r);
      }
      break;
    }
    case Arch::recvmmsg: {
      Registers r = t->regs();
      int nmmsgs = r.syscall_result_signed();

      remote_ptr<typename Arch::mmsghdr> msg = r.arg2();
      remote_ptr<typename Arch::mmsghdr> oldmsg = nullptr;

      bool has_saved_ptr = has_saved_arg_ptrs(t);
      if (has_saved_ptr) {
        oldmsg = pop_arg_ptr<typename Arch::mmsghdr>(t);
        r.set_arg2(oldmsg);
        t->set_regs(r);
      }

      record_and_restore_msgvec<Arch>(t, has_saved_ptr, nmmsgs, msg, oldmsg);
      break;
    }
    case Arch::rt_sigtimedwait: {
      Registers r = t->regs();
      if (t->ev().Syscall().saved_args.empty()) {
        remote_ptr<typename Arch::siginfo_t> info = r.arg2();
        if (!info.is_null()) {
          t->record_remote(info);
        } else {
          record_noop_data(t);
        }
        break;
      }

      AutoRestoreScratch restore_scratch(t);
      auto info = pop_arg_ptr<typename Arch::siginfo_t>(t);
      if (!info.is_null()) {
        restore_scratch.restore_and_record_arg(info);
        r.set_arg2(info);
      } else {
        record_noop_data(t);
      }
      t->set_regs(r);
      break;
    }
    case Arch::sendfile64: {
      AutoRestoreScratch restore_scratch(t);
      auto offset = pop_arg_ptr<loff_t>(t);

      Registers r = t->regs();
      if (!offset.is_null()) {
        restore_scratch.restore_and_record_arg(offset);
        r.set_arg3(offset);
      } else {
        record_noop_data(t);
      }

      t->set_regs(r);
      break;
    }
    case Arch::sendmmsg: {
      remote_ptr<typename Arch::mmsghdr> msg = t->regs().arg2();
      record_each_msglen<Arch>(t, t->regs().syscall_result_signed(), msg);
      break;
    }
    case Arch::socketcall:
      process_socketcall<Arch>(t, (int)t->regs().arg1_signed(),
                               t->regs().arg2());
      break;

    case Arch::splice: {
      AutoRestoreScratch restore_scratch(t);
      auto off_out = pop_arg_ptr<loff_t>(t);
      auto off_in = pop_arg_ptr<loff_t>(t);

      Registers r = t->regs();
      if (!off_in.is_null()) {
        restore_scratch.restore_and_record_arg(off_in);
        r.set_arg2(off_in);
      } else {
        record_noop_data(t);
      }
      if (!off_out.is_null()) {
        restore_scratch.restore_and_record_arg(off_out);
        r.set_arg4(off_out);
      } else {
        record_noop_data(t);
      }

      t->set_regs(r);
      break;
    }
    case Arch::_sysctl: {
      auto oldlenp = pop_arg_ptr<size_t>(t);
      auto oldval = pop_arg_ptr<void>(t);
      size_t oldlen = t->read_mem(oldlenp);
      t->record_remote(oldlenp);
      t->record_remote(oldval, oldlen);
      break;
    }
    case Arch::waitid: {
      AutoRestoreScratch restore_scratch(t);
      auto infop = pop_arg_ptr<typename Arch::siginfo_t>(t);

      Registers r = t->regs();
      if (!infop.is_null()) {
        restore_scratch.restore_and_record_arg(infop);
        r.set_arg3(infop);
      } else {
        record_noop_data(t);
      }
      t->set_regs(r);
      break;
    }
    case Arch::waitpid:
    case Arch::wait4: {
      AutoRestoreScratch restore_scratch(t);
      auto rusage = pop_arg_ptr<typename Arch::rusage>(t);
      auto status = pop_arg_ptr<int>(t);

      Registers r = t->regs();
      if (!status.is_null()) {
        restore_scratch.restore_and_record_arg(status);
        r.set_arg2(status);
      } else {
        record_noop_data(t);
      }
      if (!rusage.is_null()) {
        restore_scratch.restore_and_record_arg(rusage);
        r.set_arg4(rusage);
      } else if (Arch::wait4 == syscallno) {
        record_noop_data(t);
      }
      t->set_regs(r);
      break;
    }
    case Arch::write:
    case Arch::writev:
      break;
    case Arch::sched_setaffinity: {
      // Restore the register that we altered.
      Registers r = t->regs();
      r.set_arg1(pop_arg_ptr<void>(t));
      // Pretend the syscall succeeded.
      r.set_syscall_result(0);
      t->set_regs(r);
      break;
    }

    case SYS_rrcall_init_buffers:
      t->init_buffers(nullptr, SHARE_DESCHED_EVENT_FD);
      break;

    case SYS_rrcall_monkeypatch_vdso:
      monkeypatch_vdso(t);
      break;

    default:
      check_syscall_rejected(t);
      break;
  }
}

void rec_process_syscall(Task* t) {
  RR_ARCH_FUNCTION(rec_process_syscall_arch, t->arch(), t)
}
