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

#include "drm.h"
#include "kernel_abi.h"
#include "log.h"
#include "recorder.h" // for terminate_recording()
#include "recorder_sched.h"
#include "remote_syscalls.h"
#include "session.h"
#include "syscalls.h"
#include "task.h"
#include "trace.h"
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
  void* buf = (void*)t->regs().arg2();
  size_t len = t->regs().arg3();

  ASSERT(t, buf) << "Can't save a null buffer";

  t->record_remote(buf, len);
}

void rec_before_record_syscall_entry(Task* t, int syscallno)
    RR_ARCH_FUNCTION(rec_before_record_syscall_entry_arch, t->arch(), t,
                     syscallno)

    /**
     * Read the socketcall args pushed by |t| as part of the syscall in
     * |regs| into the |args| outparam.  Also store the address of the
     * socketcall args into |*argsp|.
     */
    template <typename T>
void read_socketcall_args(Task* t, long** argsp, T* args) {
  void* p = (void*)t->regs().arg2();
  t->read_mem(p, args);
  *argsp = (long*)p;
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
static void push_arg_ptr(Task* t, void* argp) {
  t->ev().Syscall().saved_args.push(argp);
}

/**
 * Reset scratch state for |t|, because scratch can't be used for
 * |event|.  Log a warning as well.
 */
static int abort_scratch(Task* t, const char* event) {
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
  return 0; /* don't allow context-switching */
}

/**
 * Return nonzero if the scratch state initialized for |t| fits
 * within the allocated region (and didn't overflow), zero otherwise.
 */
static int can_use_scratch(Task* t, uint8_t* scratch_end) {
  uint8_t* scratch_start = (uint8_t*)t->scratch_ptr;

  assert(t->ev().Syscall().tmp_data_ptr == t->scratch_ptr);

  t->ev().Syscall().tmp_data_num_bytes = (scratch_end - scratch_start);
  return (0 <= t->ev().Syscall().tmp_data_num_bytes &&
          t->ev().Syscall().tmp_data_num_bytes <= t->scratch_size);
}

/**
 * Return nonzero if it's OK to context-switch away from |t| for its
 * ipc call.  If so, prepare any required scratch buffers for |t|.
 */
template <typename Arch>
static int prepare_ipc(Task* t, int would_need_scratch) {
  int call = t->regs().arg1_signed();
  uint8_t* scratch =
      would_need_scratch ? (uint8_t*)t->ev().Syscall().tmp_data_ptr : nullptr;

  assert(!t->desched_rec());

  switch (call) {
    case MSGRCV: {
      if (!would_need_scratch) {
        return 1;
      }
      size_t msgsize = t->regs().arg3();
      typename Arch::ipc_kludge_args kludge;
      void* child_kludge = (void*)t->regs().arg5();
      t->read_mem(child_kludge, &kludge);

      push_arg_ptr(t, kludge.msgbuf);
      kludge.msgbuf = scratch;
      scratch += msgsize;
      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, "msgrcv");
      }
      t->write_mem(child_kludge, kludge);
      return 1;
    }
    case MSGSND:
      return 1;
    default:
      return 0;
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
                                       uint8_t** scratch) {
  auto tmpmsg = *msg;
  // reserve space
  uint8_t* scratch_tmp = *scratch;
  if (msg->msg_name) {
    tmpmsg.msg_name = scratch_tmp;
    scratch_tmp += msg->msg_namelen;
  }

  typename Arch::iovec iovs[msg->msg_iovlen];
  ssize_t num_iov_bytes = read_iovs<Arch>(t, *msg, iovs);
  tmpmsg.msg_iov = (typename Arch::iovec*)scratch_tmp;
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
static bool reserve_scratch_for_msgvec(Task* t, unsigned int vlen,
                                       typename Arch::mmsghdr* pmsgvec,
                                       uint8_t** scratch) {
  typename Arch::mmsghdr msgvec[vlen];
  t->read_bytes_helper(pmsgvec, sizeof(msgvec), (uint8_t*)msgvec);

  // Reserve scratch for struct mmsghdr *msgvec
  auto tmpmsgvec = (typename Arch::mmsghdr*)*scratch;
  *scratch += sizeof(msgvec);

  // Reserve scratch for child pointers of struct msghdr
  for (unsigned int i = 0; i < vlen; ++i) {
    if (!reserve_scratch_for_msghdr<Arch>(t, &(msgvec[i].msg_hdr), scratch)) {
      return false;
    }
  }

  // Write back the modified msgvec
  t->write_bytes_helper(tmpmsgvec, sizeof(msgvec), (uint8_t*)msgvec);
  return true;
}

/**
 * Initialize any necessary state to execute the socketcall that |t|
 * is stopped at, for example replacing tracee args with pointers into
 * scratch memory if necessary.
 */
template <typename Arch>
static int prepare_socketcall(Task* t, int would_need_scratch) {
  uint8_t* scratch =
      would_need_scratch ? (uint8_t*)t->ev().Syscall().tmp_data_ptr : nullptr;
  long* argsp;
  void* tmpargsp;
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
  int call = r.arg1_signed();
  switch (call) {
    /* ssize_t recv([int sockfd, void *buf, size_t len, int flags]) */
    case SYS_RECV: {
      typename Arch::recv_args args;

      if (!would_need_scratch) {
        return 1;
      }
      read_socketcall_args(t, &argsp, &args);
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
      r.set_arg2((uintptr_t)(tmpargsp = scratch));
      scratch += sizeof(args);
      /* The |buf| pointer. */
      push_arg_ptr(t, (void*)args.buf);
      args.buf = scratch;
      scratch += args.len;
      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, "recv");
      }

      t->write_mem(tmpargsp, args);
      t->set_regs(r);
      return 1;
    }

    /* int accept([int sockfd, struct sockaddr *addr, socklen_t *addrlen]) */
    /* int accept4([int sockfd, struct sockaddr *addr, socklen_t *addrlen, int
     * flags]) */
    case SYS_ACCEPT:
    case SYS_ACCEPT4: {
      if (!would_need_scratch) {
        return 1;
      }
      Registers r = t->regs();
      void* argsp = (void*)r.arg2();
      typename Arch::accept4_args args;
      if (SYS_ACCEPT == call) {
        t->read_mem(argsp, &args._);
      } else {
        t->read_mem(argsp, &args);
      }

      typename Arch::socklen_t addrlen;
      t->read_mem(args._.addrlen, &addrlen);

      // We use the same basic scheme here as for RECV
      // above.  For accept() though, there are two
      // (in)outparams: |addr| and |addrlen|.  |*addrlen| is
      // the total size of |addr|, so we reserve that much
      // space for it.  |*addrlen| is set to the size of the
      // returned sockaddr, so we reserve space for
      // |addrlen| too.

      // Reserve space for scratch socketcall args.
      push_arg_ptr(t, argsp);
      void* tmpargsp = scratch;
      r.set_arg2((uintptr_t)tmpargsp);
      scratch += (SYS_ACCEPT == call) ? sizeof(args._) : sizeof(args);

      push_arg_ptr(t, args._.addrlen);
      args._.addrlen = (typename Arch::socklen_t*)scratch;
      scratch += sizeof(*args._.addrlen);

      push_arg_ptr(t, args._.addr);
      args._.addr = (typename Arch::sockaddr*)scratch;
      scratch += addrlen;
      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, "accept");
      }

      if (SYS_ACCEPT == call) {
        t->write_mem(tmpargsp, args._);
      } else {
        t->write_mem(tmpargsp, args);
      }
      t->write_mem(args._.addrlen, addrlen);
      t->set_regs(r);
      return 1;
    }
    case SYS_RECVFROM: {
      if (!would_need_scratch) {
        return 1;
      }
      Registers r = t->regs();
      void* argsp = (void*)r.arg2();
      typename Arch::recvfrom_args args;
      t->read_mem(argsp, &args);

      // Reserve space for scratch socketcall args.
      push_arg_ptr(t, argsp);
      void* tmpargsp = scratch;
      r.set_arg2((uintptr_t)tmpargsp);
      scratch += sizeof(args);

      push_arg_ptr(t, args.buf);
      args.buf = scratch;
      scratch += args.len;

      typename Arch::socklen_t addrlen;
      if (args.src_addr) {
        t->read_mem(args.addrlen, &addrlen);

        push_arg_ptr(t, args.addrlen);
        args.addrlen = (typename Arch::socklen_t*)scratch;
        scratch += sizeof(*args.addrlen);

        push_arg_ptr(t, args.src_addr);
        args.src_addr = (typename Arch::sockaddr*)scratch;
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
        t->write_mem(args.addrlen, addrlen);
      }
      t->set_regs(r);
      return 1;
    }
    case SYS_RECVMSG: {
      Registers r = t->regs();
      void* argsp = (void*)r.arg2();
      typename Arch::recvmsg_args args;
      t->read_mem(argsp, &args);
      if (args.flags & MSG_DONTWAIT) {
        return 0;
      }
      if (!would_need_scratch) {
        return 1;
      }
      typename Arch::msghdr msg;
      t->read_mem(args.msg, &msg);

      // Reserve scratch for the arg
      push_arg_ptr(t, argsp);
      void* tmpargsp = scratch;
      scratch += sizeof(args);
      r.set_arg2((uintptr_t)tmpargsp);

      // Reserve scratch for the struct msghdr
      uint8_t* scratch_msg = scratch;
      scratch += sizeof(msg);

      // Reserve scratch for the child pointers of struct msghdr
      if (reserve_scratch_for_msghdr<Arch>(t, &msg, &scratch)) {
        t->write_mem(scratch_msg, msg);
      } else {
        return 0;
      }

      args.msg = (typename Arch::msghdr*)scratch_msg;
      t->write_mem(tmpargsp, args);
      t->set_regs(r);

      return 1;
    }
    case SYS_SENDMSG: {
      Registers r = t->regs();
      void* argsp = (void*)r.arg2();
      typename Arch::recvmsg_args args;
      t->read_mem(argsp, &args);
      return !(args.flags & MSG_DONTWAIT);
    }
    case SYS_SENDMMSG: {
      Registers r = t->regs();
      void* argsp = (void*)r.arg2();
      typename Arch::sendmmsg_args args;
      t->read_mem(argsp, &args);
      return !(args.flags & MSG_DONTWAIT);
    }
    case SYS_RECVMMSG: {
      Registers r = t->regs();
      void* argsp = (void*)r.arg2();
      typename Arch::recvmmsg_args args;
      t->read_mem(argsp, &args);

      if (args.flags & MSG_DONTWAIT) {
        return 0;
      }
      if (!would_need_scratch) {
        return 1;
      }

      // Reserve scratch for the arg
      push_arg_ptr(t, argsp);
      void* tmpargsp = scratch;
      scratch += sizeof(args);
      r.set_arg2((uintptr_t)tmpargsp);

      // Update msgvec pointer of tmp arg
      typename Arch::mmsghdr* poldmsgvec = args.msgvec;
      args.msgvec = (typename Arch::mmsghdr*)scratch;
      t->write_mem(tmpargsp, args);

      if (reserve_scratch_for_msgvec<Arch>(t, args.vlen, poldmsgvec,
                                           &scratch)) {
        t->set_regs(r);
        return 1;
      } else
        return 0;
    }
    default:
      return 0;
  }
}

#define RR_KCMP_FILE 0

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
 * Returns 1 if the syscall should be interruptible, 0 otherwise.
 */
template <typename Arch>
static int set_up_scratch_for_syscallbuf(Task* t, int syscallno) {
  const struct syscallbuf_record* rec = t->desched_rec();

  assert(rec);
  ASSERT(t, syscallno == rec->syscallno) << "Syscallbuf records syscall "
                                         << t->syscallname(rec->syscallno)
                                         << ", but expecting "
                                         << t->syscallname(syscallno);

  reset_scratch_pointers(t);
  t->ev().Syscall().tmp_data_ptr =
      (uint8_t*)t->syscallbuf_child +
      (rec->extra_data - (uint8_t*)t->syscallbuf_hdr);
  /* |rec->size| is the entire record including extra data; we
   * just care about the extra data here. */
  t->ev().Syscall().tmp_data_num_bytes = rec->size - sizeof(*rec);

  switch (syscallno) {
    case Arch::write:
    case Arch::writev:
      return !is_stdio_fd<Arch>(t, (int)t->regs().arg1_signed());
  }

  return 1;
}

static bool exec_file_supported(const string& filename) {
  /* All this function does is reject 64-bit ELF binaries. Everything
     else we (optimistically) indicate support for. Missing or corrupt
     files will cause execve to fail normally. When we support 64-bit,
     this entire function can be removed. */
  int fd = open(filename.c_str(), O_RDONLY);
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
  close(fd);
  return ok;
}

template <typename Arch> static int rec_prepare_syscall_arch(Task* t) {
  int syscallno = t->ev().Syscall().no;
  /* If we are called again due to a restart_syscall, we musn't
   * redirect to scratch again as we will lose the original
   * addresses values. */
  bool restart = (syscallno == Arch::restart_syscall);
  int would_need_scratch;
  uint8_t* scratch = NULL;

  if (t->desched_rec()) {
    return set_up_scratch_for_syscallbuf<Arch>(t, syscallno);
  }

  /* For syscall params that may need scratch memory, they
   * *will* need scratch memory if |would_need_scratch| is
   * nonzero.  They *don't* need scratch memory if we're
   * restarting a syscall, since if that's the case we've
   * already set it up. */
  would_need_scratch = !restart;
  if (would_need_scratch) {
    /* Don't stomp scratch pointers that were set up for
     * the restarted syscall.
     *
     * TODO: but, we'll stomp if we reenter through a
     * signal handler ... */
    reset_scratch_pointers(t);
    scratch = (uint8_t*)t->ev().Syscall().tmp_data_ptr;
  }

  if (syscallno < 0) {
    // Invalid syscall. Don't let it accidentally match a
    // syscall number below that's for an undefined syscall.
    return 0;
  }

  switch (syscallno) {
    case Arch::splice: {
      Registers r = t->regs();
      loff_t* off_in = (loff_t*)r.arg2();
      loff_t* off_out = (loff_t*)r.arg4();

      if (!would_need_scratch) {
        return 1;
      }

      push_arg_ptr(t, off_in);
      if (off_in) {
        loff_t* off_in2 = (loff_t*)scratch;
        scratch += sizeof(*off_in2);
        t->remote_memcpy(off_in2, off_in, sizeof(*off_in2));
        r.set_arg2((uintptr_t)off_in2);
      }
      push_arg_ptr(t, off_out);
      if (off_out) {
        loff_t* off_out2 = (loff_t*)scratch;
        scratch += sizeof(*off_out2);
        t->remote_memcpy(off_out2, off_out, sizeof(*off_out2));
        r.set_arg4((uintptr_t)off_out2);
      }
      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }

      t->set_regs(r);
      return 1;
    }

    case Arch::sendfile64: {
      Registers r = t->regs();
      loff_t* offset = (loff_t*)r.arg3();

      if (!would_need_scratch) {
        return 1;
      }

      push_arg_ptr(t, offset);
      if (offset) {
        loff_t* offset2 = (loff_t*)scratch;
        scratch += sizeof(*offset2);
        t->remote_memcpy(offset2, offset, sizeof(*offset2));
        r.set_arg3((uintptr_t)offset2);
      }
      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }

      t->set_regs(r);
      return 1;
    }

    case Arch::clone: {
      unsigned long flags = t->regs().arg1();
      push_arg_ptr(t, (void*)(uintptr_t)flags);
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
      return 0;
    }

    case Arch::exit:
      t->stable_exit = true;
      if (t->task_group()->task_set().size() == 1) {
        t->task_group()->exit_code = (int)t->regs().arg1();
      }
      destroy_buffers(t);
      return 0;

    case Arch::exit_group:
      if (t->task_group()->task_set().size() == 1) {
        t->stable_exit = true;
      }
      t->task_group()->exit_code = (int)t->regs().arg1();
      return 0;

    case Arch::execve: {
      t->pre_exec();

      Registers r = t->regs();
      string raw_filename = t->read_c_str((void*)r.arg1());
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
      return 0;
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
          return 1;
        default:
          return 0;
      }

    /* int futex(int *uaddr, int op, int val, const struct timespec *timeout,
     * int *uaddr2, int val3); */
    case Arch::futex:
      switch ((int)t->regs().arg2_signed() & FUTEX_CMD_MASK) {
        case FUTEX_WAIT:
        case FUTEX_WAIT_BITSET:
          return 1;
        default:
          return 0;
      }

    case Arch::ipc:
      return prepare_ipc<Arch>(t, would_need_scratch);

    case Arch::socketcall:
      return prepare_socketcall<Arch>(t, would_need_scratch);

    case Arch::_newselect:
      return 1;

    /* ssize_t read(int fd, void *buf, size_t count); */
    case Arch::read: {
      if (!would_need_scratch) {
        return 1;
      }
      Registers r = t->regs();

      push_arg_ptr(t, (void*)r.arg2());
      r.set_arg2((uintptr_t)scratch);
      scratch += (size_t)r.arg3();

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }

      t->set_regs(r);
      return 1;
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
      return !is_stdio_fd<Arch>(t, fd);
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
      int* status = (int*)r.arg2();
      typename Arch::rusage* rusage =
          (Arch::wait4 == syscallno) ? (typename Arch::rusage*)r.arg4() : NULL;

      if (!would_need_scratch) {
        return 1;
      }
      push_arg_ptr(t, status);
      if (status) {
        r.set_arg2((uintptr_t)scratch);
        scratch += sizeof(*status);
      }
      push_arg_ptr(t, rusage);
      if (rusage) {
        r.set_arg4((uintptr_t)scratch);
        scratch += sizeof(*rusage);
      }

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }

      t->set_regs(r);
      return 1;
    }

    case Arch::waitid: {
      if (!would_need_scratch) {
        return 1;
      }

      Registers r = t->regs();
      auto infop = (typename Arch::siginfo_t*)r.arg3();
      push_arg_ptr(t, infop);
      if (infop) {
        r.set_arg3((uintptr_t)scratch);
        scratch += sizeof(*infop);
      }

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }

      t->set_regs(r);
      return 1;
    }

    case Arch::pause:
      return 1;

    /* int poll(struct pollfd *fds, nfds_t nfds, int timeout) */
    /* int ppoll(struct pollfd *fds, nfds_t nfds,
     *           const struct timespec *timeout_ts,
     *           const sigset_t *sigmask); */
    case Arch::poll:
    case Arch::ppoll: {
      Registers r = t->regs();
      auto fds = (typename Arch::pollfd*)r.arg1();
      auto fds2 = (typename Arch::pollfd*)scratch;
      nfds_t nfds = r.arg2();

      if (!would_need_scratch) {
        return 1;
      }
      /* XXX fds can be NULL, right? */
      push_arg_ptr(t, fds);
      r.set_arg1((uintptr_t)fds2);
      scratch += nfds * sizeof(*fds);

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }
      /* |fds| is an inout param, so we need to copy over
       * the source data. */
      t->remote_memcpy(fds2, fds, nfds * sizeof(*fds));
      t->set_regs(r);
      return 1;
    }

    /* int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned
     * long arg4, unsigned long arg5); */
    case Arch::prctl: {
      /* TODO: many of these prctls are not blocking. */
      if (!would_need_scratch) {
        return 1;
      }
      Registers r = t->regs();
      switch ((int)r.arg1_signed()) {
        case PR_GET_ENDIAN:
        case PR_GET_FPEMU:
        case PR_GET_FPEXC:
        case PR_GET_PDEATHSIG:
        case PR_GET_TSC:
        case PR_GET_UNALIGN: {
          int* outparam = (int*)r.arg2();

          push_arg_ptr(t, outparam);
          r.set_arg2((uintptr_t)scratch);
          scratch += sizeof(*outparam);

          if (!can_use_scratch(t, scratch)) {
            return abort_scratch(t, t->syscallname(syscallno));
          }

          t->set_regs(r);
          return 1;
        }
        case PR_GET_NAME:
        case PR_SET_NAME:
          return 0;

        default:
          /* TODO: there are many more prctls with
           * outparams ... */
          return 1;
      }
      FATAL() << "Not reached";
    }

    case Arch::_sysctl: {
      typename Arch::__sysctl_args sysctl_args;
      void* args_ptr = (void*)t->regs().arg1();
      t->read_mem(args_ptr, &sysctl_args);

      push_arg_ptr(t, sysctl_args.oldval);
      push_arg_ptr(t, sysctl_args.oldlenp);
      return 0;
    }

    /* int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int
     * timeout); */
    case Arch::epoll_wait: {
      if (!would_need_scratch) {
        return 1;
      }

      Registers r = t->regs();
      auto events = (typename Arch::epoll_event*)r.arg2();
      int maxevents = r.arg3_signed();

      push_arg_ptr(t, events);
      r.set_arg2((uintptr_t)scratch);
      scratch += maxevents * sizeof(*events);

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }

      /* (Unlike poll(), the |events| param is a pure
       * outparam, no copy-over needed.) */
      t->set_regs(r);
      return 1;
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
      return 0;

    case Arch::epoll_pwait:
      FATAL() << "Unhandled syscall " << t->syscallname(syscallno);
      return 1;

    /* The following two syscalls enable context switching not for
     * liveness/correctness reasons, but rather because if we
     * didn't context-switch away, rr might end up busy-waiting
     * needlessly.  In addition, albeit far less likely, the
     * client program may have carefully optimized its own context
     * switching and we should take the hint. */

    /* int nanosleep(const struct timespec *req, struct timespec *rem); */
    case Arch::nanosleep: {
      if (!would_need_scratch) {
        return 1;
      }

      Registers r = t->regs();
      auto rem = (typename Arch::timespec*)r.arg2();
      push_arg_ptr(t, rem);
      if (rem) {
        r.set_arg2((uintptr_t)scratch);
        scratch += sizeof(*rem);
      }

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }

      t->set_regs(r);
      return 1;
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
      t->pseudo_blocked = 1;
      t->session().schedule_one_round_robin(t);
      return 1;

    case Arch::recvmmsg: {
      Registers r = t->regs();

      if ((unsigned int)r.arg4() & MSG_DONTWAIT) {
        return 0;
      }
      if (!would_need_scratch) {
        return 1;
      }

      auto poldmsgvec = (typename Arch::mmsghdr*)r.arg2();
      push_arg_ptr(t, (void*)r.arg2());
      r.set_arg2((uintptr_t)scratch);

      if (reserve_scratch_for_msgvec<Arch>(t, r.arg3(), poldmsgvec, &scratch)) {
        t->set_regs(r);
        return 1;
      } else
        return 0;
    }
    case Arch::rt_sigtimedwait: {
      if (!would_need_scratch) {
        return 1;
      }
      Registers r = t->regs();
      siginfo_t* info = (siginfo_t*)r.arg2();
      push_arg_ptr(t, info);
      if (info) {
        r.set_arg2((uintptr_t)scratch);
        // TODO: is this size arch-dependent?
        scratch += sizeof(*info);
      }

      if (!can_use_scratch(t, scratch)) {
        return abort_scratch(t, t->syscallname(syscallno));
      }
      t->set_regs(r);
      return 1;
    }
    case Arch::rt_sigsuspend:
    case Arch::sigsuspend:
      return 1;

    case Arch::sendmmsg: {
      Registers r = t->regs();
      unsigned flags = (unsigned int)r.arg4();
      return !(flags & MSG_DONTWAIT);
    }

    case Arch::sched_setaffinity: {
      // Ignore all sched_setaffinity syscalls. They might interfere
      // with our own affinity settings.
      Registers r = t->regs();
      push_arg_ptr(t, reinterpret_cast<void*>(r.arg1()));
      // Set arg1 to an invalid PID to ensure this syscall is ignored.
      r.set_arg1(-1);
      t->set_regs(r);
      return 0;
    }

    default:
      return 0;
  }
}

int rec_prepare_syscall(Task* t)
    RR_ARCH_FUNCTION(rec_prepare_syscall_arch, t->arch(), t)

    /**
     * Write a trace data record that when replayed will be a no-op.  This
     * is used to avoid having special cases in replay code for failed
     * syscalls, e.g.
     */
    static void record_noop_data(Task* t) {
  t->record_local(nullptr, 0, nullptr);
}

template <typename Arch> static void rec_prepare_restart_syscall_arch(Task* t) {
  int syscallno = t->ev().Syscall().no;
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
      auto rem = (typename Arch::timespec*)t->ev().Syscall().saved_args.top();
      auto rem2 = (typename Arch::timespec*)t->regs().arg2();

      if (rem) {
        t->remote_memcpy(rem, rem2, sizeof(*rem));
        t->record_remote(rem, sizeof(*rem));
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

void rec_prepare_restart_syscall(Task* t)
    RR_ARCH_FUNCTION(rec_prepare_restart_syscall_arch, t->arch(),
                     t) template <typename Arch>
static void init_scratch_memory(Task* t) {
  const int scratch_size = 512 * page_size();
  size_t sz = scratch_size;
  // The PROT_EXEC looks scary, and it is, but it's to prevent
  // this region from being coalesced with another anonymous
  // segment mapped just after this one.  If we named this
  // segment, we could remove this hack.
  int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  int fd = -1;
  off64_t offset_pages = 0;
  {
    /* initialize the scratchpad for blocking system calls */
    AutoRemoteSyscalls remote(t);
    t->scratch_ptr = (void*)remote.syscall(Arch::mmap2, 0, sz, prot, flags, fd,
                                           offset_pages);
    t->scratch_size = scratch_size;
  }
  // record this mmap for the replay
  Registers r = t->regs();
  uintptr_t saved_result = r.syscall_result();
  r.set_syscall_result((uintptr_t)t->scratch_ptr);
  t->set_regs(r);

  struct mmapped_file file = { 0 };
  file.time = t->trace_time();
  file.tid = t->tid;
  file.start = t->scratch_ptr;
  file.end = (uint8_t*)t->scratch_ptr + scratch_size;
  sprintf(file.filename, "scratch for thread %d", t->tid);
  t->ofstream() << file;

  r.set_syscall_result(saved_result);
  t->set_regs(r);

  t->vm()->map(t->scratch_ptr, sz, prot, flags, page_size() * offset_pages,
               MappableResource::scratch(t->rec_tid));
}

/**
 * Read the scratch data written by the kernel in the syscall and
 * return an opaque handle to it.  The outparam |iter| can be used to
 * copy the read memory.
 *
 * The returned opaque handle must be passed to
 * |finish_restoring_scratch()|.
 */
static void* start_restoring_scratch(Task* t, uint8_t** iter) {
  // TODO: manage this in Task.
  void* scratch = t->ev().Syscall().tmp_data_ptr;
  ssize_t num_bytes = t->ev().Syscall().tmp_data_num_bytes;

  assert(num_bytes >= 0);

  uint8_t* data = (uint8_t*)malloc(num_bytes);
  t->read_bytes_helper(scratch, num_bytes, data);
  return *iter = data;
}

/**
 * Return nonzero if tracee pointers were saved while preparing for
 * the syscall |t->ev|.
 */
static int has_saved_arg_ptrs(Task* t) {
  return !t->ev().Syscall().saved_args.empty();
}

/**
 * Return the replaced tracee argument pointer saved by the matching
 * call to |push_arg_ptr()|.
 */
template <typename T> static T* pop_arg_ptr(Task* t) {
  assert(!t->ev().Syscall().saved_args.empty());
  void* arg = t->ev().Syscall().saved_args.top();
  t->ev().Syscall().saved_args.pop();
  return static_cast<T*>(arg);
}

/**
 * Write |num_bytes| of data from |parent_data_iter| to |child_addr|.
 * Record the written data so that it can be restored during replay of
 * |syscallno|.
 */
static void restore_and_record_arg_buf(Task* t, size_t num_bytes,
                                       void* child_addr,
                                       uint8_t** parent_data_iter) {
  // TODO: move scratch-arg tracking into Task
  uint8_t* parent_data = *parent_data_iter;
  t->write_bytes_helper(child_addr, num_bytes, parent_data);
  t->record_local(child_addr, num_bytes, parent_data);
  *parent_data_iter += num_bytes;
}

template <typename T>
static void restore_and_record_arg(Task* t, T* child_arg,
                                   uint8_t** parent_data_iter) {
  return restore_and_record_arg_buf(t, sizeof(*child_arg), child_arg,
                                    parent_data_iter);
}

/**
 * Finish the sequence of operations begun by the most recent
 * |start_restoring_scratch()| and check that no mistakes were made.
 * |*data| must be the opaque handle returned by |start_*()|.
 *
 * Don't call this directly; use one of the helpers below.
 */
enum {
  NO_SLACK = 0,
  ALLOW_SLACK = 1
};
static void finish_restoring_scratch_slack(Task* t, uint8_t* iter, void** datap,
                                           int slack) {
  uint8_t* data = (uint8_t*)*datap;
  ssize_t consumed = (iter - data);
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

  free(data);
}

/**
 * Like above, but require that all saved scratch data was consumed.
 */
static void finish_restoring_scratch(Task* t, uint8_t* iter, void** data) {
  return finish_restoring_scratch_slack(t, iter, data, NO_SLACK);
}

/**
 * Like above, but allow some saved scratch data to remain unconsumed,
 * for example if a buffer wasn't filled entirely.
 */
static void finish_restoring_some_scratch(Task* t, uint8_t* iter, void** data) {
  return finish_restoring_scratch_slack(t, iter, data, ALLOW_SLACK);
}

template <typename Arch> static void process_execve(Task* t) {
  Registers r = t->regs();
  if (SYSCALL_FAILED(r.syscall_result_signed())) {
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

  long* stack_ptr = (long*)t->regs().sp();

  /* start_stack points to argc - iterate over argv pointers */

  /* FIXME: there are special cases, like when recording gcc,
   *        where the stack pointer does not point to argc. For example,
   *        it may point to &argc.
   */
  // long* argc = (long*)t->read_word((uint8_t*)stack_ptr);
  // stack_ptr += *argc + 1;
  intptr_t argc = t->read_word(stack_ptr);
  stack_ptr += argc + 1;

  // unsigned long* null_ptr = read_child_data(t, sizeof(void*), stack_ptr);
  // assert(*null_ptr == 0);
  intptr_t null_ptr = t->read_word(stack_ptr);
  assert(null_ptr == 0);
  stack_ptr++;

  /* should now point to envp (pointer to environment strings) */
  while (0 != t->read_word(stack_ptr)) {
    stack_ptr++;
  }
  stack_ptr++;

  /* should now point to ELF Auxiliary Table */
  static const unsigned int elf_aux[] = {
    AT_SYSINFO, AT_SYSINFO_EHDR, AT_HWCAP, AT_PAGESZ, AT_CLKTCK, AT_PHDR,
    AT_PHENT,   AT_PHNUM,        AT_BASE,  AT_FLAGS,  AT_ENTRY,  AT_UID,
    AT_EUID,    AT_GID,          AT_EGID,  AT_SECURE
  };

  struct ElfEntry {
    typename Arch::unsigned_word key;
    typename Arch::unsigned_word value;
  };
  union {
    ElfEntry entries[ALEN(elf_aux)];
    uint8_t bytes[sizeof(entries)];
  } table;
  t->read_bytes(stack_ptr, table.bytes);
  stack_ptr += 2 * ALEN(elf_aux);

  for (int i = 0; i < ssize_t(ALEN(elf_aux)); ++i) {
    auto expected_field = elf_aux[i];
    const ElfEntry& entry = table.entries[i];
    ASSERT(t, expected_field == entry.key)
        << "Elf aux entry " << i << " should be " << HEX(expected_field)
        << ", but is " << HEX(entry.key);
  }

  intptr_t at_random = t->read_word(stack_ptr);
  stack_ptr++;
  ASSERT(t, AT_RANDOM == at_random) << "ELF item should be " << HEX(AT_RANDOM)
                                    << ", but is " << HEX(at_random);

  void* rand_addr = (void*)t->read_word(stack_ptr);
  // XXX where does the magic number come from?
  t->record_remote(rand_addr, 16);

  init_scratch_memory<Arch>(t);
}

static void record_ioctl_data(Task* t, ssize_t num_bytes) {
  void* param = (void*)t->regs().arg3();
  t->record_remote(param, num_bytes);
}

/**
 * Record.the page above the top of |t|'s stack.  The SIOC* ioctls
 * have been observed to write beyond the end of tracees' stacks, as
 * if they had allocated scratch space for themselves.  All we can do
 * for now is try to record the scratch data.
 */
static void record_scratch_stack_page(Task* t) {
  t->record_remote((uint8_t*)t->sp() - page_size(), page_size());
}

template <typename Arch> static void process_ioctl(Task* t, int request) {
  int type = _IOC_TYPE(request);
  int nr = _IOC_NR(request);
  int dir = _IOC_DIR(request);
  int size = _IOC_SIZE(request);
  void* param = (void*)t->regs().arg3();

  LOG(debug) << "handling ioctl(" << HEX(request) << "): type:" << HEX(type)
             << " nr:" << HEX(nr) << " dir:" << HEX(dir) << " size:" << size;

  ASSERT(t, !t->is_desched_event_syscall())
      << "Failed to skip past desched ioctl()";

  /* Some ioctl()s are irregular and don't follow the _IOC()
   * conventions.  Special case them here. */
  switch (request) {
    case SIOCETHTOOL: {
      typename Arch::ifreq ifr;
      t->read_mem(param, &ifr);

      record_scratch_stack_page(t);
      t->record_remote(ifr.ifr_ifru.ifru_data,
                       sizeof(typename Arch::ethtool_cmd));
      return;
    }
    case SIOCGIFCONF: {
      typename Arch::ifconf ifconf;
      t->read_mem(param, &ifconf);

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
      print_register_file_tid(t);
      ASSERT(t, false) << "Unknown ioctl(" << HEX(request)
                       << "): type:" << HEX(type) << " nr:" << HEX(nr)
                       << " dir:" << HEX(dir) << " size:" << size
                       << " addr:" << HEX(t->regs().arg3());
  }
}

template <typename Arch> static void process_ipc(Task* t, int call) {
  LOG(debug) << "ipc call: " << call;

  switch (call) {
    case MSGCTL: {
      int cmd = get_ipc_command((int)t->regs().arg3_signed());
      void* buf = (void*)t->regs().arg5();
      ssize_t buf_size;
      switch (cmd) {
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
      }
      t->record_remote(buf, buf_size);
      return;
    }
    case MSGRCV: {
      // The |msgsize| arg is only the size of message
      // payload; there's also a |msgtype| tag set just
      // before the payload.
      size_t buf_size = sizeof(long) + t->regs().arg3();
      typename Arch::ipc_kludge_args kludge;
      void* child_kludge = (void*)t->regs().arg5();

      t->read_mem(child_kludge, &kludge);
      if (has_saved_arg_ptrs(t)) {
        void* src = kludge.msgbuf;
        void* dst = pop_arg_ptr<void>(t);

        kludge.msgbuf = dst;
        t->write_mem(child_kludge, kludge);

        t->remote_memcpy((uint8_t*)dst, (uint8_t*)src, buf_size);
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

  if (SYSCALL_FAILED(t->regs().syscall_result_signed())) {
    // We purely emulate failed mmaps.
    return;
  }
  void* addr = (void*)t->regs().syscall_result();
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

  struct mmapped_file file;
  // TODO: save a reflink copy of the resource to the
  // trace directory as |fs/[st_dev].[st_inode]|.  Then
  // we wouldn't have to care about looking up a name
  // for the resource.
  file.time = t->trace_time();
  file.tid = t->tid;
  if (!t->fdstat(fd, &file.stat, file.filename, sizeof(file.filename))) {
    FATAL() << "Failed to fdstat " << fd;
  }
  file.start = addr;
  file.end = (uint8_t*)addr + size;

  if (strstr(file.filename, SYSCALLBUF_LIB_FILENAME) && (prot & PROT_EXEC)) {
    t->syscallbuf_lib_start = file.start;
    t->syscallbuf_lib_end = file.end;
  }

  file.copied = should_copy_mmap_region(file.filename, &file.stat, prot, flags,
                                        WARN_DEFAULT);
  if (file.copied) {
    off64_t end = (off64_t)file.stat.st_size - offset;
    t->record_remote(addr, min(end, (off64_t)size));
  }
  t->ofstream() << file;

  t->vm()->map(addr, size, prot, flags, offset,
               MappableResource(FileId(file.stat), file.filename));
}

/*
 * Restore all data of msghdr from src* to dst* (all child pointers) and
 * record child memory where the pointer members point for replay
 */
template <typename Arch>
static void record_and_restore_msghdr(Task* t, typename Arch::msghdr* dst,
                                      typename Arch::msghdr* src) {
  typename Arch::msghdr msg, tmpmsg;
  t->read_mem(dst, &msg);
  t->read_mem(src, &tmpmsg);

  msg.msg_namelen = tmpmsg.msg_namelen;
  msg.msg_flags = tmpmsg.msg_flags;
  msg.msg_controllen = tmpmsg.msg_controllen;
  t->write_mem(dst, msg);
  t->record_local(dst, sizeof(msg), &msg);

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
static void record_struct_msghdr(Task* t, typename Arch::msghdr* child_msghdr) {
  typename Arch::msghdr msg;
  t->read_mem(child_msghdr, &msg);

  // Record the entire struct, because some of the direct fields
  // are written as inoutparams.
  t->record_local(child_msghdr, sizeof(msg), &msg);
  t->record_remote(msg.msg_name, msg.msg_namelen);

  // Read all the inout iovecs in one shot.
  typename Arch::iovec iovs[msg.msg_iovlen];
  t->read_bytes_helper(msg.msg_iov, msg.msg_iovlen * sizeof(iovs[0]),
                       (uint8_t*)iovs);
  for (size_t i = 0; i < msg.msg_iovlen; ++i) {
    auto iov = &iovs[i];
    t->record_remote(iov->iov_base, iov->iov_len);
  }

  t->record_remote(msg.msg_control, msg.msg_controllen);
}

/** Like record_struct_msghdr(), but records mmsghdr. */
template <typename Arch>
static void record_struct_mmsghdr(Task* t,
                                  typename Arch::mmsghdr* child_mmsghdr) {
  /* struct mmsghdr has an inline struct msghdr as its first
   * field, so it's OK to make this "cast". */
  record_struct_msghdr<Arch>(t, (typename Arch::msghdr*)child_mmsghdr);
  /* We additionally have to record the outparam number of
   * received bytes. */
  t->record_remote(&child_mmsghdr->msg_len, sizeof(child_mmsghdr->msg_len));
}

/*
 * Restore all data of msgvec from pnewmsg to poldmsg and
 * record child memory where the pointer members point for replay
 */
template <typename Arch>
static void record_and_restore_msgvec(Task* t, bool has_saved_arg_ptrs,
                                      int nmmsgs,
                                      typename Arch::mmsghdr* pnewmsg,
                                      typename Arch::mmsghdr* poldmsg) {
  if (!has_saved_arg_ptrs) {
    for (int i = 0; i < nmmsgs; ++i) {
      record_struct_mmsghdr<Arch>(t, pnewmsg + i);
    }
    return;
  }

  typename Arch::mmsghdr old;
  typename Arch::mmsghdr tmp;
  for (int i = 0; i < nmmsgs; ++i) {
    t->read_mem(poldmsg + i, &old);
    t->read_mem(pnewmsg + i, &tmp);

    old.msg_len = tmp.msg_len;
    t->write_mem(poldmsg + i, old);

    // record the msghdr part of mmsghdr
    record_and_restore_msghdr<Arch>(t, (typename Arch::msghdr*)(poldmsg + i),
                                    (typename Arch::msghdr*)(pnewmsg + i));
    // record mmsghdr.msg_len
    t->record_local(&((poldmsg + i)->msg_len), sizeof(old.msg_len),
                    &old.msg_len);
  }
}

/*
 * Record msg_len of each element of msgvec
 * */
template <typename Arch>
static void record_each_msglen(Task* t, int nmmsgs,
                               typename Arch::mmsghdr* msgvec) {
  /* Record the outparam msg_len fields. */
  for (int i = 0; i < nmmsgs; ++i, ++msgvec) {
    t->record_remote(&msgvec->msg_len, sizeof(msgvec->msg_len));
  }
}

template <typename Arch>
static void process_socketcall(Task* t, int call, void* base_addr) {
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
      typename Arch::getsockname_args args;
      t->read_mem(base_addr, &args);
      typename Arch::socklen_t len = t->read_word(args.addrlen);
      t->record_remote(args.addrlen, sizeof(*args.addrlen));
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
      typename Arch::recv_args args;
      void* buf;
      void* argsp;
      uint8_t* iter;
      void* data = NULL;
      ssize_t nrecvd = t->regs().syscall_result_signed();
      if (has_saved_arg_ptrs(t)) {
        buf = pop_arg_ptr<void>(t);
        argsp = pop_arg_ptr<void>(t);
        data = start_restoring_scratch(t, &iter);
        /* We don't need to record the fudging of the
         * socketcall arguments, because we won't
         * replay that. */
        memcpy(&args, iter, sizeof(args));
        iter += sizeof(args);
      } else {
        long* argsp;
        read_socketcall_args(t, &argsp, &args);
        buf = (void*)args.buf;
      }

      /* Restore |buf| contents. */
      if (0 < nrecvd) {
        if (data) {
          restore_and_record_arg_buf(t, nrecvd, buf, &iter);
        } else {
          t->record_remote(buf, nrecvd);
        }
      } else {
        record_noop_data(t);
      }

      if (data) {
        Registers r = t->regs();
        /* Restore the pointer to the original args. */
        r.set_arg2((uintptr_t)argsp);
        t->set_regs(r);
        finish_restoring_some_scratch(t, iter, &data);
      }
      return;
    }
    case SYS_RECVFROM: {
      typename Arch::recvfrom_args args;
      t->read_mem(base_addr, &args);

      ssize_t recvdlen = t->regs().syscall_result_signed();
      if (has_saved_arg_ptrs(t)) {
        uint8_t* src_addrp = pop_arg_ptr<uint8_t>(t);
        void* addrlenp = pop_arg_ptr<void>(t);
        uint8_t* buf = pop_arg_ptr<uint8_t>(t);
        uint8_t* argsp = pop_arg_ptr<uint8_t>(t);

        if (recvdlen > 0) {
          t->remote_memcpy(buf, args.buf, recvdlen);
        }
        args.buf = buf;

        if (src_addrp) {
          typename Arch::socklen_t addrlen;
          t->read_mem(args.addrlen, &addrlen);
          t->remote_memcpy(src_addrp, args.src_addr, addrlen);
          t->write_mem(addrlenp, addrlen);
          args.src_addr = (typename Arch::sockaddr*)src_addrp;
          args.addrlen = (typename Arch::socklen_t*)addrlenp;
        }
        Registers r = t->regs();
        r.set_arg2((uintptr_t)argsp);
        t->set_regs(r);
      }

      if (recvdlen > 0) {
        t->record_remote(args.buf, recvdlen);
      } else {
        record_noop_data(t);
      }
      if (args.src_addr) {
        typename Arch::socklen_t addrlen;
        t->read_mem(args.addrlen, &addrlen);

        t->record_remote(args.addrlen, sizeof(*args.addrlen));
        t->record_remote(args.src_addr, addrlen);
      } else {
        record_noop_data(t);
        record_noop_data(t);
      }
      return;
    }
    /* ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags); */
    case SYS_RECVMSG: {
      Registers r = t->regs();
      auto tmpargsp = (typename Arch::recvmsg_args*)r.arg2();
      typename Arch::recvmsg_args tmpargs;
      t->read_mem(tmpargsp, &tmpargs);
      if (!has_saved_arg_ptrs(t)) {
        return record_struct_msghdr<Arch>(t, tmpargs.msg);
      }

      uint8_t* argsp = pop_arg_ptr<uint8_t>(t);
      typename Arch::recvmsg_args args;
      t->read_mem(argsp, &args);

      record_and_restore_msghdr<Arch>(t, args.msg, tmpargs.msg);

      r.set_arg2((uintptr_t)argsp);
      t->set_regs(r);
      return;
    }

    /*
     *  int getsockopt(int sockfd, int level, int optname, const void *optval,
     * socklen_t* optlen);
     */
    case SYS_GETSOCKOPT: {
      typename Arch::getsockopt_args args;
      t->read_mem(base_addr, &args);
      typename Arch::socklen_t optlen = t->read_word(args.optlen);
      t->record_remote(args.optlen, sizeof(*args.optlen));
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
      uint8_t* orig_argsp = pop_arg_ptr<uint8_t>(t);

      uint8_t* iter;
      void* data = start_restoring_scratch(t, &iter);
      // Consume the scratch args.
      if (SYS_ACCEPT == call) {
        iter += sizeof(typename Arch::accept_args);
      } else {
        iter += sizeof(typename Arch::accept4_args);
      }
      auto addrlen = *(typename Arch::socklen_t*)iter;
      restore_and_record_arg_buf(t, sizeof(addrlen), (uint8_t*)addrlenp, &iter);
      restore_and_record_arg_buf(t, addrlen, (uint8_t*)addrp, &iter);

      /* Restore the pointer to the original args. */
      r.set_arg2((uintptr_t)orig_argsp);
      t->set_regs(r);

      finish_restoring_some_scratch(t, iter, &data);
      return;
    }

    /* int socketpair(int domain, int type, int protocol, int sv[2]);
     *
     * values returned in sv
     */
    case SYS_SOCKETPAIR: {
      typename Arch::socketpair_args args;
      t->read_mem(base_addr, &args);
      t->record_remote(args.sv, 2 * sizeof(*args.sv));
      return;
    }

    /* int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
     *              unsigned int flags, struct timespec *timeout);*/
    case SYS_RECVMMSG: {
      Registers r = t->regs();
      int nmmsgs = r.syscall_result_signed();

      auto tmpargsp = (typename Arch::recvmmsg_args*)r.arg2();
      typename Arch::recvmmsg_args tmpargs;
      t->read_mem(tmpargsp, &tmpargs);

      typename Arch::recvmmsg_args args;
      uint8_t* argsp = NULL;
      bool has_saved_ptr = has_saved_arg_ptrs(t);
      if (has_saved_ptr) {
        argsp = pop_arg_ptr<uint8_t>(t);
        t->read_mem(argsp, &args);
        r.set_arg2((uintptr_t)argsp);
        t->set_regs(r);
      }

      record_and_restore_msgvec<Arch>(t, has_saved_ptr, nmmsgs, tmpargs.msgvec,
                                      args.msgvec);
      return;
    }

    /* int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
    *              unsigned int flags);*/
    case SYS_SENDMMSG: {
      auto argsp = (typename Arch::sendmmsg_args*)t->regs().arg2();
      typename Arch::sendmmsg_args args;
      t->read_mem(argsp, &args);

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
  t->maybe_update_vm(syscallno, STATE_SYSCALL_EXIT);

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
      t->set_robust_list((void*)t->regs().arg1(), (size_t)t->regs().arg2());
      return;

    case Arch::set_thread_area:
      t->set_thread_area((void*)t->regs().arg1());
      return;

    case Arch::set_tid_address:
      t->set_tid_addr((void*)t->regs().arg1());
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
    print_register_file_tid(t);
    int syscallno = t->ev().Syscall().no;
    FATAL() << "Unhandled syscall " << t->syscallname(syscallno) << "("
            << syscallno << ") returned " << t->regs().syscall_result_signed();
  }
}

template <typename Arch> static void rec_process_syscall_arch(Task* t) {
  int syscallno = t->ev().Syscall().no;

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
// These macros are used to generate code that
// processes the "regular" syscalls.  Irregular
// syscalls are implemented by hand-written case
// statements below.
#define SYSCALLNO_X86(num)
#define SYSCALLNO_X86_64(num)
#define SYSCALL_UNDEFINED_X86_64()
#define SYSCALL_DEF0(_call, _)                                                 \
  case Arch::_call:                                                            \
    break;
#define SYSCALL_DEF1(_call, _, _t0, _r0)                                       \
  case Arch::_call:                                                            \
    t->record_remote((void*)t->regs()._r0(), sizeof(_t0));                     \
    break;
#define SYSCALL_DEF1_DYNSIZE(_call, _, _s0, _r0)                               \
  case Arch::_call:                                                            \
    t->record_remote((void*)t->regs()._r0(), _s0);                             \
    break;
#define SYSCALL_DEF1_STR(_call, _, _r0)                                        \
  case Arch::_call:                                                            \
    t->record_remote_str((void*)t->regs()._r0());                              \
    break;
#define SYSCALL_DEF2(_call, _, _t0, _r0, _t1, _r1)                             \
  case Arch::_call:                                                            \
    t->record_remote((void*)t->regs()._r0(), sizeof(_t0));                     \
    t->record_remote((void*)t->regs()._r1(), sizeof(_t1));                     \
    break;
#define SYSCALL_DEF3(_call, _, _t0, _r0, _t1, _r1, _t2, _r2)                   \
  case Arch::_call:                                                            \
    t->record_remote((void*)t->regs()._r0(), sizeof(_t0));                     \
    t->record_remote((void*)t->regs()._r1(), sizeof(_t1));                     \
    t->record_remote((void*)t->regs()._r2(), sizeof(_t2));                     \
    break;
#define SYSCALL_DEF4(_call, _, _t0, _r0, _t1, _r1, _t2, _r2, _t3, _r3)         \
  case Arch::_call:                                                            \
    t->record_remote((void*)t->regs()._r0(), sizeof(_t0));                     \
    t->record_remote((void*)t->regs()._r1(), sizeof(_t1));                     \
    t->record_remote((void*)t->regs()._r2(), sizeof(_t2));                     \
    t->record_remote((void*)t->regs()._r3(), sizeof(_t3));                     \
    break;
#define SYSCALL_DEF_IRREG(_call, _) // manually implemented below
#define SYSCALL_DEF_UNSUPPORTED(_call)

#include "syscall_defs.h"

    case Arch::clone: {
      long new_tid = t->regs().syscall_result_signed();
      Task* new_task = t->session().find_task(new_tid);
      unsigned long flags = (uintptr_t)pop_arg_ptr<void>(t);

      if (flags & CLONE_UNTRACED) {
        Registers r = t->regs();
        r.set_arg1(flags);
        t->set_regs(r);
      }

      if (new_tid < 0)
        break;

      new_task->push_event(SyscallEvent(syscallno));

      /* record child id here */
      int pid_size = sizeof(typename Arch::pid_t);
      new_task->record_remote((void*)t->regs().arg3(), pid_size);
      new_task->record_remote((void*)t->regs().arg4(), pid_size);

      new_task->record_remote((void*)new_task->regs().arg5(),
                              sizeof(typename Arch::user_desc));
      new_task->record_remote((void*)new_task->regs().arg3(), pid_size);
      new_task->record_remote((void*)new_task->regs().arg4(), pid_size);

      new_task->pop_syscall();

      init_scratch_memory<Arch>(new_task);
      // The new tracee just "finished" a clone that was
      // started by its parent.  It has no pending events,
      // so it can be context-switched out.
      new_task->switchable = 1;

      break;
    }
    case Arch::epoll_wait: {
      uint8_t* iter;
      void* data = start_restoring_scratch(t, &iter);
      auto events = pop_arg_ptr<typename Arch::epoll_event>(t);
      int maxevents = t->regs().arg3_signed();
      if (events) {
        restore_and_record_arg_buf(t, maxevents * sizeof(*events),
                                   (uint8_t*)events, &iter);
        Registers r = t->regs();
        r.set_arg2((uintptr_t)events);
        t->set_regs(r);
      } else {
        record_noop_data(t);
      }
      finish_restoring_scratch(t, iter, &data);
      break;
    }
    case Arch::execve:
      process_execve<Arch>(t);
      break;

    case Arch::fcntl64: {
      int cmd = t->regs().arg2_signed();
      switch (cmd) {
        case F_DUPFD:
        case F_GETFD:
        case F_GETFL:
        case F_SETFL:
        case F_SETFD:
        case F_SETOWN:
        case F_SETOWN_EX:
        case F_SETSIG:
          break;

        case F_GETLK:
          t->record_remote((void*)t->regs().arg3(),
                           sizeof(typename Arch::flock));
          break;

        case F_SETLK:
        case F_SETLKW:
          break;

#if F_GETLK != F_GETLK64
        case F_GETLK64:
          static_assert(
              sizeof(typename Arch::flock) < sizeof(typename Arch::flock64),
              "struct flock64 not declared differently from struct flock");
          t->record_remote((void*)t->regs().arg3(),
                           sizeof(typename Arch::flock64));
          break;
#endif

#if F_SETLK64 != F_SETLK
        case F_SETLK64:
#endif
#if F_SETLKW64 != F_SETLKW
        case F_SETLKW64:
#endif
          break;

        case F_GETOWN_EX:
          t->record_remote((void*)t->regs().arg3(),
                           sizeof(typename Arch::f_owner_ex));
          break;

        default:
          FATAL() << "Unknown fcntl " << cmd;
      }
      break;
    }
    case Arch::futex: {
      t->record_remote((void*)t->regs().arg1(), sizeof(int));
      int op = (int)t->regs().arg2_signed() & FUTEX_CMD_MASK;

      switch (op) {

        case FUTEX_WAKE:
        case FUTEX_WAIT_BITSET:
        case FUTEX_WAIT:
          break;

        case FUTEX_CMP_REQUEUE:
        case FUTEX_WAKE_OP:
          t->record_remote((void*)t->regs().arg5(), sizeof(int));
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
      void* value = (void*)t->regs().arg3();

      if (len > 0) {
        t->record_remote(value, len);
      } else {
        record_noop_data(t);
      }
      break;
    }
    case Arch::ioctl:
      process_ioctl<Arch>(t, (int)t->regs().arg2_signed());
      break;

    case Arch::ipc:
      process_ipc<Arch>(t, (unsigned int)t->regs().arg1());
      break;

    case Arch::mmap: {
      typename Arch::mmap_args args;
      t->read_mem((void*)t->regs().arg1(), &args);
      process_mmap(t, syscallno, args.len, args.prot, args.flags, args.fd,
                   args.offset / 4096);
      break;
    }
    case Arch::mmap2:
      process_mmap(t, syscallno, (size_t)t->regs().arg2(),
                   (int)t->regs().arg3_signed(), (int)t->regs().arg4_signed(),
                   (int)t->regs().arg5_signed(),
                   (off_t)t->regs().arg6_signed());
      break;

    case Arch::nanosleep: {
      auto rem = pop_arg_ptr<typename Arch::timespec>(t);
      uint8_t* iter;
      void* data = start_restoring_scratch(t, &iter);

      if (rem) {
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
          restore_and_record_arg(t, rem, &iter);
        }
        r.set_arg2((uintptr_t)rem);
        t->set_regs(r);
      }

      finish_restoring_some_scratch(t, iter, &data);
      break;
    }
    case Arch::open: {
      string pathname = t->read_c_str((void*)t->regs().arg1());
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
      uint8_t* iter;
      void* data = start_restoring_scratch(t, &iter);
      auto fds = pop_arg_ptr<typename Arch::pollfd>(t);
      size_t nfds = t->regs().arg2();

      restore_and_record_arg_buf(t, nfds * sizeof(*fds), (uint8_t*)fds, &iter);
      Registers r = t->regs();
      r.set_arg1((uintptr_t)fds);
      t->set_regs(r);
      finish_restoring_scratch(t, iter, &data);
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
          t->update_prname((void*)t->regs().arg2());
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
        uint8_t* iter;
        void* data = start_restoring_scratch(t, &iter);
        uint8_t* arg = pop_arg_ptr<uint8_t>(t);

        restore_and_record_arg_buf(t, size, arg, &iter);
        Registers r = t->regs();
        r.set_arg2((uintptr_t)arg);
        t->set_regs(r);

        finish_restoring_scratch(t, iter, &data);
      } else {
        record_noop_data(t);
      }
      break;
    }
    case Arch::quotactl: {
      int cmd = (int)t->regs().arg1_signed() & SUBCMDMASK;
      void* addr = (void*)t->regs().arg4();
      switch (cmd) {
        case Q_GETQUOTA:
          t->record_remote(addr, sizeof(typename Arch::dqblk));
          break;
        case Q_GETINFO:
          t->record_remote(addr, sizeof(typename Arch::dqinfo));
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
      void* buf;
      uint8_t* iter;
      void* data = nullptr;

      ssize_t nread = t->regs().syscall_result_signed();
      if (has_saved_arg_ptrs(t)) {
        buf = pop_arg_ptr<void>(t);
        data = start_restoring_scratch(t, &iter);
      } else {
        buf = (void*)t->regs().arg2();
      }

      if (nread > 0) {
        if (data) {
          restore_and_record_arg_buf(t, nread, buf, &iter);
        } else {
          t->record_remote(buf, nread);
        }
      } else {
        record_noop_data(t);
      }

      if (data) {
        Registers r = t->regs();
        r.set_arg2((uintptr_t)buf);
        t->set_regs(r);
        finish_restoring_some_scratch(t, iter, &data);
      }
      break;
    }
    case Arch::recvmmsg: {
      Registers r = t->regs();
      int nmmsgs = r.syscall_result_signed();

      auto msg = (typename Arch::mmsghdr*)r.arg2();
      typename Arch::mmsghdr* oldmsg = NULL;

      bool has_saved_ptr = has_saved_arg_ptrs(t);
      if (has_saved_ptr) {
        oldmsg = pop_arg_ptr<typename Arch::mmsghdr>(t);
        r.set_arg2((uintptr_t)oldmsg);
        t->set_regs(r);
      }

      record_and_restore_msgvec<Arch>(t, has_saved_ptr, nmmsgs, msg, oldmsg);
      break;
    }
    case Arch::rt_sigtimedwait: {
      Registers r = t->regs();
      if (t->ev().Syscall().saved_args.empty()) {
        siginfo_t* info = (siginfo_t*)r.arg2();
        if (info) {
          t->record_remote(info, sizeof(*info));
        } else {
          record_noop_data(t);
        }
        break;
      }
      siginfo_t* info = pop_arg_ptr<siginfo_t>(t);
      uint8_t* iter;
      void* data = start_restoring_scratch(t, &iter);

      if (info) {
        restore_and_record_arg(t, info, &iter);
        r.set_arg2((uintptr_t)info);
      } else {
        record_noop_data(t);
      }
      t->set_regs(r);
      finish_restoring_scratch(t, iter, &data);
      break;
    }
    case Arch::sendfile64: {
      loff_t* offset = pop_arg_ptr<loff_t>(t);
      uint8_t* iter;
      void* data = start_restoring_scratch(t, &iter);

      Registers r = t->regs();
      if (offset) {
        restore_and_record_arg(t, offset, &iter);
        r.set_arg3((uintptr_t)offset);
      } else {
        record_noop_data(t);
      }

      t->set_regs(r);
      finish_restoring_scratch(t, iter, &data);
      break;
    }
    case Arch::sendmmsg: {
      auto msg = (typename Arch::mmsghdr*)t->regs().arg2();

      record_each_msglen<Arch>(t, t->regs().syscall_result_signed(), msg);
      break;
    }
    case Arch::socketcall:
      process_socketcall<Arch>(t, (int)t->regs().arg1_signed(),
                               (void*)t->regs().arg2());
      break;

    case Arch::splice: {
      loff_t* off_out = pop_arg_ptr<loff_t>(t);
      loff_t* off_in = pop_arg_ptr<loff_t>(t);
      uint8_t* iter;
      void* data = start_restoring_scratch(t, &iter);

      Registers r = t->regs();
      if (off_in) {
        restore_and_record_arg(t, off_in, &iter);
        r.set_arg2((uintptr_t)off_in);
      } else {
        record_noop_data(t);
      }
      if (off_out) {
        restore_and_record_arg(t, off_out, &iter);
        r.set_arg4((uintptr_t)off_out);
      } else {
        record_noop_data(t);
      }

      t->set_regs(r);
      finish_restoring_scratch(t, iter, &data);
      break;
    }
    case Arch::_sysctl: {
      size_t* oldlenp = pop_arg_ptr<size_t>(t);
      void* oldval = pop_arg_ptr<void>(t);
      size_t oldlen;
      t->read_mem(oldlenp, &oldlen);

      t->record_remote(oldlenp, sizeof(size_t));
      t->record_remote(oldval, oldlen);
      break;
    }
    case Arch::waitid: {
      auto infop = pop_arg_ptr<typename Arch::siginfo_t>(t);
      uint8_t* iter;
      void* data = start_restoring_scratch(t, &iter);

      Registers r = t->regs();
      if (infop) {
        restore_and_record_arg(t, infop, &iter);
        r.set_arg3((uintptr_t)infop);
      } else {
        record_noop_data(t);
      }
      t->set_regs(r);

      finish_restoring_scratch(t, iter, &data);
      break;
    }
    case Arch::waitpid:
    case Arch::wait4: {
      auto rusage = pop_arg_ptr<typename Arch::rusage>(t);
      int* status = pop_arg_ptr<int>(t);
      uint8_t* iter;
      void* data = start_restoring_scratch(t, &iter);

      Registers r = t->regs();
      if (status) {
        restore_and_record_arg(t, status, &iter);
        r.set_arg2((uintptr_t)status);
      } else {
        record_noop_data(t);
      }
      if (rusage) {
        restore_and_record_arg(t, rusage, &iter);
        r.set_arg4((uintptr_t)rusage);
      } else if (Arch::wait4 == syscallno) {
        record_noop_data(t);
      }
      t->set_regs(r);

      finish_restoring_scratch(t, iter, &data);
      break;
    }
    case Arch::write:
    case Arch::writev:
      break;
    case Arch::sched_setaffinity: {
      // Restore the register that we altered.
      Registers r = t->regs();
      r.set_arg1(reinterpret_cast<uintptr_t>(pop_arg_ptr<void>(t)));
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

void rec_process_syscall(Task* t)
    RR_ARCH_FUNCTION(rec_process_syscall_arch, t->arch(), t)
