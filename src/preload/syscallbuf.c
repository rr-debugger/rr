/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#define RR_IMPLEMENT_PRELOAD

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "syscallbuf.h"

/**
 * Buffer syscalls, so that rr can process the entire buffer with one
 * trap instead of a trap per call.
 *
 * This file is compiled into a dso that's PRELOADed in recorded
 * applications.  The dso replaces libc syscall wrappers with our own
 * implementation that saves nondetermistic outparams in a fixed-size
 * buffer.  When the buffer is full or the recorded application
 * invokes an un-buffered syscall or receives a signal, we trap to rr
 * and it records the state of the buffer.
 *
 * During replay, rr simply refills the buffer with the recorded data
 * when it reaches the "flush-buffer" events that were recorded.  Then
 * rr emulates each buffered syscall, and the code here restores the
 * client data from the refilled buffer.
 *
 * The crux of the implementation here is to selectively ptrace-trap
 * syscalls.  The normal (un-buffered) syscalls generate a ptrace
 * trap, and the buffered syscalls trap directly to the kernel.  This
 * is implemented with a seccomp-bpf which examines the syscall and
 * decides how to handle it (see seccomp-bpf.h and Task::spawn).
 *
 * Because this code runs in the tracee's address space and overrides
 * system calls, the code is rather delicate.  The following rules
 * must be followed
 *
 * o No rr headers (other than seccomp-bpf.h and rr.h) may be included
 * o All syscalls invoked by this code must be called directly, not
 *   through libc wrappers (which this file may itself indirectly override)
 *
 * The wrapper functions are named sys_xxxx. Each wrapper normally makes one
 * untraced syscall or one traced syscall of the same type, but there are
 * exceptions. For example sys_read can make a number of untraced syscalls
 * instead of a single untraced syscall. A critical rule is that any traced
 * or MAY_BLOCK untraced syscall *must* be the last syscall performed by the
 * wrapper.
 */

#include <dlfcn.h>
#include <limits.h>
#include <asm/errno.h>
#include <asm/ioctls.h>
#include <asm/poll.h>
#include <asm/signal.h>
#include <asm/siginfo.h>
#include <asm/stat.h>
#include <asm/statfs.h>
#include <linux/eventpoll.h>
#include <linux/futex.h>
#include <linux/fcntl.h>
#include <linux/if_packet.h>
#include <linux/ioctl.h>
#include <linux/mman.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/quota.h>
#include <linux/resource.h>
#include <linux/stat.h>
#include <linux/socket.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/uio.h>
#include <linux/un.h>
#include <stdarg.h>
#include <stdio.h>
#include <syscall.h>
#include <sysexits.h>
#include <unistd.h>

#include "preload_interface.h"
#include "rr/rr.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef BTRFS_IOCTL_MAGIC
#define BTRFS_IOCTL_MAGIC 0x94
#endif
#ifndef BTRFS_IOC_CLONE_RANGE
struct btrfs_ioctl_clone_range_args {
  int64_t src_fd;
  uint64_t src_offset;
  uint64_t src_length;
  uint64_t dest_offset;
};
#define BTRFS_IOC_CLONE_RANGE                                                  \
  _IOW(BTRFS_IOCTL_MAGIC, 13, struct btrfs_ioctl_clone_range_args)
#endif
#ifndef MADV_FREE
#define MADV_FREE 8
#endif

/* NB: don't include any other local headers here. */

#ifdef memcpy
#undef memcpy
#endif
#define memcpy you_must_use_local_memcpy

#ifdef syscall
#undef syscall
#endif
#define syscall you_must_use_traced_syscall

/**
 * Declaring this to avoid issues with the declaration of f_owner_ex
 * across distros. See https://github.com/rr-debugger/rr/issues/2693 */
struct rr_f_owner_ex {
  int type;
  int pid;
};

#ifndef __ARCH_FLOCK64_PAD
#define __ARCH_FLOCK64_PAD
#endif
struct rr_flock64 {
    short  l_type;
    short  l_whence;
    __kernel_loff_t l_start;
    __kernel_loff_t l_len;
    __kernel_pid_t  l_pid;
    __ARCH_FLOCK64_PAD
};

/* Nonzero when syscall buffering is enabled. */
static int buffer_enabled;
/* Nonzero after process-global state has been initialized. */
static int process_inited;

RR_HIDDEN struct preload_globals globals;
RR_HIDDEN char impose_syscall_delay;
RR_HIDDEN char impose_spurious_desched;
RR_HIDDEN int (*real_pthread_mutex_lock)(void* mutex);
RR_HIDDEN int (*real_pthread_mutex_trylock)(void* mutex);
RR_HIDDEN int (*real_pthread_mutex_timedlock)(void* mutex,
                                              const struct timespec* abstime);

static struct preload_thread_locals* const thread_locals =
    (struct preload_thread_locals*)PRELOAD_THREAD_LOCALS_ADDR;

/**
 * Return a pointer to the buffer header, which happens to occupy the
 * initial bytes in the mapped region.
 */
static struct syscallbuf_hdr* buffer_hdr(void) {
  return (struct syscallbuf_hdr*)thread_locals->buffer;
}

/**
 * This is for testing purposes only.
 */
void* syscallbuf_ptr(void) {
  return thread_locals->buffer;
}

/**
 * Return a pointer to the byte just after the last valid syscall record in
 * the buffer.
 */
static uint8_t* buffer_last(void) {
  return (uint8_t*)next_record(buffer_hdr());
}

/**
 * Return a pointer to the byte just after the very end of the mapped
 * region.
 */
static uint8_t* buffer_end(void) {
  return thread_locals->buffer + thread_locals->buffer_size;
}

/**
 * Same as libc memcpy(), but usable within syscallbuf transaction
 * critical sections.
 */
static void local_memcpy(void* dest, const void* source, int n) {
#if defined(__i386__) || defined(__x86_64__)
  /* On modern x86-ish CPUs rep movsb is fast, usually able to move
   * 64 bytes at a time.
   */
  __asm__ __volatile__("rep movsb\n\t"
                       : "+S"(source), "+D"(dest), "+c"(n)
                       :
                       : "cc", "memory");
#else
#error Unknown architecture
#endif
}

/**
 * Same as libc memset(), but usable within syscallbuf transaction
 * critical sections.
 */
static void local_memset(void* dest, uint8_t c, int n) {
#if defined(__i386__) || defined(__x86_64__)
  /* On modern x86-ish CPUs rep stosb is fast, usually able to move
   * 64 bytes at a time.
   */
  __asm__ __volatile__("rep stosb\n\t"
                       : "+a"(c), "+D"(dest), "+c"(n)
                       :
                       : "cc", "memory");
#else
#error Unknown architecture
#endif
}

/**
 * Xorshift* RNG
 */
static int64_t local_random(void) {
  uint64_t x = globals.random_seed;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  globals.random_seed = x;
  return x * 0x2545F4914F6CDD1D;
}

/* The following are wrappers for the syscalls invoked by this library
 * itself.  These syscalls will generate ptrace traps.
 * stack_param_1 and stack_param_2 are pushed onto the stack just before
 * the syscall, for SYS_rrcall_notify_syscall_hook_exit which takes stack
 * parameters as well as register parameters.
 * syscall_instruction is the actual syscall invocation instruction
 * (a function which we call with the registers set up appropriately).
 */

extern RR_HIDDEN long _raw_syscall(int syscallno, long a0, long a1, long a2,
                                   long a3, long a4, long a5,
                                   void* syscall_instruction,
                                   long stack_param_1, long stack_param_2);

static int privileged_traced_syscall(int syscallno, long a0, long a1, long a2,
                                     long a3, long a4, long a5) {
  return _raw_syscall(syscallno, a0, a1, a2, a3, a4, a5,
                      RR_PAGE_SYSCALL_PRIVILEGED_TRACED, 0, 0);
}
#define privileged_traced_syscall6(no, a0, a1, a2, a3, a4, a5)                 \
  privileged_traced_syscall(no, (uintptr_t)a0, (uintptr_t)a1, (uintptr_t)a2,   \
                            (uintptr_t)a3, (uintptr_t)a4, (uintptr_t)a5)
#define privileged_traced_syscall5(no, a0, a1, a2, a3, a4)                     \
  privileged_traced_syscall6(no, a0, a1, a2, a3, a4, 0)
#define privileged_traced_syscall4(no, a0, a1, a2, a3)                         \
  privileged_traced_syscall5(no, a0, a1, a2, a3, 0)
#define privileged_traced_syscall3(no, a0, a1, a2)                             \
  privileged_traced_syscall4(no, a0, a1, a2, 0)
#define privileged_traced_syscall2(no, a0, a1)                                 \
  privileged_traced_syscall3(no, a0, a1, 0)
#define privileged_traced_syscall1(no, a0) privileged_traced_syscall2(no, a0, 0)
#define privileged_traced_syscall0(no) privileged_traced_syscall1(no, 0)

/**
 * Make a raw traced syscall using the params in |call|.
 */
static long traced_raw_syscall(const struct syscall_info* call) {
  /* FIXME: pass |call| to avoid pushing these on the stack
   * again. */
  return _raw_syscall(call->no, call->args[0], call->args[1], call->args[2],
                      call->args[3], call->args[4], call->args[5],
                      RR_PAGE_SYSCALL_TRACED, 0, 0);
}

#if defined(SYS_fcntl64)
#define RR_FCNTL_SYSCALL SYS_fcntl64
#else
#define RR_FCNTL_SYSCALL SYS_fcntl
#endif

static int privileged_traced_fcntl(int fd, int cmd, ...) {
  va_list ap;
  void* arg;

  va_start(ap, cmd);
  arg = va_arg(ap, void*);
  va_end(ap);

  return privileged_traced_syscall3(RR_FCNTL_SYSCALL, fd, cmd, arg);
}

static pid_t privileged_traced_getpid(void) {
  return privileged_traced_syscall0(SYS_getpid);
}

static pid_t privileged_traced_gettid(void) {
  return privileged_traced_syscall0(SYS_gettid);
}

static int privileged_traced_perf_event_open(struct perf_event_attr* attr,
                                             pid_t pid, int cpu, int group_fd,
                                             unsigned long flags) {
  return privileged_traced_syscall5(SYS_perf_event_open, attr, pid, cpu,
                                    group_fd, flags);
}

static __attribute__((noreturn)) void privileged_traced_raise(int sig) {
  privileged_traced_syscall2(SYS_kill, privileged_traced_getpid(), sig);
  __builtin_unreachable();
}

static ssize_t privileged_traced_write(int fd, const void* buf, size_t count) {
  return privileged_traced_syscall3(SYS_write, fd, buf, count);
}

static void logmsg(const char* msg) {
  privileged_traced_write(STDERR_FILENO, msg, rrstrlen(msg));
}

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#ifndef NDEBUG
#define assert(cond)                                                           \
  do {                                                                         \
    if (!(cond)) {                                                             \
      logmsg(__FILE__ ":" STR(__LINE__) ": Assertion `" #cond "' failed.\n");  \
      privileged_traced_raise(SIGABRT);                                        \
    }                                                                          \
  } while (0)
#else
#define assert(cond)                                                           \
  do {                                                                         \
    __attribute__((unused)) size_t s = sizeof(cond);                           \
  } while (0)
#endif

#define fatal(msg)                                                             \
  do {                                                                         \
    logmsg(__FILE__ ":" STR(__LINE__) ": Fatal error: " msg "\n");            \
    privileged_traced_raise(SIGABRT);                                          \
  } while (0)

/**
 * Unlike |traced_syscall()|, this helper is implicitly "raw" (returns
 * the direct kernel return value), because the syscall hooks have to
 * save that raw return value.
 * This is only called from syscall wrappers that are doing a proper
 * buffered syscall.
 */
static long untraced_syscall_base(int syscallno, long a0, long a1, long a2,
                                  long a3, long a4, long a5,
                                  void* syscall_instruction) {
  struct syscallbuf_record* rec = (struct syscallbuf_record*)buffer_last();
  /* Ensure tools analyzing the replay can find the pending syscall result */
  thread_locals->pending_untraced_syscall_result = &rec->ret;
  long ret = _raw_syscall(syscallno, a0, a1, a2, a3, a4, a5,
                          syscall_instruction, 0, 0);
  unsigned char tmp_in_replay = globals.in_replay;
/* During replay, return the result that's already in the buffer, instead
   of what our "syscall" returned. */
#if defined(__i386__) || defined(__x86_64__)
  /* On entry, during recording %eax/%rax are whatever the kernel returned
   * but during replay they may be invalid (e.g. 0). During replay, reload
   * %eax/%rax from |rec->ret|. At the end of this sequence all registers
   * will match between recording and replay. We clobber the temporary
   * in_replay register, and the condition codes, to ensure this.
   * This all assumes the compiler doesn't create unnecessary temporaries
   * holding values like |ret|. Inspection of generated code shows it doesn't.
   */
  __asm__("test %1,%1\n\t"
          "cmovne %2,%0\n\t"
          "xor %1,%1\n\t"
          : "+a"(ret), "+c"(tmp_in_replay)
          : "m"(rec->ret)
          : "cc");
#else
#error Unknown architecture
#endif
  return ret;
}
#define untraced_syscall6(no, a0, a1, a2, a3, a4, a5)                          \
  untraced_syscall_base(no, (uintptr_t)a0, (uintptr_t)a1, (uintptr_t)a2,       \
                        (uintptr_t)a3, (uintptr_t)a4, (uintptr_t)a5,           \
                        RR_PAGE_SYSCALL_UNTRACED_RECORDING_ONLY)
#define untraced_syscall5(no, a0, a1, a2, a3, a4)                              \
  untraced_syscall6(no, a0, a1, a2, a3, a4, 0)
#define untraced_syscall4(no, a0, a1, a2, a3)                                  \
  untraced_syscall5(no, a0, a1, a2, a3, 0)
#define untraced_syscall3(no, a0, a1, a2) untraced_syscall4(no, a0, a1, a2, 0)
#define untraced_syscall2(no, a0, a1) untraced_syscall3(no, a0, a1, 0)
#define untraced_syscall1(no, a0) untraced_syscall2(no, a0, 0)
#define untraced_syscall0(no) untraced_syscall1(no, 0)

#define untraced_replayed_syscall6(no, a0, a1, a2, a3, a4, a5)                 \
  untraced_syscall_base(no, (uintptr_t)a0, (uintptr_t)a1, (uintptr_t)a2,       \
                        (uintptr_t)a3, (uintptr_t)a4, (uintptr_t)a5,           \
                        RR_PAGE_SYSCALL_UNTRACED)
#define untraced_replayed_syscall5(no, a0, a1, a2, a3, a4)                     \
  untraced_replayed_syscall6(no, a0, a1, a2, a3, a4, 0)
#define untraced_replayed_syscall4(no, a0, a1, a2, a3)                         \
  untraced_replayed_syscall5(no, a0, a1, a2, a3, 0)
#define untraced_replayed_syscall3(no, a0, a1, a2)                             \
  untraced_replayed_syscall4(no, a0, a1, a2, 0)
#define untraced_replayed_syscall2(no, a0, a1)                                 \
  untraced_replayed_syscall3(no, a0, a1, 0)
#define untraced_replayed_syscall1(no, a0) untraced_replayed_syscall2(no, a0, 0)
#define untraced_replayed_syscall0(no) untraced_replayed_syscall1(no, 0)

static long __attribute__((unused))
untraced_replay_assist_syscall_base(int syscallno, long a0, long a1, long a2,
                                    long a3, long a4, long a5,
                                    void* syscall_instruction)  {
  struct syscallbuf_record* rec = (struct syscallbuf_record*)buffer_last();
  rec->replay_assist = 1;
  return untraced_syscall_base(syscallno, a0, a1, a2, a3, a4, a5, syscall_instruction);
}

#define untraced_replay_assist_syscall6(no, a0, a1, a2, a3, a4, a5)            \
  untraced_replay_assist_syscall_base(                                         \
                        no, (uintptr_t)a0, (uintptr_t)a1, (uintptr_t)a2,       \
                        (uintptr_t)a3, (uintptr_t)a4, (uintptr_t)a5,           \
                        RR_PAGE_SYSCALL_UNTRACED_REPLAY_ASSIST)
#define untraced_replay_assist_syscall5(no, a0, a1, a2, a3, a4)                \
  untraced_replay_assist_syscall6(no, a0, a1, a2, a3, a4, 0)
#define untraced_replay_assist_syscall4(no, a0, a1, a2, a3)                    \
  untraced_replay_assist_syscall5(no, a0, a1, a2, a3, 0)
#define untraced_replay_assist_syscall3(no, a0, a1, a2)                        \
  untraced_replay_assist_syscall4(no, a0, a1, a2, 0)
#define untraced_replay_assist_syscall2(no, a0, a1)                            \
  untraced_replay_assist_syscall3(no, a0, a1, 0)
#define untraced_replay_assist_syscall1(no, a0)                                \
  untraced_replay_assist_syscall2(no, a0, 0)
#define untraced_replay_assist_syscall0(no)                                    \
  untraced_replay_assist_syscall1(no, 0)

#define privileged_untraced_syscall6(no, a0, a1, a2, a3, a4, a5)               \
  _raw_syscall(no, (uintptr_t)a0, (uintptr_t)a1, (uintptr_t)a2, (uintptr_t)a3, \
               (uintptr_t)a4, (uintptr_t)a5,                                   \
               RR_PAGE_SYSCALL_PRIVILEGED_UNTRACED_RECORDING_ONLY, 0, 0)
#define privileged_untraced_syscall5(no, a0, a1, a2, a3, a4)                   \
  privileged_untraced_syscall6(no, a0, a1, a2, a3, a4, 0)
#define privileged_untraced_syscall4(no, a0, a1, a2, a3)                       \
  privileged_untraced_syscall5(no, a0, a1, a2, a3, 0)
#define privileged_untraced_syscall3(no, a0, a1, a2)                           \
  privileged_untraced_syscall4(no, a0, a1, a2, 0)
#define privileged_untraced_syscall2(no, a0, a1)                               \
  privileged_untraced_syscall3(no, a0, a1, 0)
#define privileged_untraced_syscall1(no, a0)                                   \
  privileged_untraced_syscall2(no, a0, 0)
#define privileged_untraced_syscall0(no) privileged_untraced_syscall1(no, 0)

#define replay_only_syscall6(no, a0, a1, a2, a3, a4, a5)                       \
  _raw_syscall(no, (uintptr_t)a0, (uintptr_t)a1, (uintptr_t)a2, (uintptr_t)a3, \
               (uintptr_t)a4, (uintptr_t)a5,                                   \
               RR_PAGE_SYSCALL_PRIVILEGED_UNTRACED_REPLAY_ONLY, 0, 0)
#define replay_only_syscall5(no, a0, a1, a2, a3, a4)                           \
  replay_only_syscall6(no, a0, a1, a2, a3, a4, 0)
#define replay_only_syscall4(no, a0, a1, a2, a3)                               \
  replay_only_syscall5(no, a0, a1, a2, a3, 0)
#define replay_only_syscall3(no, a0, a1, a2)                                   \
  replay_only_syscall4(no, a0, a1, a2, 0)
#define replay_only_syscall2(no, a0, a1) replay_only_syscall3(no, a0, a1, 0)
#define replay_only_syscall1(no, a0) replay_only_syscall2(no, a0, 0)
#define replay_only_syscall0(no) replay_only_syscall1(no, 0)

static int privileged_untraced_close(int fd) {
  return privileged_untraced_syscall1(SYS_close, fd);
}

static int privileged_untraced_fcntl(int fd, int cmd, ...) {
  va_list ap;
  void* arg;

  va_start(ap, cmd);
  arg = va_arg(ap, void*);
  va_end(ap);

  return privileged_untraced_syscall3(RR_FCNTL_SYSCALL, fd, cmd, arg);
}

/**
 * Do what's necessary to set up buffers for the caller.
 * |untraced_syscall_ip| lets rr know where our untraced syscalls will
 * originate from.  |addr| is the address of the control socket the
 * child expects to connect to.  |msg| is a pre-prepared IPC that can
 * be used to share fds; |fdptr| is a pointer to the control-message
 * data buffer where the fd number being shared will be stored.
 * |args_vec| provides the tracer with preallocated space to make
 * socketcall syscalls.
 *
 * Return a pointer to the syscallbuf (with an initialized header
 * including the available size), if syscallbuf is enabled.
 *
 * This is a "magic" syscall implemented by rr.
 */
static void rrcall_init_buffers(struct rrcall_init_buffers_params* args) {
  privileged_traced_syscall1(SYS_rrcall_init_buffers, args);
}

/**
 * Return a counter that generates a signal targeted at this task
 * every time the task is descheduled |nr_descheds| times.
 */
static int open_desched_event_counter(size_t nr_descheds, pid_t tid) {
  struct perf_event_attr attr;
  int tmp_fd, fd;
  struct rr_f_owner_ex own;

  local_memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_CONTEXT_SWITCHES;
  attr.disabled = 1;
  attr.sample_period = nr_descheds;

  tmp_fd = privileged_traced_perf_event_open(&attr, 0 /*self*/, -1 /*any cpu*/,
                                             -1, 0);
  if (0 > tmp_fd) {
    fatal("Failed to perf_event_open");
  }
  fd = privileged_traced_fcntl(tmp_fd, F_DUPFD_CLOEXEC,
                               RR_DESCHED_EVENT_FLOOR_FD);
  if (fd > 0) {
    if (privileged_untraced_close(tmp_fd)) {
      fatal("Failed to close tmp_fd");
    }
  } else {
    // We may be unable to find an fd above the RR_DESCHED_EVENT_FLOOR_FD (e.g
    // because of a low ulimit). In that case, just use the tmp_fd we already
    // have.
    fd = tmp_fd;
  }
  if (privileged_untraced_fcntl(fd, F_SETFL, FASYNC)) {
    fatal("Failed to fcntl(FASYNC) the desched counter");
  }
  own.type = F_OWNER_TID;
  own.pid = tid;
  if (privileged_untraced_fcntl(fd, F_SETOWN_EX, &own)) {
    fatal("Failed to fcntl(SETOWN_EX) the desched counter to this");
  }
  if (privileged_untraced_fcntl(fd, F_SETSIG, globals.desched_sig)) {
    fatal("Failed to fcntl(SETSIG) the desched counter");
  }

  return fd;
}

/**
 * Initialize thread-local buffering state, if enabled and not already
 * initialized.
 */
static void init_thread(void) {
  struct rrcall_init_buffers_params args;

  assert(process_inited);
  if (thread_locals->thread_inited) {
    return;
  }
  thread_locals->thread_inited = 1;

  /* Do not do any syscall buffering in a DiversionSession! */
  if (!buffer_enabled || globals.in_diversion) {
    return;
  }

  /* NB: we want this setup emulated during replay. */
  thread_locals->desched_counter_fd =
      open_desched_event_counter(1, privileged_traced_gettid());

  args.desched_counter_fd = thread_locals->desched_counter_fd;

  /* Trap to rr: let the magic begin!
   *
   * If the desched signal is currently blocked, then the tracer
   * will clear our TCB guard and we won't be able to buffer
   * syscalls.  But the tracee will set the guard when (or if)
   * the signal is unblocked. */
  rrcall_init_buffers(&args);

  thread_locals->cloned_file_data_fd = args.cloned_file_data_fd;
  /* rr initializes the buffer header. */
  thread_locals->buffer = args.syscallbuf_ptr;
  thread_locals->buffer_size = args.syscallbuf_size;
  thread_locals->scratch_buf = args.scratch_buf;
  thread_locals->usable_scratch_size = args.usable_scratch_size;
}

// We don't include libc headers, since they include with Linux headers,
// so declared this prototype manually
extern const char* getenv(const char*);

/**
 * Initialize process-global buffering state, if enabled.
 * NOTE: constructors go into a special section by default so this won't
 * be counted as syscall-buffering code!
 */
static void __attribute__((constructor)) init_process(void) {
  struct rrcall_init_preload_params params;

  extern char _syscallbuf_final_exit_instruction;
  extern char _syscallbuf_code_start;
  extern char _syscallbuf_code_end;
  extern char do_breakpoint_fault_addr;

#if defined(__i386__)
  extern RR_HIDDEN void __morestack(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_3d_01_f0_ff_ff(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_90_90_90(void);
  struct syscall_patch_hook syscall_patch_hooks[] = {
    /* pthread_cond_broadcast has 'int 80' followed by
     * cmp $-4095,%eax (in glibc-2.18-16.fc20.i686) */
    { 0,
      5,
      { 0x3d, 0x01, 0xf0, 0xff, 0xff },
      (uintptr_t)_syscall_hook_trampoline_3d_01_f0_ff_ff },
    /* Our vdso syscall patch has 'int 80' followed by onp; nop; nop */
    { 0, 3, { 0x90, 0x90, 0x90 }, (uintptr_t)_syscall_hook_trampoline_90_90_90 }
  };
  extern char _get_pc_thunks_start;
  extern char _get_pc_thunks_end;
#elif defined(__x86_64__)
  extern RR_HIDDEN void _syscall_hook_trampoline_48_3d_01_f0_ff_ff(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_48_3d_00_f0_ff_ff(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_48_8b_3c_24(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_5a_5e_c3(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_89_c2_f7_da(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_90_90_90(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_ba_01_00_00_00(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_89_c1_31_d2(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_c3_nop(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_40_80_f6_81(void);

  struct syscall_patch_hook syscall_patch_hooks[] = {
    /* Many glibc syscall wrappers (e.g. read) have 'syscall' followed
     * by
     * cmp $-4095,%rax (in glibc-2.18-16.fc20.x86_64) */
    { 0,
      6,
      { 0x48, 0x3d, 0x01, 0xf0, 0xff, 0xff },
      (uintptr_t)_syscall_hook_trampoline_48_3d_01_f0_ff_ff },
    /* Many glibc syscall wrappers (e.g. __libc_recv) have 'syscall'
     * followed by
     * cmp $-4096,%rax (in glibc-2.18-16.fc20.x86_64) */
    { 0,
      6,
      { 0x48, 0x3d, 0x00, 0xf0, 0xff, 0xff },
      (uintptr_t)_syscall_hook_trampoline_48_3d_00_f0_ff_ff },
    /* Many glibc syscall wrappers (e.g. read) have 'syscall' followed
     * by
     * mov (%rsp),%rdi (in glibc-2.18-16.fc20.x86_64) */
    { 0,
      4,
      { 0x48, 0x8b, 0x3c, 0x24 },
      (uintptr_t)_syscall_hook_trampoline_48_8b_3c_24 },
    /* __lll_unlock_wake has 'syscall' followed by
     * pop %rdx; pop %rsi; ret */
    { PATCH_IS_MULTIPLE_INSTRUCTIONS,
      3,
      { 0x5a, 0x5e, 0xc3 },
      (uintptr_t)_syscall_hook_trampoline_5a_5e_c3 },
    /* posix_fadvise64 has 'syscall' followed by
     * mov %eax,%edx; neg %edx (in glibc-2.22-11.fc23.x86_64) */
    { PATCH_IS_MULTIPLE_INSTRUCTIONS,
      4,
      { 0x89, 0xc2, 0xf7, 0xda },
      (uintptr_t)_syscall_hook_trampoline_89_c2_f7_da },
    /* Our VDSO vsyscall patches have 'syscall' followed by "nop; nop;
       nop" */
    { PATCH_IS_MULTIPLE_INSTRUCTIONS,
      3,
      { 0x90, 0x90, 0x90 },
      (uintptr_t)_syscall_hook_trampoline_90_90_90 },
    /* glibc-2.22-17.fc23.x86_64 has 'syscall' followed by 'mov $1,%rdx'
     * in
     * pthread_barrier_wait.
     */
    { 0,
      5,
      { 0xba, 0x01, 0x00, 0x00, 0x00 },
      (uintptr_t)_syscall_hook_trampoline_ba_01_00_00_00 },
    /* pthread_sigmask has 'syscall' followed by 'mov %eax,%ecx; xor
       %edx,%edx' */
    { PATCH_IS_MULTIPLE_INSTRUCTIONS,
      4,
      { 0x89, 0xc1, 0x31, 0xd2 },
      (uintptr_t)_syscall_hook_trampoline_89_c1_31_d2 },
    /* getpid has 'syscall' followed by 'retq; nopl 0x0(%rax,%rax,1) */
    { PATCH_IS_MULTIPLE_INSTRUCTIONS,
      9,
      { 0xc3, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 },
      (uintptr_t)_syscall_hook_trampoline_c3_nop },
    /* liblsan internal_close has 'syscall' followed by 'retq; nopl 0x0(%rax,%rax,1) */
    { PATCH_IS_MULTIPLE_INSTRUCTIONS,
      6,
      { 0xc3, 0x0f, 0x1f, 0x44, 0x00, 0x00 },
      (uintptr_t)_syscall_hook_trampoline_c3_nop },
    /* glibc-2.29-15.fc30.x86_64 getpid has 'syscall' followed by 'retq; nopl 0x0(%rax) */
    { PATCH_IS_MULTIPLE_INSTRUCTIONS,
      5,
      { 0xc3, 0x0f, 0x1f, 0x40, 0x00 },
      (uintptr_t)_syscall_hook_trampoline_c3_nop },
    /* liblsan internal_open has 'syscall' followed by 'retq; nopl (%rax) */
    { PATCH_IS_MULTIPLE_INSTRUCTIONS,
      4,
      { 0xc3, 0x0f, 0x1f, 0x00 },
      (uintptr_t)_syscall_hook_trampoline_c3_nop },
    /* liblsan internal_dup2 has 'syscall' followed by 'retq; xchg %ax,%ax */
    { PATCH_IS_MULTIPLE_INSTRUCTIONS,
      3,
      { 0xc3, 0x66, 0x90 },
      (uintptr_t)_syscall_hook_trampoline_c3_nop },
    /* Go runtime has 'syscall' followed by 'retq; int3; int3 */
    { PATCH_IS_MULTIPLE_INSTRUCTIONS,
      3,
      { 0xc3, 0xcc, 0xcc },
      (uintptr_t)_syscall_hook_trampoline_c3_nop },
    /* glibc-2.31 on Ubuntu 20.04 has 'xor $0x81, %sil' followed by 'syscall' */
    { PATCH_SYSCALL_INSTRUCTION_IS_LAST,
      4,
      { 0x40, 0x80, 0xf6, 0x81 },
      (uintptr_t)_syscall_hook_trampoline_40_80_f6_81 },
  };
#elif defined(__aarch64__)
  struct syscall_patch_hook syscall_patch_hooks[] = {};
#endif

  assert(sizeof(struct preload_thread_locals) <= PRELOAD_THREAD_LOCALS_SIZE);

  if (process_inited) {
    return;
  }

  buffer_enabled = !!getenv(SYSCALLBUF_ENABLED_ENV_VAR);

  if (!buffer_enabled) {
    // Don't risk executing the syscall before. If there is an external seccomp
    // filter that doesn't like unknown syscalls, we risk breaking the recording.
    return;
  }

  params.syscallbuf_enabled = buffer_enabled;

#ifdef __i386__
  params.syscallhook_vsyscall_entry = (void*)__morestack;
  params.get_pc_thunks_start = &_get_pc_thunks_start;
  params.get_pc_thunks_end = &_get_pc_thunks_end;
#else
  params.syscallhook_vsyscall_entry = NULL;
  params.get_pc_thunks_start = NULL;
  params.get_pc_thunks_end = NULL;
#endif
  params.syscallbuf_code_start = &_syscallbuf_code_start;
  params.syscallbuf_code_end = &_syscallbuf_code_end;
  params.syscallbuf_final_exit_instruction =
      &_syscallbuf_final_exit_instruction;
  params.syscall_patch_hook_count =
      sizeof(syscall_patch_hooks) / sizeof(syscall_patch_hooks[0]);
  params.syscall_patch_hooks = syscall_patch_hooks;
  params.globals = &globals;

  globals.breakpoint_value = (uint64_t)-1;
  globals.fdt_uniform = 1;
  params.breakpoint_instr_addr = &do_breakpoint_fault_addr;
  params.breakpoint_mode_sentinel = -1;

  privileged_traced_syscall1(SYS_rrcall_init_preload, &params);
  int err = privileged_traced_syscall1(SYS_rrcall_init_preload, &params);
  if (err != 0) {
    fatal("Failed to communicated with rr tracer.\n"
          "Perhaps a restrictive seccomp filter is in effect (e.g. docker?)?\n"
          "Adjust the seccomp filter to allow syscalls above 1000, disable it,\n"
          "or try using `rr record -n` (slow).");
  }

  real_pthread_mutex_lock = dlsym(RTLD_NEXT, "pthread_mutex_lock");
  real_pthread_mutex_trylock = dlsym(RTLD_NEXT, "pthread_mutex_trylock");
  real_pthread_mutex_timedlock = dlsym(RTLD_NEXT, "pthread_mutex_timedlock");

  process_inited = 1;
}

/**
 * syscall hooks start here.
 *
 * !!! NBB !!!: from here on, all code that executes within the
 * critical sections of transactions *MUST KEEP $ip IN THE SYSCALLBUF
 * CODE*.  That means no calls into libc, even for innocent-looking
 * functions like |memcpy()|.
 *
 * How syscall hooks operate:
 *
 * 1. The rr tracer monkey-patches __kernel_vsyscall() to jump to
 *    _syscall_hook_trampoline() above.
 * 2. When a call is made to __kernel_vsyscall(), it jumps to
 *    _syscall_hook_trampoline(), where the syscall params are
 *    packaged up into a call to syscall_hook() below.
 * 3. syscall_hook() dispatches to a syscall processor function.
 * 4. The syscall processor prepares a new record in the buffer. See
 *    struct syscallbuf_record for record fields.  If the buffer runs
 *    out of space, the processor function aborts and makes a traced
 *    syscall, trapping to rr.  rr then flushes the buffer.  Records
 *    are directly saved to trace, and a buffer-flush event is
 *    recorded without execution info because it's a synthetic event.
 * 5. Then, the syscall processor redirects all potential output
 *    for the syscall to the record (and corrects the overall size of
 *    the record while it does so).
 * 6. The syscall is invoked through a asm helper that does *not*
 *    ptrace-trap to rr.
 * 7. The syscall output, written on the buffer, is copied to the
 *    original pointers provided by the user.  Take notice that this
 *    part saves us the injection of the data on replay, as we only
 *    need to push the data to the buffer and the wrapper code will
 *    copy it to the user address for us.
 * 8. The return value and overall size are saved to the record.
 */

/**
 * Call this and save the result at the start of every system call we
 * want to buffer. The result is a pointer into the record space. You
 * can add to this pointer to allocate space in the trace record.
 * However, do not read or write through this pointer until
 * start_commit_syscall() has been called.  And you *must* call
 * start_commit_syscall() after this is called, otherwise buffering
 * state will be inconsistent between syscalls.
 *
 * See |sys_clock_gettime()| for a simple example of how this helper
 * should be used to buffer outparam data.
 */

static void* prep_syscall(void) {
  /* We don't need to worry about a race between testing
   * |locked| and setting it here. rr recording is responsible
   * for ensuring signals are not delivered during
   * syscall_buffer prologue and epilogue code.
   *
   * XXX except for synchronous signals generated in the syscall
   * buffer code, while reading/writing user pointers */
  buffer_hdr()->locked |= SYSCALLBUF_LOCKED_TRACEE;
  /* "Allocate" space for a new syscall record, not including
   * syscall outparam data. */
  return buffer_last() + sizeof(struct syscallbuf_record);
}

static enum syscallbuf_fd_classes fd_class(int fd) {
  if (fd < 0) {
    return FD_CLASS_INVALID;
  }
  if (fd >= SYSCALLBUF_FDS_DISABLED_SIZE - 1) {
    fd = SYSCALLBUF_FDS_DISABLED_SIZE - 1;
  }
  return globals.syscallbuf_fd_class[fd];
}

static int is_bufferable_fd(int fd) {
  switch (fd_class(fd)) {
    case FD_CLASS_INVALID:
    case FD_CLASS_UNTRACED:
      return 1;
    default:
      return 0;
  }
}

/**
 * Like prep_syscall, but preps a syscall to operate on a particular fd. If
 * syscallbuf is disabled for this fd, returns NULL (in which case
 * start_commit_syscall will abort cleanly and a traced syscall will be used).
 * Allow negative fds to pass through; they'll either trigger an error or
 * receive special treatment by the kernel (e.g. AT_FDCWD).
 */
static void* prep_syscall_for_fd(int fd) {
  if (!is_bufferable_fd(fd)) {
    return NULL;
  }
  return prep_syscall();
}

static void arm_desched_event(void) {
  /* Don't trace the ioctl; doing so would trigger a flushing
   * ptrace trap, which is exactly what this code is trying to
   * avoid! :) Although we don't allocate extra space for these
   * ioctl's, we do record that we called them; the replayer
   * knows how to skip over them. */
  if ((int)privileged_untraced_syscall3(SYS_ioctl,
                                        thread_locals->desched_counter_fd,
                                        PERF_EVENT_IOC_ENABLE, 0)) {
    fatal("Failed to ENABLE counter");
  }
}

static void disarm_desched_event(void) {
  /* See above. */
  if ((int)privileged_untraced_syscall3(SYS_ioctl,
                                        thread_locals->desched_counter_fd,
                                        PERF_EVENT_IOC_DISABLE, 0)) {
    fatal("Failed to DISABLE counter");
  }
}

/**
 * Return 1 if it's ok to proceed with buffering this system call.
 * Return 0 if we should trace the system call.
 * This must be checked before proceeding with the buffered system call.
 */
/* (Negative numbers so as to not be valid syscall numbers, in case
 * the |int| arguments below are passed in the wrong order.) */
enum { MAY_BLOCK = -1, WONT_BLOCK = -2 };

static int fd_write_blocks(int fd) {
  if (!globals.fdt_uniform) {
    // If we're not uniform, it is possible for this fd to be untraced in one
    // of the other tasks that share this fd table. Always assume it could block.
    return MAY_BLOCK;
  }
  switch (fd_class(fd)) {
    case FD_CLASS_UNTRACED:
    case FD_CLASS_TRACED:
      return MAY_BLOCK;
    case FD_CLASS_INVALID:
    case FD_CLASS_PROC_MEM:
      return WONT_BLOCK;
  }
  fatal("Unknown or corrupted fd class");
}

static int start_commit_buffered_syscall(int syscallno, void* record_end,
                                         int blockness) {
  void* record_start;
  void* stored_end;
  struct syscallbuf_record* rec;

  if (!thread_locals->buffer) {
    return 0;
  }
  record_start = buffer_last();
  stored_end = record_start + stored_record_size(record_end - record_start);
  rec = record_start;

  if (stored_end < record_start + sizeof(struct syscallbuf_record)) {
    /* Either a catastrophic buffer overflow or
     * we failed to lock the buffer. Just bail out. */
    return 0;
  }
  if (stored_end > (void*)buffer_end() - sizeof(struct syscallbuf_record)) {
    /* Buffer overflow.
     * Unlock the buffer and then execute the system call
     * with a trap to rr.  Note that we reserve enough
     * space in the buffer for the next prep_syscall(). */
    buffer_hdr()->locked &= ~SYSCALLBUF_LOCKED_TRACEE;
    return 0;
  }
  /* Store this breadcrumb so that the tracer can find out what
   * syscall we're executing if our registers are in a weird
   * state.  If we end up aborting this syscall, no worry, this
   * will just be overwritten later.
   *
   * NBB: this *MUST* be set before the desched event is
   * armed. */
  rec->syscallno = syscallno;
  rec->desched = MAY_BLOCK == blockness;
  rec->size = record_end - record_start;

  if (rec->desched) {
    pid_t pid = 0;
    pid_t tid = 0;
    uid_t uid = 0;
    if (impose_spurious_desched) {
      pid = privileged_untraced_syscall0(SYS_getpid);
      tid = privileged_untraced_syscall0(SYS_gettid);
      uid = privileged_untraced_syscall0(SYS_getuid);
    }

    /* NB: the ordering of the next two statements is
     * important.
     *
     * We set this flag to notify rr that it should pay
     * attention to desched signals pending for this task.
     * We have to set it *before* we arm the notification
     * because we can't set the flag atomically with
     * arming the event (too bad there's no ioctl() for
     * querying the event enabled-ness state).  That's
     * important because if the notification is armed,
     * then rr must be confident that when it disarms the
     * event, the tracee is at an execution point that
     * *must not* need the desched event.
     *
     * If we were to set the flag non-atomically after the
     * event was armed, then if a desched signal was
     * delivered right at the instruction that set the
     * flag, rr wouldn't know that it needed to advance
     * the tracee to the untraced syscall entry point.
     * (And if rr didn't do /that/, then the syscall might
     * block without rr knowing it, and the recording
     * session would deadlock.) */
    buffer_hdr()->desched_signal_may_be_relevant = 1;
    arm_desched_event();
    if (impose_spurious_desched) {
      siginfo_t si;
      si.si_code = POLL_IN;
      si.si_fd = thread_locals->desched_counter_fd;
      si.si_pid = pid;
      si.si_uid = uid;
      privileged_untraced_syscall4(SYS_rt_tgsigqueueinfo, pid, tid,
                                   globals.desched_sig,
                                   &si);
    }
  }
  return 1;
}

static void __attribute__((noinline)) do_breakpoint(size_t value)
{
  char *unsafe_value = ((char*)-1)-0xf;
  char **safe_value = &unsafe_value;
  uint64_t *breakpoint_value_addr = &globals.breakpoint_value;
  __asm__ __volatile__(
                      "mov (%1),%1\n\t"
                      "cmp %0,%1\n\t"
                      "cmove %3,%2\n\t"
                      // This will segfault if `value` matches
                      // the `breakpoint_value` set by rr. We
                      // detect this segfault and treat it
                      // specially.
                      "do_breakpoint_fault_addr:\n\t"
                      ".global do_breakpoint_fault_addr\n\t"
                      "mov (%2),%2\n\t"
                      "xor %1,%1\n\t"
                      "xor %2,%2\n\t"
                      "xor %3,%3\n\t"
                      : "+a"(value), "+D"(breakpoint_value_addr),
                        "+S"(safe_value), "+c"(unsafe_value)
                      :
                      : "cc", "memory");
}

/**
 * Commit the record for a buffered system call.  record_end can be
 * adjusted downward from what was passed to
 * start_commit_buffered_syscall, if not all of the initially
 * requested space is needed.  The result of this function should be
 * returned directly by the kernel syscall hook.
 */
static long commit_raw_syscall(int syscallno, void* record_end, long ret) {
  void* record_start = buffer_last();
  struct syscallbuf_record* rec = record_start;
  struct syscallbuf_hdr* hdr = buffer_hdr();
  int call_breakpoint = 0;

  assert(record_end >= record_start);
  rec->size = record_end - record_start;

  assert(hdr->locked);

  /* NB: the ordering of this statement with the
   * |disarm_desched_event()| call below is important.
   *
   * We clear this flag to notify rr that the may-block syscall
   * has finished, so there's no danger of blocking anymore.
   * (And thus the desched signal is no longer relevant.)  We
   * have to clear this *before* disarming the event, because if
   * rr sees the flag set, it has to PTRACE_SYSCALL this task to
   * ensure it reaches an execution point where the desched
   * signal is no longer relevant.  We have to use the ioctl()
   * that disarms the event as a safe "backstop" that can be hit
   * by the PTRACE_SYSCALL.
   *
   * If we were to clear the flag *after* disarming the event,
   * and the signal arrived at the instruction that cleared the
   * flag, and rr issued the PTRACE_SYSCALL, then this tracee
   * could fly off to any unknown execution point, including an
   * iloop.  So the recording session could livelock. */
  hdr->desched_signal_may_be_relevant = 0;

  if (rec->syscallno != syscallno) {
    fatal("Record syscall number mismatch");
  }

  if (hdr->abort_commit) {
    /* We were descheduled in the middle of a may-block
     * syscall, and it was recorded as a normal entry/exit
     * pair.  So don't record the syscall in the buffer or
     * replay will go haywire. */
    hdr->abort_commit = 0;
    hdr->failed_during_preparation = 0;
    /* Clear the return value that rr puts there during replay */
    rec->ret = 0;
  } else {
    rec->ret = ret;
    // Finish 'rec' first before updating num_rec_bytes, since
    // rr might read the record anytime after this update.
    hdr->num_rec_bytes += stored_record_size(rec->size);
    call_breakpoint = 1;
  }

  if (rec->desched) {
    disarm_desched_event();
  }
  /* NBB: for may-block syscalls that are descheduled, the
   * tracer uses the previous ioctl() as a stable point to reset
   * the record counter.  Therefore nothing from here on in the
   * current txn must touch the record counter (at least, must
   * not assume it's unchanged). */

  buffer_hdr()->locked &= ~SYSCALLBUF_LOCKED_TRACEE;

  if (call_breakpoint) {
    /* Call the breakpoint function corresponding to the record we just
     * committed. This function just returns, but during replay it gives rr
     * a chance to set a breakpoint for when a specific syscallbuf record
     * has been processed.
     */
    do_breakpoint(hdr->num_rec_bytes/8);
  }

  return ret;
}

/**
 * |ret_size| is the result of a syscall indicating how much data was returned
 * in scratch buffer |buf2|; this function copies that data to |buf| and returns
 * a pointer to the end of it. If there is no scratch buffer (|buf2| is NULL)
 * just returns |ptr|.
 */
static void* copy_output_buffer(long ret_size, void* ptr, void* buf,
                                void* buf2) {
  if (!buf2) {
    return ptr;
  }
  if (ret_size <= 0 || buffer_hdr()->failed_during_preparation) {
    return buf2;
  }
  local_memcpy(buf, buf2, ret_size);
  return buf2 + ret_size;
}

/**
 * Copy an input parameter to the syscallbuf where the kernel needs to
 * read and write it. During replay, we do a no-op self-copy in the buffer
 * so that the buffered data is not lost.
 * This code is written in assembler to ensure that the registers that receive
 * values differing between record and replay (%0, rsi/esi, and flags)
 * are reset to values that are the same between record and replay immediately
 * afterward. This guards against diverging register values leaking into
 * later code.
 * Use local_memcpy or plain assignment instead if the kernel is not going to
 * overwrite the values.
 */
static void memcpy_input_parameter(void* buf, void* src, int size) {
#if defined(__i386__) || defined(__x86_64__)
  unsigned char tmp_in_replay = globals.in_replay;
  __asm__ __volatile__("test %0,%0\n\t"
                       "cmovne %1,%2\n\t"
                       "rep movsb\n\t"
                       "xor %0,%0\n\t"
                       "xor %2,%2\n\t"
                       : "+a"(tmp_in_replay), "+D"(buf), "+S"(src), "+c"(size)
                       :
                       : "cc", "memory");
#else
#error Unknown architecture
#endif
}

/**
 * During recording, we copy *real to *buf.
 * During replay, we copy *buf to *real.
 * Behaves like memcpy_input_parameter in terms of hiding differences between
 * recording and replay.
 */
static void copy_futex_int(uint32_t* buf, uint32_t* real) {
#if defined(__i386__) || defined(__x86_64__)
  uint32_t tmp_in_replay = globals.in_replay;
  __asm__ __volatile__("test %0,%0\n\t"
                       "mov %2,%0\n\t"
                       "cmovne %1,%0\n\t"
                       "mov %0,%1\n\t"
                       "mov %0,%2\n\t"
                       /* This instruction is just to clear flags */
                       "xor %0,%0\n\t"
                       : "+a"(tmp_in_replay)
                       : "m"(*buf), "m"(*real)
                       : "cc", "memory");
#else
#error Unknown architecture
#endif
}

static int trace_chaos_mode_syscalls = 0;
static int buffer_chaos_mode_syscalls = 0;

static int force_traced_syscall_for_chaos_mode(void) {
  if (!globals.in_chaos) {
    return 0;
  }
  while (1) {
    if (buffer_chaos_mode_syscalls) {
      --buffer_chaos_mode_syscalls;
      return 0;
    }
    if (trace_chaos_mode_syscalls) {
      --trace_chaos_mode_syscalls;
      return 1;
    }
    /* force a run of up to 50 syscalls to be traced */
    trace_chaos_mode_syscalls = (local_random() % 50) + 1;
    buffer_chaos_mode_syscalls = (trace_chaos_mode_syscalls - 5) * 10;
    if (buffer_chaos_mode_syscalls < 0) {
      buffer_chaos_mode_syscalls = 0;
    }
  }
}

/* Keep syscalls in alphabetical order, please. */

/**
 * Call this for syscalls that have no memory effects, don't block, and
 * aren't fd-related.
 */
static long sys_generic_nonblocking(const struct syscall_info* call) {
  void* ptr = prep_syscall();
  long ret;

  if (!start_commit_buffered_syscall(call->no, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall6(call->no, call->args[0], call->args[1], call->args[2],
                          call->args[3], call->args[4], call->args[5]);
  return commit_raw_syscall(call->no, ptr, ret);
}

/**
 * Call this for syscalls that have no memory effects, don't block, and
 * have an fd as their first parameter.
 */
static long sys_generic_nonblocking_fd(const struct syscall_info* call) {
  int fd = call->args[0];
  void* ptr = prep_syscall_for_fd(fd);
  long ret;

  if (!start_commit_buffered_syscall(call->no, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall6(call->no, fd, call->args[1], call->args[2],
                          call->args[3], call->args[4], call->args[5]);
  return commit_raw_syscall(call->no, ptr, ret);
}

static long sys_clock_gettime(const struct syscall_info* call) {
  const int syscallno = SYS_clock_gettime;
  __kernel_clockid_t clk_id = (__kernel_clockid_t)call->args[0];
  struct timespec* tp = (struct timespec*)call->args[1];

  void* ptr = prep_syscall();
  struct timespec* tp2 = NULL;
  long ret;

  assert(syscallno == call->no);

  if (tp) {
    tp2 = ptr;
    ptr += sizeof(*tp2);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall2(syscallno, clk_id, tp2);
  if (tp && ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    /* This is small and won't get optimized to a memcpy call outside
       our library. */
    *tp = *tp2;
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}

#ifdef SYS_clock_gettime64

static long sys_clock_gettime64(const struct syscall_info* call) {
  const int syscallno = SYS_clock_gettime64;
  __kernel_clockid_t clk_id = (__kernel_clockid_t)call->args[0];
  struct __kernel_timespec* tp = (struct __kernel_timespec*)call->args[1];

  void* ptr = prep_syscall();
  struct __kernel_timespec* tp2 = NULL;
  long ret;

  assert(syscallno == call->no);

  if (tp) {
    tp2 = ptr;
    ptr += sizeof(*tp2);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall2(syscallno, clk_id, tp2);
  if (tp && ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    /* This is small and won't get optimized to a memcpy call outside
       our library. */
    *tp = *tp2;
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}
#endif

#if defined(SYS_creat)
static long sys_open(const struct syscall_info* call);
static long sys_creat(const struct syscall_info* call) {
  const char* pathname = (const char*)call->args[0];
  __kernel_mode_t mode = call->args[1];
  /* Thus sayeth the man page:
   *
   *   creat() is equivalent to open() with flags equal to
   *   O_CREAT|O_WRONLY|O_TRUNC. */
  struct syscall_info open_call;
  open_call.no = SYS_open;
  open_call.args[0] = (long)pathname;
  open_call.args[1] = O_CREAT | O_TRUNC | O_WRONLY;
  open_call.args[2] = mode;
  return sys_open(&open_call);
}
#endif

static int sys_fcntl64_no_outparams(const struct syscall_info* call) {
  const int syscallno = RR_FCNTL_SYSCALL;
  int fd = call->args[0];
  int cmd = call->args[1];
  long arg = call->args[2];

  /* None of the no-outparam fcntl's are known to be
   * may-block. */
  void* ptr = prep_syscall_for_fd(fd);
  long ret;

  assert(syscallno == call->no);

  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall3(syscallno, fd, cmd, arg);
  return commit_raw_syscall(syscallno, ptr, ret);
}

static int sys_fcntl64_own_ex(const struct syscall_info* call) {
  const int syscallno = RR_FCNTL_SYSCALL;
  int fd = call->args[0];
  int cmd = call->args[1];
  struct rr_f_owner_ex* owner = (struct rr_f_owner_ex*)call->args[2];

  /* The OWN_EX fcntl's aren't may-block. */
  void* ptr = prep_syscall_for_fd(fd);
  struct rr_f_owner_ex* owner2 = NULL;
  long ret;

  assert(syscallno == call->no);

  if (owner) {
    owner2 = ptr;
    ptr += sizeof(*owner2);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  if (owner2) {
    memcpy_input_parameter(owner2, owner, sizeof(*owner2));
  }
  ret = untraced_syscall3(syscallno, fd, cmd, owner2);
  if (owner2 && ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    local_memcpy(owner, owner2, sizeof(*owner));
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}

static int sys_fcntl64_setlk64(const struct syscall_info* call) {
  if (force_traced_syscall_for_chaos_mode()) {
    /* Releasing a lock could unblock a higher priority task */
    return traced_raw_syscall(call);
  }

  const int syscallno = RR_FCNTL_SYSCALL;
  int fd = call->args[0];
  int cmd = call->args[1];
  struct rr_flock64* lock = (struct rr_flock64*)call->args[2];

  void* ptr = prep_syscall_for_fd(fd);
  struct rr_flock64* lock2 = NULL;
  long ret;

  assert(syscallno == call->no);

  if (lock) {
    lock2 = ptr;
    ptr += sizeof(*lock2);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  if (lock2) {
    memcpy_input_parameter(lock2, lock, sizeof(*lock2));
  }
  ret = untraced_syscall3(syscallno, fd, cmd, lock2);
  if (lock2 && ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    local_memcpy(lock, lock2, sizeof(*lock));
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}

static int sys_fcntl64_setlkw64(const struct syscall_info* call) {
  if (force_traced_syscall_for_chaos_mode()) {
    /* Releasing a lock could unblock a higher priority task */
    return traced_raw_syscall(call);
  }

  const int syscallno = RR_FCNTL_SYSCALL;
  int fd = call->args[0];
  int cmd = call->args[1];
  struct rr_flock64* lock = (struct rr_flock64*)call->args[2];

  void* ptr = prep_syscall_for_fd(fd);
  long ret;

  assert(syscallno == call->no);

  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall3(syscallno, fd, cmd, lock);
  return commit_raw_syscall(syscallno, ptr, ret);
}

#if defined(SYS_fcntl64)
static long sys_fcntl64(const struct syscall_info* call)
#else
static long sys_fcntl(const struct syscall_info* call)
#endif
{
  switch (call->args[1]) {
    case F_DUPFD:
    case F_GETFD:
    case F_GETFL:
    case F_GETOWN:
    case F_SETFL:
    case F_SETFD:
    case F_SETOWN:
    case F_SETSIG:
      return sys_fcntl64_no_outparams(call);

    case F_GETOWN_EX:
    case F_SETOWN_EX:
      return sys_fcntl64_own_ex(call);

#if F_SETLK != F_SETLK64
    case F_SETLK64:
#else
    case F_SETLK:
#endif
      return sys_fcntl64_setlk64(call);

#if F_SETLKW != F_SETLKW64
    case F_SETLKW64:
#else
    case F_SETLKW:
#endif
      return sys_fcntl64_setlkw64(call);

    default:
      return traced_raw_syscall(call);
  }
}

static long ret_buf_len(long ret, size_t len) {
  if (ret < 0) {
    return 0;
  }
  if (len > LONG_MAX) {
    return ret;
  }
  return ret < (long)len ? ret : (long)len;
}

static long sys_flistxattr(const struct syscall_info* call) {
  const int syscallno = SYS_flistxattr;
  int fd = (int)call->args[0];
  char* buf = (char*)call->args[1];
  size_t size = call->args[2];

  void* ptr = prep_syscall_for_fd(fd);
  void* buf2 = NULL;
  long ret;

  assert(syscallno == call->no);

  if (buf && size > 0) {
    buf2 = ptr;
    ptr += size;
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall3(syscallno, fd, buf2, size);
  ptr = copy_output_buffer(ret_buf_len(ret, size), ptr, buf, buf2);
  return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_safe_nonblocking_ioctl(const struct syscall_info* call) {
  const int syscallno = SYS_ioctl;
  int fd = call->args[0];

  void* ptr = prep_syscall_for_fd(fd);
  long ret;

  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall3(syscallno, fd, call->args[1], call->args[2]);
  return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_ioctl_fionread(const struct syscall_info* call) {
  const int syscallno = SYS_ioctl;
  int fd = call->args[0];
  int* value = (int*)call->args[2];
  void* buf = NULL;

  void* ptr = prep_syscall_for_fd(fd);
  long ret;

  if (value) {
    buf = ptr;
    ptr += sizeof(*value);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall3(syscallno, fd, FIONREAD, buf);
  if (buf && ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    local_memcpy(value, buf, sizeof(*value));
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_ioctl(const struct syscall_info* call) {
  switch (call->args[1]) {
    case BTRFS_IOC_CLONE_RANGE:
    case FIOCLEX:
    case FIONCLEX:
      return sys_safe_nonblocking_ioctl(call);
    case FIONREAD:
      return sys_ioctl_fionread(call);
    default:
      return traced_raw_syscall(call);
  }
}

static long sys_futex(const struct syscall_info* call) {
  enum {
    FUTEX_USES_UADDR2 = 1 << 0,
  };

  /* This can make wakeups a lot more expensive. We assume
     that wakeups are only used when some thread is actually waiting,
     in which case we're at most doubling the overhead of the combined
     wait + wakeup. */
  if (globals.in_chaos) {
    return traced_raw_syscall(call);
  }

  int op = call->args[1];
  int flags = 0;
  switch (FUTEX_CMD_MASK & op) {
    case FUTEX_WAKE_BITSET:
    case FUTEX_WAKE:
      break;
    case FUTEX_REQUEUE:
    case FUTEX_CMP_REQUEUE:
    case FUTEX_WAKE_OP:
      flags |= FUTEX_USES_UADDR2;
      break;

    /* It turns out not to be worth buffering the FUTEX_WAIT*
     * calls.  When a WAIT call is made, we know almost for sure
     * that the tracee is going to be desched'd (otherwise the
     * userspace CAS would have succeeded).  This is unlike
     * read/write, f.e., where the vast majority of calls aren't
     * desched'd and the overhead is worth it.  So all that
     * buffering WAIT does is add the overhead of arming/disarming
     * desched (which is a measurable perf loss).
     *
     * NB: don't ever try to buffer FUTEX_LOCK_PI; it requires
     * special processing in the tracer process (in addition to
     * not being worth doing for perf reasons). */
    default:
      return traced_raw_syscall(call);
  }

  const int syscallno = SYS_futex;
  uint32_t* uaddr = (uint32_t*)call->args[0];
  uint32_t val = call->args[2];
  const struct timespec* timeout = (const struct timespec*)call->args[3];
  uint32_t* uaddr2 = (uint32_t*)call->args[4];
  uint32_t val3 = call->args[5];

  void* ptr = prep_syscall();
  uint32_t* saved_uaddr;
  uint32_t* saved_uaddr2 = NULL;
  long ret;

  assert(syscallno == call->no);

  /* We have to record the value of the futex at kernel exit,
   * but we can't substitute a scratch pointer for the uaddrs:
   * the futex identity is the memory cell.  There are schemes
   * that would allow us to use scratch futexes, but they get
   * complicated quickly. */
  saved_uaddr = ptr;
  ptr += sizeof(*saved_uaddr);
  if (FUTEX_USES_UADDR2 & flags) {
    saved_uaddr2 = ptr;
    ptr += sizeof(*saved_uaddr2);
  }
  /* See above; it's not worth buffering may-block futex
   * calls. */
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall6(syscallno, uaddr, op, val, timeout, uaddr2, val3);
  /* During recording, save the real outparams to the buffer.
   * During replay, save the values from the buffer to the real outparams.
   *
   * The *ONLY* reason it's correct for us to read the outparams
   * carelessly is that rr protects this syscallbuf
   * transaction as as a critical section. */
  copy_futex_int(saved_uaddr, uaddr);
  if (saved_uaddr2) {
    copy_futex_int(saved_uaddr2, uaddr2);
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_generic_getdents(const struct syscall_info* call) {
  int fd = (int)call->args[0];
  void* buf = (void*)call->args[1];
  unsigned int count = (unsigned int)call->args[2];

  void* ptr = prep_syscall_for_fd(fd);
  void* buf2 = NULL;
  long ret;

  if (buf && count > 0) {
    buf2 = ptr;
    ptr += count;
  }
  if (!start_commit_buffered_syscall(call->no, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall3(call->no, fd, buf2, count);
  ptr = copy_output_buffer(ret, ptr, buf, buf2);
  return commit_raw_syscall(call->no, ptr, ret);
}

#if defined(SYS_getdents)
static long sys_getdents(const struct syscall_info* call) {
  return sys_generic_getdents(call);
}
#endif

static long sys_getdents64(const struct syscall_info* call) {
  return sys_generic_getdents(call);
}

static long sys_gettimeofday(const struct syscall_info* call) {
  const int syscallno = SYS_gettimeofday;
  struct timeval* tp = (struct timeval*)call->args[0];
  struct timezone* tzp = (struct timezone*)call->args[1];

  /* XXX it seems odd that clock_gettime() is spec'd to be
   * async-signal-safe while gettimeofday() isn't, but that's
   * what the docs say! */
  void* ptr = prep_syscall();
  struct timeval* tp2 = NULL;
  struct timezone* tzp2 = NULL;
  long ret;

  assert(syscallno == call->no);

  if (tp) {
    tp2 = ptr;
    ptr += sizeof(*tp2);
  }
  if (tzp) {
    tzp2 = ptr;
    ptr += sizeof(*tzp2);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall2(syscallno, tp2, tzp2);
  if (ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    if (tp) {
      /* This is small and won't get optimized to a memcpy call outside
         our library. */
      *tp = *tp2;
    }
    if (tzp) {
      /* This is small and won't get optimized to a memcpy call outside
         our library. */
      *tzp = *tzp2;
    }
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_generic_getxattr(const struct syscall_info* call) {
  const char* path = (const char*)call->args[0];
  const char* name = (const char*)call->args[1];
  void* value = (void*)call->args[2];
  size_t size = call->args[3];

  void* ptr = prep_syscall();
  void* value2 = NULL;
  long ret;

  if (value && size > 0) {
    value2 = ptr;
    ptr += size;
  }
  if (!start_commit_buffered_syscall(call->no, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall4(call->no, path, name, value2, size);
  ptr = copy_output_buffer(ret_buf_len(ret, size), ptr, value, value2);
  return commit_raw_syscall(call->no, ptr, ret);
}

static long sys_getxattr(const struct syscall_info* call) {
  return sys_generic_getxattr(call);
}

static long sys_lgetxattr(const struct syscall_info* call) {
  return sys_generic_getxattr(call);
}

static long sys_fgetxattr(const struct syscall_info* call) {
  int fd = (int)call->args[0];
  const char* name = (const char*)call->args[1];
  void* value = (void*)call->args[2];
  size_t size = call->args[3];

  void* ptr = prep_syscall_for_fd(fd);
  void* value2 = NULL;
  long ret;

  if (value && size > 0) {
    value2 = ptr;
    ptr += size;
  }
  if (!start_commit_buffered_syscall(call->no, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall4(call->no, fd, name, value2, size);
  ptr = copy_output_buffer(ret_buf_len(ret, size), ptr, value, value2);
  return commit_raw_syscall(call->no, ptr, ret);
}

static long sys_generic_listxattr(const struct syscall_info* call) {
  char* path = (char*)call->args[0];
  char* buf = (char*)call->args[1];
  size_t size = call->args[2];

  void* ptr = prep_syscall();
  void* buf2 = NULL;
  long ret;

  if (buf && size > 0) {
    buf2 = ptr;
    ptr += size;
  }
  if (!start_commit_buffered_syscall(call->no, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall3(call->no, path, buf2, size);
  ptr = copy_output_buffer(ret_buf_len(ret, size), ptr, buf, buf2);
  return commit_raw_syscall(call->no, ptr, ret);
}

static long sys_listxattr(const struct syscall_info* call) {
  return sys_generic_listxattr(call);
}

static long sys_llistxattr(const struct syscall_info* call) {
  return sys_generic_listxattr(call);
}

#if defined(SYS__llseek)
static long sys__llseek(const struct syscall_info* call) {
  const int syscallno = SYS__llseek;
  int fd = call->args[0];
  unsigned long offset_high = call->args[1];
  unsigned long offset_low = call->args[2];
  __kernel_loff_t* result = (__kernel_loff_t*)call->args[3];
  unsigned int whence = call->args[4];

  void* ptr = prep_syscall_for_fd(fd);
  __kernel_loff_t* result2 = NULL;
  long ret;

  assert(syscallno == call->no);

  if (result) {
    result2 = ptr;
    ptr += sizeof(*result2);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  if (result2) {
    memcpy_input_parameter(result2, result, sizeof(*result2));
  }
  ret = untraced_syscall5(syscallno, fd, offset_high, offset_low, result2,
                          whence);
  if (result2) {
    *result = *result2;
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}
#endif

static long sys_madvise(const struct syscall_info* call) {
  const int syscallno = SYS_madvise;
  void* addr = (void*)call->args[0];
  size_t length = call->args[1];
  int advice = call->args[2];

  void* ptr;
  long ret;

  switch (advice) {
    // Whitelist advice values that we know are OK to pass through to the
    // kernel directly.
    case MADV_NORMAL:
    case MADV_RANDOM:
    case MADV_SEQUENTIAL:
    case MADV_WILLNEED:
    case MADV_DONTNEED:
    case MADV_MERGEABLE:
    case MADV_UNMERGEABLE:
    case MADV_HUGEPAGE:
    case MADV_NOHUGEPAGE:
    case MADV_DONTDUMP:
    case MADV_DODUMP:
      break;
    case MADV_FREE:
      // See record_syscall. We disallow MADV_FREE because it creates
      // nondeterminism.
      advice = -1;
      break;
    default:
      return traced_raw_syscall(call);
  }

  ptr = prep_syscall();

  assert(syscallno == call->no);

  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  /* Ensure this syscall happens during replay. In particular MADV_DONTNEED
   * must be executed.
   */
  ret = untraced_replayed_syscall3(syscallno, addr, length, advice);
  return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_mprotect(const struct syscall_info* call) {
  const int syscallno = SYS_mprotect;
  void* addr = (void*)call->args[0];
  size_t length = call->args[1];
  int prot = call->args[2];
  struct mprotect_record* mrec;

  void* ptr;
  long ret;

  if ((prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC)) || !buffer_hdr() ||
      buffer_hdr()->mprotect_record_count >= MPROTECT_RECORD_COUNT) {
    return traced_raw_syscall(call);
  }

  ptr = prep_syscall();

  assert(syscallno == call->no);

  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  mrec = &globals.mprotect_records[buffer_hdr()->mprotect_record_count++];
  mrec->start = (uint64_t)(uintptr_t)addr;
  mrec->size = length;
  mrec->prot = prot;
  ret = untraced_replayed_syscall3(syscallno, addr, length, prot);
  if (ret < 0 && ret != -ENOMEM) {
    /* indicate that nothing was mprotected */
    mrec->size = 0;
  }
  buffer_hdr()->mprotect_record_count_completed++;

  return commit_raw_syscall(syscallno, ptr, ret);
}

static int supported_open(const char* file_name, int flags) {
  if (is_gcrypt_deny_file(file_name)) {
    /* This needs to be a traced syscall. We want to return an
       open file even if the file doesn't exist and the untraced syscall
       returns ENOENT. */
    return 0;
  }
  if (flags & O_DIRECT) {
    /* O_DIRECT needs to go to rr so we can blacklist the file for
       syscall buffering. */
    return 0;
  }
  /* Writeable opens need to go to rr to be checked in case
     they could write to a mapped file.
     But if they're O_EXCL | O_CREAT, a new file must be created
     so that will be fine. */
  return !(flags & (O_RDWR | O_WRONLY)) ||
    (flags & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT);
}

static long sys_readlinkat(const struct syscall_info* call);

static int check_file_open_ok(const struct syscall_info* call, int ret, int did_abort) {
  if (did_abort || ret < 0) {
    return ret;
  }
  char buf[100];
  sprintf(buf, "/proc/self/fd/%d", ret);
  char link[PATH_MAX];
  struct syscall_info readlink_call =
    { SYS_readlinkat, { -1, (long)buf, (long)link, sizeof(link), 0, 0 } };
  long link_ret = sys_readlinkat(&readlink_call);
  if (link_ret >= 0 && link_ret < (ssize_t)sizeof(link)) {
    link[link_ret] = 0;
    if (allow_buffered_open(link)) {
      return ret;
    }
  }
  /* Clean up by closing the file descriptor we should not have opened and
     opening it again, traced this time.
     Use a privileged traced syscall for the close to ensure it
     can't fail due to lack of privilege.
     We could try an untraced close syscall here, falling back to traced
     syscall, but that's a bit more complicated and we're already on
     the slow (and hopefully rare) path. */
  privileged_traced_syscall1(SYS_close, ret);
  return traced_raw_syscall(call);
}

#if defined(SYS_open)
static long sys_open(const struct syscall_info* call) {
  if (force_traced_syscall_for_chaos_mode()) {
    /* Opening a FIFO could unblock a higher priority task */
    return traced_raw_syscall(call);
  }

  const int syscallno = SYS_open;
  const char* pathname = (const char*)call->args[0];
  int flags = call->args[1];
  __kernel_mode_t mode = call->args[2];
  void* ptr;
  long ret;

  assert(syscallno == call->no);

  if (!supported_open(pathname, flags)) {
    return traced_raw_syscall(call);
  }

  ptr = prep_syscall();
  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall3(syscallno, pathname, flags, mode);
  int did_abort = buffer_hdr()->abort_commit;
  ret = commit_raw_syscall(syscallno, ptr, ret);
  return check_file_open_ok(call, ret, did_abort);
}
#endif

static long sys_openat(const struct syscall_info* call) {
  if (force_traced_syscall_for_chaos_mode()) {
    /* Opening a FIFO could unblock a higher priority task */
    return traced_raw_syscall(call);
  }

  const int syscallno = SYS_openat;
  int dirfd = call->args[0];
  const char* pathname = (const char*)call->args[1];
  int flags = call->args[2];
  __kernel_mode_t mode = call->args[3];
  void* ptr;
  long ret;

  assert(syscallno == call->no);

  if (!supported_open(pathname, flags)) {
    return traced_raw_syscall(call);
  }

  ptr = prep_syscall();
  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall4(syscallno, dirfd, pathname, flags, mode);
  int did_abort = buffer_hdr()->abort_commit;
  ret = commit_raw_syscall(syscallno, ptr, ret);
  return check_file_open_ok(call, ret, did_abort);
}

#if defined(SYS_poll)
/**
 * Make this function external so desched_ticks.py can set a breakpoint on it.
 * Make it visiblity-"protected" so that our local definition binds to it
 * directly and doesn't go through a PLT thunk (which would mean temporarily
 * leaving syscallbuf code).
 */
__attribute__((visibility("protected"))) void __before_poll_syscall_breakpoint(
    void) {}

static long sys_poll(const struct syscall_info* call) {
  const int syscallno = SYS_poll;
  struct pollfd* fds = (struct pollfd*)call->args[0];
  unsigned int nfds = call->args[1];
  int timeout = call->args[2];

  void* ptr = prep_syscall();
  struct pollfd* fds2 = NULL;
  long ret;

  assert(syscallno == call->no);

  if (fds && nfds > 0) {
    fds2 = ptr;
    ptr += nfds * sizeof(*fds2);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  if (fds2) {
    memcpy_input_parameter(fds2, fds, nfds * sizeof(*fds2));
  }

  __before_poll_syscall_breakpoint();

  /* Try a no-timeout version of the syscall first. If this doesn't return
     anything, and we should have blocked, we'll try again with a traced syscall
     which will be the one that blocks. This usually avoids the
     need to trigger desched logic, which adds overhead, especially the
     rrcall_notify_syscall_hook_exit that gets triggered. */
  ret = untraced_syscall3(syscallno, fds2, nfds, 0);

  if (fds2 && ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    /* NB: even when poll returns 0 indicating no pending
     * fds, it still sets each .revent outparam to 0.
     * (Reasonably.)  So we always need to copy on return
     * value >= 0.
     * It's important that we not copy when there's an error.
     * The syscallbuf commit might have been aborted, which means
     * during replay fds2 might be non-recorded data, so we'd be
     * incorrectly trashing 'fds'. */
    local_memcpy(fds, fds2, nfds * sizeof(*fds));
  }
  commit_raw_syscall(syscallno, ptr, ret);

  if (ret != 0 || timeout == 0) {
    return ret;
  }
  /* The syscall didn't return anything, and we should have blocked.
     Just perform a raw syscall now since we're almost certain to block. */
  return traced_raw_syscall(call);
}
#endif

static long sys_epoll_wait(const struct syscall_info* call) {
  int epfd = call->args[0];
  struct epoll_event* events = (struct epoll_event*)call->args[1];
  int max_events = call->args[2];
  int timeout = call->args[3];

  void* ptr;
  struct epoll_event* events2 = NULL;
  long ret;

  ptr = prep_syscall();

  assert(SYS_epoll_pwait == call->no
#if defined(SYS_epoll_wait)
        || SYS_epoll_wait == call->no
#endif
  );

  if (events && max_events > 0) {
    events2 = ptr;
    ptr += max_events * sizeof(*events2);
  }
  if (!start_commit_buffered_syscall(call->no, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  /* Try a no-timeout version of the syscall first. If this doesn't return
     anything, and we should have blocked, we'll try again with a traced syscall
     which will be the one that blocks. This usually avoids the
     need to trigger desched logic, which adds overhead, especially the
     rrcall_notify_syscall_hook_exit that gets triggered.
     N.B.: SYS_epoll_wait only has four arguments, but we don't care
     if the last two arguments are garbage */
  ret = untraced_syscall6(call->no, epfd, events2, max_events, 0,
    call->args[4], call->args[5]);

  ptr = copy_output_buffer(ret * sizeof(*events2), ptr, events, events2);
  ret = commit_raw_syscall(call->no, ptr, ret);
  if (timeout == 0 || (ret != EINTR && ret != 0)) {
    /* If we got some real results, or a non-EINTR error, we can just
       return it directly.
       If we got no results and the timeout was 0, we can just return 0.
       If we got EINTR and the timeout was 0, a signal must have
       interrupted the syscall (not sure if this can happen...). If the signal
       needs to be handled, we'll handle it as we exit the syscallbuf.
       Returning EINTR is fine because that's what the syscall would have
       returned had it run traced. (We didn't enable the desched signal
       so no extra signals could have affected our untraced syscall that
       could not have been delivered to a traced syscall.) */
    return ret;
  }
  /* Some timeout was requested and either we got no results or we got
     EINTR.
     In the former case we just have to wait, so we do a traced syscall.
     In the latter case, the syscall must have been interrupted by a
     signal (which rr will have handled or stashed, and won't deliver until
     we exit syscallbuf code or do a traced syscall). The kernel doesn't
     automatically restart the syscall because of a longstanding bug (as of
     4.17 anyway). Doing a traced syscall will allow a stashed signal to be
     processed (if necessary) and allow things to proceed normally after that.
     Note that if rr decides to deliver a signal to the tracee, that will
     itself interrupt the syscall and cause it to return EINTR just as
     would happen without rr.
  */
  return traced_raw_syscall(call);
}

#define CLONE_SIZE_THRESHOLD 0x10000

static long sys_read(const struct syscall_info* call) {
  if (force_traced_syscall_for_chaos_mode()) {
    /* Reading from a pipe could unblock a higher priority task */
    return traced_raw_syscall(call);
  }

  const int syscallno = SYS_read;
  int fd = call->args[0];
  void* buf = (void*)call->args[1];
  size_t count = call->args[2];

  void* ptr;
  void* buf2 = NULL;
  long ret;

  /* Try cloning data using CLONE_RANGE ioctl.
   * XXX switch to FIOCLONERANGE when that's more widely available. It's the
   * same ioctl number so it won't affect rr per se but it'd be cleaner code.
   * 64-bit only for now, since lseek and pread64 need special handling for
   * 32-bit.
   * Basically we break down the read into three syscalls lseek, clone and
   * read-from-clone, each of which is individually syscall-buffered.
   * Crucially, the read-from-clone syscall does NOT store data in the syscall
   * buffer; instead, we perform the syscall during replay, assuming that
   * cloned_file_data_fd is open to the same file during replay.
   * Reads that hit EOF are rejected by the CLONE_RANGE ioctl so we take the
   * slow path. That's OK.
   * There is a possible race here: between cloning the data and reading from
   * |fd|, |fd|'s data may be overwritten, in which case the data read during
   * replay will not match the data read during recording, causing divergence.
   * I don't see any performant way to avoid this race; I tried reading from
   * the cloned data instead of |fd|, but that is very slow because readahead
   * doesn't work. (The cloned data file always ends at the current offset so
   * there is nothing to readahead.) However, if an application triggers this
   * race, it's almost certainly a bad bug because Linux can return any
   * interleaving of old+new data for the read even without rr.
   */
  if (buf && count >= CLONE_SIZE_THRESHOLD &&
      thread_locals->cloned_file_data_fd >= 0 && is_bufferable_fd(fd) &&
      sizeof(void*) == 8 && !(count & 4095)) {
    struct syscall_info lseek_call = { SYS_lseek,
                                       { fd, 0, SEEK_CUR, 0, 0, 0 } };
    off_t lseek_ret = sys_generic_nonblocking_fd(&lseek_call);
    if (lseek_ret >= 0 && !(lseek_ret & 4095)) {
      struct btrfs_ioctl_clone_range_args ioctl_args;
      int ioctl_ret;
      void* ioctl_ptr = prep_syscall();
      ioctl_args.src_fd = fd;
      ioctl_args.src_offset = lseek_ret;
      ioctl_args.src_length = count;
      ioctl_args.dest_offset = thread_locals->cloned_file_data_offset;

      /* Don't call sys_ioctl here; cloned_file_data_fd has syscall buffering
       * disabled for it so rr can reject attempts to close/dup to it. But
       * we want to allow syscall buffering of this ioctl on it.
       */
      if (!start_commit_buffered_syscall(SYS_ioctl, ioctl_ptr, WONT_BLOCK)) {
        struct syscall_info ioctl_call = { SYS_ioctl,
                                           { thread_locals->cloned_file_data_fd,
                                             BTRFS_IOC_CLONE_RANGE,
                                             (long)&ioctl_args, 0, 0, 0 } };
        ioctl_ret = traced_raw_syscall(&ioctl_call);
      } else {
        ioctl_ret =
            untraced_syscall3(SYS_ioctl, thread_locals->cloned_file_data_fd,
                              BTRFS_IOC_CLONE_RANGE, &ioctl_args);
        ioctl_ret = commit_raw_syscall(SYS_ioctl, ioctl_ptr, ioctl_ret);
      }

      if (ioctl_ret >= 0) {
        struct syscall_info read_call = { SYS_read,
                                          { fd, (long)buf, count, 0, 0, 0 } };
        thread_locals->cloned_file_data_offset += count;

        replay_only_syscall3(SYS_dup3, thread_locals->cloned_file_data_fd, fd, 0);

        ptr = prep_syscall();
        if (count > thread_locals->usable_scratch_size) {
          if (!start_commit_buffered_syscall(SYS_read, ptr, WONT_BLOCK)) {
            return traced_raw_syscall(&read_call);
          }
          ret = untraced_replayed_syscall3(SYS_read, fd, buf, count);
        } else {
          if (!start_commit_buffered_syscall(SYS_read, ptr, MAY_BLOCK)) {
            return traced_raw_syscall(&read_call);
          }
          ret = untraced_replayed_syscall3(SYS_read, fd,
                                           thread_locals->scratch_buf, count);
          copy_output_buffer(ret, NULL, buf, thread_locals->scratch_buf);
        }
        // Do this now before we finish processing the syscallbuf record.
        // This means the syscall will be executed in
        // ReplaySession::flush_syscallbuf instead of
        // ReplaySession::enter_syscall or something similar.
        replay_only_syscall1(SYS_close, fd);
        ret = commit_raw_syscall(SYS_read, ptr, ret);
        return ret;
      }
    }
  }

  ptr = prep_syscall_for_fd(fd);

  assert(syscallno == call->no);

  if (buf && count > 0) {
    buf2 = ptr;
    ptr += count;
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall3(syscallno, fd, buf2, count);
  ptr = copy_output_buffer(ret, ptr, buf, buf2);
  return commit_raw_syscall(syscallno, ptr, ret);
}

/* On x86-32, pread/pwrite take the offset in two registers. We don't bother
 * handling that.
 */
#if !defined(__i386__)
static long sys_pread64(const struct syscall_info* call) {
  const int syscallno = SYS_pread64;
  int fd = call->args[0];
  void* buf = (void*)call->args[1];
  size_t count = call->args[2];
  off_t offset = call->args[3];

  void* ptr;
  void* buf2 = NULL;
  long ret;

  ptr = prep_syscall_for_fd(fd);

  assert(syscallno == call->no);

  if (buf && count > 0) {
    buf2 = ptr;
    ptr += count;
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall4(syscallno, fd, buf2, count, offset);
  ptr = copy_output_buffer(ret, ptr, buf, buf2);
  return commit_raw_syscall(syscallno, ptr, ret);
}
#endif

#if defined(SYS_readlink)
static long sys_readlink(const struct syscall_info* call) {
  const int syscallno = SYS_readlink;
  const char* path = (const char*)call->args[0];
  char* buf = (char*)call->args[1];
  int bufsiz = call->args[2];

  void* ptr = prep_syscall();
  char* buf2 = NULL;
  long ret;

  assert(syscallno == call->no);

  if (buf && bufsiz > 0) {
    buf2 = ptr;
    ptr += bufsiz;
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall3(syscallno, path, buf2, bufsiz);
  ptr = copy_output_buffer(ret, ptr, buf, buf2);
  return commit_raw_syscall(syscallno, ptr, ret);
}
#endif

static long sys_readlinkat(const struct syscall_info* call) {
  const int syscallno = SYS_readlinkat;
  int dirfd = call->args[0];
  const char* path = (const char*)call->args[1];
  char* buf = (char*)call->args[2];
  int bufsiz = call->args[3];

  void* ptr = prep_syscall();
  char* buf2 = NULL;
  long ret;

  assert(syscallno == call->no);

  if (buf && bufsiz > 0) {
    buf2 = ptr;
    ptr += bufsiz;
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall4(syscallno, dirfd, path, buf2, bufsiz);
  ptr = copy_output_buffer(ret, ptr, buf, buf2);
  return commit_raw_syscall(syscallno, ptr, ret);
}

#if defined(SYS_socketcall)
static long sys_socketcall_recv(const struct syscall_info* call) {
  if (force_traced_syscall_for_chaos_mode()) {
    /* Reading from a socket could unblock a higher priority task */
    return traced_raw_syscall(call);
  }

  const int syscallno = SYS_socketcall;
  long* args = (long*)call->args[1];
  int sockfd = args[0];
  void* buf = (void*)args[1];
  size_t len = args[2];
  unsigned int flags = args[3];
  unsigned long new_args[4];

  void* ptr = prep_syscall_for_fd(sockfd);
  void* buf2 = NULL;
  long ret;

  assert(syscallno == call->no);

  if (buf && len > 0) {
    buf2 = ptr;
    ptr += len;
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }

  new_args[0] = sockfd;
  new_args[1] = (unsigned long)buf2;
  new_args[2] = len;
  new_args[3] = flags;
  ret = untraced_syscall2(SYS_socketcall, SYS_RECV, new_args);
  /* Account for MSG_TRUNC */
  ptr = copy_output_buffer(ret_buf_len(ret, len), ptr, buf, buf2);
  return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_socketcall(const struct syscall_info* call) {
  switch (call->args[0]) {
    case SYS_RECV:
      return sys_socketcall_recv(call);
    default:
      return traced_raw_syscall(call);
  }
}
#endif

#ifdef SYS_recvfrom
static long sys_recvfrom(const struct syscall_info* call) {
  if (force_traced_syscall_for_chaos_mode()) {
    /* Reading from a socket could unblock a higher priority task */
    return traced_raw_syscall(call);
  }

  const int syscallno = SYS_recvfrom;
  int sockfd = call->args[0];
  void* buf = (void*)call->args[1];
  size_t len = call->args[2];
  int flags = call->args[3];
  /* struct sockaddr isn't useful here since some sockaddrs are bigger than
   * it. To avoid making false assumptions, treat the sockaddr parameter
   * as an untyped buffer.
   */
  void* src_addr = (void*)call->args[4];
  socklen_t* addrlen = (socklen_t*)call->args[5];

  void* ptr = prep_syscall_for_fd(sockfd);
  void* buf2 = NULL;
  struct sockaddr* src_addr2 = NULL;
  socklen_t* addrlen2 = NULL;
  long ret;

  assert(syscallno == call->no);
  /* If addrlen is NULL then src_addr must also be null */
  assert(addrlen || !src_addr);

  if (src_addr) {
    src_addr2 = ptr;
    ptr += *addrlen;
  }
  if (addrlen) {
    addrlen2 = ptr;
    ptr += sizeof(*addrlen);
  }
  if (buf && len > 0) {
    buf2 = ptr;
    ptr += len;
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }
  if (addrlen) {
    memcpy_input_parameter(addrlen2, addrlen, sizeof(*addrlen2));
  }
  ret = untraced_syscall6(syscallno, sockfd, buf2, len, flags, src_addr2,
                          addrlen2);

  if (ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    if (src_addr2) {
      socklen_t actual_size = *addrlen2;
      if (actual_size > *addrlen) {
        actual_size = *addrlen;
      }
      local_memcpy(src_addr, src_addr2, actual_size);
    }
    if (addrlen2) {
      *addrlen = *addrlen2;
    }
  }
  ptr = copy_output_buffer(ret_buf_len(ret, len), ptr, buf, buf2);
  return commit_raw_syscall(syscallno, ptr, ret);
}
#endif

#ifdef SYS_recvmsg

/* These macros are from musl Copyright © 2005-2020 Rich Felker, et al. (MIT LICENSE) */
#define __CMSG_LEN(cmsg) (((cmsg)->cmsg_len + sizeof(long) - 1) & ~(long)(sizeof(long) - 1))
#define __CMSG_NEXT(cmsg) ((unsigned char *)(cmsg) + __CMSG_LEN(cmsg))
#define __MHDR_END(mhdr) ((unsigned char *)(mhdr)->msg_control + (mhdr)->msg_controllen)

#define CMSG_DATA(cmsg) ((unsigned char *) (((struct cmsghdr *)(cmsg)) + 1))
#define CMSG_NXTHDR(mhdr, cmsg) ((cmsg)->cmsg_len < sizeof (struct cmsghdr) || \
	(__CMSG_LEN(cmsg) + sizeof(struct cmsghdr) >= (unsigned long)(__MHDR_END(mhdr) - (unsigned char *)(cmsg))) \
	? 0 : (struct cmsghdr *)__CMSG_NEXT(cmsg))
#define CMSG_FIRSTHDR(mhdr) ((size_t) (mhdr)->msg_controllen >= sizeof (struct cmsghdr) ? (struct cmsghdr *) (mhdr)->msg_control : (struct cmsghdr *) 0)

struct cmsghdr {
  __kernel_size_t	cmsg_len;
  int cmsg_level;
  int cmsg_type;
};

struct msghdr /* struct user_msghdr in the kernel */ {
  void* msg_name;
  int msg_namelen;
  struct iovec* msg_iov;
  __kernel_size_t msg_iovlen;
  void* msg_control;
  __kernel_size_t msg_controllen;
  unsigned int msg_flags;
};

#define SCM_RIGHTS 0x01
#define SOL_PACKET 263

static int msg_received_file_descriptors(struct msghdr* msg) {
  struct cmsghdr* cmh;
  for (cmh = CMSG_FIRSTHDR(msg); cmh; cmh = CMSG_NXTHDR(msg, cmh)) {
    if (cmh->cmsg_level == SOL_SOCKET && cmh->cmsg_type == SCM_RIGHTS) {
      return 1;
    }
  }
  return 0;
}

static long sys_recvmsg(const struct syscall_info* call) {
  if (force_traced_syscall_for_chaos_mode()) {
    /* Reading from a socket could unblock a higher priority task */
    return traced_raw_syscall(call);
  }

  const int syscallno = SYS_recvmsg;
  int sockfd = call->args[0];
  struct msghdr* msg = (struct msghdr*)call->args[1];
  int flags = call->args[2];

  void* ptr = prep_syscall_for_fd(sockfd);
  long ret;
  struct msghdr* msg2;
  void* ptr_base = ptr;
  void* ptr_overwritten_end;
  void* ptr_bytes_start;
  void* ptr_end;
  size_t i;

  assert(syscallno == call->no);

  /* Compute final buffer size up front, before writing syscall inputs to the
   * buffer. Thus if we decide not to buffer this syscall, we bail out
   * before trying to write to a buffer that won't be recorded and may be
   * invalid (e.g. overflow).
   */
  ptr += sizeof(struct msghdr) + sizeof(struct iovec) * msg->msg_iovlen;
  if (msg->msg_name) {
    ptr += msg->msg_namelen;
  }
  if (msg->msg_control) {
    ptr += msg->msg_controllen;
  }
  for (i = 0; i < msg->msg_iovlen; ++i) {
    ptr += msg->msg_iov[i].iov_len;
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }

  /**
   * The kernel only writes to the struct msghdr, and the iov buffers. We must
   * not overwrite that data (except using memcpy_input_parameter) during
   * replay. For the rest of the data, the values we write here during replay
   * are guaranteed to match what was recorded in the buffer.
   * We can't rely on the values we wrote here during recording also being
   * here during replay since the syscall might have been aborted and our
   * written data not recorded.
   */
  msg2 = ptr = ptr_base;
  memcpy_input_parameter(msg2, msg, sizeof(*msg));
  ptr += sizeof(struct msghdr);
  msg2->msg_iov = ptr;
  ptr += sizeof(struct iovec) * msg->msg_iovlen;
  ptr_overwritten_end = ptr;
  if (msg->msg_name) {
    msg2->msg_name = ptr;
    ptr += msg->msg_namelen;
  }
  if (msg->msg_control) {
    msg2->msg_control = ptr;
    ptr += msg->msg_controllen;
  }
  ptr_bytes_start = ptr;
  for (i = 0; i < msg->msg_iovlen; ++i) {
    msg2->msg_iov[i].iov_base = ptr;
    ptr += msg->msg_iov[i].iov_len;
    msg2->msg_iov[i].iov_len = msg->msg_iov[i].iov_len;
  }

  ret = untraced_syscall3(syscallno, sockfd, msg2, flags);

  if (ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    size_t bytes = ret;
    size_t i;
    if (msg->msg_name) {
      local_memcpy(msg->msg_name, msg2->msg_name, msg2->msg_namelen);
    }
    msg->msg_namelen = msg2->msg_namelen;
    if (msg->msg_control) {
      local_memcpy(msg->msg_control, msg2->msg_control, msg2->msg_controllen);
    }
    msg->msg_controllen = msg2->msg_controllen;
    ptr_end = ptr_bytes_start + bytes;
    for (i = 0; i < msg->msg_iovlen; ++i) {
      long copy_bytes =
          bytes < msg->msg_iov[i].iov_len ? bytes : msg->msg_iov[i].iov_len;
      local_memcpy(msg->msg_iov[i].iov_base, msg2->msg_iov[i].iov_base,
                   copy_bytes);
      bytes -= copy_bytes;
    }
    msg->msg_flags = msg2->msg_flags;

    if (msg_received_file_descriptors(msg)) {
      /* When we reach a safe point, notify rr that the control message with
       * file descriptors was received.
       */
      thread_locals->notify_control_msg = msg;
    }
  } else {
    /* Allocate record space as least to cover the data we overwrote above.
     * We don't want to start the next record overlapping that data, since then
     * we'll corrupt it during replay.
     */
    ptr_end = ptr_overwritten_end;
  }
  return commit_raw_syscall(syscallno, ptr_end, ret);
}
#endif

#ifdef SYS_sendmsg
static long sys_sendmsg(const struct syscall_info* call) {
  if (force_traced_syscall_for_chaos_mode()) {
    /* Sending to a socket could unblock a higher priority task */
    return traced_raw_syscall(call);
  }

  const int syscallno = SYS_sendmsg;
  int sockfd = call->args[0];
  struct msghdr* msg = (struct msghdr*)call->args[1];
  int flags = call->args[2];

  void* ptr = prep_syscall_for_fd(sockfd);
  long ret;

  assert(syscallno == call->no);

  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall3(syscallno, sockfd, msg, flags);

  return commit_raw_syscall(syscallno, ptr, ret);
}
#endif

#ifdef SYS_sendto
static long sys_sendto(const struct syscall_info* call) {
  if (force_traced_syscall_for_chaos_mode()) {
    /* Sending to a socket could unblock a higher priority task */
    return traced_raw_syscall(call);
  }

  const int syscallno = SYS_sendto;
  int sockfd = call->args[0];
  void* buf = (void*)call->args[1];
  size_t len = call->args[2];
  int flags = call->args[3];
  const struct sockaddr* dest_addr = (const struct sockaddr*)call->args[4];
  socklen_t addrlen = call->args[5];

  void* ptr = prep_syscall_for_fd(sockfd);
  long ret;

  assert(syscallno == call->no);

  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret =
      untraced_syscall6(syscallno, sockfd, buf, len, flags, dest_addr, addrlen);

  return commit_raw_syscall(syscallno, ptr, ret);
}
#endif

#ifdef SYS_setsockopt
static long sys_setsockopt(const struct syscall_info* call) {
  const int syscallno = SYS_setsockopt;
  int sockfd = call->args[0];
  int level = call->args[1];
  int optname = call->args[2];
  void* optval = (void*)call->args[3];
  socklen_t* optlen = (socklen_t*)call->args[4];

  if (level == SOL_PACKET &&
      (optname == PACKET_RX_RING || optname == PACKET_TX_RING)) {
    // Let rr intercept this (and probably disable it)
    return traced_raw_syscall(call);
  }
  if (level == SOL_NETLINK &&
      (optname == NETLINK_RX_RING || optname == NETLINK_TX_RING)) {
    // Let rr intercept this (and probably disable it)
    return traced_raw_syscall(call);
  }

  void* ptr = prep_syscall_for_fd(sockfd);
  long ret;

  assert(syscallno == call->no);

  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall5(syscallno, sockfd, level, optname, optval, optlen);

  return commit_raw_syscall(syscallno, ptr, ret);
}
#endif

#ifdef SYS_socketpair
typedef int two_ints[2];
static long sys_socketpair(const struct syscall_info* call) {
  const int syscallno = SYS_socketpair;
  int domain = call->args[0];
  int type = call->args[1];
  int protocol = call->args[2];
  two_ints* sv = (two_ints*)call->args[3];

  void* ptr = prep_syscall();
  struct timezone* sv2 = NULL;
  long ret;

  assert(syscallno == call->no);

  sv2 = ptr;
  ptr += sizeof(*sv2);
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall4(syscallno, domain, type, protocol, sv2);
  if (ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    local_memcpy(sv, sv2, sizeof(*sv));
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}
#endif

#if defined(SYS_time)
static long sys_time(const struct syscall_info* call) {
  const int syscallno = SYS_time;
  __kernel_time_t* tp = (__kernel_time_t*)call->args[0];

  void* ptr = prep_syscall();
  long ret;

  assert(syscallno == call->no);

  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall1(syscallno, NULL);
  if (tp) {
    /* No error is possible here. */
    *tp = ret;
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}
#endif

#if defined(__i386__)
typedef struct stat64 stat64_t;
#else
typedef struct stat stat64_t;
#endif
static long sys_xstat64(const struct syscall_info* call) {
  const int syscallno = call->no;
  /* NB: this arg may be a string or an fd, but for the purposes
   * of this generic helper we don't care. */
  long what = call->args[0];
  stat64_t* buf = (stat64_t*)call->args[1];

  /* Like open(), not arming the desched event because it's not
   * needed for correctness, and there are no data to suggest
   * whether it's a good idea perf-wise. */
  void* ptr = prep_syscall();
  stat64_t* buf2 = NULL;
  long ret;

  if (buf) {
    buf2 = ptr;
    ptr += sizeof(*buf2);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall2(syscallno, what, buf2);
  if (buf2 && ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    local_memcpy(buf, buf2, sizeof(*buf));
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}

#ifdef SYS_statx
/* Like sys_xstat64, but with different arguments */
static long sys_statx(const struct syscall_info* call) {
  const int syscallno = call->no;
  struct statx* buf = (struct statx*)call->args[4];

  void* ptr = prep_syscall();
  struct statx* buf2 = NULL;
  long ret;

  if (buf) {
    buf2 = ptr;
    ptr += sizeof(*buf2);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall5(syscallno,
    call->args[0], call->args[1], call->args[2], call->args[3],
    buf2);
  if (buf2 && ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    local_memcpy(buf, buf2, sizeof(*buf));
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}
#endif

static long sys_quotactl(const struct syscall_info* call) {
  const int syscallno = call->no;
  int cmd = call->args[0];
  const char* special = (const char*)call->args[1];
  int id = call->args[2];
  void* addr = (void*)call->args[3];

  if ((cmd >> SUBCMDSHIFT) != Q_GETQUOTA) {
    return traced_raw_syscall(call);
  }

  void* ptr = prep_syscall();
  struct if_dqblk* buf2 = NULL;
  long ret;

  if (addr) {
    buf2 = ptr;
    ptr += sizeof(*buf2);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall4(syscallno, cmd, special, id, buf2);
  if (buf2 && ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    local_memcpy(addr, buf2, sizeof(*buf2));
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_statfs(const struct syscall_info* call) {
  const int syscallno = call->no;
  /* NB: this arg may be a string or an fd, but for the purposes
   * of this generic helper we don't care. */
  long what = call->args[0];
  struct statfs* buf = (struct statfs*)call->args[1];

  /* Like open(), not arming the desched event because it's not
   * needed for correctness, and there are no data to suggest
   * whether it's a good idea perf-wise. */
  void* ptr = prep_syscall();
  struct statfs* buf2 = NULL;
  long ret;

  if (buf) {
    buf2 = ptr;
    ptr += sizeof(*buf2);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall2(syscallno, what, buf2);
  if (buf2 && ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    local_memcpy(buf, buf2, sizeof(*buf));
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_write(const struct syscall_info* call) {
  if (force_traced_syscall_for_chaos_mode()) {
    /* Writing to a pipe or FIFO could unblock a higher priority task */
    return traced_raw_syscall(call);
  }

  const int syscallno = SYS_write;
  int fd = call->args[0];
  const void* buf = (const void*)call->args[1];
  size_t count = call->args[2];

  void* ptr = prep_syscall_for_fd(fd);
  long ret;

  assert(syscallno == call->no);

  if (!start_commit_buffered_syscall(syscallno, ptr, fd_write_blocks(fd))) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall3(syscallno, fd, buf, count);

  return commit_raw_syscall(syscallno, ptr, ret);
}

/* On x86-32, pread/pwrite take the offset in two registers. We don't bother
 * handling that.
 */
#if !defined(__i386__)
static long sys_pwrite64(const struct syscall_info* call) {
  const int syscallno = SYS_pwrite64;
  int fd = call->args[0];
  const void* buf = (const void*)call->args[1];
  size_t count = call->args[2];
  off_t offset = call->args[3];

  enum syscallbuf_fd_classes cls = fd_class(fd);
  if (cls == FD_CLASS_TRACED) {
    return traced_raw_syscall(call);
  }
  void* ptr = prep_syscall();
  assert(syscallno == call->no);

  if (!start_commit_buffered_syscall(syscallno, ptr, fd_write_blocks(fd))) {
    return traced_raw_syscall(call);
  }

  long ret;
  if (cls == FD_CLASS_PROC_MEM) {
    ret = untraced_replay_assist_syscall4(syscallno, fd, buf, count, offset);
  } else {
    ret = untraced_syscall4(syscallno, fd, buf, count, offset);
  }

  return commit_raw_syscall(syscallno, ptr, ret);
}
#endif

static long sys_writev(const struct syscall_info* call) {
  if (force_traced_syscall_for_chaos_mode()) {
    /* Writing to a pipe or FIFO could unblock a higher priority task */
    return traced_raw_syscall(call);
  }

  int syscallno = SYS_writev;
  int fd = call->args[0];
  const struct iovec* iov = (const struct iovec*)call->args[1];
  unsigned long iovcnt = call->args[2];

  void* ptr = prep_syscall_for_fd(fd);
  long ret;

  assert(syscallno == call->no);

  if (!start_commit_buffered_syscall(syscallno, ptr, fd_write_blocks(fd))) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall3(syscallno, fd, iov, iovcnt);

  return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_ptrace(const struct syscall_info* call) {
  int syscallno = SYS_ptrace;
  long request = call->args[0];
  pid_t pid = call->args[1];
  void* addr = (void*)call->args[2];
  void* data = (void*)call->args[3];

  if (request != PTRACE_PEEKDATA || !data) {
    return traced_raw_syscall(call);
  }

  /* We try to emulate PTRACE_PEEKDATA using process_vm_readv. That might not
   * work for permissions reasons; if it fails for any reason, we retry with
   * a traced syscall.
   * This does mean that if a process issues a PTRACE_PEEKDATA while not
   * actually ptracing the target, it might succeed under rr whereas normally
   * it would have failed. That's hard to avoid and unlikely to be a real
   * problem in practice (typically it would fail on some other ptrace call like
   * PTRACE_GETREGS before or after the PEEKDATA).
   */
  void* ptr = prep_syscall();
  long ret;
  void* data2;

  assert(syscallno == call->no);
  syscallno = SYS_process_vm_readv;

  data2 = ptr;
  ptr += sizeof(long);

  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  struct iovec local_iov = { data2, sizeof(long) };
  struct iovec remote_iov = { addr, sizeof(long) };
  ret = untraced_syscall6(syscallno, pid, &local_iov, 1, &remote_iov, 1, 0);
  if (ret > 0 && !buffer_hdr()->failed_during_preparation) {
    local_memcpy(data, data2, ret);
  }
  commit_raw_syscall(syscallno, ptr, ret);

  if (ret != sizeof(long)) {
    return traced_raw_syscall(call);
  }
  return ret;
}

static long sys_getrusage(const struct syscall_info* call) {
  const int syscallno = SYS_getrusage;
  int who = (int)call->args[0];
  struct rusage* buf = (struct rusage*)call->args[1];
  void* ptr = prep_syscall();
  long ret;
  struct rusage* buf2 = NULL;

  assert(syscallno == call->no);

  if (buf) {
    buf2 = ptr;
    ptr += sizeof(struct rusage);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall2(syscallno, who, buf2);
  if (buf2 && ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    local_memcpy(buf, buf2, sizeof(*buf));
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}

// The alignment of this struct is incorrect, but as long as it's not
// used inside other structures, defining it this way makes the code below
// easier.
typedef uint64_t kernel_sigset_t;

static long sys_rt_sigprocmask(const struct syscall_info* call) {
  const int syscallno = SYS_rt_sigprocmask;
  long ret;
  kernel_sigset_t modified_set;
  void* oldset2;
  struct syscallbuf_hdr* hdr;

  if (call->args[3] != sizeof(kernel_sigset_t)) {
    // Unusual sigset size. Bail.
    return traced_raw_syscall(call);
  }

  void* ptr = prep_syscall();

  int how = (int)call->args[0];
  const kernel_sigset_t* set = (const kernel_sigset_t*)call->args[1];
  kernel_sigset_t* oldset = (kernel_sigset_t*)call->args[2];

  oldset2 = ptr;
  ptr += sizeof(kernel_sigset_t);

  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  if (set && (how == SIG_BLOCK || how == SIG_SETMASK)) {
    local_memcpy(&modified_set, set, sizeof(kernel_sigset_t));
    // SIGSTKFLT (PerfCounters::TIME_SLICE_SIGNAL) and
    // SIGPWR(SYSCALLBUF_DESCHED_SIGNAL) are used by rr
    modified_set &=
        ~(((uint64_t)1) << (SIGSTKFLT - 1)) &
        ~(((uint64_t)1) << (globals.desched_sig - 1));
    set = &modified_set;
  }

  hdr = buffer_hdr();
  hdr->in_sigprocmask_critical_section = 1;

  ret =
      untraced_syscall4(syscallno, how, set, oldset2, sizeof(kernel_sigset_t));
  if (ret >= 0 && !buffer_hdr()->failed_during_preparation) {
    if (oldset) {
      local_memcpy(oldset, oldset2, sizeof(kernel_sigset_t));
    }
    if (set) {
      kernel_sigset_t previous_set;
      local_memcpy(&previous_set, oldset2, sizeof(kernel_sigset_t));
      switch (how) {
        case SIG_UNBLOCK:
          previous_set &= ~*set;
          break;
        case SIG_BLOCK:
          previous_set |= *set;
          break;
        case SIG_SETMASK:
          previous_set = *set;
          break;
      }
      hdr->blocked_sigs = previous_set;
      // We must update the generation last to ensure that an update is not
      // lost.
      ++hdr->blocked_sigs_generation;
    }
  }
  hdr->in_sigprocmask_critical_section = 0;

  commit_raw_syscall(syscallno, ptr, ret);

  if (ret == -EAGAIN) {
    // The rr supervisor emulated EAGAIN because there was a pending signal.
    // Retry using a traced syscall so the pending signal(s) can be delivered.
    return traced_raw_syscall(call);
  }
  return ret;
}

static long syscall_hook_internal(const struct syscall_info* call) {
  switch (call->no) {
#define CASE(syscallname)                                                      \
  case SYS_##syscallname:                                                      \
    return sys_##syscallname(call)
#define CASE_GENERIC_NONBLOCKING(syscallname)                                  \
  case SYS_##syscallname:                                                      \
    return sys_generic_nonblocking(call)
#define CASE_GENERIC_NONBLOCKING_FD(syscallname)                               \
  case SYS_##syscallname:                                                      \
    return sys_generic_nonblocking_fd(call)
#if defined(SYS_access)
    CASE_GENERIC_NONBLOCKING(access);
#endif
    CASE(clock_gettime);
#if defined(SYS_clock_gettime64)
    CASE(clock_gettime64);
#endif
    CASE_GENERIC_NONBLOCKING_FD(close);
#if defined(SYS_creat)
    CASE(creat);
#endif
    CASE_GENERIC_NONBLOCKING_FD(dup);
#if defined(SYS_epoll_wait)
case SYS_epoll_wait:
#endif
case SYS_epoll_pwait:
    return sys_epoll_wait(call);
    CASE_GENERIC_NONBLOCKING_FD(fadvise64);
    CASE_GENERIC_NONBLOCKING(fchmod);
#if defined(SYS_fcntl64)
    CASE(fcntl64);
#else
    CASE(fcntl);
#endif
    CASE(fgetxattr);
    CASE(flistxattr);
    CASE_GENERIC_NONBLOCKING_FD(fsetxattr);
    CASE_GENERIC_NONBLOCKING_FD(ftruncate);
    CASE(futex);
#if defined(SYS_getdents)
    CASE(getdents);
#endif
    CASE(getdents64);
    CASE_GENERIC_NONBLOCKING(getegid);
    CASE_GENERIC_NONBLOCKING(geteuid);
    CASE_GENERIC_NONBLOCKING(getgid);
    CASE_GENERIC_NONBLOCKING(getpid);
    CASE_GENERIC_NONBLOCKING(getppid);
    CASE(getrusage);
    CASE_GENERIC_NONBLOCKING(gettid);
    CASE(gettimeofday);
    CASE_GENERIC_NONBLOCKING(getuid);
    CASE(getxattr);
    CASE(ioctl);
#if defined(lchown)
    CASE_GENERIC_NONBLOCKING(lchown);
#endif
    CASE(lgetxattr);
    CASE(listxattr);
    CASE(llistxattr);
#if defined(SYS__llseek)
    CASE(_llseek);
#endif
    CASE_GENERIC_NONBLOCKING_FD(lseek);
    CASE(madvise);
#if defined(SYS_mkdir)
    CASE_GENERIC_NONBLOCKING(mkdir);
#endif
#if defined(SYS_mkdor)
    CASE_GENERIC_NONBLOCKING(mknod);
#endif
    CASE(mprotect);
#if defined(SYS_open)
    CASE(open);
#endif
    CASE(openat);
#if defined(SYS_poll)
    CASE(poll);
#endif
#if !defined(__i386__)
    CASE(pread64);
    CASE(pwrite64);
#endif
    CASE(ptrace);
    CASE(quotactl);
    CASE(read);
#if defined(SYS_readlink)
    CASE(readlink);
#endif
    CASE(readlinkat);
#if defined(SYS_recvfrom)
    CASE(recvfrom);
#endif
#if defined(SYS_recvmsg)
    CASE(recvmsg);
#endif
#if defined(SYS_rmdir)
    CASE_GENERIC_NONBLOCKING(rmdir);
#endif
    CASE(rt_sigprocmask);
#if defined(SYS_sendmsg)
    CASE(sendmsg);
#endif
#if defined(SYS_sendto)
    CASE(sendto);
#endif
#if defined(SYS_setsockopt)
    CASE(setsockopt);
#endif
    CASE_GENERIC_NONBLOCKING(setxattr);
#if defined(SYS_socketcall)
    CASE(socketcall);
#endif
#if defined(SYS_socketpair)
    CASE(socketpair);
#endif
#if defined(SYS_symlink)
    CASE_GENERIC_NONBLOCKING(symlink);
#endif
#if defined(SYS_time)
    CASE(time);
#endif
    CASE_GENERIC_NONBLOCKING(truncate);
#if defined(SYS_unlink)
    CASE_GENERIC_NONBLOCKING(unlink);
#endif
    CASE_GENERIC_NONBLOCKING(unlinkat);
    CASE_GENERIC_NONBLOCKING_FD(utimensat);
    CASE(write);
    CASE(writev);
#if defined(SYS_fstat64)
    case SYS_fstat64:
#elif defined(SYS_fstat)
    case SYS_fstat:
#endif
#if defined(SYS_lstat64)
    case SYS_lstat64:
#elif defined(SYS_lstat)
    case SYS_lstat:
#endif
#if defined(SYS_stat64)
    case SYS_stat64:
#elif defined(SYS_stat)
    case SYS_stat:
#endif
      return sys_xstat64(call);
#if defined(SYS_statx)
    case SYS_statx:
      return sys_statx(call);
#endif
    case SYS_statfs:
    case SYS_fstatfs:
      return sys_statfs(call);
#undef CASE
#undef CASE_GENERIC_NONBLOCKING
#undef CASE_GENERIC_NONBLOCKING_FD
    default:
      return traced_raw_syscall(call);
  }
}

/* Delay for testing purposes */
static void do_delay(void) {
  int i;
  int result = 0;
  for (i = 0; i < 10000000; ++i) {
    result += i * i;
  }
  // Make sure result is used so this doesn't get optimized away
  impose_syscall_delay = result | 1;
}

/* Explicitly declare this as hidden so we can call it from
 * _syscall_hook_trampoline without doing all sorts of special PIC handling.
 */
RR_HIDDEN long syscall_hook(const struct syscall_info* call) {
  // Initialize thread-local state if this is the first syscall for this
  // thread.
  init_thread();

  if (!thread_locals->buffer || buffer_hdr()->locked) {
    /* We may be reentering via a signal handler. Bail. */
    return traced_raw_syscall(call);
  }

  thread_locals->original_syscall_parameters = call;

  if (impose_syscall_delay) {
    do_delay();
  }

  long result = syscall_hook_internal(call);
  if (buffer_hdr() && buffer_hdr()->notify_on_syscall_hook_exit) {
    // Sometimes a signal is delivered to interrupt an untraced syscall in
    // a non-restartable way (e.g. seccomp SIGSYS). Those signals must be
    // handled outside any syscallbuf transactions. We defer them until
    // this SYS_rrcall_notify_syscall_hook_exit, which is triggered by rr
    // setting notify_on_syscall_hook_exit. The parameters to the
    // SYS_rrcall_notify_syscall_hook_exit are magical and fully control
    // the syscall parameters and result seen by the signal handler.
    //
    // SYS_rrcall_notify_syscall_hook_exit will clear
    // notify_on_syscall_hook_exit. Clearing it ourselves is tricky to get
    // right without races.
    //
    // During recording, this flag is set when the recorder needs to delay
    // delivery of a signal until we've stopped using the syscallbuf.
    // During replay, this flag is set when the next event is entering a
    // SYS_rrcall_notify_syscall_hook_exit.
    //
    // The correctness argument is as follows:
    // Correctness requires that a) replay's setting of the flag happens before
    // we read the flag in the call to syscall_hook that triggered the
    // SYS_rrcall_notify_syscall_hook_exit and b) replay's setting of the flag
    // must happen after we read the flag in the previous execution of
    // syscall_hook.
    // Condition a) holds as long as no events are recorded between the
    // checking of the flag above and the execution of this syscall. This
    // should be the case; no synchronous signals or syscalls are
    // triggerable, all async signals other than SYSCALLBUF_DESCHED_SIGNAL
    // are delayed, and SYSCALLBUF_DESCHED_SIGNAL shouldn't fire since we've
    // disarmed the desched fd at this point. SYSCALLBUF_FLUSH events may be
    // emitted when we process the SYS_rrcall_notify_syscall_hook_exit event,
    // but replay of those events ends at the last flushed syscall, before
    // we exit syscall_hook_internal.
    // Condition b) failing would mean no new events were generated between
    // testing the flag in the previous syscall_hook and the execution of this
    // SYS_rrcall_notify_syscall_hook_exit. However, every invocation of
    // syscall_hook_internal generates either a traced syscall or a syscallbuf
    // record that would be flushed by SYSCALLBUF_FLUSH, so that can't
    // happen.
    result = _raw_syscall(SYS_rrcall_notify_syscall_hook_exit, call->args[0],
                          call->args[1], call->args[2], call->args[3],
                          call->args[4], call->args[5],
                          RR_PAGE_SYSCALL_PRIVILEGED_TRACED, result, call->no);
  }
  // Do work that can only be safely done after syscallbuf can be flushed
  if (thread_locals->notify_control_msg) {
    privileged_traced_syscall1(SYS_rrcall_notify_control_msg,
                               thread_locals->notify_control_msg);
    thread_locals->notify_control_msg = NULL;
  }
  thread_locals->original_syscall_parameters = NULL;
  return result;
}
