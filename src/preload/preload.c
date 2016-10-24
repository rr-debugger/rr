/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#define RR_IMPLEMENT_PRELOAD

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "preload_interface.h"

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
 */

/**
 * We also use this preload library to disable XShm by overriding
 * XShmQueryExtension.
 */

#include "rr/rr.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <linux/futex.h>
#include <linux/net.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <syscall.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

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

/* NB: don't include any other local headers here. */

#ifdef memcpy
#undef memcpy
#endif
#define memcpy you_must_use_local_memcpy

#ifdef syscall
#undef syscall
#endif
#define syscall you_must_use_traced_syscall

static void* xmalloc(size_t size) {
  void* mem_ptr = malloc(size);
  if (!mem_ptr) {
    abort();
  }
  return mem_ptr;
}

#define RR_HIDDEN __attribute__((visibility("hidden")))

/**
 * Represents syscall params.  Makes it simpler to pass them around,
 * and avoids pushing/popping all the data for calls.
 */
struct syscall_info {
  long no;
  long args[6];
};

/* Nonzero when syscall buffering is enabled. */
static int buffer_enabled;
/* Nonzero after process-global state has been initialized. */
static int process_inited;

static struct preload_globals globals;

static struct preload_thread_locals* const thread_locals =
    (struct preload_thread_locals*)PRELOAD_THREAD_LOCALS_ADDR;

/* Points at the libc/pthread pthread_create().  We wrap
 * pthread_create, so need to retain this pointer to call out to the
 * libc version. There is no __pthread_create stub to call. There are
 * some explicitly-versioned stubs but let's not use those. */
static int (*real_pthread_create)(pthread_t* thread, const pthread_attr_t* attr,
                                  void* (*start_routine)(void*), void* arg);

static int (*real_pthread_mutex_timedlock)(pthread_mutex_t* mutex,
                                           const struct timespec* abstime);

/**
 * Return a pointer to the buffer header, which happens to occupy the
 * initial bytes in the mapped region.
 */
static struct syscallbuf_hdr* buffer_hdr(void) {
  return (struct syscallbuf_hdr*)thread_locals->buffer;
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

static int update_errno_ret(long ret) {
  /* EHWPOISON is the last known errno as of linux 3.9.5. */
  if (0 > ret && ret >= -EHWPOISON) {
    errno = -ret;
    ret = -1;
  }
  return ret;
}

static int privileged_traced_syscall(int syscallno, long a0, long a1, long a2,
                                     long a3, long a4, long a5) {
  long ret = _raw_syscall(syscallno, a0, a1, a2, a3, a4, a5,
                          RR_PAGE_SYSCALL_PRIVILEGED_TRACED, 0, 0);
  return update_errno_ret(ret);
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
 * Make a raw traced syscall using the params in |call|.  "Raw" traced
 * syscalls return the raw kernel return value, and don't transform it
 * to -1/errno per POSIX semantics.
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

static int privileged_traced_raise(int sig) {
  return privileged_traced_syscall2(SYS_kill, privileged_traced_getpid(), sig);
}

static ssize_t privileged_traced_write(int fd, const void* buf, size_t count) {
  return privileged_traced_syscall3(SYS_write, fd, buf, count);
}

/* We can't use the rr logging helpers because they rely on libc
 * syscall-invoking functions, so roll our own here.
 *
 * XXX just use these for all logging? */

__attribute__((format(printf, 1, 2))) static void logmsg(const char* msg, ...) {
  va_list args;
  char buf[1024];
  int len;

  va_start(args, msg);
  len = vsnprintf(buf, sizeof(buf) - 1, msg, args);
  va_end(args);

  privileged_traced_write(STDERR_FILENO, buf, len);
}

#ifndef NDEBUG
#define assert(cond)                                                           \
  do {                                                                         \
    if (!(cond)) {                                                             \
      logmsg("%s:%d: Assertion `" #cond "' failed.\n", __FILE__, __LINE__);    \
      privileged_traced_raise(SIGABRT);                                        \
    }                                                                          \
  } while (0)
#else
#define assert(cond) ((void)0)
#endif

#define fatal(msg, ...)                                                        \
  do {                                                                         \
    logmsg("[FATAL] (%s:%d: errno: %s: tid: %d) " msg "\n", __FILE__,          \
           __LINE__, strerror(errno), privileged_traced_gettid(),              \
           ##__VA_ARGS__);                                                     \
    privileged_traced_syscall1(SYS_exit_group, EX_OSERR);                      \
  } while (0)

#ifdef DEBUGTAG
#define debug(msg, ...) logmsg("[" DEBUGTAG "] " msg "\n", ##__VA_ARGS__)
#else
#define debug(msg, ...) ((void)0)
#endif

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
  struct f_owner_ex own;

  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_CONTEXT_SWITCHES;
  attr.disabled = 1;
  attr.sample_period = nr_descheds;

  tmp_fd = privileged_traced_perf_event_open(&attr, 0 /*self*/, -1 /*any cpu*/,
                                             -1, 0);
  if (0 > tmp_fd) {
    fatal("Failed to perf_event_open(cs, period=%zu)", nr_descheds);
  }
  fd = privileged_traced_fcntl(tmp_fd, F_DUPFD_CLOEXEC,
                               RR_DESCHED_EVENT_FLOOR_FD);
  if (0 > fd) {
    fatal("Failed to dup desched fd");
  }
  if (privileged_untraced_close(tmp_fd)) {
    fatal("Failed to close tmp_fd");
  }
  if (privileged_untraced_fcntl(fd, F_SETFL, O_ASYNC)) {
    fatal("Failed to fcntl(O_ASYNC) the desched counter");
  }
  own.type = F_OWNER_TID;
  own.pid = tid;
  if (privileged_untraced_fcntl(fd, F_SETOWN_EX, &own)) {
    fatal("Failed to fcntl(SETOWN_EX) the desched counter to this");
  }
  if (privileged_untraced_fcntl(fd, F_SETSIG, SYSCALLBUF_DESCHED_SIGNAL)) {
    fatal("Failed to fcntl(SETSIG, %d) the desched counter",
          SYSCALLBUF_DESCHED_SIGNAL);
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
  /* Do not do any syscall buffering in a DiversionSession! */
  if (!buffer_enabled || globals.in_diversion) {
    thread_locals->thread_inited = 1;
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
  thread_locals->scratch_size = args.scratch_size;

  thread_locals->thread_inited = 1;
}

extern char _breakpoint_table_entry_start;
extern char _breakpoint_table_entry_end;

/**
 * Initialize process-global buffering state, if enabled.
 */
static void __attribute__((constructor)) init_process(void) {
  struct rrcall_init_preload_params params;

#if defined(__i386__)
  extern RR_HIDDEN void _syscallhook_vsyscall_entry(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_3d_01_f0_ff_ff(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_90_90_90(void);
  struct syscall_patch_hook syscall_patch_hooks[] = {
    /* pthread_cond_broadcast has 'int 80' followed by
     * cmp $-4095,%eax (in glibc-2.18-16.fc20.i686) */
    { 5,
      { 0x3d, 0x01, 0xf0, 0xff, 0xff },
      (uintptr_t)_syscall_hook_trampoline_3d_01_f0_ff_ff },
    /* Our vdso syscall patch has 'int 80' followed by onp; nop; nop */
    { 3, { 0x90, 0x90, 0x90 }, (uintptr_t)_syscall_hook_trampoline_90_90_90 }
  };

  /* Load GLIBC 2.1 version of pthread_create. Otherwise we may get the 2.0
     version, which cannot handle the pthread_attr values passed by callers
     expecting to call the glibc 2.1 version. */
  real_pthread_create = dlvsym(RTLD_NEXT, "pthread_create", "GLIBC_2.1");
#elif defined(__x86_64__)
  extern RR_HIDDEN void _syscall_hook_trampoline_48_3d_01_f0_ff_ff(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_48_3d_00_f0_ff_ff(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_48_8b_3c_24(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_5a_5e_c3(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_89_c2_f7_da(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_90_90_90(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_ba_01_00_00_00(void);
  extern RR_HIDDEN void _syscall_hook_trampoline_89_c1_31_d2(void);

  struct syscall_patch_hook syscall_patch_hooks[] = {
    /* Many glibc syscall wrappers (e.g. read) have 'syscall' followed
     * by
     * cmp $-4095,%rax (in glibc-2.18-16.fc20.x86_64) */
    { 6,
      { 0x48, 0x3d, 0x01, 0xf0, 0xff, 0xff },
      (uintptr_t)_syscall_hook_trampoline_48_3d_01_f0_ff_ff },
    /* Many glibc syscall wrappers (e.g. __libc_recv) have 'syscall'
     * followed by
     * cmp $-4096,%rax (in glibc-2.18-16.fc20.x86_64) */
    { 6,
      { 0x48, 0x3d, 0x00, 0xf0, 0xff, 0xff },
      (uintptr_t)_syscall_hook_trampoline_48_3d_00_f0_ff_ff },
    /* Many glibc syscall wrappers (e.g. read) have 'syscall' followed
     * by
     * mov (%rsp),%rdi (in glibc-2.18-16.fc20.x86_64) */
    { 4,
      { 0x48, 0x8b, 0x3c, 0x24 },
      (uintptr_t)_syscall_hook_trampoline_48_8b_3c_24 },
    /* __lll_unlock_wake has 'syscall' followed by
     * pop %rdx; pop %rsi; ret */
    { 3, { 0x5a, 0x5e, 0xc3 }, (uintptr_t)_syscall_hook_trampoline_5a_5e_c3 },
    /* posix_fadvise64 has 'syscall' followed by
     * mov %eax,%edx; neg %edx (in glibc-2.22-11.fc23.x86_64) */
    { 4,
      { 0x89, 0xc2, 0xf7, 0xda },
      (uintptr_t)_syscall_hook_trampoline_89_c2_f7_da },
    /* Our VDSO vsyscall patches have 'syscall' followed by "nop; nop;
       nop" */
    { 3,
      { 0x90, 0x90, 0x90 },
      (uintptr_t)_syscall_hook_trampoline_ba_01_00_00_00 },
    /* glibc-2.22-17.fc23.x86_64 has 'syscall' followed by 'mov $1,%rdx'
     * in
     * pthread_barrier_wait.
     */
    { 5,
      { 0xba, 0x01, 0x00, 0x00, 0x00 },
      (uintptr_t)_syscall_hook_trampoline_ba_01_00_00_00 },
    /* pthread_sigmask has 'syscall' followed by 'mov %eax,%ecx; xor
       %edx,%edx' */
    { 4,
      { 0x89, 0xc1, 0x31, 0xd2 },
      (uintptr_t)_syscall_hook_trampoline_89_c1_31_d2 }
  };

  real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
#else
#error Unknown architecture
#endif

  assert(sizeof(struct preload_thread_locals) <= PRELOAD_THREAD_LOCALS_SIZE);

  if (process_inited) {
    return;
  }

  buffer_enabled = !!getenv(SYSCALLBUF_ENABLED_ENV_VAR);

  params.syscallbuf_enabled = buffer_enabled;
#ifdef __i386__
  params.syscallhook_vsyscall_entry = (void*)_syscallhook_vsyscall_entry;
#else
  params.syscallhook_vsyscall_entry = 0;
#endif
  params.syscall_patch_hook_count =
      sizeof(syscall_patch_hooks) / sizeof(syscall_patch_hooks[0]);
  params.syscall_patch_hooks = syscall_patch_hooks;
  params.globals = &globals;
  params.breakpoint_table = &_breakpoint_table_entry_start;
  params.breakpoint_table_entry_size =
      &_breakpoint_table_entry_end - &_breakpoint_table_entry_start;

  privileged_traced_syscall1(SYS_rrcall_init_preload, &params);

  process_inited = 1;
}

/**
 * In a thread newly created by |pthread_create()|, first initialize
 * thread-local internal rr data, then trampoline into the user's
 * thread function.
 */
struct thread_func_data {
  void* (*start_routine)(void*);
  void* arg;
};

static void* thread_trampoline(void* arg) {
  struct thread_func_data data = *(struct thread_func_data*)arg;
  free(arg);

  return data.start_routine(data.arg);
}

/**
 * Interpose |pthread_create()| so that we can use a custom trampoline
 * function (see above) that initializes rr thread-local data for new
 * threads.
 *
 * This is a wrapper of |pthread_create()|, but not like the ones
 * below: we don't wrap |pthread_create()| in order to buffer its
 * syscalls, rather in order to initialize rr thread data.
 */
int pthread_create(pthread_t* thread, const pthread_attr_t* attr,
                   void* (*start_routine)(void*), void* arg) {
  struct thread_func_data* data = xmalloc(sizeof(*data));
  int ret;

  /* Init syscallbuf now if we haven't yet (e.g. if pthread_create is called
   * during library initialization before our preload library).
   * This also fetches real_pthread_create which we'll need below. */
  init_process();

  data->start_routine = start_routine;
  data->arg = arg;
  ret = real_pthread_create(thread, attr, thread_trampoline, data);
  return ret;
}

#define PTHREAD_MUTEX_TYPE_MASK 3
#define PTHREAD_MUTEX_PRIO_INHERIT_NP 32

static void fix_mutex_kind(pthread_mutex_t* mutex) {
  /* Disable priority inheritance. */
  mutex->__data.__kind &= ~PTHREAD_MUTEX_PRIO_INHERIT_NP;
}

/*
 * We bind directly to __pthread_mutex_lock and __pthread_mutex_trylock
 * because setting up indirect function pointers in init_process requires
 * calls to dlsym which itself can call pthread_mutex_lock (e.g. via
 * application code overriding malloc/calloc to use a pthreads-based
 * implementation).
 */
extern int __pthread_mutex_lock(pthread_mutex_t* mutex);
extern int __pthread_mutex_trylock(pthread_mutex_t* mutex);

/* Prevent use of lock elision; Haswell's TSX/RTM features used by
   lock elision increment the rbc perf counter for instructions which
   are later rolled back if the transaction fails. */
int pthread_mutex_lock(pthread_mutex_t* mutex) {
  fix_mutex_kind(mutex);
  return __pthread_mutex_lock(mutex);
}

int pthread_mutex_timedlock(pthread_mutex_t* mutex,
                            const struct timespec* abstime) {
  fix_mutex_kind(mutex);
  /* No __pthread_mutex_timedlock stub exists, so we have to use the
   * indirect call.
   */
  if (!real_pthread_mutex_timedlock) {
    real_pthread_mutex_timedlock = dlsym(RTLD_NEXT, "pthread_mutex_timedlock");
  }
  return real_pthread_mutex_timedlock(mutex, abstime);
}

int pthread_mutex_trylock(pthread_mutex_t* mutex) {
  fix_mutex_kind(mutex);
  return __pthread_mutex_trylock(mutex);
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
  if (!thread_locals->buffer) {
    return NULL;
  }
  if (buffer_hdr()->locked) {
    /* We may be reentering via a signal handler. Return
     * an invalid pointer. */
    return NULL;
  }
  /* We don't need to worry about a race between testing
   * |locked| and setting it here. rr recording is responsible
   * for ensuring signals are not delivered during
   * syscall_buffer prologue and epilogue code.
   *
   * XXX except for synchronous signals generated in the syscall
   * buffer code, while reading/writing user pointers */
  buffer_hdr()->locked = 1;
  /* "Allocate" space for a new syscall record, not including
   * syscall outparam data. */
  return buffer_last() + sizeof(struct syscallbuf_record);
}

static int is_bufferable_fd(int fd) {
  return fd < 0 || (fd < SYSCALLBUF_FDS_DISABLED_SIZE &&
                    !globals.syscallbuf_fds_disabled[fd]);
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
    fatal("Failed to ENABLE counter %d", thread_locals->desched_counter_fd);
  }
}

static void disarm_desched_event(void) {
  /* See above. */
  if ((int)privileged_untraced_syscall3(SYS_ioctl,
                                        thread_locals->desched_counter_fd,
                                        PERF_EVENT_IOC_DISABLE, 0)) {
    fatal("Failed to DISABLE counter %d", thread_locals->desched_counter_fd);
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
    buffer_hdr()->locked = 0;
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
  }
  return 1;
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
  void (*breakpoint_function)(void) = 0;

  assert(record_end >= record_start);
  rec->size = record_end - record_start;

  assert(buffer_hdr()->locked);

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
    fatal("Record is for %d but trying to commit %d", rec->syscallno,
          syscallno);
  }

  if (hdr->abort_commit) {
    /* We were descheduled in the middle of a may-block
     * syscall, and it was recorded as a normal entry/exit
     * pair.  So don't record the syscall in the buffer or
     * replay will go haywire. */
    hdr->abort_commit = 0;
    /* Clear the return value that rr puts there during replay */
    rec->ret = 0;
  } else {
    int breakpoint_entry_size =
        &_breakpoint_table_entry_end - &_breakpoint_table_entry_start;

    rec->ret = ret;
    // Finish 'rec' first before updating num_rec_bytes, since
    // rr might read the record anytime after this update.
    hdr->num_rec_bytes += stored_record_size(rec->size);

    breakpoint_function =
        (void*)(&_breakpoint_table_entry_start +
                (hdr->num_rec_bytes / 8) * breakpoint_entry_size);
  }

  if (rec->desched) {
    disarm_desched_event();
  }
  /* NBB: for may-block syscalls that are descheduled, the
   * tracer uses the previous ioctl() as a stable point to reset
   * the record counter.  Therefore nothing from here on in the
   * current txn must touch the record counter (at least, must
   * not assume it's unchanged). */

  buffer_hdr()->locked = 0;

  if (breakpoint_function) {
    /* Call the breakpoint function corresponding to the record we just
     * committed. This function just returns, but during replay it gives rr
     * a chance to set a breakpoint for when a specific syscallbuf record
     * has been processed.
     */
    breakpoint_function();
  }

  return ret;
}

/**
 * |ret_size| is the result of a syscall indicating how much data was returned
 * in scratch buffer |buf2|; this function copies that data to |buf| and returns
 * a pointer to the end of it. If there is no scratch buffer (|buf2| is NULL)
 * just returns |ptr|.
 */
static void* copy_output_buffer(int ret_size, void* ptr, void* buf,
                                void* buf2) {
  if (!buf2) {
    return ptr;
  }
  if (ret_size <= 0) {
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
  clockid_t clk_id = (clockid_t)call->args[0];
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
  if (tp) {
    local_memcpy(tp, tp2, sizeof(*tp));
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_open(const struct syscall_info* call);
static long sys_creat(const struct syscall_info* call) {
  const char* pathname = (const char*)call->args[0];
  mode_t mode = call->args[1];
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
  struct f_owner_ex* owner = (struct f_owner_ex*)call->args[2];

  /* The OWN_EX fcntl's aren't may-block. */
  void* ptr = prep_syscall_for_fd(fd);
  struct f_owner_ex* owner2 = NULL;
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
  if (owner2) {
    local_memcpy(owner, owner2, sizeof(*owner));
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}

static int sys_fcntl64_setlk64(const struct syscall_info* call) {
  const int syscallno = RR_FCNTL_SYSCALL;
  int fd = call->args[0];
  int cmd = call->args[1];
  struct flock64* lock = (struct flock64*)call->args[2];

  void* ptr = prep_syscall_for_fd(fd);
  struct flock64* lock2 = NULL;
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
  if (lock2) {
    local_memcpy(lock, lock2, sizeof(*lock));
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}

static int sys_fcntl64_setlkw64(const struct syscall_info* call) {
  const int syscallno = RR_FCNTL_SYSCALL;
  int fd = call->args[0];
  int cmd = call->args[1];
  struct flock64* lock = (struct flock64*)call->args[2];

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
  ptr = copy_output_buffer(ret > (long)size ? (long)size : ret, ptr, buf, buf2);
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

static long sys_ioctl(const struct syscall_info* call) {
  switch (call->args[1]) {
    case BTRFS_IOC_CLONE_RANGE:
    case FIOCLEX:
    case FIONCLEX:
      return sys_safe_nonblocking_ioctl(call);
    default:
      return traced_raw_syscall(call);
  }
}

static long sys_futex(const struct syscall_info* call) {
  enum {
    FUTEX_USES_UADDR2 = 1 << 0,
  };

  int op = call->args[1];
  int flags = 0;
  switch (FUTEX_CMD_MASK & op) {
    case FUTEX_WAKE:
      break;
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

static long sys_getdents(const struct syscall_info* call) {
  return sys_generic_getdents(call);
}

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
  if (tp) {
    local_memcpy(tp, tp2, sizeof(*tp));
  }
  if (tzp) {
    local_memcpy(tzp, tzp2, sizeof(*tzp));
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
  ptr = copy_output_buffer(ret > (long)size ? (long)size : ret, ptr, value,
                           value2);
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
  ptr = copy_output_buffer(ret > (long)size ? (long)size : ret, ptr, value,
                           value2);
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
  ptr = copy_output_buffer(ret > (long)size ? (long)size : ret, ptr, buf, buf2);
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
  loff_t* result = (loff_t*)call->args[3];
  unsigned int whence = call->args[4];

  void* ptr = prep_syscall_for_fd(fd);
  loff_t* result2 = NULL;
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
  buffer_hdr()->mprotect_record_count_completed++;

  return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_open(const struct syscall_info* call) {
  const int syscallno = SYS_open;
  const char* pathname = (const char*)call->args[0];
  int flags = call->args[1];
  mode_t mode = call->args[2];

  /* NB: not arming the desched event is technically correct,
   * since open() can't deadlock if it blocks.  However, not
   * allowing descheds here may cause performance issues if the
   * open does block for a while.  Err on the side of simplicity
   * until we have perf data. */
  void* ptr;
  long ret;

  assert(syscallno == call->no);

  /* The strcmp()s done here are OK because we're not in the
   * critical section yet. */
  if (!allow_buffered_open(pathname)) {
    return traced_raw_syscall(call);
  }

  ptr = prep_syscall();
  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall3(syscallno, pathname, flags, mode);
  return commit_raw_syscall(syscallno, ptr, ret);
}

/**
 * Make this function external so desched_ticks.py can set a breakpoint on it.
 */
void __before_poll_syscall_breakpoint(void) {}

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
  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }
  if (fds2) {
    memcpy_input_parameter(fds2, fds, nfds * sizeof(*fds2));
  }

  __before_poll_syscall_breakpoint();

  ret = untraced_syscall3(syscallno, fds2, nfds, timeout);

  if (fds2 && ret >= 0) {
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
  return commit_raw_syscall(syscallno, ptr, ret);
}

#define CLONE_SIZE_THRESHOLD 0x10000

static long sys_read(const struct syscall_info* call) {
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
    if (lseek_ret > 0 && !(lseek_ret & 4095)) {
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

        replay_only_syscall2(SYS_dup2, thread_locals->cloned_file_data_fd, fd);

        ptr = prep_syscall();
        if (count > thread_locals->scratch_size) {
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

#if defined(SYS_socketcall)
static long sys_socketcall_recv(const struct syscall_info* call) {
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
  ptr = copy_output_buffer(ret, ptr, buf, buf2);
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

  if (ret >= 0) {
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
  ptr = copy_output_buffer(ret, ptr, buf, buf2);
  return commit_raw_syscall(syscallno, ptr, ret);
}
#endif

#ifdef SYS_recvmsg
static long sys_recvmsg(const struct syscall_info* call) {
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

  if (ret >= 0) {
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

    if (msg->msg_controllen) {
      /* When we reach a safe point, notify rr that the control message was
       * received.
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
  local_memcpy(sv, sv2, sizeof(*sv));
  return commit_raw_syscall(syscallno, ptr, ret);
}
#endif

static long sys_time(const struct syscall_info* call) {
  const int syscallno = SYS_time;
  time_t* tp = (time_t*)call->args[0];

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

static long sys_xstat64(const struct syscall_info* call) {
  const int syscallno = call->no;
  /* NB: this arg may be a string or an fd, but for the purposes
   * of this generic helper we don't care. */
  long what = call->args[0];
  struct stat64* buf = (struct stat64*)call->args[1];

  /* Like open(), not arming the desched event because it's not
   * needed for correctness, and there are no data to suggest
   * whether it's a good idea perf-wise. */
  void* ptr = prep_syscall();
  struct stat64* buf2 = NULL;
  long ret;

  if (buf) {
    buf2 = ptr;
    ptr += sizeof(*buf2);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }
  ret = untraced_syscall2(syscallno, what, buf2);
  if (buf2) {
    local_memcpy(buf, buf2, sizeof(*buf));
  }
  return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_write(const struct syscall_info* call) {
  const int syscallno = SYS_write;
  int fd = call->args[0];
  const void* buf = (const void*)call->args[1];
  size_t count = call->args[2];

  void* ptr = prep_syscall_for_fd(fd);
  long ret;

  assert(syscallno == call->no);

  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall3(syscallno, fd, buf, count);

  return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_writev(const struct syscall_info* call) {
  int syscallno = SYS_writev;
  int fd = call->args[0];
  const struct iovec* iov = (const struct iovec*)call->args[1];
  unsigned long iovcnt = call->args[2];

  void* ptr = prep_syscall_for_fd(fd);
  long ret;

  assert(syscallno == call->no);

  if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
    return traced_raw_syscall(call);
  }

  ret = untraced_syscall3(syscallno, fd, iov, iovcnt);

  return commit_raw_syscall(syscallno, ptr, ret);
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
  if (buf2 && ret >= 0) {
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
  void* oldset2 = NULL;
  struct syscallbuf_hdr* hdr;
  kernel_sigset_t previous_set;

  void* ptr = prep_syscall();

  int how = (int)call->args[0];
  const kernel_sigset_t* set = (const kernel_sigset_t*)call->args[1];
  kernel_sigset_t* oldset = (kernel_sigset_t*)call->args[2];

  if (oldset) {
    oldset2 = ptr;
    ptr += sizeof(kernel_sigset_t);
  }
  if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
    return traced_raw_syscall(call);
  }

  if (set && (how == SIG_BLOCK || how == SIG_SETMASK)) {
    local_memcpy(&modified_set, set, sizeof(kernel_sigset_t));
    // SIGSTKFLT (PerfCounters::TIME_SLICE_SIGNAL) and
    // SIGPWR(SYSCALLBUF_DESCHED_SIGNAL) are used by rr
    modified_set &=
        ~(((uint64_t)1) << (SIGSTKFLT - 1)) & ~(((uint64_t)1) << (SIGPWR - 1));
    set = &modified_set;
  }

  hdr = buffer_hdr();
  previous_set = hdr->blocked_sigs;

  /* Update |blocked_sigs| now so that if the syscall succeeds and a blocked
   * signal is raised before it returns, rr sees the updated signal mask.
   */
  if (set) {
    switch (how) {
      case SIG_UNBLOCK:
        hdr->blocked_sigs &= ~*set;
        break;
      case SIG_BLOCK:
        hdr->blocked_sigs |= *set;
        break;
      case SIG_SETMASK:
        hdr->blocked_sigs = *set;
        break;
    }
  }

  ret = untraced_syscall4(syscallno, how, set, oldset2, call->args[3]);
  if (ret == 0) {
    if (oldset2) {
      local_memcpy(oldset, oldset2, sizeof(kernel_sigset_t));
    }
  } else {
    /* Ssyscall failed; don't update |blocked_sigs|! */
    hdr->blocked_sigs = previous_set;
  }

  return commit_raw_syscall(syscallno, ptr, ret);
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
    CASE_GENERIC_NONBLOCKING(access);
    CASE(clock_gettime);
    CASE_GENERIC_NONBLOCKING_FD(close);
    CASE(creat);
    CASE_GENERIC_NONBLOCKING(fchmod);
    CASE_GENERIC_NONBLOCKING_FD(fadvise64);
#if defined(SYS_fcntl64)
    CASE(fcntl64);
#else
    CASE(fcntl);
#endif
    CASE(rt_sigprocmask);
    CASE(fgetxattr);
    CASE(flistxattr);
    CASE_GENERIC_NONBLOCKING_FD(fsetxattr);
    CASE(futex);
    CASE(getdents);
    CASE(getdents64);
    CASE_GENERIC_NONBLOCKING(geteuid);
    CASE_GENERIC_NONBLOCKING(getpid);
    CASE(getrusage);
    CASE_GENERIC_NONBLOCKING(gettid);
    CASE(gettimeofday);
    CASE(getxattr);
    CASE(ioctl);
    CASE_GENERIC_NONBLOCKING(lchown);
    CASE(lgetxattr);
    CASE(listxattr);
    CASE(llistxattr);
#if defined(SYS__llseek)
    CASE(_llseek);
#endif
    CASE_GENERIC_NONBLOCKING_FD(lseek);
    CASE(madvise);
    CASE_GENERIC_NONBLOCKING(mkdir);
    CASE_GENERIC_NONBLOCKING(mknod);
    CASE(mprotect);
    CASE(open);
    CASE(poll);
    CASE(read);
    CASE(readlink);
#if defined(SYS_recvfrom)
    CASE(recvfrom);
#endif
#if defined(SYS_recvmsg)
    CASE(recvmsg);
#endif
#if defined(SYS_sendmsg)
    CASE(sendmsg);
#endif
    CASE_GENERIC_NONBLOCKING(setxattr);
#if defined(SYS_socketcall)
    CASE(socketcall);
#endif
#if defined(SYS_socketpair)
    CASE(socketpair);
#endif
    CASE_GENERIC_NONBLOCKING(symlink);
    CASE(time);
    CASE_GENERIC_NONBLOCKING_FD(utimensat);
    CASE(write);
    CASE(writev);
#undef CASE
#if defined(SYS_fstat64)
    case SYS_fstat64:
#else
    case SYS_fstat:
#endif
#if defined(SYS_lstat64)
    case SYS_lstat64:
#else
    case SYS_lstat:
#endif
#if defined(SYS_stat64)
    case SYS_stat64:
#else
    case SYS_stat:
#endif
      return sys_xstat64(call);
    default:
      return traced_raw_syscall(call);
  }
}

/* Explicitly declare this as hidden so we can call it from
 * _syscall_hook_trampoline without doing all sorts of special PIC handling.
 */
RR_HIDDEN long syscall_hook(const struct syscall_info* call) {
  // Initialize thread-local state if this is the first syscall for this
  // thread.
  init_thread();

  long result = syscall_hook_internal(call);
  if (buffer_hdr() && buffer_hdr()->notify_on_syscall_hook_exit) {
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
    //
    // Another crazy thing is going on here: it's possible that a signal
    // intended to be delivered
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
  return result;
}

/**
 * Exported glibc synonym for |sysconf()|.  We can't use |dlsym()| to
 * resolve the next "sysconf" symbol, because
 *  - dlysym usually calls malloc()
 *  - custom allocators like jemalloc may use sysconf()
 *  - if our sysconf wrapper is re-entered during initialization, it
 *    has nothing to fall back on to get the conf name, and chaos will
 *    likely ensue if we return something random.
 */
long __sysconf(int name);

/**
 *  Pretend that only 1 processor is configured/online, because rr
 *  binds all tracees to one logical CPU.
 */
long sysconf(int name) {
  switch (name) {
    case _SC_NPROCESSORS_ONLN:
    case _SC_NPROCESSORS_CONF:
      return globals.pretend_num_cores ? globals.pretend_num_cores : 1;
  }
  return __sysconf(name);
}

/** Disable XShm since rr doesn't work with it */
int XShmQueryExtension(__attribute__((unused)) void* dpy) { return 0; }

/** Make sure XShmCreateImage returns null in case an application doesn't do
    extension checks first. */
void* XShmCreateImage(__attribute__((unused)) register void* dpy,
                      __attribute__((unused)) register void* visual,
                      __attribute__((unused)) unsigned int depth,
                      __attribute__((unused)) int format,
                      __attribute__((unused)) char* data,
                      __attribute__((unused)) void* shminfo,
                      __attribute__((unused)) unsigned int width,
                      __attribute__((unused)) unsigned int height) {
  return 0;
}

/**
 * This is for testing purposes only.
 */
void very_slow_exit_syscall(void) {
  int i;
  int result = 0;
  struct syscall_info info;
  for (i = 0; i < 1000000; ++i) {
    result += i * i;
  }
  info.no = SYS_exit;
  info.args[0] = result;
  syscall_hook(&info);
}

/**
 * glibc geteuid() can be compiled to instructions ending in "syscall; ret"
 * which can't be hooked. So override it here and call the hook directly.
 */
uid_t geteuid(void) {
  struct syscall_info call = { SYS_geteuid, { 0, 0, 0, 0, 0, 0 } };
  return syscall_hook(&call);
}

typedef void* (*fopen_ptr)(const char* filename, const char* mode);

static void random_device_init_helper(void* this) {
  void** file_ptr = (void**)this;
  void* f_ptr = dlsym(RTLD_DEFAULT, "fopen");
  fopen_ptr fopen = (fopen_ptr)f_ptr;
  *file_ptr = fopen("/dev/urandom", "rb");
}

/**
 * libstdc++3 uses RDRAND. Bypass that with this incredible hack.
 */
void _ZNSt13random_device7_M_initERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE(
    void* this, __attribute__((unused)) void* token) {
  random_device_init_helper(this);
}

/**
 * gcc 4.8.4 in Ubuntu 14.04-32
 */
void _ZNSt13random_device7_M_initERKSs(void* this,
                                       __attribute__((unused)) void* token) {
  random_device_init_helper(this);
}
