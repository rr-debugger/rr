/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PRELOAD_INTERFACE_H_
#define RR_PRELOAD_INTERFACE_H_

/* Bump this whenever the interface between syscallbuf and rr changes in a way
 * that would require changes to replay. So be very careful making changes to
 * this file! Many changes would require a bump in this value, and support
 * code in rr to handle old protocol versions. And when we bump it we'll need
 * to figure out a way to test the old protocol versions.
 * To be clear, changes that only affect recording and not replay, such as
 * changes to the layout of syscall_patch_hook, do not need to bump this.
 * Note also that SYSCALLBUF_PROTOCOL_VERSION is stored in the trace header, so
 * replay always has access to the SYSCALLBUF_PROTOCOL_VERSION used during
 * recording, even before the preload library is ever loaded.
 *
 * Version 0: initial rr 5.0.0 release
 */
#define SYSCALLBUF_PROTOCOL_VERSION 0

#ifdef RR_IMPLEMENT_PRELOAD
/* Avoid using <string.h> library functions */
static inline int streq(const char* s1, const char* s2) {
  while (1) {
    if (*s1 != *s2) {
      return 0;
    }
    if (!*s1) {
      return 1;
    }
    ++s1;
    ++s2;
  }
  return 1;
}
static inline size_t rrstrlen(const char* s) {
  size_t ret = 0;
  while (*s) {
    ++s;
    ++ret;
  }
  return ret;
}
#else
#include <string.h>
static inline int streq(const char* s1, const char* s2) {
  return !strcmp(s1, s2);
}
static inline size_t rrstrlen(const char* s) { return strlen(s); }
#include "../remote_ptr.h"
#endif

#include <signal.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/user.h>

static inline int strprefix(const char* s1, const char* s2) {
  while (1) {
    if (!*s1) {
      return 1;
    }
    if (*s1 != *s2) {
      return 0;
    }
    ++s1;
    ++s2;
  }
  return 1;
}

static inline const char* extract_file_name(const char* s) {
  const char* ret = s;
  while (*s) {
    if (*s == '/') {
      ret = s + 1;
    }
    ++s;
  }
  return ret;
}

/* This header file is included by preload.c and various rr .cc files. It
 * defines the interface between the preload library and rr. preload.c
 * #defines RR_IMPLEMENT_PRELOAD to let us handle situations where rr and
 * preload.c need to see slightly different definitions of the same constructs.
 *
 * preload.c compiles this as C code. All rr modules compile this as C++ code.
 * We do not use 'extern "C"' because we don't actually link between C and C++
 * and 'extern "C"' is not compatible with our use of templates below.
 */

#define SYSCALLBUF_LIB_FILENAME_BASE "librrpreload"
#define SYSCALLBUF_LIB_FILENAME SYSCALLBUF_LIB_FILENAME_BASE ".so"
#define SYSCALLBUF_LIB_FILENAME_PADDED SYSCALLBUF_LIB_FILENAME_BASE ".so:::"
#define SYSCALLBUF_LIB_FILENAME_32 SYSCALLBUF_LIB_FILENAME_BASE "_32.so"

/* This is pretty arbitrary. On Linux SIGPWR is sent to PID 1 (init) on
 * power failure, and it's unlikely rr will be recording that.
 * Note that SIGUNUSED means SIGSYS which actually *is* used (by seccomp),
 * so we can't use it. */
#define SYSCALLBUF_DESCHED_SIGNAL SIGPWR

/* Set this env var to enable syscall buffering. */
#define SYSCALLBUF_ENABLED_ENV_VAR "_RR_USE_SYSCALLBUF"

/* Size of table mapping fd numbers to syscallbuf-disabled flag.
 * Most Linux kernels limit fds to 1024 so it probably doesn't make sense
 * to raise this value... */
#define SYSCALLBUF_FDS_DISABLED_SIZE 1024

#define MPROTECT_RECORD_COUNT 1000

/* Must match generate_rr_page.py */
#define RR_PAGE_ADDR 0x70000000
#define RR_PAGE_SYSCALL_STUB_SIZE 3
#define RR_PAGE_SYSCALL_INSTRUCTION_END 2
#define RR_PAGE_SYSCALL_ADDR(index)                                            \
  ((void*)(RR_PAGE_ADDR + RR_PAGE_SYSCALL_STUB_SIZE * (index)))
#define RR_PAGE_SYSCALL_TRACED RR_PAGE_SYSCALL_ADDR(0)
#define RR_PAGE_SYSCALL_PRIVILEGED_TRACED RR_PAGE_SYSCALL_ADDR(1)
#define RR_PAGE_SYSCALL_UNTRACED RR_PAGE_SYSCALL_ADDR(2)
#define RR_PAGE_SYSCALL_UNTRACED_REPLAY_ONLY RR_PAGE_SYSCALL_ADDR(3)
#define RR_PAGE_SYSCALL_UNTRACED_RECORDING_ONLY RR_PAGE_SYSCALL_ADDR(4)
#define RR_PAGE_SYSCALL_PRIVILEGED_UNTRACED RR_PAGE_SYSCALL_ADDR(5)
#define RR_PAGE_SYSCALL_PRIVILEGED_UNTRACED_REPLAY_ONLY RR_PAGE_SYSCALL_ADDR(6)
#define RR_PAGE_SYSCALL_PRIVILEGED_UNTRACED_RECORDING_ONLY                     \
  RR_PAGE_SYSCALL_ADDR(7)
#define RR_PAGE_FF_BYTES (RR_PAGE_ADDR + RR_PAGE_SYSCALL_STUB_SIZE * 8)

/* PRELOAD_THREAD_LOCALS_ADDR should not change.
 * Tools depend on this address. */
#define PRELOAD_THREAD_LOCALS_ADDR (RR_PAGE_ADDR + PAGE_SIZE)
#define PRELOAD_THREAD_LOCALS_SIZE 104

/* "Magic" (rr-implemented) syscalls that we use to initialize the
 * syscallbuf.
 *
 * NB: magic syscalls must be positive, because with at least linux
 * 3.8.0 / eglibc 2.17, rr only gets a trap for the *entry* of invalid
 * syscalls, not the exit.  rr can't handle that yet. */
/* TODO: static_assert(LAST_SYSCALL < SYS_rrcall_init_buffers) */

/**
 * The preload library calls SYS_rrcall_init_preload during its
 * initialization.
 */
#define SYS_rrcall_init_preload 442
/**
 * The preload library calls SYS_rrcall_init_buffers in each thread that
 * gets created (including the initial main thread).
 */
#define SYS_rrcall_init_buffers 443
/**
 * The preload library calls SYS_rrcall_notify_syscall_hook_exit when
 * unlocking the syscallbuf and notify_after_syscall_hook_exit has been set.
 * The word at 4/8(sp) is returned in the syscall result and the word at
 * 8/16(sp) is stored in original_syscallno.
 */
#define SYS_rrcall_notify_syscall_hook_exit 444
/**
 * When the preload library detects that control data has been received in a
 * syscallbuf'ed recvmsg, it calls this syscall with a pointer to the
 * 'struct msg' returned.
 */
#define SYS_rrcall_notify_control_msg 445
/**
 * When rr replay has restored the auxv vectors for a new process (completing
 * emulation of exec), it calls this syscall. It takes one parameter, the tid
 * of the task that it has restored auxv vectors for.
 */
#define SYS_rrcall_reload_auxv 446
/**
 * When rr replay has flushed a syscallbuf 'mprotect' record, notify any outer
 * rr of that flush. The first parameter is the tid of the task, the second
 * parameter is the address, the third parameter is the length, and the
 * fourth parameter is the prot.
 */
#define SYS_rrcall_mprotect_record 447

/* Define macros that let us compile a struct definition either "natively"
 * (when included by preload.c) or as a template over Arch for use by rr.
 */
#ifdef RR_IMPLEMENT_PRELOAD
#define TEMPLATE_ARCH
#define PTR(T) T*
#define PTR_ARCH(T) T*
#define VOLATILE volatile
#define SIGNED_LONG long
#else
#define TEMPLATE_ARCH template <typename Arch>
#define PTR(T) typename Arch::template ptr<T>
#define PTR_ARCH(T) typename Arch::template ptr<T<Arch>>
#define VOLATILE
#define SIGNED_LONG typename Arch::signed_long
#endif

/**
 * To support syscall buffering, we replace syscall instructions with a "call"
 * instruction that calls a hook in the preload library to handle the syscall.
 * Since the call instruction takes more space than the syscall instruction,
 * the patch replaces one or more instructions after the syscall instruction as
 * well; those instructions are folded into the tail of the hook function
 * and we have multiple hook functions, each one corresponding to an
 * instruction that follows a syscall instruction.
 * Each instance of this struct describes an instruction that can follow a
 * syscall and a hook function to patch with.
 *
 * This is not (and must not ever be) used during replay so we can change it
 * without bumping SYSCALLBUF_PROTOCOL_VERSION.
 */
struct syscall_patch_hook {
  uint8_t is_multi_instruction;
  uint8_t next_instruction_length;
  /* Avoid any padding or anything that would make the layout arch-specific. */
  uint8_t next_instruction_bytes[14];
  uint64_t hook_address;
};

/**
 * We buffer mprotect syscalls. Their effects need to be noted so we can
 * update AddressSpace's cache of memory layout, which stores prot bits. So,
 * the preload code builds a list of mprotect_records corresponding to the
 * mprotect syscalls that have been buffered. This list is read by rr whenever
 * we flush the syscallbuf, and its effects performed. The actual mprotect
 * syscalls are performed during recording and replay.
 *
 * We simplify things by making this arch-independent.
 */
struct mprotect_record {
  uint64_t start;
  uint64_t size;
  int32_t prot;
  int32_t padding;
};

/**
 * Must be arch-independent.
 * Variables used to communicate between preload and rr.
 * We package these up into a single struct to simplify the preload/rr
 * interface.
 * You can add to the end of this struct without breaking trace compatibility,
 * but don't move existing fields. Do not write to it during replay except for
 * the 'in_replay' field. Be careful reading fields during replay as noted
 * below, since they don't all exist in all trace versions.
 */
struct preload_globals {
  /* 0 during recording, 1 during replay. Set by rr.
   * This MUST NOT be used in conditional branches. It should only be used
   * as the condition for conditional moves so that control flow during replay
   * does not diverge from control flow during recording.
   * We also have to be careful that values different between record and replay
   * don't accidentally leak into other memory locations or registers.
   * USE WITH CAUTION.
   */
  unsigned char in_replay;
  /* 0 during recording and replay, 1 during diversion. Set by rr.
   */
  unsigned char in_diversion;
  /* 1 if chaos mode is enabled. DO NOT READ from rr during replay, because
     this field is not initialized in old traces. */
  unsigned char in_chaos;
  /* Padding, currently unused; can be used later. */
  unsigned char padding;
  /* Number of cores to pretend we have. 0 means 1. rr sets this when
   * the preload library is initialized. */
  int pretend_num_cores;
  /**
   * Set by rr.
   * If syscallbuf_fds_disabled[fd] is nonzero, then operations on that fd
   * must be performed through traced syscalls, not the syscallbuf.
   * The rr supervisor modifies this array directly to dynamically turn
   * syscallbuf on and off for particular fds. fds outside the array range must
   * never use the syscallbuf.
   */
  VOLATILE char syscallbuf_fds_disabled[SYSCALLBUF_FDS_DISABLED_SIZE];
  /* mprotect records. Set by preload. */
  struct mprotect_record mprotect_records[MPROTECT_RECORD_COUNT];
  /* Random seed that can be used for various purposes. DO NOT READ from rr
     during replay, because this field does not exist in old traces. */
  uint64_t random_seed;
};

/**
 * Represents syscall params.  Makes it simpler to pass them around,
 * and avoids pushing/popping all the data for calls.
 */
TEMPLATE_ARCH
struct syscall_info {
  SIGNED_LONG no;
  SIGNED_LONG args[6];
};

/**
 * Can be architecture dependent. The rr process does not manipulate
 * these except to save and restore the values on task switches so that
 * the values are always effectively local to the current task. rr also
 * sets the |syscallbuf_stub_alt_stack| field.
 * We use this instead of regular libc TLS because sometimes buggy application
 * code breaks libc TLS for some tasks. With this approach we can be sure
 * thread-locals are usable for any task in any state.
 */
TEMPLATE_ARCH
struct preload_thread_locals {
  /* The offset of this field MUST NOT CHANGE, it is part of the preload ABI
   * rr depends on.
   * Offset of this field is hardcoded in syscall_hook.S and
   * assembly_templates.py.
   * Pointer to alt-stack used by syscallbuf stubs (allocated at the end of
   * the scratch buffer.
   */
  PTR(void) syscallbuf_stub_alt_stack;
  /* The offset of this field MUST NOT CHANGE, it is part of the preload ABI
   * tools can depend on.
   * Where syscall result will be (or during replay, has been) saved.
   */
  PTR(int64_t) pending_untraced_syscall_result;
  /* The offset of this field MUST NOT CHANGE, it is part of the preload ABI
   * rr depends on.
   * Scratch space used by stub code.
   */
  PTR(void) stub_scratch_1;
  /* The offset of this field MUST NOT CHANGE, it is part of the preload ABI
   * rr depends on.
   */
  int alt_stack_nesting_level;
  /**
   * We could use this later.
   */
  int unused_padding;
  /* The offset of this field MUST NOT CHANGE, it is part of the preload ABI
   * rr depends on. It contains the parameters to the patched syscall, or
   * zero if we're not processing a buffered syscall. Do not depend on this
   * existing during replay, some traces with SYSCALLBUF_PROTOCOL_VERSION 0
   * don't have it.
   */
  PTR_ARCH(const struct syscall_info) original_syscall_parameters;

  /* Nonzero when thread-local state like the syscallbuf has been
   * initialized.  */
  int thread_inited;
  /* The offset of this field MUST NOT CHANGE, it is part of the ABI tools
   * depend on. When buffering is enabled, points at the thread's mapped buffer
   * segment.  At the start of the segment is an object of type |struct
   * syscallbuf_hdr|, so |buffer| is also a pointer to the buffer
   * header. */
  PTR(uint8_t) buffer;
  size_t buffer_size;
  /* This is used to support the buffering of "may-block" system calls.
   * The problem that needs to be addressed can be introduced with a
   * simple example; assume that we're buffering the "read" and "write"
   * syscalls.
   *
   *  o (Tasks W and R set up a synchronous-IO pipe open between them; W
   *    "owns" the write end of the pipe; R owns the read end; the pipe
   *    buffer is full)
   *  o Task W invokes the write syscall on the pipe
   *  o Since write is a buffered syscall, the seccomp filter traps W
   *    directly to the kernel; there's no trace event for W delivered
   *    to rr.
   *  o The pipe is full, so W is descheduled by the kernel because W
   *    can't make progress.
   *  o rr thinks W is still running and doesn't schedule R.
   *
   * At this point, progress in the recorded application can only be
   * made by scheduling R, but no one tells rr to do that.  Oops!
   *
   * Thus enter the "desched counter".  It's a perf_event for the "sw t
   * switches" event (which, more precisely, is "sw deschedule"; it
   * counts schedule-out, not schedule-in).  We program the counter to
   * deliver a signal to this task when there's new counter data
   * available.  And we set up the "sample period", how many descheds
   * are triggered before the signal is delivered, to be "1".  This
   * means that when the counter is armed, the next desched (i.e., the
   * next time the desched counter is bumped up) of this task will
   * deliver the signal to it.  And signal delivery always generates a
   * ptrace trap, so rr can deduce that this task was descheduled and
   * schedule another.
   *
   * The description above is sort of an idealized view; there are
   * numerous implementation details that are documented in
   * handle_signal.c, where they're dealt with. */
  int desched_counter_fd;
  int cloned_file_data_fd;
  off_t cloned_file_data_offset;
  PTR(void) scratch_buf;
  size_t scratch_size;

  PTR(struct msghdr) notify_control_msg;
};

/**
 * Packs up the parameters passed to |SYS_rrcall_init_preload|.
 * We use this struct because it's a little cleaner.
 */
TEMPLATE_ARCH
struct rrcall_init_preload_params {
  /* All "In" params. */
  /* The syscallbuf lib's idea of whether buffering is enabled.
   * We let the syscallbuf code decide in order to more simply
   * replay the same decision that was recorded. */
  int syscallbuf_enabled;
  int syscall_patch_hook_count;
  PTR(struct syscall_patch_hook) syscall_patch_hooks;
  PTR(void) syscallhook_vsyscall_entry;
  PTR(void) syscallbuf_code_start;
  PTR(void) syscallbuf_code_end;
  PTR(void) get_pc_thunks_start;
  PTR(void) get_pc_thunks_end;
  PTR(void) syscallbuf_final_exit_instruction;
  PTR(struct preload_globals) globals;
  /* Address of the first entry of the breakpoint table.
   * After processing a sycallbuf record (and unlocking the syscallbuf),
   * we call a function in this table corresponding to the record processed.
   * rr can set a breakpoint in this table to break on the completion of a
   * particular syscallbuf record. */
  PTR(void) breakpoint_table;
  int breakpoint_table_entry_size;
};

/**
 * Packs up the inout parameters passed to |SYS_rrcall_init_buffers|.
 * We use this struct because there are too many params to pass
 * through registers on at least x86.  (It's also a little cleaner.)
 */
TEMPLATE_ARCH
struct rrcall_init_buffers_params {
  /* The fd we're using to track desched events. */
  int desched_counter_fd;
  /* "Out" params. */
  int cloned_file_data_fd;
  /* Returned pointer to and size of the shared syscallbuf
   * segment. */
  PTR(void) syscallbuf_ptr;
  /* Returned pointer to rr's syscall scratch buffer */
  PTR(void) scratch_buf;
  uint32_t syscallbuf_size;
  uint32_t scratch_size;
};

/**
 * The syscall buffer comprises an array of these variable-length
 * records, along with the header below.
 */
struct syscallbuf_record {
  /* Return value from the syscall.  This can be a memory
   * address, so must be as big as a memory address can be.
   * We use 64 bits rather than make syscallbuf_record Arch-specific as that
   * gets cumbersome.
   */
  int64_t ret;
  /* Syscall number.
   *
   * NB: the x86 linux ABI has 350 syscalls as of 3.9.6 and
   * x86-64 defines 313, so this is a pretty safe storage
   * allocation.  It would be an earth-shattering event if the
   * syscall surface were doubled in a short period of time, and
   * even then we would have a comfortable cushion.  Still,
   *
   * TODO: static_assert this can hold largest syscall num */
  uint16_t syscallno;
  /* Did the tracee arm/disarm the desched notification for this
   * syscall? */
  uint8_t desched;
  uint8_t _padding;
  /* Size of entire record in bytes: this struct plus extra
   * recorded data stored inline after the last field, not
   * including padding.
   *
   * TODO: static_assert this can repr >= buffer size */
  uint32_t size;
  /* Extra recorded outparam data starts here. */
  uint8_t extra_data[0];
};

/**
 * This struct summarizes the state of the syscall buffer.  It happens
 * to be located at the start of the buffer.
 */
struct syscallbuf_hdr {
  /* The number of valid syscallbuf_record bytes in the buffer,
   * not counting this header.
   * Make this volatile so that memory writes aren't reordered around
   * updates to this field. */
  volatile uint32_t num_rec_bytes;
  /* Number of mprotect calls since last syscallbuf flush. The last record in
   * the list may not have been applied yet.
   */
  volatile uint32_t mprotect_record_count;
  /* Number of records whose syscalls have definitely completed.
   * May be one less than mprotect_record_count.
   */
  volatile uint32_t mprotect_record_count_completed;
  /* True if the current syscall should not be committed to the
   * buffer, for whatever reason; likely interrupted by
   * desched. Set by rr. */
  volatile uint8_t abort_commit;
  /* True if, next time we exit the syscall buffer hook, libpreload should
   * execute SYS_rrcall_notify_syscall_hook_exit to give rr the opportunity to
   * deliver a signal and/or reset the syscallbuf. */
  volatile uint8_t notify_on_syscall_hook_exit;
  /* This tracks whether the buffer is currently in use for a
   * system call or otherwise unavailable. This is helpful when
   * a signal handler runs during a wrapped system call; we don't want
   * it to use the buffer for its system calls. The different reasons why the
   * buffer could be locked, use different bits of this field and the buffer
   * may be used only if all are clear. See enum syscallbuf_locked_why for
   * used bits.
   */
  volatile uint8_t locked;
  /* Nonzero when rr needs to worry about the desched signal.
   * When it's zero, the desched signal can safely be
   * discarded. */
  volatile uint8_t desched_signal_may_be_relevant;
  /* A copy of the tasks's signal mask. Updated by preload when a buffered
   * rt_sigprocmask executes.
   */
  volatile uint64_t blocked_sigs;
  /* Incremented by preload every time a buffered rt_sigprocmask executes.
   * Cleared during syscallbuf reset.
   */
  volatile uint32_t blocked_sigs_generation;
  /* Nonzero when preload is in the process of calling an untraced
   * sigprocmask; the real sigprocmask may or may not match blocked_sigs.
   */
  volatile uint8_t in_sigprocmask_critical_section;
  /* Nonzero when the syscall was aborted during preparation without doing
   * anything */
  volatile uint8_t failed_during_preparation;

  struct syscallbuf_record recs[0];
} __attribute__((__packed__));
/* TODO: static_assert(sizeof(uint32_t) ==
 *                     sizeof(struct syscallbuf_hdr)) */

/**
 * Each bit of of syscallbuf_hdr->locked indicates a reason why the syscallbuf
 * is locked. These are all the bits that are currently defined.
 */
enum syscallbuf_locked_why {
  /* Used by the tracee, during interruptible syscalls to avoid recursion */
  SYSCALLBUF_LOCKED_TRACEE = 0x1,
  /* Used by the tracer to prevent syscall buffering when necessary to preserve
     semantics (e.g. for ptracees whose syscalls are being observed) */
  SYSCALLBUF_LOCKED_TRACER = 0x2
};

/**
 * Return a pointer to what may be the next syscall record.
 *
 * THIS POINTER IS NOT GUARANTEED TO BE VALID!!!  Caveat emptor.
 */
inline static struct syscallbuf_record* next_record(
    struct syscallbuf_hdr* hdr) {
  uintptr_t next = (uintptr_t)hdr->recs + hdr->num_rec_bytes;
  return (struct syscallbuf_record*)next;
}

/**
 * Return the amount of space that a record of |length| will occupy in
 * the buffer if committed, including padding.
 */
inline static long stored_record_size(size_t length) {
  /* Round up to a whole number of 64-bit words. */
  return (length + 7) & ~7;
}

/**
 * Return nonzero if an attempted open() of |filename| should be
 * blocked.
 *
 * The background of this hack is that rr doesn't support DRI/DRM
 * currently, so we use the blunt stick of refusing to open this
 * interface file as a way of disabling it entirely.  (In addition to
 * tickling xorg.conf, which doesn't entirely do the trick.)  It's
 * known how to fix this particular, so let's not let this hack grow
 * too much by piling on.
 */
inline static int is_blacklisted_filename(const char* filename) {
  const char* f;
  if (strprefix("/dev/dri/", filename) || streq("/dev/nvidiactl", filename) ||
      streq("/usr/share/alsa/alsa.conf", filename)) {
    return 1;
  }
  f = extract_file_name(filename);
  return strprefix("rr-test-blacklist-file_name", f) ||
         strprefix("pulse-shm-", f);
}

inline static int is_blacklisted_memfd(const char* name) {
  return streq("pulseaudio", name);
}

inline static int is_blacklisted_socket(const char* filename) {
  /* Blacklist the nscd socket because glibc communicates with the daemon over
   * shared memory rr can't handle.
   */
  return streq("/var/run/nscd/socket", filename);
}

inline static int is_gcrypt_deny_file(const char* filename) {
  return streq("/etc/gcrypt/hwf.deny", filename);
}

inline static int is_terminal(const char* filename) {
  return strprefix("/dev/tty", filename) || strprefix("/dev/pts", filename);
}

inline static int is_proc_mem_file(const char* filename) {
  if (!strprefix("/proc/", filename)) {
    return 0;
  }
  return streq(filename + rrstrlen(filename) - 4, "/mem");
}

inline static int is_proc_fd_dir(const char* filename) {
  if (!strprefix("/proc/", filename)) {
    return 0;
  }

  int len = rrstrlen(filename);
  const char* fd_bit = filename + len;
  if (*fd_bit == '/') {
    fd_bit--;
  }

  return strprefix("/fd", fd_bit - 3);
}

/**
 * Returns nonzero if an attempted open() of |filename| can be syscall-buffered.
 * When this returns zero, the open must be forwarded to the rr process.
 * This is imperfect because it doesn't handle symbolic links, hard links,
 * files accessed with non-absolute paths, /proc mounted in differnet places,
 * etc etc etc. Handling those efficiently (no additional syscalls in
 * common cases) is a problem. Maybe we could afford fstat after every open...
 */
inline static int allow_buffered_open(const char* filename) {
  return !is_blacklisted_filename(filename) && !is_gcrypt_deny_file(filename) &&
         !is_terminal(filename) && !is_proc_mem_file(filename) &&
         !is_proc_fd_dir(filename);
}

#endif /* RR_PRELOAD_INTERFACE_H_ */
