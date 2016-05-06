/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PRELOAD_INTERFACE_H_
#define RR_PRELOAD_INTERFACE_H_

#include <signal.h>
#include <stdint.h>
#include <string.h>

#ifndef RR_IMPLEMENT_PRELOAD
#include "../remote_ptr.h"
#endif

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

/* Define macros that let us compile a struct definition either "natively"
 * (when included by preload.c) or as a template over Arch for use by rr.
 */
#ifdef RR_IMPLEMENT_PRELOAD
#define TEMPLATE_ARCH
#define PTR(T) T *
#define VOLATILE volatile
#else
#define TEMPLATE_ARCH template <typename Arch>
#define PTR(T) typename Arch::template ptr<T>
#define VOLATILE
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
 */
struct syscall_patch_hook {
  uint8_t next_instruction_length;
  uint8_t next_instruction_bytes[6];
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
  /* 1 when thread-locals have been initialized for this task, 0 otherwise */
  unsigned char thread_locals_initialized;
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
  PTR(void) syscall_hook_trampoline;
  PTR(void) syscall_hook_end;
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
  uint8_t abort_commit;
  /* True if, next time we exit the syscall buffer hook, libpreload should
   * execute SYS_rrcall_notify_syscall_hook_exit to give rr the opportunity to
   * deliver a signal and/or reset the syscallbuf. */
  uint8_t notify_on_syscall_hook_exit;
  /* This tracks whether the buffer is currently in use for a
   * system call. This is helpful when a signal handler runs
   * during a wrapped system call; we don't want it to use the
   * buffer for its system calls. */
  uint8_t locked;
  /* Nonzero when rr needs to worry about the desched signal.
   * When it's zero, the desched signal can safely be
   * discarded. */
  uint8_t desched_signal_may_be_relevant;

  struct syscallbuf_record recs[0];
} __attribute__((__packed__));
/* TODO: static_assert(sizeof(uint32_t) ==
 *                     sizeof(struct syscallbuf_hdr)) */

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
  return !strncmp("/dev/dri/", filename, 9) ||
         !strcmp("/dev/nvidiactl", filename) ||
         !strcmp("/usr/share/alsa/alsa.conf", filename);
}

inline static int is_dev_tty(const char* filename) {
  return !strcmp("/dev/tty", filename);
}

inline static int is_proc_mem_file(const char* filename) {
  if (strncmp("/proc/", filename, 6)) {
    return 0;
  }
  return !strcmp(filename + strlen(filename) - 4, "/mem");
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
  return !is_blacklisted_filename(filename) && !is_dev_tty(filename) &&
         !is_proc_mem_file(filename);
}

#endif /* RR_PRELOAD_INTERFACE_H_ */
