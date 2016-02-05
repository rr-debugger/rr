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

/* This size counts the header along with record data. */
#define SYSCALLBUF_BUFFER_SIZE (1 << 20)

/* Set this env var to enable syscall buffering. */
#define SYSCALLBUF_ENABLED_ENV_VAR "_RR_USE_SYSCALLBUF"

/* Size of table mapping fd numbers to syscallbuf-disabled flag.
 * Most Linux kernels limit fds to 1024 so it probably doesn't make sense
 * to raise this value... */
#define SYSCALLBUF_FDS_DISABLED_SIZE 1024

#define RR_PAGE_ADDR 0x70000000
#define RR_PAGE_SYSCALL_STUB_SIZE 3
#define RR_PAGE_SYSCALL_INSTRUCTION_END 2
#define RR_PAGE_IN_TRACED_SYSCALL_ADDR                                         \
  (RR_PAGE_ADDR + RR_PAGE_SYSCALL_INSTRUCTION_END)
#define RR_PAGE_IN_PRIVILEGED_TRACED_SYSCALL_ADDR                              \
  (RR_PAGE_ADDR + RR_PAGE_SYSCALL_STUB_SIZE + RR_PAGE_SYSCALL_INSTRUCTION_END)
#define RR_PAGE_IN_UNTRACED_REPLAYED_SYSCALL_ADDR                              \
  (RR_PAGE_ADDR + RR_PAGE_SYSCALL_STUB_SIZE * 2 +                              \
   RR_PAGE_SYSCALL_INSTRUCTION_END)
#define RR_PAGE_IN_UNTRACED_SYSCALL_ADDR                                       \
  (RR_PAGE_ADDR + RR_PAGE_SYSCALL_STUB_SIZE * 3 +                              \
   RR_PAGE_SYSCALL_INSTRUCTION_END)
#define RR_PAGE_IN_PRIVILEGED_UNTRACED_SYSCALL_ADDR                            \
  (RR_PAGE_ADDR + RR_PAGE_SYSCALL_STUB_SIZE * 4 +                              \
   RR_PAGE_SYSCALL_INSTRUCTION_END)
#define RR_PAGE_FF_BYTES                                                       \
  (RR_PAGE_ADDR + RR_PAGE_SYSCALL_STUB_SIZE * 5 +                              \
   RR_PAGE_SYSCALL_INSTRUCTION_END)

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

/* Define macros that let us compile a struct definition either "natively"
 * (when included by preload.c) or as a template over Arch for use by rr.
 */
#ifdef RR_IMPLEMENT_PRELOAD
#define TEMPLATE_ARCH
#define PTR(T) T *
#else
#define TEMPLATE_ARCH template <typename Arch>
#define PTR(T) typename Arch::template ptr<T>
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
 * Packs up the parameters passed to |SYS_rrcall_init_preload|.
 * We use this struct because it's a little cleaner.
 */
TEMPLATE_ARCH
struct rrcall_init_preload_params {
  /* "In" params. */
  /* The syscallbuf lib's idea of whether buffering is enabled.
   * We let the syscallbuf code decide in order to more simply
   * replay the same decision that was recorded. */
  int syscallbuf_enabled;
  int syscall_patch_hook_count;
  PTR(struct syscall_patch_hook) syscall_patch_hooks;
  PTR(void) syscall_hook_trampoline;
  PTR(void) syscall_hook_stub_buffer;
  PTR(void) syscall_hook_stub_buffer_end;
  /* Array of size SYSCALLBUF_FDS_DISABLED_SIZE */
  PTR(volatile char) syscallbuf_fds_disabled;
  /* Address of the flag which is 0 during recording and 1 during replay. */
  PTR(unsigned char) in_replay_flag;
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
  /* padding for 64-bit archs. Structs written to tracee memory must not have
   * holes!
   */
  int padding;

  /* "Out" params. */
  /* Returned pointer to and size of the shared syscallbuf
   * segment. */
  PTR(void) syscallbuf_ptr;
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

#endif /* RR_PRELOAD_INTERFACE_H_ */
