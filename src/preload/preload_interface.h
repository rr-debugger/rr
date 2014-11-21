/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PRELOAD_INTERFACE_H_
#define RR_PRELOAD_INTERFACE_H_

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

/* This is pretty arbitrary; SIGSYS is unused by linux, and hopefully
 * normal applications don't use it either. */
#define SYSCALLBUF_DESCHED_SIGNAL SIGSYS

#define SYSCALLBUF_LIB_FILENAME "librrpreload.so"
/* This size counts the header along with record data. */
#define SYSCALLBUF_BUFFER_SIZE (1 << 20)

/* Set this env var to enable syscall buffering. */
#define SYSCALLBUF_ENABLED_ENV_VAR "_RR_USE_SYSCALLBUF"

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
#define SYS_rrcall_init_preload 443
/**
 * The preload library calls SYS_rrcall_init_buffers in each thread that
 * gets created (including the initial main thread).
 */
#define SYS_rrcall_init_buffers 442

/* Define macros that let us compile a struct definition either "natively"
 * (when included by preload.c) or as a template over Arch for use by rr.
 */
#ifdef RR_IMPLEMENT_PRELOAD
#define TEMPLATE_ARCH
#define PTR(T) T *
#else
#define TEMPLATE_ARCH template <typename Arch>
#define PTR(T) remote_ptr<T>
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
  uint8_t next_instruction_bytes[3];
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
  PTR(void) vsyscall_hook_trampoline;
  int syscall_patch_hook_count;
  PTR(struct syscall_patch_hook) syscall_patch_hooks;
};

/**
 * Packs up the inout parameters passed to |SYS_rrcall_init_buffers|.
 * We use this struct because there are too many params to pass
 * through registers on at least x86.  (It's also a little cleaner.)
 */
TEMPLATE_ARCH
struct rrcall_init_buffers_params {
  /* "In" params. */
  /* The syscallbuf lib's idea of whether buffering is enabled.
   * We let the syscallbuf code decide in order to more simply
   * replay the same decision that was recorded. */
  int syscallbuf_enabled;
  /* Where our traced syscalls will originate. */
  PTR(uint8_t) traced_syscall_ip;
  /* Where our untraced syscalls will originate. */
  PTR(uint8_t) untraced_syscall_ip;
  /* The fd we're using to track desched events. */
  int desched_counter_fd;

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
  uint32_t syscallno : 10;
  /* Did the tracee arm/disarm the desched notification for this
   * syscall? */
  uint32_t desched : 1;
  /* Size of entire record in bytes: this struct plus extra
   * recorded data stored inline after the last field, not
   * including padding.
   *
   * TODO: static_assert this can repr >= buffer size */
  uint32_t size : 21;
  /* Extra recorded outparam data starts here. */
  uint8_t extra_data[0];
} __attribute__((__packed__));

/**
 * This struct summarizes the state of the syscall buffer.  It happens
 * to be located at the start of the buffer.
 */
struct syscallbuf_hdr {
  /* The number of valid syscallbuf_record bytes in the buffer,
   * not counting this header. */
  uint32_t num_rec_bytes : 29;
  /* True if the current syscall should not be committed to the
   * buffer, for whatever reason; likely interrupted by
   * desched. */
  uint32_t abort_commit : 1;
  /* This tracks whether the buffer is currently in use for a
   * system call. This is helpful when a signal handler runs
   * during a wrapped system call; we don't want it to use the
   * buffer for its system calls. */
  uint32_t locked : 1;
  /* Nonzero when rr needs to worry about the desched signal.
   * When it's zero, the desched signal can safely be
   * discarded. */
  uint32_t desched_signal_may_be_relevant : 1;

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
  /* Round up to a whole number of 32-bit words. */
  return (length + sizeof(int) - 1) & ~(sizeof(int) - 1);
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
  return (!strcmp("/dev/dri/card0", filename) ||
          !strcmp("/dev/nvidiactl", filename) ||
          !strcmp("/usr/share/alsa/alsa.conf", filename));
}

#endif /* RR_PRELOAD_INTERFACE_H_ */
