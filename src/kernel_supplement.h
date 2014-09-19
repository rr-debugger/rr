/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_KERNEL_SUPPLEMENT_H_
#define RR_KERNEL_SUPPLEMENT_H_

#include <sys/ptrace.h>

/* Definitions that should be part of system headers (and maybe are on some but
 * not all systems).
 * This should not contain anything for which rr needs all the definitions
 * across architectures; those definitions belong in kernel_abi.h.
 */

#define PTRACE_EVENT_NONE 0
#define PTRACE_EVENT_STOP 128

#define PTRACE_SYSEMU 31
#define PTRACE_SYSEMU_SINGLESTEP 32

#ifndef PTRACE_O_TRACESECCOMP
#define PTRACE_O_TRACESECCOMP 0x00000080
#define PTRACE_EVENT_SECCOMP_OBSOLETE 8 // ubuntu 12.04
#define PTRACE_EVENT_SECCOMP 7          // ubuntu 12.10 and future kernels
#endif

// These are defined by the include/linux/errno.h in the kernel tree.
// Since userspace doesn't see these errnos in normal operation, that
// header apparently isn't distributed with libc.
#define ERESTARTSYS 512
#define ERESTARTNOINTR 513
#define ERESTARTNOHAND 514
#define ERESTART_RESTARTBLOCK 516

/* (There are various GNU and BSD extensions that define this, but
 * it's not worth the bother to sort those out.) */
typedef void (*sig_handler_t)(int);

/* We need to complement sigsets in order to update the Task blocked
 * set, but POSIX doesn't appear to define a convenient helper.  So we
 * define our own linux-compatible sig_set_t and use bit operators to
 * manipulate sigsets. */
typedef uint64_t sig_set_t;
static_assert(_NSIG / 8 == sizeof(sig_set_t), "Update sig_set_t for _NSIG.");

/**
 * The kernel SYS_sigaction ABI is different from the libc API; this
 * is the kernel layout.  We see these at SYS_sigaction traps.
 */
struct kernel_sigaction {
  sig_handler_t k_sa_handler;
  unsigned long sa_flags;
  void (*sa_restorer)(void);
  sigset_t sa_mask;
};

#endif /* RR_KERNEL_SUPPLEMENT_H_ */
