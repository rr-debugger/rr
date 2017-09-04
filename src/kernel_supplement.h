/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_KERNEL_SUPPLEMENT_H_
#define RR_KERNEL_SUPPLEMENT_H_

#include <linux/if_tun.h>
#include <linux/mman.h>
#include <linux/seccomp.h>
#include <linux/usbdevice_fs.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>

namespace rr {

/* Definitions that should be part of system headers (and maybe are on some but
 * not all systems).
 * This should not contain anything for which rr needs all the definitions
 * across architectures; those definitions belong in kernel_abi.h.
 */

#ifndef PTRACE_EVENT_NONE
#define PTRACE_EVENT_NONE 0
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#ifndef PTRACE_OLDSETOPTIONS
#define PTRACE_OLDSETOPTIONS 21
#endif

#ifndef PTRACE_GET_THREAD_AREA
#define PTRACE_GET_THREAD_AREA 25
#endif

#ifndef PTRACE_SET_THREAD_AREA
#define PTRACE_SET_THREAD_AREA 26
#endif

#ifndef PTRACE_ARCH_PRCTL
#define PTRACE_ARCH_PRCTL 30
#endif

#ifndef PTRACE_SYSEMU
#define PTRACE_SYSEMU 31
#endif
#ifndef PTRACE_SYSEMU_SINGLESTEP
#define PTRACE_SYSEMU_SINGLESTEP 32
#endif

#ifndef PTRACE_GETSIGMASK
#define PTRACE_GETSIGMASK 0x420a
#endif

#ifndef PTRACE_SETSIGMASK
#define PTRACE_SETSIGMASK 0x420b
#endif

#ifndef PTRACE_O_TRACESECCOMP
#define PTRACE_O_TRACESECCOMP 0x00000080
#define PTRACE_EVENT_SECCOMP_OBSOLETE 8 // ubuntu 12.04
#define PTRACE_EVENT_SECCOMP 7          // ubuntu 12.10 and future kernels
#endif

#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL (1 << 20)
#endif

#ifndef SECCOMP_SET_MODE_STRICT
#define SECCOMP_SET_MODE_STRICT 0
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

// These are defined by the include/linux/errno.h in the kernel tree.
// Since userspace doesn't see these errnos in normal operation, that
// header apparently isn't distributed with libc.
#define ERESTARTSYS 512
#define ERESTARTNOINTR 513
#define ERESTARTNOHAND 514
#define ERESTART_RESTARTBLOCK 516

// These definitions haven't made it out to current libc-dev packages
// yet.
#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#define GRND_RANDOM 0x0002
#endif

/* We need to complement sigsets in order to update the Task blocked
 * set, but POSIX doesn't appear to define a convenient helper.  So we
 * define our own linux-compatible sig_set_t and use bit operators to
 * manipulate sigsets. */
typedef uint64_t sig_set_t;
static_assert(_NSIG / 8 == sizeof(sig_set_t), "Update sig_set_t for _NSIG.");

#ifndef BTRFS_IOCTL_MAGIC
#define BTRFS_IOCTL_MAGIC 0x94
#endif
#ifndef BTRFS_IOC_CLONE
#define BTRFS_IOC_CLONE _IOW(BTRFS_IOCTL_MAGIC, 9, int)
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

#ifndef USBDEVFS_GET_CAPABILITIES
#define USBDEVFS_GET_CAPABILITIES _IOR('U', 26, __u32)
#endif
#ifndef USBDEVFS_DISCONNECT_CLAIM
struct usbdevfs_disconnect_claim {
  unsigned int interface;
  unsigned int flags;
  char driver[USBDEVFS_MAXDRIVERNAME + 1];
};
#define USBDEVFS_DISCONNECT_CLAIM                                              \
  _IOR('U', 27, struct usbdevfs_disconnect_claim)
#endif
#ifndef USBDEVFS_ALLOC_STREAMS
struct usbdevfs_streams {
  unsigned int num_streams;
  unsigned int num_eps;
  unsigned char eps[0];
};
#define USBDEVFS_ALLOC_STREAMS _IOR('U', 28, struct usbdevfs_streams)
#define USBDEVFS_FREE_STREAMS _IOR('U', 29, struct usbdevfs_streams)
#endif

#ifndef TUNSETVNETLE
#define TUNSETVNETLE _IOW('T', 220, int)
#endif
#ifndef TUNGETVNETLE
#define TUNGETVNETLE _IOR('T', 221, int)
#endif
#ifndef TUNSETVNETBE
#define TUNSETVNETBE _IOW('T', 222, int)
#endif
#ifndef TUNGETVNETBE
#define TUNGETVNETBE _IOR('T', 223, int)
#endif

#ifndef TIOCGPKT
#define TIOCGPKT _IOR('T', 0x38, int)
#endif
#ifndef TIOCGPTLCK
#define TIOCGPTLCK _IOR('T', 0x39, int)
#endif
#ifndef TIOCGEXCL
#define TIOCGEXCL _IOR('T', 0x40, int)
#endif

struct rr_input_mask {
  uint32_t type;
  uint32_t codes_size;
  uint64_t codes_ptr;
};

#ifndef EVIOCGMASK
#define EVIOCGMASK _IOR('E', 0x92, struct rr_input_mask)
#endif

#ifndef MADV_FREE
#define MADV_FREE 8
#endif
#ifndef MADV_DONTDUMP
#define MADV_DONTDUMP 16
#endif
#ifndef MADV_DODUMP
#define MADV_DODUMP 17
#endif
#ifndef MADV_SOFT_OFFLINE
#define MADV_SOFT_OFFLINE 101
#endif

#ifndef BUS_MCEERR_AR
#define BUS_MCEERR_AR 4
#endif

#ifndef BUS_MCEERR_AO
#define BUS_MCEERR_AO 5
#endif

// Defined in the ip_tables header for each protocol, but always to the same,
// value, so it should be fine to set this here
#ifndef SO_SET_REPLACE
#define SO_SET_REPLACE 64
#endif

#ifndef HCIGETDEVLIST
#define HCIGETDEVLIST _IOR('H', 210, int)
#endif
#ifndef HCIGETDEVINFO
#define HCIGETDEVINFO _IOR('H', 211, int)
#endif

// Unfortuantely the header that defines these is not C++ safe, we we'll
// have to redefine them here
#ifndef KEYCTL_GET_KEYRING_ID
#define KEYCTL_GET_KEYRING_ID 0
#endif
#ifndef KEYCTL_JOIN_SESSION_KEYRING
#define KEYCTL_JOIN_SESSION_KEYRING 1
#endif
#ifndef KEYCTL_UPDATE
#define KEYCTL_UPDATE 2
#endif
#ifndef KEYCTL_REVOKE
#define KEYCTL_REVOKE 3
#endif
#ifndef KEYCTL_CHOWN
#define KEYCTL_CHOWN 4
#endif
#ifndef KEYCTL_SETPERM
#define KEYCTL_SETPERM 5
#endif
#ifndef KEYCTL_DESCRIBE
#define KEYCTL_DESCRIBE 6
#endif
#ifndef KEYCTL_CLEAR
#define KEYCTL_CLEAR 7
#endif
#ifndef KEYCTL_LINK
#define KEYCTL_LINK 8
#endif
#ifndef KEYCTL_UNLINK
#define KEYCTL_UNLINK 9
#endif
#ifndef KEYCTL_SEARCH
#define KEYCTL_SEARCH 10
#endif
#ifndef KEYCTL_READ
#define KEYCTL_READ 11
#endif
#ifndef KEYCTL_INSTANTIATE
#define KEYCTL_INSTANTIATE 12
#endif
#ifndef KEYCTL_NEGATE
#define KEYCTL_NEGATE 13
#endif
#ifndef KEYCTL_SET_REQKEY_KEYRING
#define KEYCTL_SET_REQKEY_KEYRING 14
#endif
#ifndef KEYCTL_SET_TIMEOUT
#define KEYCTL_SET_TIMEOUT 15
#endif
#ifndef KEYCTL_ASSUME_AUTHORITY
#define KEYCTL_ASSUME_AUTHORITY 16
#endif
#ifndef KEYCTL_GET_SECURITY
#define KEYCTL_GET_SECURITY 17
#endif
#ifndef KEYCTL_SESSION_TO_PARENT
#define KEYCTL_SESSION_TO_PARENT 18
#endif
#ifndef KEYCTL_REJECT
#define KEYCTL_REJECT 19
#endif
#ifndef KEYCTL_INSTANTIATE_IOV
#define KEYCTL_INSTANTIATE_IOV 20
#endif
#ifndef KEYCTL_INVALIDATE
#define KEYCTL_INVALIDATE 21
#endif
#ifndef KEYCTL_GET_PERSISTENT
#define KEYCTL_GET_PERSISTENT 22
#endif
#ifndef KEYCTL_DH_COMPUTE
#define KEYCTL_DH_COMPUTE 23
#endif

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif
#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

// New in the 4.6 kernel.
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
// New in the 4.12 kernel
#ifndef ARCH_GET_CPUID
#define ARCH_GET_CPUID 0x1011
#endif
#ifndef ARCH_SET_CPUID
#define ARCH_SET_CPUID 0x1012
#endif

} // namespace rr

#endif /* RR_KERNEL_SUPPLEMENT_H_ */
