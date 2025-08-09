/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_KERNEL_SUPPLEMENT_H_
#define RR_KERNEL_SUPPLEMENT_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <linux/capability.h>
#include <linux/dma-buf.h>
#include <linux/if_tun.h>
#include <linux/mman.h>
#include <linux/seccomp.h>
#include <linux/usbdevice_fs.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

namespace rr {

/* Definitions that should be part of system headers (and maybe are on some but
 * not all systems).
 * This should not contain anything for which rr needs all the definitions
 * across architectures; those definitions belong in kernel_abi.h.
 */

#define KERNEL_CONSTANT(constant) \
  constant = KernelConstants::constant

enum _ptrace_request {
  KERNEL_CONSTANT(PTRACE_TRACEME),
  KERNEL_CONSTANT(PTRACE_PEEKTEXT),
  KERNEL_CONSTANT(PTRACE_PEEKDATA),
  KERNEL_CONSTANT(PTRACE_PEEKUSR),
  KERNEL_CONSTANT(PTRACE_PEEKUSER),
  KERNEL_CONSTANT(PTRACE_POKETEXT),
  KERNEL_CONSTANT(PTRACE_POKEDATA),
  KERNEL_CONSTANT(PTRACE_POKEUSR),
  KERNEL_CONSTANT(PTRACE_POKEUSER),
  KERNEL_CONSTANT(PTRACE_CONT),
  KERNEL_CONSTANT(PTRACE_KILL),
  KERNEL_CONSTANT(PTRACE_SINGLESTEP),
  KERNEL_CONSTANT(PTRACE_GETREGS),
  KERNEL_CONSTANT(PTRACE_GETFPREGS),
  KERNEL_CONSTANT(PTRACE_SETFPREGS),
  KERNEL_CONSTANT(PTRACE_ATTACH),
  KERNEL_CONSTANT(PTRACE_DETACH),
  KERNEL_CONSTANT(PTRACE_SYSCALL),
  KERNEL_CONSTANT(PTRACE_SETOPTIONS),
  KERNEL_CONSTANT(PTRACE_GETEVENTMSG),
  KERNEL_CONSTANT(PTRACE_GETSIGINFO),
  KERNEL_CONSTANT(PTRACE_SETSIGINFO),
  KERNEL_CONSTANT(PTRACE_GETREGSET),
  KERNEL_CONSTANT(PTRACE_SETREGSET),
  KERNEL_CONSTANT(PTRACE_SEIZE),
  KERNEL_CONSTANT(PTRACE_INTERRUPT),
  KERNEL_CONSTANT(PTRACE_LISTEN),
  KERNEL_CONSTANT(PTRACE_GETSIGMASK),
  KERNEL_CONSTANT(PTRACE_SETSIGMASK),
  KERNEL_CONSTANT(PTRACE_GET_SYSCALL_INFO),
};

enum _ptrace_eventcodes {
  KERNEL_CONSTANT(PTRACE_EVENT_NONE),
  KERNEL_CONSTANT(PTRACE_EVENT_FORK),
  KERNEL_CONSTANT(PTRACE_EVENT_VFORK),
  KERNEL_CONSTANT(PTRACE_EVENT_CLONE),
  KERNEL_CONSTANT(PTRACE_EVENT_EXEC),
  KERNEL_CONSTANT(PTRACE_EVENT_VFORK_DONE),
  KERNEL_CONSTANT(PTRACE_EVENT_EXIT),
  KERNEL_CONSTANT(PTRACE_EVENT_SECCOMP),
  KERNEL_CONSTANT(PTRACE_EVENT_SECCOMP_OBSOLETE),
  KERNEL_CONSTANT(PTRACE_EVENT_STOP),
};

enum _ptrace_options {
  KERNEL_CONSTANT(PTRACE_O_TRACESYSGOOD),
  KERNEL_CONSTANT(PTRACE_O_TRACEFORK),
  KERNEL_CONSTANT(PTRACE_O_TRACEVFORK),
  KERNEL_CONSTANT(PTRACE_O_TRACECLONE),
  KERNEL_CONSTANT(PTRACE_O_TRACEEXEC),
  KERNEL_CONSTANT(PTRACE_O_TRACEVFORKDONE),
  KERNEL_CONSTANT(PTRACE_O_TRACEEXIT),
  KERNEL_CONSTANT(PTRACE_O_TRACESECCOMP),
  KERNEL_CONSTANT(PTRACE_O_EXITKILL),
};

enum _ptrace_get_syscall_info_op {
  KERNEL_CONSTANT(PTRACE_SYSCALL_INFO_NONE),
  KERNEL_CONSTANT(PTRACE_SYSCALL_INFO_ENTRY),
  KERNEL_CONSTANT(PTRACE_SYSCALL_INFO_EXIT),
  KERNEL_CONSTANT(PTRACE_SYSCALL_INFO_SECCOMP),
};

#undef KERNEL_CONSTANT

#ifndef SECCOMP_SET_MODE_STRICT
#define SECCOMP_SET_MODE_STRICT 0
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif
#ifndef SECCOMP_GET_ACTION_AVAIL
#define SECCOMP_GET_ACTION_AVAIL 2
#endif
#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES 3
#endif

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef PR_GET_SPECULATION_CTRL
#define PR_GET_SPECULATION_CTRL 52
#endif
#ifndef PR_SET_SPECULATION_CTRL
#define PR_SET_SPECULATION_CTRL 53
#endif

// This is used on AArch64 and available in linux/signal.h, but
// including that header will conflict with a number of our
// struct definitions.
#ifndef TRAP_HWBKPT
#define TRAP_HWBKPT 4
#endif

// This is used on AArch64 and not available on CentOS 7.8
#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif

#ifndef NT_ARM_PACA_KEYS
#define NT_ARM_PACA_KEYS 0x407
#endif

#ifndef NT_ARM_PACG_KEYS
#define NT_ARM_PACG_KEYS 0x408
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
#ifndef TIOCGPTPEER
#define TIOCGPTPEER _IO('T', 0x41)
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
#ifndef MADV_WIPEONFORK
#define MADV_WIPEONFORK 18
#endif
#ifndef MADV_KEEPONFORK
#define MADV_KEEPONFORK 19
#endif
#ifndef MADV_SOFT_OFFLINE
#define MADV_SOFT_OFFLINE 101
#endif
#ifndef MADV_COLD
#define MADV_COLD 20
#endif
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif
#ifndef MADV_POPULATE_READ
#define MADV_POPULATE_READ 22
#endif
#ifndef MADV_POPULATE_WRITE
#define MADV_POPULATE_WRITE 23
#endif
#ifndef MADV_DONTNEED_LOCKED
#define MADV_DONTNEED_LOCKED 24
#endif
#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif
#ifndef MADV_GUARD_INSTALL
#define MADV_GUARD_INSTALL 102
#endif
#ifndef MADV_GUARD_REMOVE
#define MADV_GUARD_REMOVE 103
#endif

#ifndef BUS_MCEERR_AR
#define BUS_MCEERR_AR 4
#endif

#ifndef BUS_MCEERR_AO
#define BUS_MCEERR_AO 5
#endif

// Defined in the ip_tables header for each protocol, but always to the same,
// value, so it should be fine to set this here
#ifndef IPT_SO_SET_REPLACE
#define IPT_SO_SET_REPLACE 64
#endif
#ifndef IPV6T_SO_SET_REPLACE
#define IPV6T_SO_SET_REPLACE 64
#endif

#ifndef HCIGETDEVLIST
#define HCIGETDEVLIST _IOR('H', 210, int)
#endif
#ifndef HCIGETDEVINFO
#define HCIGETDEVINFO _IOR('H', 211, int)
#endif

// Unfortunately the header that defines these is not C++ safe, we we'll
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

// New in the 3.17 kernel.
#ifndef VIDIOC_QUERY_EXT_CTRL
/* This definition omits the size because in prepare_ioctl
   it is masked away anyway. And the real size is taken from
   the real request by _IOC_SIZE(request). */
#define VIDIOC_QUERY_EXT_CTRL _IOWR('V', 103, 0)
#endif

// New in the 4.6 kernel.
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

// These are only defined on x86. For simplicity, we defined
// them here for all architectures.
#ifndef ARCH_SET_GS
#define ARCH_SET_GS 0x1001
#endif
#ifndef ARCH_SET_FS
#define ARCH_SET_FS 0x1002
#endif
#ifndef ARCH_GET_FS
#define ARCH_GET_FS 0x1003
#endif
#ifndef ARCH_GET_GS
#define ARCH_GET_GS 0x1004
#endif

// New in the 4.12 kernel
#ifndef ARCH_GET_CPUID
#define ARCH_GET_CPUID 0x1011
#endif
#ifndef ARCH_SET_CPUID
#define ARCH_SET_CPUID 0x1012
#endif

// New in the 4.15 kernel
#ifndef MAP_SYNC
#define MAP_SYNC  0x80000
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

enum {
  RR_BPF_MAP_CREATE,
  RR_BPF_MAP_LOOKUP_ELEM,
  RR_BPF_MAP_UPDATE_ELEM,
  RR_BPF_MAP_DELETE_ELEM,
  RR_BPF_MAP_GET_NEXT_KEY,
  RR_BPF_PROG_LOAD,
  RR_BPF_OBJ_PIN,
  RR_BPF_OBJ_GET,
  RR_BPF_PROG_ATTACH,
  RR_BPF_PROG_DETACH,
  RR_BPF_PROG_TEST_RUN,
  RR_BPF_PROG_GET_NEXT_ID,
  RR_BPF_MAP_GET_NEXT_ID,
  RR_BPF_PROG_GET_FD_BY_ID,
  RR_BPF_MAP_GET_FD_BY_ID,
  RR_BPF_OBJ_GET_INFO_BY_FD,
  RR_BPF_PROG_QUERY,
  RR_BPF_RAW_TRACEPOINT_OPEN,
  RR_BPF_BTF_LOAD,
  RR_BPF_BTF_GET_FD_BY_ID,
  RR_BPF_TASK_FD_QUERY,
  RR_BPF_MAP_LOOKUP_AND_DELETE_ELEM,
  RR_BPF_MAP_FREEZE,
  RR_BPF_BTF_GET_NEXT_ID,
  RR_BPF_MAP_LOOKUP_BATCH,
  RR_BPF_MAP_LOOKUP_AND_DELETE_BATCH,
  RR_BPF_MAP_UPDATE_BATCH,
  RR_BPF_MAP_DELETE_BATCH,
  RR_BPF_LINK_CREATE,
  RR_BPF_LINK_UPDATE,
  RR_BPF_LINK_GET_FD_BY_ID,
  RR_BPF_LINK_GET_NEXT_ID,
  RR_BPF_ENABLE_STATS,
  RR_BPF_ITER_CREATE,
  RR_BPF_LINK_DETACH,
  RR_BPF_PROG_BIND_MAP,
  RR_BPF_TOKEN_CREATE,
};

#ifndef O_PATH
#define O_PATH 040000000
#endif

#ifndef MAX_HANDLE_SZ
#define MAX_HANDLE_SZ 128
#endif

#ifndef P_PIDFD
#define P_PIDFD 3
#endif

#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x1000
#endif

#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME 15
#endif

#ifndef CAP_PERFMON
#define CAP_PERFMON 38
#endif

#ifndef SEGV_PKUERR
#define SEGV_PKUERR 4
#endif

#define RR_RSEQ_FLAG_UNREGISTER (1 << 0)
#define RR_RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT 0
#define RR_RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT 1
#define RR_RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT 2
#define RR_RSEQ_CPU_ID_UNINITIALIZED -1

// New in the 4.20 kernel
#ifndef BLKGETZONESZ
#define BLKGETZONESZ _IOR(0x12, 132, __u32)
#endif
#ifndef BLKGETNRZONES
#define BLKGETNRZONES _IOR(0x12, 133, __u32)
#endif

// New in the 5.4 kernel
#ifndef PR_SET_TAGGED_ADDR_CTRL
#define PR_SET_TAGGED_ADDR_CTRL 55
#endif
#ifndef PR_GET_TAGGED_ADDR_CTRL
#define PR_GET_TAGGED_ADDR_CTRL 56
#endif
#ifndef PR_TAGGED_ADDR_ENABLE
#define PR_TAGGED_ADDR_ENABLE (1 << 0)
#endif

// New in the 5.5 kernel
#ifndef BLKOPENZONE
#define BLKOPENZONE _IOW(0x12, 134, struct blk_zone_range)
#endif
#ifndef BLKCLOSEZONE
#define BLKCLOSEZONE _IOW(0x12, 135, struct blk_zone_range)
#endif
#ifndef BLKFINISHZONE
#define BLKFINISHZONE _IOW(0x12, 136, struct blk_zone_range)
#endif

// New in the 5.7 kernel
#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

// New in the 5.13 kernel
#ifndef OTPERASE
#define OTPERASE _IOW('M', 25, struct otp_info)
#endif

// New in the 5.15 kernel
#ifndef BLKGETDISKSEQ
#define BLKGETDISKSEQ _IOR(0x12,128,__u64)
#endif

// New in the 5.17 kernel
#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

// New in the 6.1 kernel
#ifndef MEMREAD
#define MEMREAD _IOWR('M', 26, typename Arch::mtd_read_req)
#endif

// New in the 6.4 kernel
#ifndef PR_GET_AUXV
#define PR_GET_AUXV 0x41555856
#endif

// Technically not "kernel" constants, exactly, since these are defined
// in libc, but required for compat with older libcs like the rest of
// this file.
#ifndef SHF_COMPRESSED
#define SHF_COMPRESSED (1 << 11)
#endif

#ifndef ELFCOMPRESS_ZLIB
#define ELFCOMPRESS_ZLIB 1
#endif
#ifndef ELFCOMPRESS_ZSTD
#define ELFCOMPRESS_ZSTD 2
#endif

// O_LARGEFILE is defined to 0 for 64-bit builds. We need to know the
// value that is used for 32-bit processes.
#define RR_LARGEFILE_32 0x8000

#ifndef ARCH_GET_XCOMP_SUPP
#define ARCH_GET_XCOMP_SUPP 0x1021
#endif
#ifndef ARCH_GET_XCOMP_PERM
#define ARCH_GET_XCOMP_PERM 0x1022
#endif
#ifndef ARCH_REQ_XCOMP_PERM
#define ARCH_REQ_XCOMP_PERM 0x1023
#endif

#ifndef DMA_BUF_IOCTL_EXPORT_SYNC_FILE
#define DMA_BUF_IOCTL_EXPORT_SYNC_FILE _IOWR(DMA_BUF_BASE, 2, struct dma_buf_export_sync_file)
struct dma_buf_export_sync_file {
  uint32_t flags;
  int32_t fd;
};
#endif

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#endif

#ifndef ZFS_SUPER_MAGIC
#define ZFS_SUPER_MAGIC 0x2fc12fc1
#endif

} // namespace rr

// We can't include libc's ptrace.h, so declare this here.
extern "C" long int ptrace (enum rr::_ptrace_request _request, ...);

#endif /* RR_KERNEL_SUPPLEMENT_H_ */
