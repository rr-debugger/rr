/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_KERNEL_ABI_H
#define RR_KERNEL_ABI_H

// Get all the kernel definitions so we can verify our alternative versions.
#include <arpa/inet.h>
#include <asm/ldt.h>
#include <elf.h>
#include <fcntl.h>
#include <linux/ethtool.h>
#include <linux/ipc.h>
#include <linux/msg.h>
#include <linux/net.h>
#include <linux/sockios.h>
#include <linux/sysctl.h>
#include <linux/wireless.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/quota.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <termios.h>

#include <assert.h>

#include "remote_ptr.h"

enum SupportedArch {
  x86,
  x86_64,
};

namespace rr {

#if defined(__i386__)
const SupportedArch RR_NATIVE_ARCH = SupportedArch::x86;
#elif defined(__x86_64__)
const SupportedArch RR_NATIVE_ARCH = SupportedArch::x86_64;
#else
#error need to define new SupportedArch enum
#endif

template <SupportedArch a, typename system_type, typename rr_type>
struct Verifier {
  // Optimistically say we are the same size.
  static const bool same_size = true;
};

template <typename system_type, typename rr_type>
struct Verifier<RR_NATIVE_ARCH, system_type, rr_type> {
  static const bool same_size = sizeof(system_type) == sizeof(rr_type);
};

template <typename T> struct Verifier<RR_NATIVE_ARCH, T, T> {
  // Prevent us from accidentally verifying the size of rr's structure
  // with itself or (unlikely) the system's structure with itself.
};

#define RR_VERIFY_TYPE_ARCH(arch_, system_type_, rr_type_)                     \
  static_assert(Verifier<arch_, system_type_, rr_type_>::same_size,            \
                "type " #system_type_ " not correctly defined");

// For instances where the system type and the rr type are named differently.
#define RR_VERIFY_TYPE_EXPLICIT(system_type_, rr_type_)                        \
  RR_VERIFY_TYPE_ARCH(arch_, system_type_, rr_type_)

// For instances where the system type and the rr type are named identically.
#define RR_VERIFY_TYPE(type_) RR_VERIFY_TYPE_EXPLICIT(::type_, type_)

struct KernelConstants {
  static const ::size_t SIGINFO_MAX_SIZE = 128;

  // These types are the same size everywhere.
  typedef int32_t pid_t;
  typedef uint32_t uid_t;

  typedef uint32_t socklen_t;
};

// These duplicate the matching F_* constants for commands for fcntl, with two
// small differences: we unconditionally define the *64 variants to their values
// for 32-bit systems.  This change enables us to always use our constants in
// switch cases without worrying about duplicated case values and makes dealing
// with 32-bit and 64-bit tracees in the same rr process simpler.
//
// The other small difference is that we define these constants without the F_
// prefix, so as to not run afoul of the C preprocessor.
struct FcntlConstants {
  enum FcntlOperation {
    DUPFD = 0,
    GETFD = 1,
    SETFD = 2,
    GETFL = 3,
    SETFL = 4,
    GETLK = 5,
    SETLK = 6,
    SETLKW = 7,
    SETOWN = 8,
    GETOWN = 9,
    SETSIG = 10,
    GETSIG = 11,
    GETLK64 = 12,
    SETLK64 = 13,
    SETLKW64 = 14,
    SETOWN_EX = 15,
    GETOWN_EX = 16,
  };
};

struct WordSize32Defs : public KernelConstants {
  static const ::size_t SIGINFO_PAD_SIZE =
      (SIGINFO_MAX_SIZE / sizeof(int32_t)) - 3;

  typedef int16_t signed_short;
  typedef uint16_t unsigned_short;

  typedef int32_t signed_int;
  typedef uint32_t unsigned_int;

  typedef int32_t signed_long;
  typedef uint32_t unsigned_long;

  typedef int32_t signed_word;
  typedef uint32_t unsigned_word;

  typedef uint32_t size_t;

  // These really only exist as proper abstractions so that adding x32
  // (x86-64's ILP32 ABI) support is relatively easy.
  typedef int32_t syscall_slong_t;
  typedef int32_t sigchld_clock_t;

  static const size_t elfclass = ELFCLASS32;
  typedef Elf32_Ehdr ElfEhdr;
  typedef Elf32_Shdr ElfShdr;
  typedef Elf32_Sym ElfSym;
};

struct WordSize64Defs : public KernelConstants {
  static const ::size_t SIGINFO_PAD_SIZE =
      (SIGINFO_MAX_SIZE / sizeof(int32_t)) - 4;

  typedef int16_t signed_short;
  typedef uint16_t unsigned_short;

  typedef int32_t signed_int;
  typedef uint32_t unsigned_int;

  typedef int64_t signed_long;
  typedef uint64_t unsigned_long;

  typedef int64_t signed_word;
  typedef uint64_t unsigned_word;

  typedef uint64_t size_t;

  // These really only exist as proper abstractions so that adding x32
  // (x86-64's ILP32 ABI) support is relatively easy.
  typedef int64_t syscall_slong_t;
  typedef int64_t sigchld_clock_t;

  static const size_t elfclass = ELFCLASS64;
  typedef Elf64_Ehdr ElfEhdr;
  typedef Elf64_Shdr ElfShdr;
  typedef Elf64_Sym ElfSym;
};

template <SupportedArch arch_, typename wordsize>
struct BaseArch : public wordsize, public FcntlConstants {
  static SupportedArch arch() { return arch_; }

  typedef typename wordsize::syscall_slong_t syscall_slong_t;
  typedef typename wordsize::signed_int signed_int;
  typedef typename wordsize::unsigned_int unsigned_int;
  typedef typename wordsize::signed_short signed_short;
  typedef typename wordsize::unsigned_short unsigned_short;
  typedef typename wordsize::signed_long signed_long;
  typedef typename wordsize::unsigned_long unsigned_long;
  typedef typename wordsize::unsigned_word unsigned_word;
  typedef typename wordsize::sigchld_clock_t sigchld_clock_t;

  typedef syscall_slong_t time_t;
  typedef syscall_slong_t suseconds_t;
  typedef syscall_slong_t off_t;

  typedef syscall_slong_t clock_t;

  typedef signed_int __kernel_key_t;
  typedef signed_int __kernel_uid32_t;
  typedef signed_int __kernel_gid32_t;
  typedef unsigned_int __kernel_mode_t;
  typedef unsigned_long __kernel_ulong_t;
  typedef signed_long __kernel_long_t;
  typedef __kernel_long_t __kernel_time_t;
  typedef signed_int __kernel_pid_t;

  template <typename T> struct ptr {
    unsigned_word val;
    template <typename U> operator remote_ptr<U>() const { return rptr(); }
    /**
     * Sometimes you need to call rptr() directly to resolve ambiguous
     * overloading.
     */
    remote_ptr<T> rptr() const { return remote_ptr<T>(val); }
    template <typename U> ptr<T>& operator=(remote_ptr<U> p) {
      remote_ptr<T> pt = p;
      val = pt.as_int();
      assert(val == pt.as_int());
      return *this;
    }
    operator bool() const { return val; }
    size_t referent_size() const { return sizeof(T); }
  };

  union sigval_t {
    signed_int sival_int;
    ptr<void> sival_ptr;
  };

  struct sockaddr {
    unsigned_short sa_family;
    char sa_data[14];
  };
  RR_VERIFY_TYPE(sockaddr);

  struct timeval {
    time_t tv_sec;
    suseconds_t tv_usec;
  };
  RR_VERIFY_TYPE(timeval);

  struct timespec {
    time_t tv_sec;
    syscall_slong_t tv_nsec;
  };
  RR_VERIFY_TYPE(timespec);

  struct pollfd {
    signed_int fd;
    signed_short events;
    signed_short revents;
  };
  RR_VERIFY_TYPE(pollfd);

  struct iovec {
    ptr<void> iov_base;
    size_t iov_len;
  };
  RR_VERIFY_TYPE(iovec);

  struct msghdr {
    ptr<void> msg_name;
    socklen_t msg_namelen;

    ptr<iovec> msg_iov;
    size_t msg_iovlen;

    ptr<void> msg_control;
    size_t msg_controllen;

    signed_int msg_flags;
  };
  RR_VERIFY_TYPE(msghdr);

  struct mmsghdr {
    msghdr msg_hdr;
    unsigned_int msg_len;
  };
  RR_VERIFY_TYPE(mmsghdr);

// x86-64 is the only architecture to pack this structure, and it does
// so to make the x86 and x86-64 definitions identical.  So even if
// we're compiling on an x86-64 host that will support recording
// 32-bit and 64-bit programs, this is the correct way to declare
// epoll_event for both kinds of recordees.
// See <linux/eventpoll.h>.
#if defined(__x86_64__)
#define RR_EPOLL_PACKED __attribute__((packed))
#else
#define RR_EPOLL_PACKED
#endif
  struct epoll_event {
    union epoll_data {
      ptr<void> ptr_;
      signed_int fd;
      uint32_t u32;
      uint64_t u64;
    };

    uint32_t events;
    epoll_data data;
  } RR_EPOLL_PACKED;
  RR_VERIFY_TYPE(epoll_event);
#undef RR_EPOLL_PACKED

  struct rusage {
    timeval ru_utime;
    timeval ru_stime;
    signed_long ru_maxrss;
    signed_long ru_ixrss;
    signed_long ru_idrss;
    signed_long ru_isrss;
    signed_long ru_minflt;
    signed_long ru_majflt;
    signed_long ru_nswap;
    signed_long ru_inblock;
    signed_long ru_oublock;
    signed_long ru_msgnsd;
    signed_long ru_msgrcv;
    signed_long ru_nsignals;
    signed_long ru_nvcsw;
    signed_long ru_nivcsw;
  };
  RR_VERIFY_TYPE(rusage);

  struct siginfo_t {
    signed_int si_signo;
    signed_int si_errno;
    signed_int si_code;
    union {
      signed_int padding[wordsize::SIGINFO_PAD_SIZE];
      // <bits/siginfo.h> #defines all the field names belong due to X/Open
      // requirements, so we append '_'.
      struct {
        pid_t si_pid_;
        uid_t si_uid_;
      } _kill;
      struct {
        signed_int si_tid_;
        signed_int si_overrun_;
        sigval_t si_sigval_;
      } _timer;
      struct {
        pid_t si_pid_;
        uid_t si_uid_;
        sigval_t si_sigval_;
      } _rt;
      struct {
        pid_t si_pid_;
        uid_t si_uid_;
        signed_int si_status_;
        sigchld_clock_t si_utime_;
        sigchld_clock_t si_stime_;
      } _sigchld;
      struct {
        ptr<void> si_addr_;
        signed_short si_addr_lsb_;
      } _sigfault;
      struct {
        signed_long si_band_;
        signed_int si_fd_;
      } _sigpoll;
      struct {
        ptr<void> _call_addr;
        signed_int _syscall;
        unsigned_int _arch;
      } _sigsys;
    } _sifields;
  };
  RR_VERIFY_TYPE_EXPLICIT(siginfo_t, ::siginfo_t)

  typedef unsigned char cc_t;
  typedef unsigned_int speed_t;
  typedef unsigned_int tcflag_t;

  struct termios {
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;
    cc_t c_line;
    cc_t c_cc[32];
    speed_t c_ispeed;
    speed_t c_ospeed;
  };
  RR_VERIFY_TYPE(termios);

  struct winsize {
    unsigned_short ws_row;
    unsigned_short ws_col;
    unsigned_short ws_xpixel;
    unsigned_short ws_ypixel;
  };
  RR_VERIFY_TYPE(winsize);

  struct ipc64_perm {
    __kernel_key_t key;
    __kernel_uid32_t uid;
    __kernel_gid32_t gid;
    __kernel_uid32_t cuid;
    __kernel_gid32_t cgid;
    __kernel_mode_t mode;
    unsigned char __pad1[4 - sizeof(__kernel_mode_t)];
    unsigned_short seq;
    unsigned_short __pad2;
    __kernel_ulong_t unused1;
    __kernel_ulong_t unused2;
  };
  RR_VERIFY_TYPE(ipc64_perm);

  struct msqid64_ds {
    struct ipc64_perm msg_perm;
    // These msg*time fields are really __kernel_time_t plus
    // appropiate padding.  We don't touch the fields, though.
    //
    // We do, however, suffix them with _only_little_endian to
    // urge anybody who does touch them to make sure the right
    // thing is done for big-endian systems.
    uint64_t msg_stime_only_little_endian;
    uint64_t msg_rtime_only_little_endian;
    uint64_t msg_ctime_only_little_endian;
    __kernel_ulong_t msg_cbytes;
    __kernel_ulong_t msg_qnum;
    __kernel_ulong_t msg_qbytes;
    __kernel_pid_t msg_lspid;
    __kernel_pid_t msg_lrpid;
    __kernel_ulong_t unused1;
    __kernel_ulong_t unused2;
  };
  RR_VERIFY_TYPE(msqid64_ds);

  struct msginfo {
    signed_int msgpool;
    signed_int msgmap;
    signed_int msgmax;
    signed_int msgmnb;
    signed_int msgmni;
    signed_int msgssz;
    signed_int msgtql;
    unsigned_short msgseg;
  };
  RR_VERIFY_TYPE(msginfo);

  // The clone(2) syscall has four (!) different calling conventions,
  // depending on what architecture it's being compiled for.  We describe
  // the orderings for x86oids here.
  enum CloneParameterOrdering {
    FlagsStackParentTLSChild,
    FlagsStackParentChildTLS,
  };

  // Despite the clone(2) manpage describing the clone syscall as taking a
  // pointer to |struct user_desc*|, the actual kernel interface treats the
  // TLS value as a opaque cookie, which architectures are then free to do
  // whatever they like with.  See for instance the definition of TLS_VALUE
  // in nptl/sysdeps/pthread/createthread.c in the glibc source.  We need to
  // describe what the architecture uses so we can record things accurately.
  enum CloneTLSType {
    // |struct user_desc*|
    UserDescPointer,
    // This is the default choice for TLS_VALUE in the glibc source.
    PthreadStructurePointer,
  };

  struct user_desc {
    unsigned_int entry_number;
    unsigned_int base_addr;
    unsigned_int limit;
    unsigned_int seg_32bit : 1;
    unsigned_int contents : 2;
    unsigned_int read_exec_only : 1;
    unsigned_int limit_in_pages : 1;
    unsigned_int seg_not_present : 1;
    unsigned_int useable : 1;
    unsigned_int lm : 1;
  };
  RR_VERIFY_TYPE(user_desc);

  // This structure uses fixed-size fields, but the padding rules
  // for 32-bit vs. 64-bit architectures dictate that it be
  // defined in full.
  struct dqblk {
    uint64_t dqb_bhardlimit;
    uint64_t dqb_bsoftlimit;
    uint64_t dqb_curspace;
    uint64_t dqb_ihardlimit;
    uint64_t dqb_isoftlimit;
    uint64_t dqb_curinodes;
    uint64_t dqb_btime;
    uint64_t dqb_itime;
    uint32_t dqb_valid;
  };
  RR_VERIFY_TYPE(dqblk);

  struct dqinfo {
    uint64_t dqi_bgrace;
    uint64_t dqi_igrace;
    uint32_t dqi_flags;
    uint32_t dqi_valid;
  };
  RR_VERIFY_TYPE(dqinfo);

  struct ifmap {
    unsigned_long mem_start;
    unsigned_long mem_end;
    unsigned_short base_addr;
    unsigned char irq;
    unsigned char dma;
    unsigned char port;
  };
  RR_VERIFY_TYPE(ifmap);

  struct if_settings {
    unsigned_int type;
    unsigned_int size;
    union {
      ptr<void> raw_hdlc;
      ptr<void> cisco;
      ptr<void> fr;
      ptr<void> fr_pvc;
      ptr<void> fr_pvc_info;
      ptr<void> sync;
      ptr<void> tel;
    } ifs_ifsu;
  };
  RR_VERIFY_TYPE(if_settings);

  struct ifreq {
    union {
      char ifrn_name[16];
    } ifr_ifrn;
    union {
      sockaddr ifru_addr;
      sockaddr ifru_dstaddr;
      sockaddr ifru_broadaddr;
      sockaddr ifru_netmask;
      sockaddr ifru_hwaddr;
      signed_short ifru_flags;
      signed_int ifru_ivalue;
      signed_int ifru_mtu;
      ifmap ifru_map;
      char ifru_slave[16];
      char ifru_newname[16];
      ptr<void> ifru_data;
      if_settings ifru_settings;
    } ifr_ifru;
  };
  RR_VERIFY_TYPE(ifreq);

  struct ifconf {
    signed_int ifc_len;
    union {
      ptr<char> ifcu_buf;
      ptr<ifreq> ifcu_req;
    } ifc_ifcu;
  };
  RR_VERIFY_TYPE(ifconf);

  struct iw_param {
    int32_t value;
    uint8_t fixed;
    uint8_t disabled;
    uint16_t flags;
  };
  RR_VERIFY_TYPE(iw_param);

  struct iw_point {
    ptr<void> pointer;
    uint16_t length;
    uint16_t flags;
  };
  RR_VERIFY_TYPE(iw_point);

  struct iw_freq {
    int32_t m;
    int16_t e;
    uint8_t i;
    uint8_t flags;
  };
  RR_VERIFY_TYPE(iw_freq);

  struct iw_quality {
    uint8_t qual;
    uint8_t level;
    uint8_t noise;
    uint8_t updated;
  };
  RR_VERIFY_TYPE(iw_quality);

  union iwreq_data {
    char name[16];
    iw_point essid;
    iw_param nwid;
    iw_freq freq;
    iw_param sens;
    iw_param bitrate;
    iw_param txpower;
    iw_param rts;
    iw_param frag;
    uint32_t mode;
    iw_param retry;
    iw_point encoding;
    iw_param power;
    iw_quality qual;
    sockaddr ap_addr;
    sockaddr addr;
    iw_param param;
    iw_point data;
  };
  RR_VERIFY_TYPE(iwreq_data);

  struct iwreq {
    union {
      char ifrn_name[16];
    } ifr_ifrn;
    iwreq_data u;
  };
  RR_VERIFY_TYPE(iwreq);

  struct ethtool_cmd {
    uint32_t cmd;
    uint32_t supported;
    uint32_t advertising;
    uint16_t speed;
    uint8_t duplex;
    uint8_t port;
    uint8_t phy_address;
    uint8_t transceiver;
    uint8_t autoneg;
    uint8_t mdio_support;
    uint32_t maxtxpkt;
    uint32_t maxrxpkt;
    uint16_t speed_hi;
    uint8_t eth_tp_mdix;
    uint8_t eth_tp_mdix_ctrl;
    uint32_t lp_advertising;
    uint32_t reserved[2];
  };
  RR_VERIFY_TYPE(ethtool_cmd);

  struct flock {
    signed_short l_type;
    signed_short l_whence;
    off_t l_start;
    off_t l_len;
    pid_t l_pid;
  };
  RR_VERIFY_TYPE(flock);

  struct flock64 {
    signed_short l_type;
    signed_short l_whence;
    uint64_t l_start;
    uint64_t l_len;
    pid_t l_pid;
  };
  RR_VERIFY_TYPE(flock64);

  struct f_owner_ex {
    signed_int type;
    __kernel_pid_t pid;
  };
  RR_VERIFY_TYPE(f_owner_ex);

  // Define various structures that package up syscall arguments.
  // The types of their members are part of the ABI, and defining
  // them here makes their definitions more concise.
  struct accept_args {
    signed_int sockfd;
    ptr<sockaddr> addr;
    ptr<socklen_t> addrlen;
  };

  struct accept4_args {
    accept_args _;
    signed_long flags;
  };

  struct getsockname_args {
    signed_int sockfd;
    ptr<sockaddr> addr;
    ptr<socklen_t> addrlen;
  };

  struct getsockopt_args {
    signed_int sockfd;
    signed_int level;
    signed_int optname;
    ptr<void> optval;
    ptr<socklen_t> optlen;
  };

  struct recv_args {
    signed_int sockfd;
    ptr<void> buf;
    size_t len;
    signed_int flags;
  };

  struct recvfrom_args {
    signed_long sockfd;
    ptr<void> buf;
    size_t len;
    signed_long flags;
    ptr<sockaddr> src_addr;
    ptr<socklen_t> addrlen;
  };

  struct recvmsg_args {
    signed_int fd;
    ptr<msghdr> msg;
    signed_int flags;
  };

  struct recvmmsg_args {
    signed_int sockfd;
    ptr<mmsghdr> msgvec;
    unsigned_int vlen;
    unsigned_int flags;
    ptr<timespec> timeout;
  };

  struct sendmmsg_args {
    signed_int sockfd;
    ptr<mmsghdr> msgvec;
    unsigned_int vlen;
    unsigned_int flags;
  };

  struct socketpair_args {
    signed_int domain;
    signed_int type;
    signed_int protocol;
    ptr<signed_int> sv; // int sv[2]
  };

  // All architectures have an mmap syscall, but it has architecture-specific
  // calling semantics. We describe those here, and specializations need to
  // indicate which semantics they use.
  enum MmapCallingSemantics {
    StructArguments,   // x86-ish, packaged into mmap_args, below
    RegisterArguments, // arguments passed in registers, the offset
                       // is assumed to be in bytes, not in pages.
  };

  struct mmap_args {
    ptr<void> addr;
    size_t len;
    signed_int prot;
    signed_int flags;
    signed_int fd;
    off_t offset;
  };

  // All architectures have a select syscall, but like mmap, there are two
  // different calling styles: one that packages the args into a structure,
  // and one that handles the args in registers.  (Architectures using the
  // first style, like the x86, sometimes support the register-args version
  // as a separate syscall.)
  //
  // (Yes, we'd like to call these StructArguments and RegisterArguments, but
  // that would conflict with MmapCallingSemantics, above.)
  enum SelectCallingSemantics {
    SelectStructArguments,
    SelectRegisterArguments,
  };

  static const size_t MAX_FDS = 1024;
  struct fd_set {
    unsigned_long fds_bits[MAX_FDS / (8 * sizeof(unsigned_long))];
  };

  struct select_args {
    signed_int n_fds;
    ptr<fd_set> read_fds;
    ptr<fd_set> write_fds;
    ptr<fd_set> except_fds;
    ptr<struct timeval> timeout;
  };

  /**
   *  Some ipc calls require 7 params, so two of them are stashed into
   *  one of these structs and a pointer to this is passed instead.
   */
  struct ipc_kludge_args {
    ptr<void> msgbuf;
    signed_long msgtype;
  };

  struct __sysctl_args {
    ptr<signed_int> name;
    signed_int nlen;
    ptr<void> oldval;
    ptr<size_t> oldlenp;
    ptr<void> newval;
    ptr<size_t> newlen;
    unsigned_long __unused[4];
  };
  RR_VERIFY_TYPE(__sysctl_args);

  // The getgroups syscall (as well as several others) differs between
  // architectures depending on whether they ever supported 16-bit
  // {U,G}IDs or not.  Architectures such as x86, which did support
  // 16-bit {U,G}IDs, have a getgroups syscall for the 16-bit GID case
  // and a getgroups32 syscall for the 32-bit GID case.  Architectures
  // such as as x86-64, which support 32-bit GIDs exclusively, have only
  // a getgroups syscall.  We need to know which one we're dealing with
  // when recording and replaying getgroups and related syscalls.
  enum UserAndGroupIDSizesSupported {
    Mixed16And32Bit,
    Only32Bit,
  };
};

struct X86Arch : public BaseArch<SupportedArch::x86, WordSize32Defs> {
  static const size_t elfmachine = EM_386;
  static const size_t elfendian = ELFDATA2LSB;

  static const MmapCallingSemantics mmap_semantics = StructArguments;
  static const CloneTLSType clone_tls_type = UserDescPointer;
  static const CloneParameterOrdering clone_parameter_ordering =
      FlagsStackParentTLSChild;
  static const SelectCallingSemantics select_semantics = SelectStructArguments;
  static const UserAndGroupIDSizesSupported uid_gid_sizes = Mixed16And32Bit;

#include "SyscallEnumsX86.generated"

  struct user_regs_struct {
    int32_t ebx;
    int32_t ecx;
    int32_t edx;
    int32_t esi;
    int32_t edi;
    int32_t ebp;
    int32_t eax;
    int32_t xds;
    int32_t xes;
    int32_t xfs;
    int32_t xgs;
    int32_t orig_eax;
    int32_t eip;
    int32_t xcs;
    int32_t eflags;
    int32_t esp;
    int32_t xss;
  };
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86, ::user_regs_struct, user_regs_struct);

  struct user_fpregs_struct {
    int32_t cwd;
    int32_t swd;
    int32_t twd;
    int32_t fip;
    int32_t fcs;
    int32_t foo;
    int32_t fos;
    int32_t st_space[20];
  };
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86, ::user_fpregs_struct,
                      user_fpregs_struct);

  struct user_fpxregs_struct {
    uint16_t cwd;
    uint16_t swd;
    uint16_t twd;
    uint16_t fop;
    int32_t fip;
    int32_t fcs;
    int32_t foo;
    int32_t fos;
    int32_t mxcsr;
    int32_t reserved;
    int32_t st_space[32];
    int32_t xmm_space[32];
    int32_t padding[56];
  };
#if defined(__i386)
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86, ::user_fpxregs_struct,
                      user_fpxregs_struct);
#endif
};

struct X64Arch : public BaseArch<SupportedArch::x86_64, WordSize64Defs> {
  static const size_t elfmachine = EM_X86_64;
  static const size_t elfendian = ELFDATA2LSB;

  static const MmapCallingSemantics mmap_semantics = RegisterArguments;
  static const CloneTLSType clone_tls_type = PthreadStructurePointer;
  static const CloneParameterOrdering clone_parameter_ordering =
      FlagsStackParentChildTLS;
  static const SelectCallingSemantics select_semantics =
      SelectRegisterArguments;
  static const UserAndGroupIDSizesSupported uid_gid_sizes = Only32Bit;

#include "SyscallEnumsX64.generated"

  // The kernel defines the segment registers and eflags as 64-bit quantities,
  // even though the segment registers are really 16-bit and eflags is
  // architecturally defined as 32-bit.  GDB wants the segment registers and
  // eflags to appear as 32-bit quantities.  From the perspective of providing
  // registers to GDB, it's easier if we define these registers as uint32_t
  // with extra padding.
  struct user_regs_struct {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t orig_rax;
    uint64_t rip;
    uint32_t cs;
    uint32_t cs_upper;
    uint32_t eflags;
    uint32_t eflags_upper;
    uint64_t rsp;
    uint32_t ss;
    uint32_t ss_upper;
    // These _base registers are architecturally defined MSRs and really do
    // need to be 64-bit.
    uint64_t fs_base;
    uint64_t gs_base;
    uint32_t ds;
    uint32_t ds_upper;
    uint32_t es;
    uint32_t es_upper;
    uint32_t fs;
    uint32_t fs_upper;
    uint32_t gs;
    uint32_t gs_upper;
  };
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86_64, ::user_regs_struct,
                      user_regs_struct);

  struct user_fpregs_struct {
    uint16_t cwd;
    uint16_t swd;
    uint16_t ftw;
    uint16_t fop;
    uint64_t rip;
    uint64_t rdp;
    uint32_t mxcsr;
    uint32_t mxcr_mask;
    uint32_t st_space[32];
    uint32_t xmm_space[64];
    uint32_t padding[24];
  };
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86_64, ::user_fpregs_struct,
                      user_fpregs_struct);
};

#define RR_ARCH_FUNCTION(f, arch, args...)                                     \
  switch (arch) {                                                              \
    default:                                                                   \
      assert(0 && "Unknown architecture");                                     \
    case x86:                                                                  \
      return f<rr::X86Arch>(args);                                             \
    case x86_64:                                                               \
      return f<rr::X64Arch>(args);                                             \
  }

// Helper structure for determining the proper outparam sizes for syscalls
// like getgroups.
template <typename Arch> struct LegacyUIDSyscall {
  static const size_t size = (Arch::uid_gid_sizes == Arch::Only32Bit ? 4 : 2);
};

#include "SyscallHelperFunctions.generated"

} // namespace rr

#endif /* RR_KERNEL_ABI_H */
