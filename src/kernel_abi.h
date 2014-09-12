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

enum SupportedArch {
  x86,
  x86_64,
};

namespace rr {

#if defined(__i386__)
const SupportedArch RR_NATIVE_ARCH = SupportedArch::x86;
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
  RR_VERIFY_TYPE_ARCH(arch, system_type_, rr_type_)

// For instances where the system type and the rr type are named identically.
#define RR_VERIFY_TYPE(type_) RR_VERIFY_TYPE_EXPLICIT(::type_, type_)

struct KernelConstants {
  static const ::size_t SIGINFO_MAX_SIZE = 128;

  // These types are the same size everywhere.
  typedef int32_t pid_t;
  typedef uint32_t uid_t;

  typedef uint32_t socklen_t;
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

template <SupportedArch arch, typename wordsize>
struct BaseArch : public wordsize {
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
    operator T*() const {
      return reinterpret_cast<T*>(val);
    };
    T* operator=(T* p) {
      val = reinterpret_cast<uintptr_t>(p);
      // check that val is wide enough to hold the value of p
      assert(val == reinterpret_cast<uintptr_t>(p));
      return p;
    }
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

  struct mmap_args {
    ptr<void> addr;
    size_t len;
    signed_int prot;
    signed_int flags;
    signed_int fd;
    off_t offset;
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
};

struct X86Arch : public BaseArch<SupportedArch::x86, WordSize32Defs> {
  static const size_t elfmachine = EM_386;
  static const size_t elfendian = ELFDATA2LSB;

  enum Syscalls {
    restart_syscall = 0,
#define SYSCALLNO_X86(num) dummy_##num = num - 1,
#define SYSCALLNO_X86_64(num)
#define SYSCALL_UNDEFINED_X86_64()
#define SYSCALL_DEF0(_name, _type) _name,
#define SYSCALL_DEF1(_name, _type, _1, _2) _name,
#define SYSCALL_DEF1_DYNSIZE(_name, _type, _1, _2) _name,
#define SYSCALL_DEF1_STR(_name, _type, _1) _name,
#define SYSCALL_DEF2(_name, _type, _1, _2, _3, _4) _name,
#define SYSCALL_DEF3(_name, _type, _1, _2, _3, _4, _5, _6) _name,
#define SYSCALL_DEF4(_name, _type, _1, _2, _3, _4, _5, _6, _7, _8) _name,
#define SYSCALL_DEF_IRREG(_name, _type) _name,
#define SYSCALL_DEF_UNSUPPORTED(_name) _name,

#include "syscall_defs.h"
    SYSCALL_COUNT
  };

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
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86, ::user_fpxregs_struct,
                      user_fpxregs_struct);
};

struct X64Arch : public BaseArch<SupportedArch::x86_64, WordSize64Defs> {
  static const size_t elfmachine = EM_X86_64;
  static const size_t elfendian = ELFDATA2LSB;

/* First, define some macros for making up dummy syscall numbers for
 * undefined syscalls.  We need a unique dummy enum for each one.  The
 * easiest way to do that is to use __LINE__ to get a unique ID.  But to
 * make sure __LINE__ is expanded as its numeric value and not merely
 * the __LINE__ token, we need to introduce layers of indirection to
 * ensure the macros are expanded as we would like.
 */
#define DUMMY_ID_3(line) dummy_syscall##line
#define DUMMY_ID_2(line) DUMMY_ID_3(line)
#define DUMMY_ID DUMMY_ID_2(__LINE__)

private:
  enum class Undefined {
    ZERO,
#define SYSCALLNO_X86_64(num)
#define SYSCALLNO_X86(num)
#define SYSCALL_UNDEFINED_X86_64() DUMMY_ID,
#define SYSCALL_DEF0(_name, _type)
#define SYSCALL_DEF1(_name, _type, _1, _2)
#define SYSCALL_DEF1_DYNSIZE(_name, _type, _1, _2)
#define SYSCALL_DEF1_STR(_name, _type, _1)
#define SYSCALL_DEF2(_name, _type, _1, _2, _3, _4)
#define SYSCALL_DEF3(_name, _type, _1, _2, _3, _4, _5, _6)
#define SYSCALL_DEF4(_name, _type, _1, _2, _3, _4, _5, _6, _7, _8)
#define SYSCALL_DEF_IRREG(_name, _type)
#define SYSCALL_DEF_UNSUPPORTED(_name)

#include "syscall_defs.h"
    COUNT,
  };

public:
  enum Syscalls {
    restart_syscall = 219,
#define SYSCALLNO_X86(num)
#define SYSCALLNO_X86_64(num) dummy_##num = num - 1,
#define SYSCALL_UNDEFINED_X86_64()                                             \
  DUMMY_ID = (-static_cast<int>(Undefined::DUMMY_ID)) << 8,
#define SYSCALL_DEF0(_name, _type) _name,
#define SYSCALL_DEF1(_name, _type, _1, _2) _name,
#define SYSCALL_DEF1_DYNSIZE(_name, _type, _1, _2) _name,
#define SYSCALL_DEF1_STR(_name, _type, _1) _name,
#define SYSCALL_DEF2(_name, _type, _1, _2, _3, _4) _name,
#define SYSCALL_DEF3(_name, _type, _1, _2, _3, _4, _5, _6) _name,
#define SYSCALL_DEF4(_name, _type, _1, _2, _3, _4, _5, _6, _7, _8) _name,
#define SYSCALL_DEF_IRREG(_name, _type) _name,
#define SYSCALL_DEF_UNSUPPORTED(_name) _name,

#include "syscall_defs.h"
    SYSCALL_COUNT
  };

#undef DUMMY_ID
#undef DUMMY_ID_2
#undef DUMMY_ID_3

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
    uint64_t cs;
    uint64_t eflags;
    uint64_t rsp;
    uint64_t ss;
    uint64_t fs_base;
    uint64_t gs_base;
    uint64_t ds;
    uint64_t es;
    uint64_t fs;
    uint64_t gs;
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
  }

// Define a bunch of helper functions:
//
// - has_${SYSCALL}_syscall for whether a syscall is available;
// - is_${SYSCALL}_syscall for whether a number is a particular syscall; and
// - syscall_number_for_${SYSCALL} to get a syscall's number by name.  Note that
//   ${SYSCALL} must exist on the given architecture.

#define HAS_SYSCALL(_name)                                                     \
  inline bool has_##_name##_syscall(SupportedArch arch) {                      \
    switch (arch) {                                                            \
      case x86:                                                                \
        return X86Arch::_name >= 0;                                            \
      case x86_64:                                                             \
        return X64Arch::_name >= 0;                                            \
      default:                                                                 \
        assert(0 && "unsupported architecture");                               \
    }                                                                          \
  }
#define SYSCALLNO_X86_64(num)
#define SYSCALLNO_X86(num)
#define SYSCALL_UNDEFINED_X86_64()
#define SYSCALL_DEF0(_name, _type) HAS_SYSCALL(_name)
#define SYSCALL_DEF1(_name, _type, _1, _2) HAS_SYSCALL(_name)
#define SYSCALL_DEF1_DYNSIZE(_name, _type, _1, _2) HAS_SYSCALL(_name)
#define SYSCALL_DEF1_STR(_name, _type, _1) HAS_SYSCALL(_name)
#define SYSCALL_DEF2(_name, _type, _1, _2, _3, _4) HAS_SYSCALL(_name)
#define SYSCALL_DEF3(_name, _type, _1, _2, _3, _4, _5, _6) HAS_SYSCALL(_name)
#define SYSCALL_DEF4(_name, _type, _1, _2, _3, _4, _5, _6, _7, _8)             \
  HAS_SYSCALL(_name)
#define SYSCALL_DEF_IRREG(_name, _type) HAS_SYSCALL(_name)
#define SYSCALL_DEF_UNSUPPORTED(_name) HAS_SYSCALL(_name)
#include "syscall_defs.h"
HAS_SYSCALL(restart_syscall)

#undef HAS_SYSCALL

#define IS_SYSCALL(_name)                                                      \
  inline bool is_##_name##_syscall(int syscallno, SupportedArch arch) {        \
    switch (arch) {                                                            \
      case x86:                                                                \
        return syscallno >= 0 && syscallno == X86Arch::_name;                  \
      case x86_64:                                                             \
        return syscallno >= 0 && syscallno == X64Arch::_name;                  \
      default:                                                                 \
        assert(0 && "unsupported architecture");                               \
    }                                                                          \
  }
#define SYSCALLNO_X86_64(num)
#define SYSCALLNO_X86(num)
#define SYSCALL_UNDEFINED_X86_64()
#define SYSCALL_DEF0(_name, _type) IS_SYSCALL(_name)
#define SYSCALL_DEF1(_name, _type, _1, _2) IS_SYSCALL(_name)
#define SYSCALL_DEF1_DYNSIZE(_name, _type, _1, _2) IS_SYSCALL(_name)
#define SYSCALL_DEF1_STR(_name, _type, _1) IS_SYSCALL(_name)
#define SYSCALL_DEF2(_name, _type, _1, _2, _3, _4) IS_SYSCALL(_name)
#define SYSCALL_DEF3(_name, _type, _1, _2, _3, _4, _5, _6) IS_SYSCALL(_name)
#define SYSCALL_DEF4(_name, _type, _1, _2, _3, _4, _5, _6, _7, _8)             \
  IS_SYSCALL(_name)
#define SYSCALL_DEF_IRREG(_name, _type) IS_SYSCALL(_name)
#define SYSCALL_DEF_UNSUPPORTED(_name) IS_SYSCALL(_name)
#include "syscall_defs.h"
IS_SYSCALL(restart_syscall)

#undef IS_SYSCALL

#define SYSCALL_NUMBER(_name)                                                  \
  inline int syscall_number_for_##_name(SupportedArch arch) {                  \
    switch (arch) {                                                            \
      case x86:                                                                \
        assert(X86Arch::_name >= 0);                                           \
        return X86Arch::_name;                                                 \
      case x86_64:                                                             \
        assert(X64Arch::_name >= 0);                                           \
        return X64Arch::_name;                                                 \
      default:                                                                 \
        assert(0 && "unsupported architecture");                               \
    }                                                                          \
  }
#define SYSCALLNO_X86_64(num)
#define SYSCALLNO_X86(num)
#define SYSCALL_UNDEFINED_X86_64()
#define SYSCALL_DEF0(_name, _type) SYSCALL_NUMBER(_name)
#define SYSCALL_DEF1(_name, _type, _1, _2) SYSCALL_NUMBER(_name)
#define SYSCALL_DEF1_DYNSIZE(_name, _type, _1, _2) SYSCALL_NUMBER(_name)
#define SYSCALL_DEF1_STR(_name, _type, _1) SYSCALL_NUMBER(_name)
#define SYSCALL_DEF2(_name, _type, _1, _2, _3, _4) SYSCALL_NUMBER(_name)
#define SYSCALL_DEF3(_name, _type, _1, _2, _3, _4, _5, _6) SYSCALL_NUMBER(_name)
#define SYSCALL_DEF4(_name, _type, _1, _2, _3, _4, _5, _6, _7, _8)             \
  SYSCALL_NUMBER(_name)
#define SYSCALL_DEF_IRREG(_name, _type) SYSCALL_NUMBER(_name)
#define SYSCALL_DEF_UNSUPPORTED(_name) SYSCALL_NUMBER(_name)
#include "syscall_defs.h"
SYSCALL_NUMBER(restart_syscall)

#undef SYSCALL_NUMBER

} // namespace rr

#endif /* RR_KERNEL_ABI_H */
