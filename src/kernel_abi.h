/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_KERNEL_ABI_H
#define RR_KERNEL_ABI_H

#include <signal.h>

#include <vector>

#include "core.h"
#include "remote_ptr.h"

namespace rr {

class remote_code_ptr;
class Task;

enum SupportedArch { x86, x86_64, SupportedArch_MAX = x86_64 };

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

// We want verify that the types have the same size as their
// counterparts in the system header. To avoid having to include
// all system headers here, we instead make the verification macros
// a no-op unless inlcuded from kernel_abi.cc.
#ifndef RR_VERIFY_TYPE
#define RR_VERIFY_TYPE_ARCH(arch_, system_type_, rr_type_) // no-op
#define RR_VERIFY_TYPE_EXPLICIT(system_type_, rr_type_)    // no-op
#define RR_VERIFY_TYPE(x)                                  // no-op
#endif

struct KernelConstants {
  static const ::size_t SIGINFO_MAX_SIZE = 128;

  // These types are the same size everywhere.
  typedef int32_t pid_t;
  typedef uint32_t uid_t;
  typedef uint32_t gid_t;
  typedef uint32_t socklen_t;
  typedef uint64_t dev_t;
  typedef uint32_t mode_t;
  typedef int32_t __kernel_timer_t;
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
    // Open File descriptor locks (Linux specific)
    OFD_GETLK = 36,
    OFD_SETLK = 37,
    OFD_SETLKW = 38,
    // Other Linux-specific operations
    DUPFD_CLOEXEC = 0x400 + 6,
    ADD_SEALS = 0x400 + 9
  };
};

// Various ELF constants we use. These are verified to be the same
// as those in the system headers by kernel_abi.cc
enum ELFCLASS { CLASSNONE = 0, CLASS32 = 1, CLASS64 = 2 };
enum ELFENDIAN { DATA2LSB = 1 };
enum EM {
  I386 = 3,
  X86_64 = 62,
};

struct WordSize32Defs {
  static const ::size_t SIGINFO_PAD_SIZE =
      (KernelConstants::SIGINFO_MAX_SIZE / sizeof(int32_t)) - 3;

  typedef int16_t signed_short;
  typedef uint16_t unsigned_short;

  typedef int32_t signed_int;
  typedef uint32_t unsigned_int;

  typedef int32_t signed_long;
  typedef uint32_t unsigned_long;

  typedef int32_t signed_word;
  typedef uint32_t unsigned_word;

  typedef uint32_t size_t;
  typedef int32_t ssize_t;

  // These really only exist as proper abstractions so that adding x32
  // (x86-64's ILP32 ABI) support is relatively easy.
  typedef int32_t syscall_slong_t;
  typedef uint32_t syscall_ulong_t;
  typedef int32_t sigchld_clock_t;
  typedef uint32_t __statfs_word;

  static const size_t elfclass = ELFCLASS::CLASS32;
  typedef struct {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
  } ElfEhdr;
  RR_VERIFY_TYPE_ARCH(RR_NATIVE_ARCH, ::Elf32_Ehdr, ElfEhdr);
  typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
  } ElfShdr;
  RR_VERIFY_TYPE_ARCH(RR_NATIVE_ARCH, ::Elf32_Shdr, ElfShdr);
  typedef struct {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
  } ElfSym;
  RR_VERIFY_TYPE_ARCH(RR_NATIVE_ARCH, ::Elf32_Sym, ElfSym);
  typedef struct {
    int32_t d_tag;
    uint32_t d_val;
  } ElfDyn;
  RR_VERIFY_TYPE_ARCH(RR_NATIVE_ARCH, ::Elf32_Dyn, ElfDyn);
};

struct WordSize64Defs {
  static const ::size_t SIGINFO_PAD_SIZE =
      (KernelConstants::SIGINFO_MAX_SIZE / sizeof(int32_t)) - 4;

  typedef int16_t signed_short;
  typedef uint16_t unsigned_short;

  typedef int32_t signed_int;
  typedef uint32_t unsigned_int;

  typedef int64_t signed_long;
  typedef uint64_t unsigned_long;

  typedef int64_t signed_word;
  typedef uint64_t unsigned_word;

  typedef uint64_t size_t;
  typedef int64_t ssize_t;

  // These really only exist as proper abstractions so that adding x32
  // (x86-64's ILP32 ABI) support is relatively easy.
  typedef int64_t syscall_slong_t;
  typedef uint64_t syscall_ulong_t;
  typedef int64_t sigchld_clock_t;
  typedef signed_long __statfs_word;

  static const size_t elfclass = ELFCLASS::CLASS64;
  typedef struct {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
  } ElfEhdr;
  RR_VERIFY_TYPE_ARCH(RR_NATIVE_ARCH, ::Elf64_Ehdr, ElfEhdr);
  typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
  } ElfShdr;
  RR_VERIFY_TYPE_ARCH(RR_NATIVE_ARCH, ::Elf64_Shdr, ElfShdr);
  typedef struct {
    uint32_t st_name;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
  } ElfSym;
  RR_VERIFY_TYPE_ARCH(RR_NATIVE_ARCH, ::Elf64_Sym, ElfSym);
  typedef struct {
    uint64_t d_tag;
    uint64_t d_val;
  } ElfDyn;
  RR_VERIFY_TYPE_ARCH(RR_NATIVE_ARCH, ::Elf64_Dyn, ElfDyn);
};

/**
 * Structs defined in BaseArch and its derivatives should not contain any
 * holes. Holes can cause divergence if such structs are copied from rr to
 * the tracee.
 */
template <SupportedArch arch_, typename wordsize>
struct BaseArch : public wordsize,
                  public FcntlConstants,
                  public KernelConstants {
  static SupportedArch arch() { return arch_; }

  typedef typename wordsize::syscall_slong_t syscall_slong_t;
  typedef typename wordsize::syscall_ulong_t syscall_ulong_t;
  typedef typename wordsize::signed_int signed_int;
  typedef typename wordsize::unsigned_int unsigned_int;
  typedef typename wordsize::signed_short signed_short;
  typedef typename wordsize::unsigned_short unsigned_short;
  typedef typename wordsize::signed_long signed_long;
  typedef typename wordsize::unsigned_long unsigned_long;
  typedef typename wordsize::unsigned_word unsigned_word;
  typedef typename wordsize::size_t size_t;
  typedef typename wordsize::ssize_t ssize_t;
  typedef typename wordsize::sigchld_clock_t sigchld_clock_t;
  typedef typename wordsize::__statfs_word __statfs_word;

  typedef syscall_slong_t time_t;
  typedef syscall_slong_t off_t;
  typedef syscall_slong_t blkcnt_t;
  typedef syscall_slong_t blksize_t;
  typedef syscall_ulong_t rlim_t;
  typedef syscall_ulong_t fsblkcnt_t;
  typedef syscall_ulong_t fsfilcnt_t;
  typedef syscall_ulong_t ino_t;
  typedef syscall_ulong_t nlink_t;

  typedef int64_t off64_t;
  typedef uint64_t rlim64_t;
  typedef uint64_t ino64_t;
  typedef int64_t blkcnt64_t;

  typedef syscall_slong_t clock_t;
  typedef signed_int __kernel_key_t;
  typedef signed_int __kernel_uid32_t;
  typedef signed_int __kernel_gid32_t;
  typedef unsigned_int __kernel_mode_t;
  typedef unsigned_long __kernel_ulong_t;
  typedef signed_long __kernel_long_t;
  typedef __kernel_long_t __kernel_time_t;
  typedef __kernel_long_t __kernel_suseconds_t;
  typedef signed_int __kernel_pid_t;
  typedef int64_t __kernel_loff_t;

  typedef unsigned_int __u32;

  template <typename T> struct ptr {
    typedef T Referent;
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
      DEBUG_ASSERT(val == pt.as_int());
      return *this;
    }
    operator bool() const { return val; }
    static size_t referent_size() { return sizeof(T); }
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

  struct sockaddr_un {
    unsigned_short sun_family;
    char sun_path[108];
  };
  RR_VERIFY_TYPE(sockaddr_un);

  struct timeval {
    __kernel_time_t tv_sec;
    __kernel_suseconds_t tv_usec;
  };
  RR_VERIFY_TYPE(timeval);

  struct timespec {
    __kernel_time_t tv_sec;
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
    char _padding[sizeof(ptr<void>) - sizeof(socklen_t)];

    ptr<iovec> msg_iov;
    size_t msg_iovlen;

    ptr<void> msg_control;
    size_t msg_controllen;

    signed_int msg_flags;
  };
  RR_VERIFY_TYPE(msghdr);

  struct cmsghdr {
    size_t cmsg_len;
    int cmsg_level;
    int cmsg_type;
  };
  RR_VERIFY_TYPE(cmsghdr);

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
    char _padding[3];
    speed_t c_ispeed;
    speed_t c_ospeed;
  };
  RR_VERIFY_TYPE(termios);

  struct termio {
    unsigned_short c_iflag;
    unsigned_short c_oflag;
    unsigned_short c_cflag;
    unsigned_short c_lflag;
    unsigned char c_line;
    unsigned char c_cc[8];
  };
  RR_VERIFY_TYPE(termio);

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
    unsigned_short seq;
    unsigned_short __pad2;
    char __pad3[sizeof(__kernel_ulong_t) - 2 * sizeof(unsigned_short)];
    __kernel_ulong_t unused1;
    __kernel_ulong_t unused2;
  };
  RR_VERIFY_TYPE(ipc64_perm);

  struct msqid64_ds {
    ipc64_perm msg_perm;
    // These msg*time fields are really __kernel_time_t plus
    // appropriate padding.  We don't touch the fields, though.
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

  /* Don't align for the 64-bit values on 32-bit x86 */
  struct __attribute__((packed)) shmid64_ds {
    ipc64_perm shm_perm;
    size_t shm_segsz;
    uint64_t shm_atime_only_little_endian;
    uint64_t shm_dtime_only_little_endian;
    uint64_t shm_ctime_only_little_endian;
    __kernel_pid_t shm_cpid;
    __kernel_pid_t shm_lpid;
    __kernel_ulong_t shm_nattch;
    __kernel_ulong_t unused4;
    __kernel_ulong_t unused5;
  };
  RR_VERIFY_TYPE(shmid64_ds);

  struct shminfo64 {
    __kernel_ulong_t shmmax;
    __kernel_ulong_t shmmin;
    __kernel_ulong_t shmmni;
    __kernel_ulong_t shmseg;
    __kernel_ulong_t shmall;
    __kernel_ulong_t unused1;
    __kernel_ulong_t unused2;
    __kernel_ulong_t unused3;
    __kernel_ulong_t unused4;
  };
  RR_VERIFY_TYPE(shminfo64);

  struct shm_info {
    int used_ids;
    char __pad[sizeof(__kernel_ulong_t) - sizeof(int)];
    __kernel_ulong_t shm_tot;
    __kernel_ulong_t shm_rss;
    __kernel_ulong_t shm_swp;
    __kernel_ulong_t swap_attempts;
    __kernel_ulong_t swap_successes;
  };
  RR_VERIFY_TYPE(shm_info);

  struct semid64_ds {
    ipc64_perm sem_perm;
    __kernel_time_t sem_otime;
    __kernel_ulong_t __unused1;
    __kernel_time_t sem_ctime;
    __kernel_ulong_t __unused2;
    __kernel_ulong_t sem_nsems;
    __kernel_ulong_t __unused3;
    __kernel_ulong_t __unused4;
  };
  RR_VERIFY_TYPE(semid64_ds);

  struct seminfo {
    int semmap;
    int semmni;
    int semmns;
    int semmnu;
    int semmsl;
    int semopm;
    int semume;
    int semusz;
    int semvmx;
    int semaem;
  };
  RR_VERIFY_TYPE(seminfo);

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

  struct __user_cap_header_struct {
    __u32 version;
    int pid;
  };
  RR_VERIFY_TYPE(__user_cap_header_struct);

  struct __user_cap_data_struct {
    __u32 effective;
    __u32 permitted;
    __u32 inheritable;
  };
  RR_VERIFY_TYPE(__user_cap_data_struct);

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
    char __pad[sizeof(ptr<void>) - sizeof(int)];
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

  struct _flock {
    signed_short l_type;
    signed_short l_whence;
    char __pad[sizeof(off_t) - 2 * sizeof(short)];
    off_t l_start;
    off_t l_len;
    pid_t l_pid;
  };
  RR_VERIFY_TYPE_EXPLICIT(struct ::flock, _flock);

  struct flock64 {
    signed_short l_type;
    signed_short l_whence;
    // No padding on 32-bit, 4 bytes of padding on 64-bit
    char __pad[sizeof(uint32_t) - 2 * sizeof(short)];
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
    char __pad[sizeof(ptr<void>) - sizeof(int)];
    ptr<sockaddr> addr;
    ptr<socklen_t> addrlen;
  };

  struct accept4_args {
    signed_int sockfd;
    char __pad[sizeof(ptr<void>) - sizeof(int)];
    ptr<sockaddr> addr;
    ptr<socklen_t> addrlen;
    signed_long flags;
  };

  struct getsockname_args {
    signed_int sockfd;
    char __pad[sizeof(ptr<void>) - sizeof(int)];
    ptr<sockaddr> addr;
    ptr<socklen_t> addrlen;
  };

  struct getsockopt_args {
    signed_int sockfd;
    signed_int level;
    signed_int optname;
    char __pad[sizeof(ptr<void>) - sizeof(int)];
    ptr<void> optval;
    ptr<socklen_t> optlen;
  };

  struct setsockopt_args {
    signed_long sockfd;
    signed_long level;
    signed_long optname;
    ptr<void> optval;
    signed_long optlen;
  };

  struct connect_args {
    signed_long sockfd;
    ptr<void> addr;
    socklen_t addrlen;
  };

  struct recv_args {
    signed_int sockfd;
    char __pad[sizeof(ptr<void>) - sizeof(int)];
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
    char __pad[sizeof(ptr<void>) - sizeof(int)];
    ptr<msghdr> msg;
    signed_int flags;
  };

  struct recvmmsg_args {
    signed_int sockfd;
    char __pad[sizeof(ptr<void>) - sizeof(int)];
    ptr<mmsghdr> msgvec;
    unsigned_int vlen;
    unsigned_int flags;
    ptr<timespec> timeout;
  };

  struct sendmsg_args {
    signed_int fd;
    char __pad[sizeof(ptr<void>) - sizeof(int)];
    ptr<msghdr> msg;
    signed_int flags;
  };

  struct sendmmsg_args {
    signed_int sockfd;
    char __pad[sizeof(ptr<void>) - sizeof(int)];
    ptr<mmsghdr> msgvec;
    unsigned_int vlen;
    unsigned_int flags;
  };

  struct socketpair_args {
    signed_int domain;
    signed_int type;
    signed_int protocol;
    char __pad[sizeof(ptr<void>) - sizeof(int)];
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
    char __pad[sizeof(off_t) - sizeof(int)];
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
    char __pad[sizeof(ptr<void>) - sizeof(int)];
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
    char __pad[sizeof(ptr<void>) - sizeof(int)];
    ptr<void> oldval;
    ptr<size_t> oldlenp;
    ptr<void> newval;
    ptr<size_t> newlen;
    unsigned_long __rr_unused[4];
  };
  RR_VERIFY_TYPE(__sysctl_args);

  typedef struct {
    unsigned_long __val[64 / (8 * sizeof(unsigned_long))];
  } kernel_sigset_t;

  // libc reserves some space in the user facing structures for future
  // extensibility.
  typedef struct {
    unsigned_long __val[1024 / (8 * sizeof(unsigned_long))];
  } __sigset_t;
  typedef __sigset_t sigset_t;
  RR_VERIFY_TYPE(sigset_t);

  typedef struct {
    ptr<const kernel_sigset_t> ss;
    size_t ss_len;
  } pselect6_arg6;

  struct kernel_sigaction {
    ptr<void> k_sa_handler;
    unsigned_long sa_flags;
    ptr<void> sa_restorer;
    kernel_sigset_t sa_mask;
  };
  struct tms {
    clock_t tms_utime;
    clock_t tms_stime;
    clock_t tms_cutime;
    clock_t tms_cstime;
  };
  RR_VERIFY_TYPE(tms);

  struct rlimit {
    rlim_t rlim_cur;
    rlim_t rlim_max;
  };
  RR_VERIFY_TYPE(rlimit);

  struct rlimit64 {
    rlim64_t rlim_cur;
    rlim64_t rlim_max;
  };
  RR_VERIFY_TYPE(rlimit64);

  struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
  };
  RR_VERIFY_TYPE_EXPLICIT(struct ::timezone, timezone);

  struct statfs {
    __statfs_word f_type;
    __statfs_word f_bsize;
    __statfs_word f_blocks;
    __statfs_word f_bfree;
    __statfs_word f_bavail;
    __statfs_word f_files;
    __statfs_word f_ffree;
    struct {
      int __val[2];
    } f_fsid;
    __statfs_word f_namelen;
    __statfs_word f_frsize;
    __statfs_word f_flags;
    __statfs_word f_spare[4];
  };
  RR_VERIFY_TYPE_EXPLICIT(struct ::statfs, statfs);

  struct statfs64 {
    __statfs_word f_type;
    __statfs_word f_bsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint64_t f_files;
    uint64_t f_ffree;
    struct {
      int __val[2];
    } f_fsid;
    __statfs_word f_namelen;
    __statfs_word f_frsize;
    __statfs_word f_flags;
    __statfs_word f_spare[4];
  };
  RR_VERIFY_TYPE_EXPLICIT(struct ::statfs64, statfs64);

  struct itimerval {
    timeval it_interval;
    timeval it_value;
  };
  RR_VERIFY_TYPE(itimerval);

  struct itimerspec {
    timespec it_interval;
    timespec it_value;
  };
  RR_VERIFY_TYPE(itimerspec);

  typedef struct sigaltstack {
    ptr<void> ss_sp;
    int ss_flags;
    char __pad[sizeof(size_t) - sizeof(int)];
    size_t ss_size;
  } stack_t;
  RR_VERIFY_TYPE(stack_t);

  struct sysinfo {
    __kernel_long_t uptime;
    __kernel_ulong_t loads[3];
    __kernel_ulong_t totalram;
    __kernel_ulong_t freeram;
    __kernel_ulong_t sharedram;
    __kernel_ulong_t bufferram;
    __kernel_ulong_t totalswap;
    __kernel_ulong_t freeswap;
    uint16_t procs;
    uint16_t pad;
    char __pad[sizeof(__kernel_ulong_t) - 2 * sizeof(uint16_t)];
    __kernel_ulong_t totalhigh;
    __kernel_ulong_t freehigh;
    uint32_t mem_unit;
    char _f[20 - 2 * sizeof(__kernel_ulong_t) - sizeof(uint32_t)];
  };
  RR_VERIFY_TYPE_EXPLICIT(struct ::sysinfo, sysinfo);

  static const ::size_t UTSNAME_LENGTH = 65;
  struct utsname {
    char sysname[UTSNAME_LENGTH];
    char nodename[UTSNAME_LENGTH];
    char release[UTSNAME_LENGTH];
    char version[UTSNAME_LENGTH];
    char machine[UTSNAME_LENGTH];
    char domainname[UTSNAME_LENGTH];
  };
  RR_VERIFY_TYPE(utsname);

  struct sched_param {
    int __sched_priority;
  };
  RR_VERIFY_TYPE(sched_param);

  static void* cmsg_data(cmsghdr* cmsg) { return cmsg + 1; }
  static size_t cmsg_align(size_t len) {
    return (len + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1);
  }
  static size_t cmsg_space(size_t len) {
    return cmsg_align(sizeof(cmsghdr)) + cmsg_align(len);
  }
  static size_t cmsg_len(size_t len) {
    return cmsg_align(sizeof(cmsghdr)) + len;
  }

  struct v4l2_timecode {
    uint32_t type;
    uint32_t flags;
    uint8_t frames;
    uint8_t seconds;
    uint8_t minutes;
    uint8_t hours;
    uint8_t userbits[4];
  };
  RR_VERIFY_TYPE(v4l2_timecode);

  struct v4l2_buffer {
    uint32_t index;
    uint32_t type;
    uint32_t bytesused;
    uint32_t flags;
    uint32_t field;
    char __pad[sizeof(__kernel_ulong_t) - sizeof(uint32_t)];
    struct timeval timestamp;
    struct v4l2_timecode timecode;
    uint32_t sequence;
    uint32_t memory;
    union {
      uint32_t offset;
      unsigned_long userptr;
      ptr<void> planes;
      int32_t fd;
    } m;
    uint32_t length;
    uint32_t reserved2;
    uint32_t reserved;
  };
  RR_VERIFY_TYPE(v4l2_buffer);

  struct sock_filter {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
  };
  RR_VERIFY_TYPE(sock_filter);

  struct sock_fprog {
    uint16_t len;
    char _padding[sizeof(ptr<void>) - sizeof(uint16_t)];
    ptr<sock_filter> filter;
  };
  RR_VERIFY_TYPE(sock_fprog);

  struct robust_list {
    ptr<robust_list> next;
  };
  RR_VERIFY_TYPE(robust_list);

  struct robust_list_head {
    robust_list list;
    signed_long futex_offset;
    ptr<robust_list> list_op_pending;
  };
  RR_VERIFY_TYPE(robust_list_head);

  struct snd_ctl_card_info {
    int card;
    int pad;
    unsigned char id[16];
    unsigned char driver[16];
    unsigned char name[32];
    unsigned char longname[80];
    unsigned char reserved_[16];
    unsigned char mixername[80];
    unsigned char components[128];
  };
  RR_VERIFY_TYPE(snd_ctl_card_info);

  struct usbdevfs_iso_packet_desc {
    unsigned int length;
    unsigned int actual_length;
    unsigned int status;
  };
  RR_VERIFY_TYPE(usbdevfs_iso_packet_desc);

  struct usbdevfs_urb {
    unsigned char type;
    unsigned char endpoint;
    int status;
    unsigned int flags;
    ptr<void> buffer;
    int buffer_length;
    int actual_length;
    int start_frame;
    union {
      int number_of_packets;
      unsigned int stream_id;
    };
    int error_count;
    unsigned int signr;
    ptr<void> usercontext;
    struct usbdevfs_iso_packet_desc iso_frame_desc[0];
  };
  RR_VERIFY_TYPE(usbdevfs_urb);

  struct usbdevfs_ioctl {
    int ifno;
    int ioctl_code;
    ptr<void> data;
  };
  RR_VERIFY_TYPE(usbdevfs_ioctl);

  struct usbdevfs_ctrltransfer {
    uint8_t bRequestType;
    uint8_t bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
    uint32_t timeout;
    ptr<void> data;
  };
  RR_VERIFY_TYPE(usbdevfs_ctrltransfer);

  struct dirent {
    ino_t d_ino;
    off_t d_off;
    uint16_t d_reclen;
    //    uint8_t d_type;
    uint8_t d_name[256];
  };
  RR_VERIFY_TYPE(dirent);

  struct dirent64 {
    ino64_t d_ino;
    off64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    uint8_t d_name[256];
  };
  RR_VERIFY_TYPE(dirent64);

  struct mq_attr {
    signed_long mq_flags;
    signed_long mq_maxmsg;
    signed_long mq_msgsize;
    signed_long mq_curmsgs;
    signed_long __reserved[4];
  };
  RR_VERIFY_TYPE(mq_attr);

  struct xt_counters {
    uint64_t pcnt, bcnt;
  };
  RR_VERIFY_TYPE(xt_counters);

  struct ipt_replace {
    uint8_t name[32];
    uint32_t valid_hook;
    uint32_t num_entries;
    uint32_t size;
    uint32_t hook_entry[5];
    uint32_t underflow[5];
    uint32_t num_counters;
    ptr<xt_counters> counters; // ptr<xt_counters>
    // Plus hangoff here
  };
  // The corresponding header requires -fpermissive, which we don't pass. Skip
  // this check.
  // RR_VERIFY_TYPE(ipt_replace);

  struct cap_header {
    uint32_t version;
    int pid;
  };

  struct cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
  };

  struct hci_dev_req {
    uint16_t dev_id;
    uint32_t dev_opt;
  };

  struct hci_dev_list_req {
    uint16_t dev_num;
    struct hci_dev_req dev_req[0];
  };

  typedef struct { uint8_t b[6]; } __attribute__((__packed__)) bdaddr_t;

  struct hci_dev_stats {
    uint32_t err_rx;
    uint32_t err_tx;
    uint32_t cmd_tx;
    uint32_t evt_rx;
    uint32_t acl_tx;
    uint32_t acl_rx;
    uint32_t sco_tx;
    uint32_t sco_rx;
    uint32_t byte_rx;
    uint32_t byte_tx;
  };

  struct hci_dev_info {
    uint16_t dev_id;
    char name[8];

    bdaddr_t bdaddr;

    uint32_t flags;
    uint8_t type;

    uint8_t features[8];

    uint32_t pkt_type;
    uint32_t link_policy;
    uint32_t link_mode;

    uint16_t acl_mtu;
    uint16_t acl_pkts;
    uint16_t sco_mtu;
    uint16_t sco_pkts;

    struct hci_dev_stats stat;
  };

  typedef struct ifbond {
    int32_t bond_mode;
    int32_t num_slaves;
    int32_t miimon;
  } ifbond;
  RR_VERIFY_TYPE(ifbond);

  typedef struct timex {
    unsigned int modes;
    __kernel_long_t offset;
    __kernel_long_t freq;
    __kernel_long_t maxerror;
    __kernel_long_t esterror;
    int status;
    __kernel_long_t constant;
    __kernel_long_t precision;
    __kernel_long_t tolerance;
    timeval time;
    __kernel_long_t tick;
    __kernel_long_t ppsfreq;
    __kernel_long_t jitter;
    int shift;
    __kernel_long_t stabil;
    __kernel_long_t jitcnt;
    __kernel_long_t calcnt;
    __kernel_long_t errcnt;
    __kernel_long_t stbcnt;
    int tai;

    // Further padding bytes to allow for future expansion.
    int : 32;
    int : 32;
    int : 32;
    int : 32;
    int : 32;
    int : 32;
    int : 32;
    int : 32;
    int : 32;
    int : 32;
    int : 32;
  } timex;
  RR_VERIFY_TYPE(timex);

  typedef struct statx_timestamp {
    int64_t tv_sec;
    uint32_t tv_nsec;
    int32_t __reserved;
  } statx_timestamp;
  // statx_timestamp not yet widely available in system headers
  // RR_VERIFY_TYPE(statx_timestamp);

  typedef struct statx_struct {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t __spare0;
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    statx_timestamp stx_atime;
    statx_timestamp stx_btime;
    statx_timestamp stx_ctime;
    statx_timestamp stx_mtime;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t __spare2[14];
  } statx;
  // statx not yet widely available in system headers
  // RR_VERIFY_TYPE(statx);
};

struct X86Arch : public BaseArch<SupportedArch::x86, WordSize32Defs> {
  static const size_t elfmachine = EM::I386;
  static const size_t elfendian = ELFENDIAN::DATA2LSB;

  static const MmapCallingSemantics mmap_semantics = StructArguments;
  static const CloneTLSType clone_tls_type = UserDescPointer;
  static const CloneParameterOrdering clone_parameter_ordering =
      FlagsStackParentTLSChild;
  static const SelectCallingSemantics select_semantics = SelectStructArguments;

  // The getgroups syscall (as well as several others) differs between
  // architectures depending on whether they ever supported 16-bit
  // {U,G}IDs or not.  Architectures such as x86, which did support
  // 16-bit {U,G}IDs, have a getgroups syscall for the 16-bit GID case
  // and a getgroups32 syscall for the 32-bit GID case.  Architectures
  // such as as x86-64, which support 32-bit GIDs exclusively, have only
  // a getgroups syscall.  We need to know which one we're dealing with
  // when recording and replaying getgroups and related syscalls.
  typedef uint16_t legacy_uid_t;
  typedef uint16_t legacy_gid_t;

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
#if defined(__i386__)
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86, ::user_fpxregs_struct,
                      user_fpxregs_struct);
#endif

  struct sigcontext {
    uint16_t gs, __gsh;
    uint16_t fs, __fsh;
    uint16_t es, __esh;
    uint16_t ds, __dsh;
    uint32_t di;
    uint32_t si;
    uint32_t bp;
    uint32_t sp;
    uint32_t bx;
    uint32_t dx;
    uint32_t cx;
    uint32_t ax;
    uint32_t trapno;
    uint32_t err;
    uint32_t ip;
    uint16_t cs, __csh;
    uint32_t flags;
    uint32_t sp_at_signal;
    uint16_t ss, __ssh;
    uint32_t fpstate;
    uint32_t oldmask;
    uint32_t cr2;
  };
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86, ::sigcontext, sigcontext);

  struct ucontext_t {
    uint32_t uc_flags;
    uint32_t uc_link;
    stack_t uc_stack;
    sigcontext uc_mcontext;
    kernel_sigset_t uc_sigmask;
  };

  struct rt_sigframe {
    uint32_t pretcode;
    int sig;
    uint32_t pinfo;
    uint32_t puc;
    siginfo_t info;
    struct ucontext_t uc;
  };

  struct _fpstate_32 {
    uint32_t cw, sw, tag, ipoff, cssel, dataoff, datasel;
    uint16_t _st[40];
    uint16_t status, magic;
    uint32_t _fxsr_env[6], mxcsr, reserved;
    uint32_t _fxsr_st[32];
    uint32_t _xmm[32];
    uint32_t padding[56];
  };

  struct sigframe {
    uint32_t pretcode;
    int sig;
    sigcontext sc;
    _fpstate_32 unused;
    uint32_t extramask;
    char retcode[8];
  };

  struct user {
    user_regs_struct regs;
    int u_fpvalid;
    user_fpregs_struct i387;
    uint32_t u_tsize;
    uint32_t u_dsize;
    uint32_t u_ssize;
    uint32_t start_code;
    uint32_t start_stack;
    int32_t signal;
    int reserved;
    ptr<user_regs_struct> u_ar0;
    ptr<user_fpregs_struct> u_fpstate;
    uint32_t magic;
    char u_comm[32];
    int u_debugreg[8];
  };
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86, ::user, user);

  struct stat {
    dev_t st_dev;
    unsigned_short __pad1;
    ino_t st_ino;
    mode_t st_mode;
    nlink_t st_nlink;
    uid_t st_uid;
    gid_t st_gid;
    dev_t st_rdev;
    unsigned_short __pad2;
    off_t st_size;
    blksize_t st_blksize;
    blkcnt_t st_blocks;
    timespec st_atim;
    timespec st_mtim;
    timespec st_ctim;
    unsigned_long __unused4;
    unsigned_long __unused5;
  };
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86, struct ::stat, struct stat);

  struct __attribute__((packed)) stat64 {
    dev_t st_dev;
    unsigned_int __pad1;
    ino_t __st_ino;
    mode_t st_mode;
    nlink_t st_nlink;
    uid_t st_uid;
    gid_t st_gid;
    dev_t st_rdev;
    unsigned_int __pad2;
    off64_t st_size;
    blksize_t st_blksize;
    blkcnt64_t st_blocks;
    timespec st_atim;
    timespec st_mtim;
    timespec st_ctim;
    ino64_t st_ino;
  };
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86, struct ::stat64, struct stat64);
};

struct X64Arch : public BaseArch<SupportedArch::x86_64, WordSize64Defs> {
  static const size_t elfmachine = EM::X86_64;
  static const size_t elfendian = ELFENDIAN::DATA2LSB;

  static const MmapCallingSemantics mmap_semantics = RegisterArguments;
  static const CloneTLSType clone_tls_type = PthreadStructurePointer;
  static const CloneParameterOrdering clone_parameter_ordering =
      FlagsStackParentChildTLS;
  static const SelectCallingSemantics select_semantics =
      SelectRegisterArguments;

  typedef uint32_t legacy_uid_t;
  typedef uint32_t legacy_gid_t;

#include "SyscallEnumsX64.generated"

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
    // Unsigned type matches <sys/user.h>, but we need to treat this as
    // signed in practice.
    uint64_t orig_rax;
    uint64_t rip;
    uint64_t cs;
    uint64_t eflags;
    uint64_t rsp;
    uint64_t ss;
    // These _base registers are architecturally defined MSRs and really do
    // need to be 64-bit.
    uint64_t fs_base;
    uint64_t gs_base;
    uint64_t ds;
    uint64_t es;
    uint64_t fs;
    uint64_t gs;
  };
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86_64, ::user_regs_struct,
                      user_regs_struct);

  struct sigcontext {
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t di;
    uint64_t si;
    uint64_t bp;
    uint64_t bx;
    uint64_t dx;
    uint64_t ax;
    uint64_t cx;
    uint64_t sp;
    uint64_t ip;
    uint64_t flags;
    uint16_t cs;
    uint16_t gs;
    uint16_t fs;
    uint16_t __pad0;
    uint64_t err;
    uint64_t trapno;
    uint64_t oldmask;
    uint64_t cr2;
    uint64_t fpstate;
    uint64_t reserved[8];
  };
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86_64, ::sigcontext, sigcontext);

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

  struct ucontext_t {
    uint64_t ucflags;
    ptr<struct ucontext_t> uc_link;
    stack_t uc_stack;
    struct sigcontext uc_mcontext;
    sigset_t uc_sigmask;
    user_fpregs_struct uc_fpregs;
  };
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86_64, ::ucontext_t, ucontext_t);

  struct rt_sigframe {
    ptr<char> pretcode;
    struct ucontext_t uc;
    siginfo_t info;
  };

  struct user {
    struct user_regs_struct regs;
    int u_fpvalid;
    struct user_fpregs_struct i387;
    uint64_t u_tsize;
    uint64_t u_dsize;
    uint64_t u_ssize;
    uint64_t start_code;
    uint64_t start_stack;
    int64_t signal;
    int reserved;
    union {
      struct user_regs_struct* u_ar0;
      uint64_t __u_ar0_word;
    };
    union {
      struct user_fpregs_struct* u_fpstate;
      uint64_t __u_fpstate_word;
    };
    uint64_t magic;
    char u_comm[32];
    uint64_t u_debugreg[8];
  };
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86_64, ::user, user);

  struct stat {
    dev_t st_dev;
    ino_t st_ino;
    nlink_t st_nlink;
    mode_t st_mode;
    uid_t st_uid;
    gid_t st_gid;
    int __pad0;
    dev_t st_rdev;
    off_t st_size;
    blksize_t st_blksize;
    blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    syscall_slong_t __rr_unused[3];
  };
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86_64, struct ::stat, struct stat);

  struct stat64 {
    dev_t st_dev;
    ino_t st_ino;
    nlink_t st_nlink;
    mode_t st_mode;
    uid_t st_uid;
    gid_t st_gid;
    int __pad0;
    dev_t st_rdev;
    off_t st_size;
    blksize_t st_blksize;
    blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    syscall_slong_t __rr_unused[3];
  };
  RR_VERIFY_TYPE_ARCH(SupportedArch::x86_64, struct ::stat64, struct stat64);
};

#define RR_ARCH_FUNCTION(f, arch, args...)                                     \
  switch (arch) {                                                              \
    default:                                                                   \
      DEBUG_ASSERT(0 && "Unknown architecture");                               \
      RR_FALLTHROUGH;                                                          \
    case x86:                                                                  \
      return f<rr::X86Arch>(args);                                             \
    case x86_64:                                                               \
      return f<rr::X64Arch>(args);                                             \
  }

#include "SyscallHelperFunctions.generated"

/**
 * Return true if |ptr| in task |t| points to an invoke-syscall instruction,
 * and if so, return the architecture for which this is a syscall in *arch.
 */
bool get_syscall_instruction_arch(Task* t, remote_code_ptr ptr,
                                  SupportedArch* arch);

/**
 * Return true if |ptr| in task |t| points to an invoke-syscall instruction.
 */
bool is_at_syscall_instruction(Task* t, remote_code_ptr ptr);

/**
 * Return the code bytes of an invoke-syscall instruction. The vector must
 * have the length given by |syscall_instruction_length|.
 */
std::vector<uint8_t> syscall_instruction(SupportedArch arch);

/**
 * Return the length of all invoke-syscall instructions. Currently,
 * they must all have the same length!
 */
ssize_t syscall_instruction_length(SupportedArch arch);

void set_arch_siginfo(const siginfo_t& siginfo, SupportedArch a, void* dest,
                      size_t dest_size);

#if defined(__i386__)
typedef X86Arch NativeArch;
#elif defined(__x86_64__)
typedef X64Arch NativeArch;
#else
#error need to define new NativeArch
#endif

} // namespace rr

#endif /* RR_KERNEL_ABI_H */
