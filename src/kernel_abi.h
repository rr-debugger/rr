/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_KERNEL_ABI_H
#define RR_KERNEL_ABI_H

// Get all the kernel definitions so we can verify our alternative versions.
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include <assert.h>

namespace rr {

enum supported_arch {
	x86,
};

#if defined(__i386__)
#define RR_NATIVE_ARCH supported_arch::x86
#else
#error need to define new supported_arch enum
#endif

template<supported_arch a, typename system_type, typename rr_type>
struct verifier {
	// Optimistically say we are the same size.
	static const bool same_size = true;
};

template<typename system_type, typename rr_type>
struct verifier<RR_NATIVE_ARCH, system_type, rr_type> {
	static const bool same_size = sizeof(system_type) == sizeof(rr_type);
};

template<typename T>
struct verifier<RR_NATIVE_ARCH, T, T> {
	// Prevent us from accidentally verifying the size of rr's structure
	// with itself or (unlikely) the system's structure with itself.
};

// For instances where the system type and the rr type are named differently.
#define RR_VERIFY_TYPE_EXPLICIT(system_type_, rr_type_)	\
  static_assert(verifier<arch, system_type_, rr_type_>::same_size, \
		"type " #system_type_ " not correctly defined");

// For instances where the system type and the rr type are named identically.
#define RR_VERIFY_TYPE(type_) RR_VERIFY_TYPE_EXPLICIT(struct ::type_, type_)

struct kernel_constants {
	static const ::size_t SIGINFO_MAX_SIZE = 128;

	// These types are the same size everywhere.
	typedef int32_t pid_t;
	typedef uint32_t uid_t;

	typedef uint32_t socklen_t;
};

struct wordsize32_defs : public kernel_constants {
	static const ::size_t SIGINFO_PAD_SIZE = (SIGINFO_MAX_SIZE / sizeof(int32_t)) - 3;

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
};

template<supported_arch arch, typename wordsize>
struct base_arch : public wordsize {
	typedef typename wordsize::syscall_slong_t syscall_slong_t;
	typedef typename wordsize::signed_int signed_int;
	typedef typename wordsize::unsigned_int unsigned_int;
	typedef typename wordsize::signed_short signed_short;
	typedef typename wordsize::unsigned_short unsigned_short;
	typedef typename wordsize::signed_long signed_long;
	typedef typename wordsize::unsigned_word unsigned_word;
	typedef typename wordsize::sigchld_clock_t sigchld_clock_t;

	typedef syscall_slong_t time_t;
	typedef syscall_slong_t suseconds_t;
	typedef syscall_slong_t off_t;

	typedef syscall_slong_t clock_t;

	template<typename T>
	struct ptr {
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

	// XXX what to do about __EPOLL_PACKED?  Explicit specialization?
	struct epoll_event {
		union epoll_data {
			ptr<void> ptr_;
			signed_int fd;
			uint32_t u32;
			uint64_t u64;
		};

		uint32_t events;
		epoll_data data;
	};
	RR_VERIFY_TYPE(epoll_event);

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
};

struct x86_arch : public base_arch<supported_arch::x86, wordsize32_defs> {
};

} // namespace rr

#endif /* RR_KERNEL_ABI_H */
