/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

/**
 * The wrapper for the system calls, which allows interception and recording of system calls that are invoked using the libc wrapper.
 * The filter in install_syscall_filter() will ptrace all syscalls that do no originate from this wrapper, so that rr will handle them.
 *
 * Note 1: All the internal code of the wrapper uses syscall(...) to perform system calls instead of calling the libc code, to avoid recursion.
 * Note 2: This file must be excluded from the rr build, otherwise it will intercept rr's syscalls!
 *
 * TODO: (0) all the wrappers postfixed by "_" haven't been fully tested yet
 * TODO: (1) make the wrappers adhere better to libc (errno, etc)
 * TODO: (2) we do a lot of memcpy, using user supplied parameter as length, but the parameter may contain garbage...
 */
#define _GNU_SOURCE 1
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <poll.h>
#include <linux/futex.h>
#include <linux/net.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <pthread.h>
#include "wrap_syscalls.h"
#include "seccomp-bpf.h"
#include "dbg.h"

static __thread int * buffer = NULL; /* buffer[0] holds the size in bytes, withholding the 4 bytes used for buffer[0] itself */

static void * libstart = NULL;
static void * libend = NULL;

static char trace_path_[PATH_MAX] = { '\0' };

/**
 * Internal wrapper code goes here
 */

 /**
  * Do a un-intercepted syscall to make rr flush the buffer
  */
static void flush_buffer(void){
	pid_t tid = syscall(SYS_gettid);
	assert(buffer[0] == 0);
}

static void find_library_location(void)
{
	/* Open the maps file */
	pid_t tid = syscall(SYS_gettid);
	char path[PATH_MAX] = {0};
	sprintf(path, "/proc/%d/maps", tid);
	int maps_file = syscall(SYS_open,path,O_RDONLY);
	if (maps_file < 0) {
		/* FIXME for write() */
		fatal("Error reading child memory maps");
	}

	/* Read the maps file into memory */
	char file[4096];
	int retval = 0;
	do {
		syscall(SYS_read,maps_file,file,4096);
		/* For each line in the maps file: */
		char * line = file, *line_end;
		void *start, *end;
		char flags[32], binary[128] = {0}, *result = NULL;
		unsigned int dev_minor, dev_major;
		unsigned long long file_offset, inode;
		while ((line_end = strchr(line,'\n')) != NULL) {
			*line_end++ = '\0';
			sscanf(line,"%p-%p %31s %Lx %x:%x %Lu %s", &start, &end,flags, &file_offset, &dev_major, &dev_minor, &inode, binary);
			if (strstr(binary,WRAP_SYSCALLS_LIB_FILENAME) != NULL && /* found the library */
				strstr(flags,"x") != NULL ) { /* Note: the library get loaded several times, we need the (hopefully one) copy that is executable */
				libstart = start;
				libend = end;
				syscall(SYS_close,maps_file);
				return;
			}
			line = line_end;
		}
	} while (retval >= 0);
	syscall(SYS_close,maps_file);
	/* FIXME for write() */
	fatal("Unable to locate library in maps file");
	return;
}

/**
 * This installs the actual filter which examines the callsite and determines whether
 * it will be ptraced or handled by the intercepting library
 */
static void install_syscall_filter(void)
{
	/* figure out the library address */
	find_library_location();
	/* FIXME for write() */
	log_info("Wrapper library found at (%p,%p).",libstart,libend);
	struct sock_filter filter[] = {
		/* Validate architecture. Rob was right - this is not needed. */
		/*VALIDATE_ARCHITECTURE,*/
		/*
		 * Validate the call originated from our intercepting library (otherwise we trace it,
		 * unless it is, of course, clone or fork, which generate their own ptrace event)
		 */
		EXAMINE_CALLSITE((int)libstart,(int)libend),
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		/*
		 * Note: if these are traced, we get a SIGSTOP after child creation
		 * We don't need to trace them as they will be captured by their own ptrace event
		 */
		ALLOW_SYSCALL(clone),
		ALLOW_SYSCALL(fork),
		/* There is really no need for us to ptrace restart_syscall. In fact, this will cause an error in
		 * case the restarted syscall is in the wrapper
		 */
		ALLOW_SYSCALL(restart_syscall),
		/* List syscalls we wrap in our library */
		ALLOW_SYSCALL(clock_gettime),
		ALLOW_SYSCALL(gettimeofday),
		ALLOW_SYSCALL(madvise),
		ALLOW_SYSCALL(stat),
		ALLOW_SYSCALL(lstat),
		ALLOW_SYSCALL(fstat),
		/* These syscalls require more complex logic to decide whether they are to be traced */
		ALLOW_SOCKETCALL,
		ALLOW_FUTEX,
		/* These syscalls require a ptrace event for scheduling, but we still gain a speedup from wrapping them */
		TRACE_SYSCALL(write),
		TRACE_SYSCALL(writev),
		TRACE_SYSCALL(read),
		TRACE_SYSCALL(poll),
		TRACE_SYSCALL(epoll_wait),
		/* All the rest are handled in rr */
		TRACE_PROCESS,
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (syscall(SYS_prctl,PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		fatal("prctl(NO_NEW_PRIVS) failed, SECCOMP_FILTER is not available.");
	}

	if (syscall(SYS_prctl,PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		fatal("prctl(SECCOMP) failed, SECCOMP_FILTER is not available.");
	}
	/* anything that happens from this point on gets filtered! */
}

/* TODO: this will not work if older trace dirs with higher index exist */
static void find_trace_dir(void)
{
	const char* output_dir;
	if (!(output_dir = getenv("_RR_TRACE_DIR"))) {
		output_dir = ".";
	}
	int version = 0;
	struct stat64 sb;
	do {
		sprintf(trace_path_, "%s/trace_%d", output_dir, version);
	} while(syscall(SYS_stat64, trace_path_, &sb) == 0
		&& S_ISDIR(sb.st_mode)
		&& ++version);
	if (version == 0) {
		fatal("trace_dir not found.  Running outside of rr?");
	}
	sprintf(trace_path_, "%s/trace_%d", output_dir, version-1);
	/* FIXME for write() */
	log_info("Found trace_dir %s", trace_path_);
}

/**
 * Initialize the library:
 * 1. Install filter-by-callsite (once for all threads)
 * 2. Make subsequent threads call init()
 * 3. Open and mmap the recording cache, shared with rr (once for every thread)
 *
 * Remember: init() will only be called if the process uses at least one of the library's intercepted functions.
 *
 */

static void setup_buffer() {
	pid_t tid = syscall(SYS_gettid); /* libc does not supply a wrapper for gettid */
	char filename[PATH_MAX];
	sprintf(filename,"%s/%s%d", trace_path_, WRAP_SYSCALLS_CACHE_FILENAME_PREFIX, tid);
	errno = 0;
	int fd = syscall(SYS_open,filename, O_CREAT | O_RDWR, 0666); /* O_TRUNC here is bad */
	assert(fd > 0 && errno == 0);
	int retval;
	retval = syscall(SYS_ftruncate,fd,WRAP_SYSCALLS_CACHE_SIZE);
	assert(retval == 0 && errno == 0);
	buffer = (void*)syscall(SYS_mmap2, NULL, WRAP_SYSCALLS_CACHE_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);
	assert(buffer != NULL && errno == 0);
	retval = syscall(SYS_close,fd);
	assert(retval == 0 && errno == 0);
	/* buffer[0] holds the number of bytes written */
	buffer[0] = 0;
	/* make all subsequent children initialize their own buffer */
	pthread_atfork(NULL,NULL,setup_buffer);
}

static void init() {
	/* Note: the filter is installed only for record. This call will be emulated in the replay */
	if (!libstart) {
		find_trace_dir();
		install_syscall_filter();
	}
	setup_buffer();
}

/**
 * Wrappers start here.
 *
 * How wrappers operate:
 *
 * 1. The syscall is intercepted by the wrapper function.
 * 2. A new record is prepared on the buffer. A record is composed of:
 * 		[the syscall number]
 * 		[the overall size in bytes of the record]
 * 		[the return value]
 * 		[other syscall output, if such exists]
 * 	  _syscall_pre(extra_space) is invoked to check if the maximum amount of space
 * 	  needed for the record exceeds the buffer size, if so a flush is made.
 * 	  Note: these records will be written AS-IS to the raw file, and a succinct line will be written to the trace file (without register content, etc.)
 * 3. Then, the syscall wrapper code redirects all potential output for the syscall to the
 * 	  record (and corrects the overall size of the record while it does so).
 * 4. The syscall is invoked directly via assembly.
 * 5. The syscall output, written on the buffer, is copied to the original pointers provided by the user.
 *    Take notice that this part saves us the injection of the data on replay, as we only need to push the
 *    data to the buffer and the wrapper code will copy it to the user address for us.
 * 6. The first 3 parameters of the record are put in (return value and overall size are known now)
 * 7. buffer[0] is updated.
 * 8. errno is set.
 */

#define _syscall_pre(extra_space)					\
	if (!buffer)							\
		init();							\
	int ret;							\
	int record_size_in_bytes = (WRAP_SYSCALLS_RECORD_BASE_SIZE *	\
				    sizeof(int));			\
	if (buffer[0] + record_size_in_bytes + extra_space >		\
	    WRAP_SYSCALLS_CACHE_SIZE) {					\
		flush_buffer();						\
	}								\
	int * const new_record = (void*)buffer + sizeof(int) + buffer[0]; \
	void * ptr = &new_record[WRAP_SYSCALLS_RECORD_BASE_SIZE];

#define _syscall0(call,ret)						\
	asm volatile("int $0x80" : "=a"(ret) : "0"(__NR_##call));

#define _syscall2(call,arg0,arg1,ret)					\
	asm volatile("int $0x80" : "=a"(ret) : "0"(__NR_##call),	\
		     "b"((long)arg0), "c"((long)arg1));

#define _syscall3(call,arg0,arg1,arg2,ret)				\
	asm volatile("int $0x80" : "=a"(ret) : "0"(__NR_##call),	\
		     "b"((long)arg0), "c"((long)arg1), "d"((long)arg2));

#define _syscall4(call,arg0,arg1,arg2,arg3,ret)				\
	asm volatile("int $0x80" : "=a"(ret) : "0"(__NR_##call),	\
		     "b"((long)arg0), "c"((long)arg1), "d"((long)arg2), \
		     "S"((long)arg3));

#define _syscall6(call,arg0,arg1,arg2,arg3,arg4,arg5,ret)		\
	asm volatile("mov %6, %%ebp\n\t"				\
		     "int $0x80" : "=a"(ret) : "0"(__NR_##call),	\
		     "b"((long)arg0), "c"((long)arg1), "d"((long)arg2), \
		     "S"((long)arg3), "D"((long)arg4), "g"((long)arg5));

#define __syscall_return(res)						\
	do {								\
		if ((unsigned long)(res) >= (unsigned long)(-125)) {	\
			errno = -(res);					\
			res = -1;					\
		}							\
		return (res);						\
	} while (0)

#define _syscall_post(syscall) 			\
	new_record[0] = __NR_##syscall;		\
	new_record[1] = record_size_in_bytes;	\
	new_record[2] = ret;			\
	buffer[0] += record_size_in_bytes;	\
	__syscall_return(ret);

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
	_syscall_pre(tp ? sizeof(struct timespec) : 0)
	/* set it up so the syscall writes to the record cache */
	struct timespec *tp2 = NULL;
	if (tp) {
		record_size_in_bytes += sizeof(struct timespec);
		tp2 = ptr;
		ptr += sizeof(struct timespec);
	}
	_syscall2(clock_gettime,clk_id,tp2,ret)
	/* now in the replay we can simply push the recorded buffer and allow the wrapper to copy it to the actual parameters */
	if (tp)
		memcpy(tp, tp2, sizeof(struct timespec));
	_syscall_post(clock_gettime)
}


int gettimeofday(struct timeval *tp, struct timezone *tzp) {
	_syscall_pre((tp ? sizeof(struct timeval) : 0) + (tzp ? sizeof(struct timezone) : 0))
	/* set it up so the syscall writes to the record cache */
	struct timeval *tp2 = NULL;
	if (tp) {
		record_size_in_bytes += sizeof(struct timeval);
		tp2 = ptr;
		ptr += sizeof(struct timeval);
	}
	struct timezone *tzp2 = NULL;
	if (tzp) {
		record_size_in_bytes += sizeof(struct timezone);
		tzp2 = ptr;
		ptr += sizeof(struct timezone);
	}
	_syscall2(gettimeofday,tp2,tzp2,ret)
	/* now in the replay we can simply copy the recorded buffer and allow the wrapper to copy it to the actual parameters */
	if (tp)
		memcpy(tp, tp2, sizeof(struct timeval));
	if (tzp)
		memcpy(tzp, tzp2, sizeof(struct timezone));
	_syscall_post(gettimeofday)
}

int futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3) {
	_syscall_pre(sizeof(int))
	/* make room for (uaddr,*uaddr) */
	ptr = &new_record[5];
	record_size_in_bytes += 2 * sizeof(int);
	int * uaddr2_tmp = NULL;
	switch (op & FUTEX_CMD_MASK) {
		case FUTEX_CMP_REQUEUE:
		case FUTEX_WAKE_OP:
		case FUTEX_CMP_REQUEUE_PI:
			if (uaddr2) {
				record_size_in_bytes += sizeof(int);
				uaddr2_tmp = ptr;
				*uaddr2_tmp = *uaddr2;
				ptr += sizeof(int);
			}
			break;

		default:
			break;
	}
	_syscall6(futex,uaddr,op,val,timeout,uaddr2_tmp,val3,ret)
	/* record (uaddr,*uaddr) */
	new_record[3] = (int)uaddr;
	new_record[4] = *uaddr;
	if (uaddr2)
		*uaddr2 = *uaddr2_tmp;
	_syscall_post(futex)
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
	_syscall_pre((events && maxevents > 0) ? (maxevents * sizeof(struct epoll_event)) : 0)
	void *events2 = NULL;
	if (events && maxevents > 0) {
		events2 = ptr;
		ptr +=  (maxevents * sizeof(struct epoll_event));
	}
	_syscall4(epoll_wait,epfd,events2,maxevents,timeout,ret)
	if (ret > 0) {
		record_size_in_bytes += ret * sizeof(struct epoll_event);
		memcpy(events,events2,ret * sizeof(struct epoll_event));
	}
	_syscall_post(epoll_wait)
}

/* TODO: the socketcall API can block, and we need to handle that better. */

#define _copy_socketcall_args(arg0,arg1,arg2,arg3,arg4,arg5) \
volatile long args[6] = { (long)arg0, (long)arg1, (long)arg2, (long)arg3, (long)arg4, (long)arg5 };

int accept4_(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
	/* stuff gets recorded only if addr is not null */
	_syscall_pre(addr ? *addrlen + sizeof(socklen_t) : 0)
	_copy_socketcall_args(sockfd,addr,addrlen,flags, 0, 0)
	void *addr2 = NULL;
	socklen_t *addrlen2 = NULL;
	if (addr) {
		record_size_in_bytes += *addrlen;
		addr2 = ptr;
		ptr += *addrlen;
		args[1] = (long)addr2;
		record_size_in_bytes += sizeof(socklen_t);
		addrlen2 = ptr;
		ptr += sizeof(socklen_t);
		args[2] = (long)addrlen2;
	}
	_syscall2(socketcall,SYS_ACCEPT,args,ret)
	if (addr) {
		memcpy(addr, addr2, *addrlen2);
		*addrlen = *addrlen2;
	}
	_syscall_post(socketcall)
}

int accept_(int socket,struct sockaddr *addr, socklen_t *length_ptr) {
	return accept4(socket,addr,length_ptr,0);
}

int getpeername_(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	/* stuff gets recorded only if addr is not null */
	_syscall_pre(addr ? *addrlen + sizeof(socklen_t) : 0)
	_copy_socketcall_args(sockfd,addr,addrlen,0, 0, 0)
	void *addr2 = NULL;
	socklen_t *addrlen2 = NULL;
	if (addr) {
		record_size_in_bytes += *addrlen;
		addr2 = ptr;
		memcpy(addr2,addr,*addrlen);
		ptr += *addrlen;
		args[1] = (long)addr2;
		record_size_in_bytes += sizeof(socklen_t);
		addrlen2 = ptr;
		*addrlen2 = *addrlen;
		ptr += sizeof(socklen_t);
		args[2] = (long)addrlen2;
	}
	_syscall2(socketcall,SYS_GETPEERNAME,args,ret)
	if (addr) {
		memcpy(addr, addr2, *addrlen2);
		*addrlen = *addrlen2;
	}
	_syscall_post(socketcall)
}

int getsockname_(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	/* stuff gets recorded only if addr is not null */
	_syscall_pre(addr ? *addrlen + sizeof(socklen_t) : 0)
	_copy_socketcall_args(sockfd,addr,addrlen,0, 0, 0)
	void *addr2 = NULL;
	socklen_t *addrlen2 = NULL;
	if (addr) {
		record_size_in_bytes += *addrlen;
		addr2 = ptr;
		memcpy(addr2,addr,*addrlen);
		ptr += *addrlen;
		args[1] = (long)addr2;
		record_size_in_bytes += sizeof(socklen_t);
		addrlen2 = ptr;
		*addrlen2 = *addrlen;
		ptr += sizeof(socklen_t);
		args[2] = (long)addrlen2;
	}
	_syscall2(socketcall,SYS_GETSOCKNAME,args,ret)
	if (addr) {
		memcpy(addr, addr2, *addrlen2);
		*addrlen = *addrlen2;
	}
	_syscall_post(socketcall)
}

int getsockopt_(int sockfd, int level, int optname, void *optval, socklen_t* optlen) {
	/* stuff gets recorded only if optval is not null */
	_syscall_pre(optval ? *optlen + sizeof(socklen_t) : 0)
	_copy_socketcall_args(sockfd,level,optname,optval, optlen, 0)
	void *optval2 = NULL;
	socklen_t *optlen2 = NULL;
	if (optval && optlen) {
		record_size_in_bytes += *optlen;
		optval2 = ptr;
		memcpy(optval2,optval,*optlen);
		ptr += *optlen;
		args[3] = (long)optval2;
		record_size_in_bytes += sizeof(socklen_t);
		optlen2 = ptr;
		*optlen2 = *optlen;
		ptr += sizeof(socklen_t);
		args[4] = (long)optlen2;
	}
	_syscall2(socketcall,SYS_GETSOCKOPT,args,ret);
	if (optval) {
		memcpy(optval, optval2, *optlen2);
		*optlen = *optlen2;
	}
	_syscall_post(socketcall)
}


ssize_t recv_(int sockfd, void *buf, size_t len, int flags) {
	/* stuff gets recorded only if buf is not null */
	_syscall_pre((buf && len > 0) ? len : 0)
	_copy_socketcall_args(sockfd,buf,len,flags,0,0)
	void *buf2 = NULL;
	if (buf && len > 0) {
		record_size_in_bytes += len;
		buf2 = ptr;
		ptr += len;
		args[1] = (long)buf2;
	}
	_syscall2(socketcall,SYS_RECV,args,ret)
	if (buf && ret > 0) {
		memcpy(buf, buf2, ret);
	}
	_syscall_post(socketcall)
}

ssize_t recvfrom_(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
	/* stuff gets recorded only if buf, etc. is not null */
	_syscall_pre((buf ? len : 0) + (src_addr ? *addrlen +  sizeof(socklen_t) : 0))
	_copy_socketcall_args(sockfd,buf,len,flags, src_addr, addrlen)
	void *buf2 = NULL;
	if (buf) {
		record_size_in_bytes += len;
		buf2 = ptr;
		ptr += len;
		args[1] = (long)buf2;
	}
	struct sockaddr *src_addr2 = NULL;
	socklen_t *addrlen2 = NULL;
	if (src_addr) {
		record_size_in_bytes += *addrlen;
		src_addr2 = ptr;
		memcpy(src_addr2,src_addr,*addrlen);
		ptr += *addrlen;
		args[4] = (long)src_addr2;
		record_size_in_bytes += sizeof(socklen_t);
		addrlen2 = ptr;
		*addrlen2 = *addrlen;
		ptr += sizeof(socklen_t);
		args[5] = (long)addrlen2;
	}
	_syscall2(socketcall,SYS_RECVFROM,args,ret)
	if (buf)
		memcpy(buf, buf2, len);
	if (src_addr) {
		memcpy(src_addr, src_addr2, *addrlen2);
		*addrlen = *addrlen2;
	}
	_syscall_post(socketcall)
}

#define _socketcall_no_output(call,arg0,arg1,arg2,arg3,arg4,arg5) 	\
	_syscall_pre(0)													\
	_copy_socketcall_args(arg0,arg1,arg2,arg3,arg4,arg5)			\
	_syscall2(socketcall,call,args,ret) 							\
	_syscall_post(socketcall)

int socket_(int domain, int type, int protocol) {
	_socketcall_no_output(SYS_SOCKET,domain,type,protocol,0,0,0)
}

int bind_(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	_socketcall_no_output(SYS_BIND,sockfd,addr,addrlen,0,0,0)
}

int connect_(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	_socketcall_no_output(SYS_CONNECT,sockfd,addr,addrlen,0,0,0)
}

int listen_(int sockfd, int backlog) {
	_socketcall_no_output(SYS_LISTEN,sockfd,backlog,0,0,0,0)
}

ssize_t sendmsg_(int sockfd, const struct msghdr *msg, int flags) {
	_socketcall_no_output(SYS_SENDMSG,sockfd,msg,flags,0,0,0)
}

ssize_t send_(int sockfd, const void *buf, size_t len, int flags) {
	_socketcall_no_output(SYS_SEND,sockfd,buf,len,flags,0,0)
}

ssize_t sendto_(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
	_socketcall_no_output(SYS_SENDTO,sockfd,buf,len,flags,dest_addr,addrlen)
}

int setsockopt_(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
	_socketcall_no_output(SYS_SETSOCKOPT,sockfd,level,optname,optval,optlen,0)
}

int shutdown_(int socket, int how) {
	_socketcall_no_output(SYS_SHUTDOWN,socket,how,0,0,0,0)
}


#define _stat(call,file,buf) 						\
_syscall_pre( buf ? sizeof(struct stat) : 0 )		\
struct stat * buf2; 								\
if (buf) {											\
	buf2 = ptr;										\
	record_size_in_bytes += sizeof(struct stat); 	\
	ptr += sizeof(struct stat); 					\
}													\
_syscall2(call,file,buf2,ret)						\
if (ret == 0) {										\
	memcpy(buf,buf2,ret);							\
}													\
_syscall_post(call)

/* TODO: the stat API can block, and we need to handle that better. */

int fstat_(int fd, struct stat *buf){
	_stat(fstat64,fd,buf);
}

int lstat_(const char *path, struct stat *buf) {
	_stat(lstat64,path,buf);
}

int stat_(const char *path, struct stat *buf){
	_stat(stat64,path,buf);
}

/* TODO: fix the complex logic here */
ssize_t recvmsg_(int sockfd, struct msghdr *msg, int flags) {
	/* stuff gets recorded only if msg is not null */
	_syscall_pre(msg ? (sizeof(struct msghdr)
						/*+ (msg->msg_name ? msg->msg_namelen : 0)*/
					    + (msg->msg_iov ? sizeof(struct iovec) + msg->msg_iovlen : 0)
					    + (msg->msg_control ? msg->msg_controllen : 0) )
					    : 0)
	_copy_socketcall_args(sockfd,msg,flags, 0, 0, 0)
	struct msghdr *msg2 = NULL;
	void 		  *msg_name2 = NULL;
	struct iovec  *msg_iov2;        /* scatter/gather array */
	void		  *msg_iov_base2;
    void          *msg_control2;    /* ancillary data, see below */
	if (msg) {
		record_size_in_bytes += sizeof(struct msghdr);
		msg2 = ptr;
		memcpy(msg2,msg,sizeof(struct msghdr));
		ptr += sizeof(struct msghdr);
		args[1] = (long)msg2;
		if (msg->msg_iov) {
			assert(msg->msg_iovlen == 1);
			record_size_in_bytes += sizeof(struct iovec) + msg->msg_iovlen;
			msg2->msg_iov = msg_iov2 = ptr;
			memcpy(msg_iov2,msg->msg_iov,sizeof(struct iovec));
			ptr += sizeof(struct iovec);
			msg2->msg_iov->iov_base = msg_iov_base2 = ptr;
			memcpy(msg_iov_base2,msg->msg_iov->iov_base,msg->msg_iov->iov_len);
			ptr += msg->msg_iov->iov_len;
		}
		if (msg->msg_control) {
			record_size_in_bytes += msg->msg_controllen;
			msg2->msg_control = msg_control2 = ptr;
			memcpy(msg_control2,msg->msg_control,msg->msg_controllen);
			ptr += msg->msg_controllen;
		}
	}
	_syscall2(socketcall,SYS_RECVMSG,args,ret)
	if (msg) {
		if (msg->msg_iov) {
			msg->msg_iov->iov_len = msg_iov2->iov_len;
			memcpy(msg->msg_iov->iov_base,msg_iov2->iov_base,msg->msg_iov->iov_len);
		}
		if (msg->msg_control) {
			msg->msg_controllen = msg2->msg_controllen;
			memcpy(msg->msg_control,msg_control2,msg->msg_controllen);
		}
		msg->msg_flags = msg2->msg_flags;
	}
	_syscall_post(socketcall)
}

/* TODO: not working */
int socketpair_(int domain, int type, int protocol, int sv[2]) {
	_syscall_pre(sizeof(sv))
	_copy_socketcall_args(domain,type,protocol,sv, 0, 0)
	int * sv2;
	sv2 = ptr;
	ptr += sizeof(sv);
	record_size_in_bytes += sizeof(sv);
	args[3] = (long)sv2;
	_syscall2(socketcall,SYS_SOCKETPAIR,args,ret)
	memcpy(sv, sv2, sizeof(sv));
	_syscall_post(socketcall)
}

/* TODO: recv, recvfrom create a compilation error
int socketcall(int call, unsigned long *args){
	switch (call) {
	case SYS_SOCKET:
		return socket(args[0],args[1],args[2]);
	case SYS_BIND:
		return bind(args[0],(const struct sockaddr *)args[1],args[2]);
	case SYS_CONNECT:
		return connect(args[0],(const struct sockaddr *)args[1],args[2]);
	case SYS_LISTEN:
		return listen(args[0],args[1]);
	case SYS_ACCEPT:
		return accept(args[0],(struct sockaddr *)args[1],(socklen_t *)args[2]);
	case SYS_GETSOCKNAME:
		return getsockname(args[0],(struct sockaddr *)args[1],(socklen_t *)args[2]);
	case SYS_GETPEERNAME:
		return getpeername(args[0],(struct sockaddr *)args[1],(socklen_t *)args[2]);
	case SYS_SOCKETPAIR:
		return socketpair(args[0],args[1],args[2],(int *)args[3]);
	case SYS_SEND:
		return send(args[0],(void*)args[1],args[2],args[3]);
	case SYS_SENDTO:
		return sendto(args[0], (void *)args[1], args[2], args[3],(struct sockaddr *)args[4], args[5]);
	case SYS_RECV:
		return recv(args[0], (void *)args[1], args[2], args[3]);
	case SYS_RECVFROM:
		return recvfrom(args[0], (void *)args[1], args[2], args[3], (struct sockaddr *)args[4], (int *)args[5]);
	case SYS_SHUTDOWN:
		return shutdown(args[0], args[1]);
	case SYS_SETSOCKOPT:
		return setsockopt(args[0], args[1], args[2], (char *)args[3], args[4]);
	case SYS_GETSOCKOPT:
		return getsockopt(args[0], args[1], args[2], (char *)args[3], (int *)args[4]);
	case SYS_SENDMSG:
		return sendmsg(args[0], (struct msghdr *)args[1], args[2]);
	case SYS_SENDMMSG:
		return sendmmsg(args[0], (struct mmsghdr *)args[1], args[2], args[3]);
	case SYS_RECVMSG:
		return recvmsg(args[0], (struct msghdr *)args[1], args[2]);
	case SYS_RECVMMSG:
		return recvmmsg(args[0], (struct mmsghdr *)args[1], args[2], args[3],(struct timespec *)args[4]);
	case SYS_ACCEPT4:
		return accept4(args[0], (struct sockaddr *)args[1], (int *)args[2], args[3]);
	default:
		assert(0);
	}
}
*/


/* TODO: causes strange signal IOT */
int madvise_(void *addr, size_t length, int advice) {
	_syscall_pre(0)
	_syscall3(madvise,addr,length,advice,ret)
	_syscall_post(madvise)
}

/* TODO: makes the process die */
ssize_t read_(int fd, void *buf, size_t count) {
	_syscall_pre(buf ? count : 0)
	void *buf2 = NULL;
	if (buf) {
		buf2 = ptr;
		record_size_in_bytes += count;
		ptr += count;
	}
	_syscall3(read,fd,buf2,count,ret)
	if (buf && ret > 0) {
		memcpy(buf,buf2,ret);
	}
	_syscall_post(read)
}

/* FIXME: write does not work, this has to do with the fact that it runs before stuff gets initialized in the main thread (??) */
ssize_t write_(int fd, const void *buf, size_t count) {
	_syscall_pre(0)
	_syscall3(write,fd,buf,count,ret)
	_syscall_post(write)
}

ssize_t writev_(int fd, const struct iovec *iov, int iovcnt) {
	_syscall_pre(0)
	_syscall3(writev,fd,iov,iovcnt,ret)
	_syscall_post(writev)
}

/* TODO: hangs */
int poll_(struct pollfd *fds, nfds_t nfds, int timeout) {
	size_t size = nfds * sizeof(struct pollfd);
	_syscall_pre(fds ? size : 0)
	struct pollfd *fds2 = NULL;
	if (fds) {
		fds2 = ptr;
		record_size_in_bytes += size;
		memcpy(fds2, fds, size);
		ptr += size;
	}
	_syscall3(poll,fds2,nfds,timeout,ret)
	if (fds)
		memcpy(fds, fds2, size);
	_syscall_post(poll)
}

/* TODO: somehow, this slows us down. */
pid_t waitpid_(pid_t pid, int *status, int options) {
	_syscall_pre(status ? sizeof(int) : 0)
	int * status2 = NULL;
	if (status) {
		status2 = ptr;
		record_size_in_bytes += sizeof(int);
		ptr += sizeof(int);
	}
	_syscall3(waitpid,pid,status2,options,ret)
	if (status) {
		*status = *status2;
	}
	_syscall_post(waitpid)
}
