/**
 * The wrapper for the system calls, which allows interception and recording of system calls that are invoked using the libc wrapper.
 * The filter in install_syscall_filter() will ptrace all syscalls that do no originate from this wrapper, so that rr will handle them.
 *
 * Note: This file must be excluded from the rr build, otherwise it will intercept rr's syscalls!
 *
 * TODO: (0) all the wrappers postfixed by "_" haven't been fully tested yet
 * TODO: (1) make the wrappers adhere better to libc (errno, etc)
 * TODO: (2) if any of the syscalls used in init(), flush_buffer(), etc are wrapped, make sure to inline them otherwise we will recourse.
 * TODO: (3) we do a lot of memcpy, using user supplied parameter as length, but the parameter may contain garbage...
 */
#define _GNU_SOURCE 1
#include <assert.h>
#include <fcntl.h>
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

// these turn a numerical constant to a string constant, in pre-processing time.
#define STRINGIFY(s) 		#s
#define CONST_TO_STRING(c) 	STRINGIFY(c)

static __thread int * buffer = NULL; // buffer[0] holds number of written BYTES

static void * libstart = NULL;
static void * libend = NULL;

static char trace_path_[512] = { '\0' };

/**
 * Internal wrapper code goes here
 */

 // Do a un-intercepted syscall to make rr flush the buffer
static void flush_buffer(void){
	pid_t tid = syscall(SYS_gettid);
	buffer[0] = 0; // to relieve the replay from doing this
}

static void find_library_location(void)
{
	// open the maps file
	pid_t tid = getpid();
	char path[64] = {0};
	FILE* maps_file;
	sprintf(path, "/proc/%d/maps", tid);
	if ((maps_file = fopen(path, "r")) == NULL) {
		perror("Error reading child memory maps\n");
		exit(1);
	}

	// for each line in the maps file:
	char line[1024] = {0};
	void *start, *end;
	char flags[32], binary[128] = {0}, *result = NULL;
	unsigned int dev_minor, dev_major;
	unsigned long long file_offset, inode;
	while ( fgets(line,1024,maps_file) != NULL ) {
		sscanf(line,"%p-%p %31s %Lx %x:%x %Lu %s", &start, &end,flags, &file_offset, &dev_major, &dev_minor, &inode, binary);
		if (strstr(binary,WRAP_SYSCALLS_LIB_FILENAME) != NULL && // found the library
			strstr(flags,"x") != NULL ) { // notice: the library get loaded several times, we need the (hopefully one) copy that is executable
			libstart = start;
			libend = end;
			fclose(maps_file);
			return;
		}
	}
	fclose(maps_file);
	assert(0 && "unable to locate library in maps file");
	return;
}

/**
 * This installs the actual filter which examines the callsite and determines whether
 * it will be ptraced or handled by the intercepting library
 */
static void install_syscall_filter(void)
{
	// figure out the library address
	find_library_location();
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
		ALLOW_SYSCALL(gettimeofday),
		ALLOW_SYSCALL(clock_gettime),
		ALLOW_SYSCALL(madvise),
		ALLOW_SYSCALL(write),
		ALLOW_SYSCALL(writev),
		//ALLOW_SYSCALL(stat),
		ALLOW_SYSCALL(lstat),
		ALLOW_SYSCALL(fstat),
		/* These syscalls require more complex logic to decide whether they are to be traced */
		ALLOW_SOCKETCALL,
		ALLOW_FUTEX,
		/* These syscalls require a ptrace event for scheduling, but we still gain a speedup from wrapping them */
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

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		exit(1);
	}

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		exit(1);
	}
	// anything that happens from this point on gets filtered!
}

// TODO: this will not work if older trace dirs with higher index exist
static void find_trace_dir(void)
{
	int version = 0;
	char path[16] = "./trace_0";
	struct stat sb;

	while (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
		sprintf(path, "./trace_%d",++version);
	}
	sprintf(trace_path_, "./trace_%d",version-1);
}

/**
 * Initialize the library:
 * 1. Install filter-by-callsite (once for all thread)
 * 2. Make subsequent threads call init()
 * 3. Open and mmap the recording cache, shared with rr (once fopr every thread)
 *
 * Remember: init() will ony be called if the process uses at least one of the library's intercepted functions.
 *
 */
static void init() {
	/* Note: the filter is installed only for record. This call will be emulated it in the replay */
	if (!libend) {
		find_trace_dir();
		install_syscall_filter();
	}
	// make all subsequent children initialize their own buffer
	pthread_atfork(NULL,NULL,init);
	pid_t tid = syscall(SYS_gettid); // libc does not supply a wrapper for gettid
	// open the shared file TODO: open it under the trace directory
	char filename[32];
	sprintf(filename,"%s/%s%d", trace_path_, WRAP_SYSCALLS_CACHE_FILENAME_PREFIX, tid);
	// TODO: replace the following syscalls with assembly in case we want to intercept them as well
	errno = 0;
	int fd = open(filename, O_CREAT | O_RDWR, 0666); // beware of O_TRUNC!
	assert(fd > 0 && errno == 0);
	int retval;
	retval = ftruncate(fd,WRAP_SYSCALLS_CACHE_SIZE);
	assert(retval == 0 && errno == 0);
	buffer = mmap(NULL, WRAP_SYSCALLS_CACHE_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);
	assert(buffer != NULL && errno == 0);
	retval = close(fd);
	assert(retval == 0 && errno == 0);
	// buffer[0] holds the number of bytes written
	buffer[0] = 0;
	// print a message
	debug("Initialized cache buffer for thread %d at %p",tid,buffer);
}

/**
 * Wrappers start here.
 *
 * Wrappers mode of operation:
 * 1. Intercepts the syscalls and record the result in a record to the cache.
 * 2. The records will be collected by rr in the next ptrace event it receives.
 * 3. If the buffer is full, it will notify rr to flush it out.
 */

#define _syscall_pre(extra_space) 													\
if (!buffer)																		\
init();																				\
int ret;																			\
int record_size_in_bytes = WRAP_SYSCALLS_RECORD_BASE_SIZE;							\
if (buffer[0] + record_size_in_bytes + extra_space > WRAP_SYSCALLS_CACHE_SIZE) {	\
  flush_buffer();																	\
}																					\
int * const new_record = (void*)buffer + sizeof(int) + buffer[0];					\
void * ptr = &new_record[3];														\

#define _syscall2(call,arg0,arg1,ret) \
asm volatile("int $0x80" : "=a"(ret) : "0"(__NR_##call), "b"((long)arg0), "c"((long)arg1));

#define _syscall3(call,arg0,arg1,arg2,ret) \
asm volatile("int $0x80" : "=a"(ret) : "0"(__NR_##call), "b"((long)arg0), "c"((long)arg1), "d"((long)arg2));

#define _syscall4(call,arg0,arg1,arg2,arg3,ret) \
asm volatile("int $0x80" : "=a"(ret) : "0"(__NR_##call), "b"((long)arg0), "c"((long)arg1), "d"((long)arg2), "S"((long)arg3));

#define _syscall6(call,arg0,arg1,arg2,arg3,arg4,arg5,ret) \
asm volatile("mov %6, %%ebp\n\t" \
		     "int $0x80" : "=a"(ret) : "0"(__NR_##call), "b"((long)arg0), "c"((long)arg1), "d"((long)arg2), "S"((long)arg3), "D"((long)arg4), "g"((long)arg5));

#define __syscall_return(res) \
do { \
        if ((unsigned long)(res) >= (unsigned long)(-125)) { \
                errno = -(res); \
                res = -1; \
        } \
        return (res); \
} while (0)

#define _syscall_post(syscall) 			\
new_record[0] = __NR_##syscall;				\
new_record[1] = record_size_in_bytes;	\
new_record[2] = ret;					\
buffer[0] += record_size_in_bytes;		\
__syscall_return(ret);

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
	_syscall_pre(sizeof(struct timespec))
	// set it up so the syscall writes to the record cache
	struct timespec *tp2 = NULL;
	if (tp) {
		record_size_in_bytes += sizeof(struct timespec);
		tp2 = ptr;
		ptr += sizeof(struct timespec);
	}
	_syscall2(clock_gettime,clk_id,tp2,ret)
	// now in the replay we can simply push the recorded buffer and allow the wrapper to copy it to the actual parameters
	if (tp)
		memcpy(tp, tp2, sizeof(struct timespec));
	_syscall_post(clock_gettime)
}

int futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3) {
	_syscall_pre(sizeof(int))
	// make room for (uaddr,*uaddr)
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
	// record (uaddr,*uaddr)
	new_record[3] = (int)uaddr;
	new_record[4] = *uaddr;
	if (uaddr2)
		*uaddr2 = *uaddr2_tmp;
	_syscall_post(futex)
}

int gettimeofday_(struct timeval *tp, struct timezone *tzp) {
	_syscall_pre(sizeof(struct timeval) + sizeof(struct timezone))
	// set it up so the syscall writes to the record cache
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
	// now in the replay we can simply copy the recorded buffer and allow the wrapper to copy it to the actual parameters
	if (tp)
		memcpy(tp, tp2, sizeof(struct timeval));
	if (tzp)
		memcpy(tzp, tzp2, sizeof(struct timezone));
	_syscall_post(epoll_wait)
}


int epoll_wait_(int epfd, struct epoll_event *events, int maxevents, int timeout) {
	_syscall_pre(maxevents * sizeof(struct epoll_event))
	void *events2 = NULL;
	if (events) {
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


#define _copy_syscall_args(arg0,arg1,arg2,arg3,arg4,arg5) \
long args[6];			\
args[0] = (long)arg0;	\
args[1] = (long)arg1;	\
args[2] = (long)arg2;	\
args[3] = (long)arg3;	\
args[4] = (long)arg4;	\
args[5] = (long)arg5;

int accept4_(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
	// Stuff gets recorded only if addr is not null
	_syscall_pre(addr ? *addrlen + sizeof(socklen_t) : 0)
	_copy_syscall_args(sockfd,addr,addrlen,flags, 0, 0)
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


#define _socketcall_no_output(call,arg0,arg1,arg2,arg3,arg4,arg5) 	\
	_syscall_pre(0)													\
	_copy_syscall_args(arg0,arg1,arg2,arg3,arg4,arg5)				\
	_syscall2(socketcall,call,args,ret) 							\
	_syscall_post(socketcall)

int socket_(int domain, int type, int protocol) {
	_socketcall_no_output(SYS_SOCKET,domain,type,protocol,0, 0, 0)
}

int connect_(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	_socketcall_no_output(SYS_CONNECT,sockfd,addr,addrlen,0, 0, 0)
}

int bind_(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	_socketcall_no_output(SYS_BIND,sockfd,addr,addrlen,0, 0, 0)
}

int listen_(int sockfd, int backlog) {
	_socketcall_no_output(SYS_LISTEN,sockfd,backlog,0,0, 0, 0)
}

ssize_t sendmsg_(int sockfd, const struct msghdr *msg, int flags) {
	_socketcall_no_output(SYS_SENDMSG,sockfd,msg,flags,0, 0, 0)
}

ssize_t send_(int sockfd, const void *buf, size_t len, int flags) {
	_socketcall_no_output(SYS_SEND,sockfd,buf, len, flags, 0, 0)
}

ssize_t sendto_(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
	_socketcall_no_output(SYS_SENDTO,sockfd,buf, len, flags, dest_addr, addrlen)
}

int setsockopt_(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
	_socketcall_no_output(SYS_SETSOCKOPT,sockfd, level, optname, optval, optlen, 0)
}

int shutdown_(int socket, int how) {
	_socketcall_no_output(SYS_SHUTDOWN,socket, how, 0, 0, 0, 0)
}

int getpeername_(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	// Stuff gets recorded only if addr is not null
	_syscall_pre(addr ? *addrlen + sizeof(socklen_t) : 0)
	_copy_syscall_args(sockfd,addr,addrlen,0, 0, 0)
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
	// Stuff gets recorded only if addr is not null
	_syscall_pre(addr ? *addrlen + sizeof(socklen_t) : 0)
	_copy_syscall_args(sockfd,addr,addrlen,0, 0, 0)
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
	// Stuff gets recorded only if optval is not null
	_syscall_pre(optval ? *optlen + sizeof(socklen_t) : 0)
	_copy_syscall_args(sockfd,level,optname,optval, optlen, 0)
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
	// Stuff gets recorded only if buf is not null
	_syscall_pre(buf ? len : 0)
	_copy_syscall_args(sockfd,buf,len,flags,0,0)
	void *buf2 = NULL;
	if (buf) {
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

ssize_t recvmsg_(int sockfd, struct msghdr *msg, int flags) {
	// Stuff gets recorded only if msg is not null
	_syscall_pre(msg ? sizeof(struct msghdr)
					  + (msg->msg_iov ? msg->msg_iovlen * sizeof(struct iovec) : 0)
					  + (msg->msg_control ? msg->msg_controllen : 0)
					  : 0)
	_copy_syscall_args(sockfd,msg,flags, 0, 0, 0)
	struct msghdr *msg2 = NULL;
	struct iovec *msg_iov2;        // scatter/gather array
    void         *msg_control2;    // ancillary data, see below
	if (msg) {
		record_size_in_bytes += sizeof(struct msghdr);
		msg2 = ptr;
		memcpy(msg2,msg,sizeof(struct msghdr));
		ptr += sizeof(struct msghdr);
		args[1] = (long)msg2;
		if (msg->msg_iov) {
			record_size_in_bytes += msg->msg_iovlen * sizeof(struct iovec);
			msg2->msg_iov = msg_iov2 = ptr;
			memcpy(msg_iov2,msg->msg_iov,msg->msg_iovlen * sizeof(struct iovec));
			ptr += msg->msg_iovlen * sizeof(struct iovec);
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
		memcpy(msg,msg2,sizeof(struct msghdr));
		if (msg->msg_iov) {
			memcpy(msg->msg_iov,msg_iov2,msg->msg_iovlen * sizeof(struct iovec));
		}
		if (msg->msg_control) {
			memcpy(msg->msg_control,msg_control2,msg->msg_controllen);
		}
	}
	_syscall_post(socketcall)
}

ssize_t recvfrom_(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
	// Stuff gets recorded only if buf, etc. is not null
	_syscall_pre((buf ? len : 0) + (src_addr ? *addrlen +  sizeof(socklen_t) : 0))
	_copy_syscall_args(sockfd,buf,len,flags, src_addr, addrlen)
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

/* TODO: not working */
int socketpair_(int domain, int type, int protocol, int sv[2]) {
	_syscall_pre(sizeof(sv))
	_copy_syscall_args(domain,type,protocol,sv, 0, 0)
	int * sv2;
	sv2 = ptr;
	ptr += sizeof(sv);
	record_size_in_bytes += sizeof(sv);
	args[3] = (long)sv2;
	_syscall2(socketcall,SYS_SOCKETPAIR,args,ret)
	// now in the replay we can simply push the recorded buffer and allow the wrapper to copy it to the actual parameters
	memcpy(sv, sv2, sizeof(sv));
	_syscall_post(socketcall)
}

/* TODO: fill in the rest of the calls */
int socketcall_(int call, unsigned long *args){
	switch (call) {
	case SYS_ACCEPT:
		return accept(args[0],(struct sockaddr *)args[1],(socklen_t *)args[2]);
	default:
		assert(0);
	}
}

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

int fstat_(int fd, struct stat *buf){
	_stat(fstat,fd,buf);
}

int lstat_(const char *path, struct stat *buf) {
	_stat(lstat,path,buf);
}

/* FIXME: this causes SIGSEGV */
int stat_(const char *path, struct stat *buf){
	_stat(stat,path,buf);
}

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

/* TODO: causes a signal at the memcpy */
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
