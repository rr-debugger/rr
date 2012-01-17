#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>

#include <linux/futex.h>
#include <linux/net.h>
#include <linux/ipc.h>

#include <sys/ioctl.h>

#include <sys/socket.h>
#include <sys/mman.h>

#include <drm/radeon_drm.h>
#include <drm/i915_drm.h>

#include "rep_process_event.h"
#include "rep_sched.h"
#include "read_trace.h"

#include "../share/ipc.h"
#include "../share/sys.h"
#include "../share/util.h"
#include "../share/shmem.h"

/*
 * Compares the register file as it appeared in the recording phase
 * with the current register file.
 */
static void validate_args(struct context* context)
{
	struct user_regs_struct cur_reg;
	read_child_registers(context->child_tid, &cur_reg);
	compare_register_files("now", &cur_reg, "recorded", &(context->trace.recorded_regs), 1, 1);
}

/*
 * Proceeds until the next system call, which is not executed.
 */
static void goto_next_syscall_emu(struct context *ctx)
{
	assert(ctx->child_sig == 0);

	pid_t tid = ctx->child_tid;
	if (ctx->replay_sig != 0) {
		printf("global time: %u\n", ctx->trace.global_time);
	}
	//assert(ctx->replay_sig == 0);
	sys_ptrace_sysemu_sig(tid, ctx->replay_sig);
	sys_waitpid(tid, &ctx->status);
	ctx->replay_sig = 0;

	if (ctx->status == 0x57f) {
		printf("something is wrong!!!\n");
	}

	assert(signal_pending(ctx->child_sig) == 0);

	/* check if we are synchronized with the trace -- should never fail */
	const int rec_syscall = ctx->trace.recorded_regs.orig_eax;
	int current_syscall = read_child_orig_eax(tid);

	if (current_syscall != rec_syscall) {
		printf("stop reason: %x signal: %d pending sig: %d\n", ctx->status, WSTOPSIG(ctx->status), ctx->child_sig);
		printf("Internal error: syscalls out of sync: rec: %d  now: %d  time: %u\n", rec_syscall, current_syscall, ctx->trace.global_time);
		printf("ptrace_event: %x\n", GET_PTRACE_EVENT(ctx->status));
		uint64_t up = read_rbc_down(ctx->hpc);
		uint64_t down = read_rbc_down(ctx->hpc);

		printf("it fucking worked: up %llu  down %llu\n", up, down);
		sys_exit();
	}
}

/**
 *  Step over the system call to be able to reuse PTRACE_SYSTEM call
 **/
static void finish_syscall_emu(struct context *ctx)
{
	assert(ctx->child_sig == 0);
	sys_ptrace_sysemu_singlestep(ctx->child_tid);
	sys_waitpid(ctx->child_tid, &(ctx->status));

	/* we get a simple SIGTRAP in this case */
	assert(ctx->status == 0x57f);
	/* reset the single-step status */
	ctx->status = 0;
}

/*
 * Proceeds until the next system call, which is being executed.
 */
void __ptrace_cont(struct context *ctx)
{

	assert(ctx->child_sig == 0);
	pid_t my_tid = ctx->child_tid;
	goto_next_event(ctx);

	/* check if we are synchronized with the trace -- should never fail */
	int rec_syscall = ctx->trace.recorded_regs.orig_eax;
	int current_syscall = read_child_orig_eax(my_tid);

	if (current_syscall != rec_syscall) {
		printf("stop reason: %x :%d  pending sig: %d\n", ctx->status, WSTOPSIG(ctx->status), ctx->child_sig);
		fprintf(stderr, "Internal error: syscalls out of sync: rec: %d  now: %d\n", rec_syscall, current_syscall);
		sys_exit();
	}

	/* we should not have a singal pending here -- if there is one pending nevertheless,
	 * we do not deliver it to the application. This ensures that the behavior remains the
	 * same
	 */
	ctx->child_sig = 0;
}

static void set_child_data(struct context *ctx)
{
	size_t size;
	unsigned long rec_addr;
	void* data = read_raw_data(&(ctx->trace), &size, &rec_addr);
	if (data != NULL) {
		write_child_data(ctx, size, rec_addr, data);
		sys_free((void**) &data);
	}
}

static void set_return_value(struct context* context)
{
	struct user_regs_struct r;
	read_child_registers(context->child_tid, &r);
	r.eax = context->trace.recorded_regs.eax;
	write_child_registers(context->child_tid, &r);
}

/**
 * int socketcall(int call, unsigned long *args)
 *
 * socketcall()  is  a common kernel entry point for the socket system calls.  call determines
 * which socket function to invoke.  args points to a block containing the actual arguments,
 * which  are  passed  through  to  the appropriate call.
 *
 */
static void handle_socket(struct context *ctx, struct trace* trace)
{
	int state;
	pid_t tid;

	state = trace->state;
	tid = ctx->child_tid;
	/* sockets are emulated, not executed */
	if (state == STATE_SYSCALL_ENTRY) {
		goto_next_syscall_emu(ctx);
	} else {
		int call = read_child_ebx(tid);
		printf("socket call: %d\n", call);
		switch (call) {
		/* int socket(int domain, int type, int protocol); */
		case SYS_SOCKET:

		/* int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen); */
		case SYS_CONNECT:

		/* int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen); */
		case SYS_BIND:

		/* int listen(int sockfd, int backlog) */
		case SYS_LISTEN:

		/* ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) */
		case SYS_SENDMSG:

		/* ssize_t send(int sockfd, const void *buf, size_t len, int flags) */
		case SYS_SEND:

		/* ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen); */
		case SYS_SENDTO:

		/* int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen); */
		case SYS_SETSOCKOPT:

		/* int shutdown(int socket, int how) */
		case SYS_SHUTDOWN:
		{
			break;
		}

		/* int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */
		case SYS_GETPEERNAME:

		/* int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */
		case SYS_GETSOCKNAME:
		{
			set_child_data(ctx);
			set_child_data(ctx);

			break;
		}

		/* ssize_t recv(int sockfd, void *buf, size_t len, int flags) */
		case SYS_RECV:
		{
			set_child_data(ctx);
			break;
		}

		/* ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags); */
		case SYS_RECVMSG:
		{
			/* write the struct msghdr data structure */
			set_child_data(ctx);
			set_child_data(ctx);
			set_child_data(ctx);
			set_child_data(ctx);
			set_child_data(ctx);
			break;
		}

		/* int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
		 *
		 * Note: The returned address is truncated if the buffer provided is too small; in this case,
		 * addrlen will return a value greater than was supplied to the call.
		 *
		 * For now we record the size of bytes that is returned by the system call. We check in the
		 * replayer, if the buffer was actually too small and throw an error there.
		 *
		 * */
		case SYS_ACCEPT:
		{
			//FIXXME: not quite sure about socket_addr;
			set_child_data(ctx);
			set_child_data(ctx);
			break;
		}

		/* int socketpair(int domain, int type, int protocol, int sv[2]);
		 *
		 * values returned in sv
		 */
		case SYS_SOCKETPAIR:
		/**
		 *  int getsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
		 */
		case SYS_GETSOCKOPT:
		{
			set_child_data(ctx);
			break;
		}

		/* ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen); */
		case SYS_RECVFROM:
		{
			set_child_data(ctx);
			set_child_data(ctx);
			set_child_data(ctx);
			break;
		}

		default:
		fprintf(stderr, "unknwon call in socket: %d -- bailing out\n", call);
		sys_exit();
			break;
		}

		set_return_value(ctx);
		validate_args(ctx);
		finish_syscall_emu(ctx);
	}
}

/*
 * Implements the emulation/execution of system calls. Some system calls are emulated. In this
 * case, recorded data is injected into the child. Other system calls must be executed. E.g.,
 * mmap or fork cannot be emulated
 */
void rep_process_syscall(struct context* context)
{
	const int tid = context->child_tid;
	struct trace *trace = &(context->trace);
	int syscall = trace->stop_reason;
	int state = trace->state;
	struct context *ctx = context;

	assert((state == 1) || (state == 0));

	//if (context->trace.global_time > 900000) {
	//	print_syscall(context, trace);
	//}

	switch (syscall) {

	/***********************************************************************************************/
	/******************** All system calls that operate on file descriptors go here ****************/
	/***********************************************************************************************/

	/**
	 * int close(int fd)
	 *
	 * close()  closes  a file descriptor, so that it no longer refers to any file
	 * and may be reused.  Any record locks (see fcntl(2)) held on the file it was
	 * associated with, and owned by the process,  are removed (regardless of the file
	 *  descriptor that was used to obtain the lock).
	 */
	SYS_FD_ARG(close, 0)

	/**
	 * int dup(int oldfd)
	 *
	 * dup() uses the lowest-numbered unused descriptor for the new descriptor.
	 */
	SYS_FD_ARG(dup, 0)

	/**
	 * int dup2(int oldfd, int newfd)
	 *
	 * dup2()  makes newfd be the copy of oldfd, closing newfd first if necessary, but note the
	 *  following..
	 */
	SYS_FD_ARG(dup2, 0)

	/**
	 * int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
	 *
	 * This system call performs control operations on the epoll instance referred to by the file descriptor epfd.
	 * It requests that the operation op be performed for the target file descriptor, fd.
	 *
	 * FIXXME: not quite sure if something is returned!
	 */
	SYS_FD_ARG(epoll_ctl, 1)

	/**
	 * int fallocate(int fd, int mode, off_t offset, off_t len);
	 *
	 * fallocate() allows the caller to directly manipulate the allocated disk space
	 * for the file referred to by fd for the byte range starting at offset and
	 * continuing for len bytes
	 */
	SYS_FD_ARG(fallocate, 0)

	/**
	 * int fdatasync(int fd)
	 *
	 * fdatasync() is similar to fsync(), but does not flush modified metadata unless that metadata is needed in order
	 * to allow a subsequent data retrieval to be correctly handled.  For example, changes to st_atime or st_mtime (respectively,
	 * time of last access and time of last modification; see stat(2)) do not require flushing because they are not necessary
	 * for a subsequent data read to be handled correctly.  On  the other hand, a change to the file size (st_size, as made by
	 * say ftruncate(2)), would require a metadata flush
	 */
	SYS_FD_ARG(fdatasync, 0)

	/**
	 * int ftruncate(int fd, off_t length)
	 *
	 * The  truncate() and ftruncate() functions cause the regular file named by path or referenced by fd
	 * to be truncated to a size of precisely length bytes.
	 *
	 */
	SYS_FD_ARG(ftruncate64, 0)
	SYS_FD_ARG(ftruncate, 0)

	/**
	 * int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
	 *
	 * The system call getdents() reads several linux_dirent structures from the directory referred
	 * to by the open  file  descriptor fd into the buffer pointed to by dirp.  The argument count
	 * specifies the size of that buffer.
	 *
	 */
	SYS_FD_ARG(getdents64, 1)
	SYS_FD_ARG(getdents, 1)

	/*
	 * int open(const char *pathname, int flags)
	 * int open(const char *pathname, int flags, mode_t mode)
	 */
	SYS_FD_ARG(open, 0)

	/**
	 *  int pipe(int pipefd[2]);
	 *
	 * pipe()  creates  a  pipe, a unidirectional data channel that can be used for
	 * interprocess communication.  The array pipefd is used  to  return  two  file
	 * descriptors referring to the ends of the pipe.  pipefd[0] refers to the read
	 * end of the pipe.  pipefd[1] refers to the write end of the pipe.  Data writ‐
	 * ten  to the write end of the pipe is buffered by the kernel until it is read
	 * from the read end of the pipe.  For further details, see pipe(7).
	 */
	SYS_FD_ARG(pipe, 2)

	/**
	 * int pipe2(int pipefd[2], int flags)
	 *
	 * If flags is 0, then pipe2() is the same as pipe().  The following values can be bitwise
	 * ORed in flags to obtain different behavior...
	 */
	SYS_FD_ARG(pipe2, 2)

	/**
	 * int poll(struct pollfd *fds, nfds_t nfds, int timeout)
	 *
	 * poll() performs a similar task to select(2): it waits for one of a set of file descriptors to
	 * become ready to perform I/O.
	 *
	 * Potentially blocking
	 */
	SYS_FD_ARG(poll, 1)

	/**
	 * int fstat(int fd, struct stat *buf)
	 *
	 * fstat()  is  identical  to  stat(),  except  that  the  file to be stat-ed is specified
	 * by the file descriptor fd.
	 *
	 */
	SYS_FD_ARG(fstat64, 1)

	/**
	 * int fstatfs(int fd, struct statfs *buf)
	 *
	 * The  function  statfs()  returns  information  about  a mounted file system.
	 * path is the pathname of any file within the get_time(GET_TID(thread_id));mounted file system.  buf is a pointer to a
	 * statfs structure defined approximately as follows:
	 */
	SYS_FD_ARG(fstatfs64, 1)

	/**
	 * int fsync(int fd)
	 *
	 * fsync()  transfers ("flushes") all modified in-core data of (i.e., modified buffer cache pages for)
	 * the file referred to by the file descriptor fd to the disk device (or other permanent storage device)
	 * where that file  resides.   The  call  blocks until  the  device  reports that the transfer has
	 * completed.  It also flushes metadata information associated with the file (see stat(2))
	 */
	SYS_FD_ARG(fsync, 0)

	/* int fcntl(int fd, int cmd, ... ( arg ));
	 *
	 * fcntl()  performs  one  of the operations described below on the open file descriptor fd.
	 * The operation is determined by cmd. fcntl() can take an optional third argument.
	 * Whether or not this argument is required is determined by cmd. The required  argument
	 * type is indicated in parentheses after each cmd name (in most cases, the required type is long,
	 * and we identify the argument using the name arg), or void is specified if the argument is not required.
	 */
	SYS_FD_USER_DEF(fcntl64, 0,
			int cmd = read_child_ecx(tid);
			switch (cmd) {
				case F_DUPFD:
				case F_GETFD:
				case F_GETFL:
				case F_SETFL:
				case F_SETFD:
				case F_SETOWN:
				break;

				case F_SETLK:
				case F_SETLK64:
				case F_SETLKW64:
				case F_GETLK: {
					set_child_data(context);
					break;
				}

				default: printf("unknown command: %d -- bailing out\n", cmd);
					sys_exit();
			}
			set_return_value(context);
	)

	/**
	 * int inotify_rm_watch(int fd, uint32_t wd)
	 *
	 * inotify_rm_watch()  removes the watch associated with the watch descriptor wd from the
	 * inotify instance associated with the file descriptor fd.
	 */
	SYS_FD_ARG(inotify_rm_watch, 0)

	/**
	 * int inotify_add_watch(int fd, const char *pathname, uint32_t mask)
	 *
	 * inotify_add_watch()  adds  a  new watch, or modifies an existing watch,
	 * for the file whose location is specified in pathname; the  caller  must
	 * have read permission for this file.  The fd argument is a file descrip
	 * tor referring to the inotify instance whose watch list is to  be  modi‐
	 * fied.   The  events  to  be monitored for pathname are specified in the
	 * mask bit-mask argument.  See inotify(7) for a description of  the  bits
	 * that can be set in mask.
	 */
	SYS_FD_ARG(inotify_add_watch, 0)

	/**
	 *  int ioctl(int d, int request, ...)
	 *
	 * The ioctl()  function  manipulates the underlying device parameters of
	 * special files.  In particular, many operating characteristics of  char‐
	 * acter  special  files  (e.g., terminals) may be controlled with ioctl()
	 * requests.  The argument d must be an open file descriptor.
	 *
	 */
	case SYS_ioctl:
	{
		if (state == STATE_SYSCALL_ENTRY) {
			goto_next_syscall_emu(context);
		} else {
			int request = read_child_ecx(tid);
			debug_print("request: %x\n", request);

			if (request & _IOC_WRITE) {
				switch (request) {

				case TCGETS:
				case FIONREAD:
				{
					set_child_data(context);
					break;
				}

				case DRM_IOCTL_VERSION:
				{
					set_child_data(context);
					set_child_data(context);
					set_child_data(context);
					set_child_data(context);
					break;
				}

				case DRM_IOCTL_I915_GEM_PWRITE:
				{
					set_child_data(context);
					set_child_data(context);
					break;
				}

				case DRM_IOCTL_GET_MAGIC:
				case DRM_IOCTL_RADEON_INFO:
				case DRM_IOCTL_RADEON_GEM_CREATE:
				{
					print_register_file_tid(tid);

					set_child_data(context);
					break;
				}
				default:
				fprintf(stderr, "Unknown ioctl request: %x -- bailing out\n", request);
				print_register_file_tid(tid);
				sys_exit();
				}
			}

			set_return_value(context);
			validate_args(context);
			finish_syscall_emu(context);
		}
		break;
	}
	/*
	 * int _llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low,
	 * loff_t *result, unsigned int whence);
	 *
	 * The  _llseek()  function  repositions  the offset of the open file associated with the file descriptor fd to (off‐
	 * set_high<<32) | offset_low bytes relative to the beginning of the file, the current position in the file,  or  the
	 * end  of  the  file,  depending on whether whence is SEEK_SET, SEEK_CUR, or SEEK_END, respectively.  It returns the
	 * resulting file position in the argument result.
	 */
	SYS_FD_ARG(_llseek, 1)

	/**
	 * off_t lseek(int fd, off_t offset, int whence)
	 * The  lseek()  function  repositions the offset of the open file associated with the file
	 descriptor fd to the argument offset according to the directive whence as follows:
	 */
	SYS_FD_ARG(lseek, 0)

	/**
	 * int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
	 *
	 * select()  and  pselect() allow a program to monitor multiple file descriptors, waiting until one or
	 * more of the file descriptors become "ready" for some class of I/O operation (e.g., input possible).
	 * A file descriptor is considered ready if  it  is possible to perform the corresponding I/O operation
	 * (e.g., read(2)) without blocking.
	 */
	//SYS_FD_ARG(_newselect, 4)
	/**
	 * int socketcall(int call, unsigned long *args)
	 *
	 * socketcall()  is  a common kernel entry point for the socket system calls.  call determines
	 * which socket function to invoke.  args points to a block containing the actual arguments,
	 * which  are  passed  through  to  the appropriate call.
	 *
	 */
	case SYS_socketcall:
	{
		handle_socket(context, trace);
		break;
	}

	/*
	 * ssize_t read(int fd, void *buf, size_t count);
	 *
	 * read() attempts to read up to count bytes from file descriptor fd into the buffer starting at buf.
	 */
	SYS_FD_ARG(read, 1)

	/**
	 * mode_t umask(mode_t mask);
	 * umask()  sets  the  calling  process's file mode creation mask (umask) to mask & 0777
	 * (i.e., only the file permission bits of mask are used), and returns the previous value of the mask.
	 *
	 */
	SYS_FD_ARG(umask, 0)

	/*
	 * ssize_t write(int fd, const void *buf, size_t count);
	 *
	 * write() writes up to count bytes to the file referenced by the
	 * file descriptor fd from the buffer starting at buf. POSIX requires
	 * that a read() which can be proved to occur after a write() has
	 * returned returns the new data. Note that not all file systems are
	 * POSIX conforming.
	 */
	SYS_FD_ARG(write, 0)

	/**
	 * ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
	 * The writev() function writes iovcnt buffers of data described by iov
	 * to the file associated with the file descriptor fd ("gather output").
	 */
	SYS_FD_ARG(writev, 0)

	/**
	 * void *mmap2(void *addr, size_t length, int prot,int flags, int fd, off_t pgoffset);
	 *
	 * The  mmap2()  system  call operates in exactly the same way as mmap(2),
	 * except that the final argument specifies the offset into  the  file  in
	 * 4096-byte  units  (instead  of  bytes,  as  is  done by mmap(2)).  This
	 * enables applications that use a 32-bit off_t to map large files (up  to
	 * 2^44 bytes).
	 */

	case SYS_mmap2:
	{
		if (state == STATE_SYSCALL_ENTRY) {
			__ptrace_cont(context);
		} else {
			struct user_regs_struct regs;

			read_child_registers(tid, &regs);

			if (!(regs.esi & MAP_ANONYMOUS)) {
				struct user_regs_struct orig_regs;
				memcpy(&orig_regs, &regs, sizeof(struct user_regs_struct));

				/* hint the kernel where to allocate the page */
				if (regs.ebx == 0) {
					regs.ebx = context->trace.recorded_regs.eax;
				}
				/* set anonymous flag */
				regs.esi |= MAP_ANONYMOUS;
				regs.esi |= MAP_FIXED;
				regs.edi = 0;
				regs.ebp = 0;
				write_child_registers(tid, &regs);

				/* execute the mmap */
				__ptrace_cont(context);

				/* restore original register state */
				orig_regs.eax = read_child_eax(tid);
				write_child_registers(tid, &orig_regs);

				/* check if successful */
				validate_args(context);

				/* inject recorded data */
				set_child_data(context);

			} else {
				struct user_regs_struct orig_regs;
				memcpy(&orig_regs, &regs, sizeof(struct user_regs_struct));

				/* hint the kernel where to allocate the page */
				regs.ebx = context->trace.recorded_regs.eax;
				regs.esi |= MAP_FIXED;

				write_child_registers(tid, &regs);
				__ptrace_cont(context);

				/* restore original register state */
				orig_regs.eax = read_child_eax(tid);
				write_child_registers(tid, &orig_regs);

				validate_args(context);
			}
		}
		break;
	}

	/***********************************************************************************************/
	/****************************** All emulated system calls  go here *****************************/
	/***********************************************************************************************/

	/**
	 * int access(const char *pathname, int mode);
	 *
	 * access()  checks  whether  the calling process can access the file pathname.
	 * If pathname is a symbolic link, it is dereferenced.
	 *
	 */
	SYS_FD_ARG(access, 0)

	/**
	 * int chmod(const char *path, mode_t mode)
	 *
	 * The mode of the file given by path or referenced by fildes is changed
	 */
	SYS_FD_ARG(chmod, 0)

	/**
	 * int clock_gettime(clockid_t clk_id, struct timespec *tp);
	 *
	 * The functions clock_gettime() and clock_settime() retrieve and set the time of the
	 * specified clock clk_id.
	 */
	SYS_FD_ARG(clock_gettime, 1)

	/**
	 * int clock_getres(clockid_t clk_id, struct timespec *res)
	 *
	 * The  function clock_getres() finds the resolution (precision) of the specified
	 * clock clk_id, and, if res is non-NULL, stores it in the struct timespec pointed
	 * to by res.  The resolution of clocks depends on the implementation and cannot
	 * be configured by a particular process.  If the time value pointed to by  the
	 * argument tp of clock_settime() is not a multiple of res, then it is truncated
	 * to a multiple of res.
	 */
	SYS_FD_ARG(clock_getres, 1)

	/**
	 * int epoll_create(int size);
	 *
	 * epoll_create()  creates  an epoll "instance", requesting the kernel to allocate an event backing
	 * store dimensioned for size descriptors.  The size is not the maximum size of the backing store but
	 * just a hint to the kernel about how to dimension internal structures.
	 * When  no  longer  required,  the  file  descriptor returned  by epoll_create() should be closed by using close(2).
	 */
	SYS_FD_ARG(epoll_create, 0)

	/**
	 * int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
	 *
	 * The  epoll_wait() system call waits for events on the epoll instance referred to by the file descriptor epfd.
	 * The memory area pointed to by events will contain the events that will be available for the caller.  Up
	 * to maxevents are returned by epoll_wait().  The maxevents argument must be greater than zero.
	 */
	//SYS_FD_ARG(epoll_wait, context->trace.recorded_regs.eax)
	/**
	 * int futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3);
	 *
	 * The  futex()  system call provides a method for a program to wait for a
	 * value at a given address to change, and a  method  to  wake  up  anyone
	 * waiting  on a particular address (while the addresses for the same mem‐
	 * ory in separate processes may not be equal, the kernel maps them inter‐
	 * nally  so the same memory mapped in different locations will correspond
	 * for futex() calls).  This system call is typically  used  to  implement
	 * the  contended  case  of  a  lock  in  shared  memory,  as described in
	 * futex(7).
	 *
	 */
	case SYS_futex:
	{

		if (state == STATE_SYSCALL_ENTRY) {
			if (context->child_sig) {
				printf("holy crap: %d\n", context->child_sig);
			}

			goto_next_syscall_emu(context);
		} else {
			set_child_data(context);

			int op = read_child_ecx(tid) & FUTEX_CMD_MASK;

			if (op == FUTEX_WAKE || op == FUTEX_WAIT_BITSET || op == FUTEX_WAIT || op == FUTEX_UNLOCK_PI) {

			} else if (op == FUTEX_CMP_REQUEUE || op == FUTEX_WAKE_OP) {
				set_child_data(context);
			} else {
				printf("op: %d futex_wait: %d \n", op, FUTEX_WAIT);
				assert(1==0);
			}

			set_return_value(context);
			validate_args(context);
			finish_syscall_emu(context);
		}
		break;
	}

	/**
	 * char *getwd(char *buf);
	 *
	 * These  functions  return  a  null-terminated  string containing an absolute pathname
	 * that is the current working directory of the calling process.  The pathname is returned as the function result and via the argument buf, if
	 * present.
	 */
	SYS_EMU_ARG(getcwd, 1)

	/**
	 * gid_t getegid(void);
	 *
	 * getegid() returns the effective group ID of the calling process.
	 */
	SYS_EMU_ARG(getegid32, 0)

	/**
	 * uid_t geteuid(void);
	 *
	 * geteuid() returns the effective user ID of the calling process.
	 */
	SYS_EMU_ARG(geteuid32, 0)

	/**
	 * int getgroups(int size, gid_t list[]);
	 *
	 *
	 * getgroups()  returns  the  supplementary  group IDs of the calling process in list.
	 * The argument size should be set to the maximum number of items that can be stored in
	 * the buffer pointed to by list. If the calling process is a member of more than size
	 * supplementary groups, then an error results.  It is unspecified whether the effective
	 * group ID of the calling process is included in  the  returned  list. (Thus, an application
	 * should also call getegid(2) and add or remove the resulting value.)

	 *  If size is zero, list is not modified, but the total number of supplementary group IDs for the process
	 *  is returned.  This allows the caller to determine the size of a dynamically allocated list to be  used
	 *  in a further call to getgroups().
	 */
	//SYS_EMU_ARG(getgroups32, read_child_ebx(tid))
	/**
	 * pid_t getpgrp(void)
	 *
	 * The POSIX.1 getpgrp() always returns the PGID of the caller
	 */
	SYS_EMU_ARG(getpgrp, 0)

	/**
	 * gid_t getgid(void);
	 *
	 * getgid() returns the real group ID of the calling process.
	 */
	SYS_EMU_ARG(getgid32, 0)

	/**
	 * pid_t getpid(void);
	 *
	 * getpid() returns the process ID of the calling process.
	 * (This is often used by routines that generate unique temporary filenames.)The functions clock_gettime() and clock_settime() retrieve and set the time of the specified clock clk_id.
	 *
	 */
	SYS_EMU_ARG(getpid, 0)

	/**
	 * pid_t getppid(void);
	 *
	 * getppid() returns the process ID of the parent of the calling process.
	 */
	SYS_EMU_ARG(getppid, 0)

	/* int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
	 *
	 * getresuid()  returns  the  real  UID,  the effective UID, and the saved set-user-ID of
	 * the calling process, in the arguments ruid, euid, and suid, respectively.  getresgid()
	 * performs the analogous task  for  the  process's  group IDs.
	 * @return:  On success, zero is returned.  On error, -1 is returned, and errno is set appropriately.
	 */
	SYS_EMU_ARG(getresgid32, 3)

	/**
	 * pid_t gettid(void);
	 *
	 * gettid()  returns  the caller's thread ID (TID).
	 */
	SYS_EMU_ARG(gettid, 0)

	/**
	 * int gettimeofday(struct timeval *tv, struct timezone *tz);
	 *
	 * The functions gettimeofday() and settimeofday() can get and set the time as
	 * well as a timezone.  The tv argument is a struct timeval (as specified in <sys/time.h>):
	 *
	 */
	SYS_EMU_ARG(gettimeofday, 2)

	/**
	 * uid_t getuid(void);
	 *
	 *  getuid() returns the real user ID of the calling process
	 */
	SYS_EMU_ARG(getuid32, 0)

	/* int kill(pid_t pid, int sig)
	 *
	 * The kill() system call can be used to send any signal to any process group or process.
	 */
	case SYS_kill:
	{
		if (state == STATE_SYSCALL_ENTRY) {
			goto_next_syscall_emu(context);
		} else {
			set_return_value(context);
			validate_args(context);
			finish_syscall_emu(context);
		}
		break;
	}

	/**
	 * int lstat(const char *path, struct stat *buf);
	 *
	 * lstat() is identical to stat(), except that if path is a symbolic link, then
	 * the link itself is stat-ed, not the file that it refers to.
	 */
	SYS_EMU_ARG(lstat64, 1)

	/**
	 * int mkdir(const char *pathname, mode_t mode);
	 *
	 * mkdir() attempts to create a directory named pathname.
	 */
	SYS_EMU_ARG(mkdir, 0)

	/**
	 * ssize_t readlink(const char *path, char *buf, size_t bufsiz);
	 *
	 * readlink() places the contents of the symbolic link path in the buffer
	 * buf, which has size bufsiz. readlink() does not append a null byte to buf.
	 * It will truncate the contents (to a length of bufsiz characters), in case
	 * the buffer is too small to hold all of the contents.
	 */
	SYS_EMU_ARG(readlink, 1)


	/**
	 * int tgkill(int tgid, int tid, int sig)
	 * tgkill()  sends  the  signal sig to the thread with the thread ID tid in the thread group tgid.
	 * (By contrast, kill(2) can only be used to send a  signal to a process (i.e., thread group) as a
	 *  whole, and the signal will be delivered to an arbitrary thread within that process.)
	 */
	SYS_EMU_ARG(tgkill, 0);

	/**
	 * int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
	 *
	 * sched_getaffinity()  writes  the affinity mask of the process whose ID is pid into the cpu_set_t structure
	 * pointed to by mask.  The cpusetsize argument specifies the
	 *  size (in bytes) of mask.  If pid is zero, then the mask of the calling process is returned.
	 */
	SYS_EMU_ARG(sched_getaffinity, 1)

	/**
	 * int sched_getparam(pid_t pid, struct sched_param *param)
	 *
	 * sched_getparam()  retrieves  the  scheduling  parameters  for  the  process  i
	 * dentified  by  pid.  If pid is zero, then the parameters of the calling process
	 * are retrieved.
	 */
	SYS_EMU_ARG(sched_getparam, 1)

	/**
	 *  int sched_get_priority_max(int policy)
	 *
	 * sched_get_priority_max() returns the maximum priority value that can be
	 * used    with   the   scheduling   algorithm   identified   by   policy.
	 */
	SYS_EMU_ARG(sched_get_priority_max, 0)

	/**
	 * int sched_get_priority_min(int policy)
	 *
	 * sched_get_priority_min() returns the minimum priority value that can be used
	 * with the scheduling algorithm identified by  policy.
	 */
	SYS_EMU_ARG(sched_get_priority_min, 0)

	/**
	 * int sched_getscheduler(pid_t pid);
	 *
	 * sched_getscheduler() queries the scheduling policy currently applied to the
	 * process identified by pid.  If pid equals zero, the policy  of  the  calling
	 * process will be retrieved.
	 */
	SYS_EMU_ARG(sched_getscheduler, 0)

	/**
	 * int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param);
	 *
	 * sched_setscheduler()  sets  both the scheduling policy and the associated parameters
	 * for the process whose ID is specified in pid.  If pid equals zero, the scheduling policy
	 * and parameters of the calling process will be set.  The interpretation of the argument
	 * param depends on the selected policy.
	 */
	SYS_EMU_ARG(sched_setscheduler, 0)

	/**
	 * int sched_yield(void)
	 *
	 * sched_yield() causes the calling thread to relinquish the CPU.  The thread is moved to the end of
	 * the queue for its static priority and a new thread gets to run.
	 */
	SYS_EMU_ARG(sched_yield, 0)

	/**
	 * int setpgid(pid_t pid, pid_t pgid);
	 *
	 * setpgid()  sets the PGID of the process specified by pid to pgid.  If pid is zero, then
	 * the process ID of the calling process is used.  If pgid is zero, then the PGID of the
	 * process specified by pid is made the same as its process ID.  If setpgid() is used  to
	 * move  a process from one process group to another (as is done by some shells when creating
	 * pipelines), both process groups must be part of the same session (see setsid(2) and
	 * credentials(7)).  In this case, the  pgid  specifies  an  existing process group to be
	 * joined and the session ID of that group must match the session ID of the joining process.
	 */
	SYS_EMU_ARG(setpgid, 0)

	/**
	 *  int stat(const char *path, struct stat *buf);
	 *
	 *  stat() stats the file pointed to by path and fills in buf.
	 */
	SYS_EMU_ARG(stat64, 1)

	/**
	 * int statfs(const char *path, struct statfs *buf)
	 *
	 * The  function  statfs() returns information about a mounted file system.
	 * path is the pathname of any file within the mounted file system.  buf is a
	 * pointer to a statfs structure defined approximately as follows...
	 *
	 * FIXXME: we use edx here, although according to man pages this system call has only
	 * 2 paramaters. However, strace tells another story...
	 *
	 */
	SYS_EMU_ARG(statfs64, 1)

	/**
	 * int sysinfo(struct sysinfo *info)
	 *
	 * sysinfo() provides a simple way of getting overall system statistics.
	 */
	SYS_EMU_ARG(sysinfo, 1)

	/**
	 * int utimes(const char *filename, const struct timeval times[2])
	 *
	 * The utime() system call changes the access and modification times of the inode specified by
	 * filename to the actime and modtime fields of times respectively.
	 *
	 */
	SYS_EMU_ARG(utimes, 1)

	/**
	 * int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
	 *
	 * getresuid() returns the real UID, the effective UID, and the saved set-
	 * user-ID of the calling process, in the arguments ruid, euid, and  suid,
	 * respectively.    getresgid()   performs  the  analogous  task  for  the
	 * process's group IDs.
	 */
	SYS_EMU_ARG(getresuid32, 3)

	/**
	 * int inotify_init(void)
	 *
	 * inotify_init()  initializes  a  new inotify instance and returns a file
	 * descriptor associated with a new inotify event queue.
	 */
	SYS_EMU_ARG(inotify_init1, 0)

	/**
	 * int rmdir(const char *pathname)
	 *
	 * rmdir() deletes a directory, which must be empty.
	 */
	SYS_EMU_ARG(rmdir, 0)

	/**
	 * int rename(const char *oldpath, const char *newpath)
	 *
	 * rename() renames a file, moving it between directories if required.
	 */
	SYS_EMU_ARG(rename, 0)

	/**
	 * int setregid(gid_t rgid, gid_t egid)
	 *
	 * setreuid() sets real and effective user IDs of the calling process
	 */
	SYS_EMU_ARG(setregid32, 0)

	/**
	 * int statfs(const char *path, struct statfs *buf)
	 *
	 * The function statfs() returns information about a mounted file system.  path is the pathname of any file within the mounted
	 * file system.  buf is a pointer to a statfs structure defined approximately as follows:
	 */
	SYS_EMU_ARG(statfs, 1)

	/**
	 * int symlink(const char *oldpath, const char *newpath)
	 *
	 * symlink() creates a symbolic link named newpath which contains the string oldpath.
	 */
	SYS_EMU_ARG(symlink, 0)

	/**
	 * time_t time(time_t *t);
	 *
	 * time() returns the time since the Epoch (00:00:00 UTC, January 1, 1970), measured
	 *  in seconds. If t is non-NULL, the return value is also stored in the memory pointed
	 *  to by t.
	 */
	SYS_EMU_ARG(time, 1)

	/**
	 * clock_t times(struct tms *buf)
	 *
	 * times()  stores  the  current  process  times in the struct tms that buf points to.  The
	 *  struct tms is as defined in <sys/times.h>:
	 */
	SYS_EMU_ARG(times, 1)

	/**
	 * int uname(struct utsname *buf)
	 *
	 * uname() returns system information in the structure pointed to by buf. The utsname
	 * struct is defined in <sys/utsname.h>:
	 */
	SYS_EMU_ARG(uname, 1)

	/**
	 * int getrlimit(int resource, struct rlimit *rlim)
	 *
	 * getrlimit()  and  setrlimit()  get and set resource limits respectively.
	 * Each resource has an associated soft and hard limit, as defined by the rlimit structure
	 * (the rlim argument to both getrlimit() and setrlimit()):
	 */
	SYS_EMU_ARG(ugetrlimit, 1)

	/**
	 * int unlink(const char *path);
	 *
	 * The unlink() function shall remove a link to a file. If path names a symbolic link, unlink()
	 * shall remove the symbolic link named by path and shall not affect any file or directory named
	 * by the contents of the symbolic link. Otherwise, unlink() shall remove the link named by the
	 * pathname pointed to by path and shall decrement the link count of the file referenced by the link.
	 *
	 */
	SYS_EMU_ARG(unlink, 0)

	/**
	 * int utime(const char *filename, const struct utimbuf *times)
	 *
	 * The  utime()  system call changes the access and modification times of the inode specified by
	 * filename to the actime and modtime fields of times respectively.
	 *
	 * If times is NULL, then the access and modification times of the file are set to the current time.
	 *
	 * Changing timestamps is permitted when: either the process has appropriate privileges, or the effective  user  ID  equals  the
	 * user ID of the file, or times is NULL and the process has write permission for the file.
	 *
	 * FIXXME: is mod_time set by the kernel?
	 */
	//SYS_EMU_ARG(utime, 0)
	/**
	 * pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
	 *
	 * The  wait3()  and wait4() system calls are similar to waitpid(2), but
	 * additionally return resource usage information about the child in the
	 * structure pointed to by rusage.
	 */
	SYS_EMU_ARG(wait4, 2)

	/**
	 * pid_t waitpid(pid_t pid, int *status, int options);
	 *
	 * The waitpid() system call suspends execution of the calling process until
	 * a child specified by pid argument has changed state.  By default, waitpid()
	 * waits only for terminated children, but this behavior  is  modifiable  via
	 * the options argument, as described below....
	 *
	 */
	SYS_EMU_ARG(waitpid, 1)

	/************************ Executed system calls come here ***************************/

	/**
	 * int brk(void *addr)
	 *
	 * brk()  and sbrk() change the location of the program break, which defines the end of the process's
	 * data segment (i.e., theprogram break is the first location after the end of the uninitialized data
	 * segment).  Increasing the  program  break  has the effect of allocating memory to the process;
	 * decreasing the break deallocates memory.

	 * brk()  sets  the  end  of  the  data segment to the value specified by addr, when that value is reasonable, the system has
	 * enough memory, and the process does not exceed its maximum data size (see setrlimit(2)).
	 */
	SYS_EXEC_ARG_RET(context, brk, 0)

	/**
	 * int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, (pid_t *ptid, struct user_desc *tls, pid_t *ctid));
	 *
	 * clone()  creates  a new process, in a manner similar to fork(2).  It is actually a library function layered ontrace
	 * top of the underlying clone() system call, hereinafter referred to tidas sys_clone.  A description  of  sys_clone
	 * is given towards the end of this page.
	 *
	 * NOTE: clone is actually implemented by sys_clone which has the following signature:
	 *
	 * long sys_clone(unsigned long clone_flags, unsigned long newsp, void __user *parent_tid, void __user *child_tid, struct pt_regs *regs)
	 */
	case SYS_clone:
	{
		if (state == STATE_SYSCALL_ENTRY) {
			__ptrace_cont(context);
		} else {
			/* execute the system call */
			__ptrace_cont(context);
			/* wait for the signal that a new process is created */
			__ptrace_cont(context);

			unsigned long new_tid = sys_ptrace_getmsg(tid);

			/* wait until the new thread is ready */
			int status;
			sys_waitpid(new_tid, &status);

			rep_sched_register_thread(new_tid, trace->recorded_regs.eax);

			/* FIXXME: what is registers are non-null and contain an invalid address? */
			set_child_data(context);
			set_child_data(context);

			size_t size;
			unsigned long rec_addr;
			void* data = read_raw_data(&(context->trace), &size, &rec_addr);
			if (data != NULL) {
				write_child_data_n(new_tid, size, rec_addr, data);
				sys_free((void**) &data);
			}

			data = read_raw_data(&(context->trace), &size, &rec_addr);
			if (data != NULL) {
				write_child_data_n(new_tid, size, rec_addr, data);
				sys_free((void**) &data);
			}

			data = read_raw_data(&(context->trace), &size, &rec_addr);
			if (data != NULL) {
				write_child_data_n(new_tid, size, rec_addr, data);
				sys_free((void**) &data);
			}
			set_return_value(context);

			/* set the ebp register to the recorded value -- it should not point to data on
			 * that is used afterwards */
			write_child_ebp(tid, trace->recorded_regs.ebp);
			validate_args(context);
		}
		break;
	}

	/* signature:
	 * int execve(const char *filename, char *const argv[], char *const envp[]);
	 *
	 * all arguments must be recorded
	 */
	case SYS_execve:
	{

		if (state == STATE_SYSCALL_ENTRY) {
			__ptrace_cont(context);
		} else {
			__ptrace_cont(context);

			/* we need an additional ptrace syscall, since ptrace is setup with PTRACE_O_TRACEEXEC */
			__ptrace_cont(context);
			set_child_data(context);
			set_return_value(context);
			validate_args(context);
		}
		break;
	}

	/**
	 * void exit(int status)
	 * The exit() function causes normal process termination and the value of status & 0377 is
	 * returned to the parent (see wait(2)).
	 */
	case SYS_exit:
	{
		assert(state == STATE_SYSCALL_ENTRY);
		__ptrace_cont(context);
		break;
	}

	case SYS_exit_group:
	{
		assert(state == STATE_SYSCALL_ENTRY);
		__ptrace_cont(context);
		break;
	}

	/**
	 * int ipc(unsigned int call, int first, int second, int third, void *ptr, long fifth);
	 *
	 * ipc()  is  a  common  kernel entry point for the System V IPC calls for
	 * messages, semaphores, and shared memory.   call  determines  which  IPC
	 * function  to  invoke;  the  other  arguments  are passed through to the
	 * appropriate call.
	 *
	 */
	case SYS_ipc:
	{
		int call = read_child_ebx(tid);

		if (state == STATE_SYSCALL_ENTRY) {
			if (call == MSGRCV) {
				goto_next_syscall_emu(context);
			} else {
				__ptrace_cont(context);
			}
		} else {
			switch (call) {

			/* int shmget(key_t key, size_t size, int shmflg); */
			case SHMGET:
			{
				__ptrace_cont(context);
				shmem_store_key(trace->recorded_regs.eax, read_child_eax(tid));
				set_return_value(context);
				break;
			}
			/* void *shmat(int shmid, const void *shmaddr, int shmflg) */
			case SHMAT:
			{
				int orig_shmemid = read_child_ecx(tid);
				int shmid = shmem_get_key(read_child_ecx(tid));
				write_child_ecx(tid, shmid);
				__ptrace_cont(context);
				write_child_ecx(tid, orig_shmemid);
				break;
			}

			/* int shmctl(int shmid, int cmd, struct shmid_ds *buf); */
			case SHMCTL:
			{
				int orig_shmemid = read_child_ecx(tid);
				int shmid = shmem_get_key(read_child_ecx(tid));

				write_child_ecx(tid, shmid);
				__ptrace_cont(context);
				write_child_ecx(tid, orig_shmemid);
				set_child_data(context);
				break;
			}

			/* ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg); */
			case MSGRCV:
			{
				set_child_data(context);
				set_return_value(context);
				finish_syscall_emu(context);
				break;
			}

			/* int shmdt(const void *shmaddr); */
			case SHMDT:
			{
				__ptrace_cont(context);
				set_return_value(context);
				break;
			}

			default:
			printf("unknown call in ipc: %d -- bailing out\n", call);
			sys_exit();
			}

			validate_args(context);
		}
		break;
	}

	/**
	 * int madvise(void *addr, size_t length, int advice);
	 *
	 * The  madvise()  system  call  advises  the  kernel  about how to handle paging input/output
	 * in the address range beginning at address addr and with size length bytes.  It allows an application
	 * to tell the kernel how it expects to use  some  mapped  or shared  memory areas, so that the kernel
	 * can choose appropriate read-ahead and caching techniques.  This call does not influence the semantics
	 * of the application (except in the case of MADV_DONTNEED), but may influence its performance.   The  kernel
	 * is free to ignore the advice.
	 *
	 */
	SYS_EXEC_ARG_RET(context, madvise, 0)

	/*
	 * void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... ( void *new_address ));
	 *
	 *  mremap()  expands  (or  shrinks) an existing memory mapping, potentially moving it at the same time
	 *  (controlled by the flags argument and the available virtual address space).
	 */
	//SYS_EXEC_ARG(mremap, 0)
	/**
	 * int munmap(void *addr, size_t length)
	 *
	 * The munmap() system call deletes the mappings for the specified address range, and causes further
	 * references to addresses within the range to generate invalid memory references.  The region is also
	 * automatically unmapped when the process is terminated.  On the other hand, closing the file descriptor
	 * does not unmap the region.
	 */
	SYS_EXEC_ARG_RET(context, munmap, 0)

	/**
	 * int mprotect(const void *addr, size_t len, int prot)
	 *
	 * mprotect()  changes  protection  for  the calling process's memory page(s) containing any part
	 * of the address range in the interval [addr, addr+len-1].  addr must be aligned to a page boundary.
	 *
	 * If the calling process tries to access memory in a manner that violates  the  protection,  then  the  kernel  generates  a
	 * SIGSEGV signal for the process.
	 *
	 */
	SYS_EXEC_ARG_RET(context, mprotect, 0)

	/**
	 * int setrlimit(int resource, const struct rlimit *rlim)
	 *
	 * getrlimit() and setrlimit() get and set resource limits respectively.  Each resource has an associated soft and hard limit, as
	 * defined by the rlimit structure (the rlim argument to both getrlimit() and setrlimit()):
	 *
	 * struct rlimit {
	 * rlim_t rlim_cur;  // Soft limit
	 * rlim_t rlim_max;  // Hard limit (ceiling for rlim_cur)
	 * };
	 *
	 * The soft limit is the value that the kernel enforces for the corresponding resource.  The hard limit acts as a ceiling for the
	 * soft  limit:  an  unprivileged  process  may  only set its soft limit to a value in the range from 0 up to the hard limit, and
	 * (irreversibly) lower its hard limit.  A privileged process (under Linux: one with the CAP_SYS_RESOURCE  capability)  may  make
	 * arbitrary changes to either limit value.
	 *
	 * We should execute this system call, since this system call sets a limit on a resource (e.g., the stack size)
	 * This bahavior must be the same in the replay as in the recording phase.
	 */
	SYS_EXEC_ARG_RET(context, setrlimit, 1)

	/**
	 *  int prlimit(pid_t pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit);
	 *
	 * The Linux-specific prlimit() system call combines and extends the
	 * functionality of setrlimit() and getrlimit().  It can be used to both set and
	 * get the resource limits of an arbitrary process.
	 *
	 * The resource argument has the same meaning as for setrlimit() and getrlimit().
	 *
	 * If the new_limit argument is a not NULL, then the rlimit structure to which it
	 * points is used to set new values for the soft and hard limits for resource.
	 * If the old_limit argument is a not NULL, then a successful call to prlimit()
	 * places the previous soft and hard limits for resource in the rlimit structure
	 * pointed to by old_limit.
	 */
	SYS_EXEC_ARG_RET(context, prlimit64, 1)

	/**
	 * long set_robust_list(struct robust_list_head *head, size_t len)
	 *
	 * The robust futex implementation needs to maintain per-thread lists of robust futexes
	 * which are unlocked when the thread exits. These lists are managed in user space, the
	 * kernel is only notified about the location of the head of the list.

	 * set_robust_list sets the head of the list of robust futexes owned by the current thread to head.
	 * len is the size of *head.
	 */
	SYS_EXEC_ARG_RET(context, set_robust_list, 0)

	/**
	 * int set_thread_area(struct user_desc *u_info)
	 *
	 * set_thread_area()  sets  an  entry in the current thread's Thread Local
	 * Storage (TLS) array.  The TLS array entry set by set_thread_area() cor‐
	 * responds  to  the  value of u_info->entry_number passed in by the user.
	 * If this value is in bounds, set_thread_area() copies the TLS descriptor
	 * pointed to by u_info into the thread's TLS array.
	 *
	 * When  set_thread_area() is passed an entry_number of -1, it uses a free
	 * TLS entry.  If set_thread_area() finds a free TLS entry, the  value  of
	 * u_info->entry_number  is  set  upon  return  to  show  which  entry was
	 * changed.
	 *
	 */
	SYS_EXEC_ARG_RET(context, set_thread_area, 1)

	/**
	 * long set_tid_address(int *tidptr);
	 *
	 * The kernel keeps for each process two values called set_child_tid and clear_child_tid
	 * that are NULL by default.
	 *
	 * If  a  process  is  started  using  clone(2)  with   the   CLONE_CHILD_SETTID   flag,
	 * set_child_tid is set to child_tidptr, the fifth argument of that system call.
	 *
	 * When  set_child_tid  is set, the very first thing the new process does is writing its
	 * PID at this address.
	 *
	 */
	SYS_EXEC_ARG(set_tid_address, 1)

	/**
	 * int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
	 *
	 * The sigaction() system call is used to change the action taken by a process on receipt of a
	 * specific signal.  (See signal(7) for an overview of signals.)
	 *
	 * signum specifies the signal and can be any valid signal except SIGKILL and SIGSTOP.
	 *
	 * If act is non-NULL, the new action for signal signum is installed from act.  If oldact is non-NULL, the  previous  action  is
	 * saved in oldact.
	 *
	 */
	SYS_EXEC_ARG(rt_sigaction, 1)

	/**
	 * int sigaltstack(const stack_t *ss, stack_t *oss)
	 *
	 * sigaltstack()  allows a process to define a new alternate signal stack and/or retrieve the state of
	 * an existing alternate signal stack.  An alternate signal stack is used during the execution of a signal
	 * handler if the establishment of that handler (see sigaction(2)) requested it.
	 */
	//SYS_EXEC_ARG(sigaltstack, 0)
	/**
	 * int sigreturn(unsigned long __unused)
	 *
	 * When  the Linux kernel creates the stack frame for a signal handler, a call to sigreturn()
	 * is inserted into the stack frame so that upon return from the signal handler, sigreturn() will
	 * be called.
	 */

	case SYS_rt_sigreturn:
	case SYS_sigreturn:
	{
		/* go to the system call */
		__ptrace_cont(context);
		validate_args(ctx);

		/* do another step; we do that 'unchecked' since we are supposed to get a -1 in orig_eax
		 * and that -1 is not recorded */
		//sys_ptrace_syscall(tid);
		//sys_waitpid(tid, &context->status);
		/* the next event is -1 -- how knows why?*/
		//assert(read_child_orig_eax(context->child_tid) == -1);
		//assert(ctx->status == 0x857f);
		break;
	}

	/**
	 *  int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
	 *
	 *  sigprocmask() is used to fetch and/or change the signal mask of the calling
	 *  thread.  The signal mask is the set of signals whose delivery is currently
	 *   blocked for the caller (see also signal(7) for more details).
	 */
	SYS_EXEC_ARG_RET(context, rt_sigprocmask, 1)

	default:
	fprintf(stderr, " Replayer: unknown system call: %d -- bailing out global_time %u\n", syscall, ctx->trace.global_time);
	sys_exit();
	}

	if (state == STATE_SYSCALL_EXIT) {
		//get_eip_info(tid);
	}

}
