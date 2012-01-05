#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <poll.h>

#include <asm/ldt.h>
#include <linux/futex.h>
#include <linux/net.h>
#include <linux/shm.h>

#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <sys/vfs.h>

#include "write_trace.h"
#include "rec_process_event.h"
#include "handle_ioctl.h"

#include "../share/ipc.h"
#include "../share/sys.h"
#include "../share/util.h"

void rec_process_syscall(struct context *ctx)
{
	pid_t tid = ctx->child_tid;

	struct user_regs_struct regs;
	read_child_registers(tid, &regs);

	const long int syscall = regs.orig_eax;
	//print_syscall(context, &(context->trace));

	fprintf(stderr, "%d: processign syscall: %s(%ld) -- time: %u  status: %x\n", tid, syscall_to_str(syscall), syscall, get_time(tid), ctx->exec_state);

	/* main processing (recording of I/O) */
	switch (syscall) {

	SYS_REC0(restart_syscall)

	/**
	 * int access(const char *pathname, int mode);
	 *
	 * access()  checks  whether  the calling process can access the file pathname.
	 * If pathname is a symbolic link, it is dereferenced.
	 *
	 */
	SYS_REC0(access)

	/**
	 * int brk(void *addr)
	 * brk() sets the end of the data segment to the value specified by addr, when that value is
	 * reasonable, the system has enough memory, and the process does not exceed its maximum data size
	 * (see setrlimit(2)).
	 */
	SYS_REC0(brk)

	/** READ NOTE:
	 * int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, (pid_t *ptid, struct user_desc *tls, pid_t *ctid));
	 *
	 * clone()  creates  a new process, in a manner similar to fork(2).  It is actually a library function layered on
	 * top of the underlying clone() system call, hereinafter referred to as sys_clone.  A description  of  sys_clone
	 * is given towards the end of this page.
	 *
	 * NOTE: clone is actually implemented by sys_clone which has the following signature:
	 * long sys_clone(unsigned long clone_flags, unsigned long newsp, void __user *parent_tid, void __user *child_tid, struct pt_regs *regs)
	 *
	 */
	case SYS_clone:
	{

		/* record child id here */
		record_child_data_tid(tid, syscall, sizeof(pid_t), regs.edx);
		record_child_data_tid(tid, syscall, sizeof(pid_t), regs.esi);
		pid_t new_tid = regs.eax;
		record_child_data_tid(new_tid, syscall, sizeof(struct user_desc), read_child_edi(new_tid));
		record_child_data_tid(new_tid, syscall, sizeof(sizeof(pid_t)), read_child_edx(new_tid));
		record_child_data_tid(new_tid, syscall, sizeof(sizeof(pid_t)), read_child_esi(new_tid));

		break;
	}

	/**
	 * int dup2(int oldfd, int newfd)
	 *
	 * dup2()  makes newfd be the copy of oldfd, closing newfd first if necessary, but note the
	 *  following..
	 */
	SYS_REC0(dup2)

	/**
	 * void exit(int status)
	 * The exit() function causes normal process termination and the value of status & 0377 is
	 * returned to the parent (see wait(2)).
	 */
	SYS_REC0(exit)

	/**
	 * void exit_group(int status);
	 *
	 *  This system call is equivalent to exit(2) except that it terminates not only the calling thread,
	 *  but all threads in the calling process's thread group.
	 */
	SYS_REC0(exit_group)

	/**
	 * int close(int fd)
	 *
	 * close()  closes  a file descriptor, so that it no longer refers to any file
	 * and may be reused.  Any record locks (see fcntl(2)) held on the file it was
	 * associated with, and owned by the process,  are removed (regardless of the file
	 *  descriptor that was used to obtain the lock).
	 */
	SYS_REC0(close)

	/**
	 * int chdir(const char *path);
	 *
	 * chdir() changes the current working directory of the calling process to the directory
	 * specified in path.
	 */
	SYS_REC0(chdir)

	/**
	 * int chmod(const char *path, mode_t mode)
	 *
	 * The mode of the file given by path or referenced by fildes is changed
	 */
	SYS_REC0(chmod)

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
	SYS_REC1(clock_getres, sizeof(struct timespec), regs.ecx)

	/**
	 * int clock_gettime(clockid_t clk_id, struct timespec *tp);
	 *
	 * The functions clock_gettime() and clock_settime() retrieve and set the time of the
	 * specified clock clk_id.
	 */
	SYS_REC1(clock_gettime, sizeof(struct timespec), regs.ecx)

	/**
	 * int dup(int oldfd)
	 *
	 * dup() uses the lowest-numbered unused descriptor for the new descriptor.
	 */
	SYS_REC0(dup)

	/**
	 * int epoll_create(int size);
	 *
	 * epoll_create()  creates  an epoll "instance", requesting the kernel to allocate an event backing
	 * store dimensioned for size descriptors.  The size is not the maximum size of the backing store but
	 * just a hint to the kernel about how to dimension internal structures.
	 * When  no  longer  required,  the  file  descriptor returned  by epoll_create() should be closed by using close(2).
	 */
	SYS_REC0(epoll_create)

	/**
	 * int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
	 *
	 * This system call performs control operations on the epoll instance referred to by the file descriptor epfd.
	 * It requests that the operation op be performed for the target file descriptor, fd.
	 *
	 * FIXXME: not quite sure if something is returned!
	 */
	SYS_REC1(epoll_ctl, sizeof(struct epoll_event), regs.esi)

	/**
	 * int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
	 *
	 * The  epoll_wait() system call waits for events on the epoll instance referred to by the file descriptor epfd.
	 * The memory area pointed to by events will contain the events that will be available for the caller.  Up
	 * to maxevents are returned by epoll_wait().  The maxevents argument must be greater than zero.
	 */
	case SYS_epoll_wait:
	{
		struct epoll_event* events;
		int i, ret_events;

		events = (struct epoll_event*) regs.ecx;
		ret_events = regs.eax;

		for (i = 0; i < ret_events; i++) {
			record_child_data(ctx, syscall, sizeof(struct epoll_event), (long int) (events + i));
		}

		break;
	}

	/**
	 * eventfd()  creates  an  "eventfd  object"  that can be used as an event
	 * wait/notify mechanism by userspace applications, and by the  kernel  to
	 * notify  userspace  applications  of  events.   The  object  contains an
	 * unsigned 64-bit integer (uint64_t) counter that is  maintained  by  the
	 * kernel.   This  counter  is initialized with the value specified in the
	 * argument initval.
	 */
	SYS_REC0(eventfd2)

	/**
	 * int fallocate(int fd, int mode, off_t offset, off_t len);
	 *
	 * fallocate() allows the caller to directly manipulate the allocated disk space
	 * for the file referred to by fd for the byte range starting at offset and
	 * continuing for len bytes
	 */
	SYS_REC0(fallocate)

	/* int fcntl(int fd, int cmd, ... ( arg ));
	 *
	 *
	 * fcntl()  performs  one  of the operations described below on the open file descriptor fd.
	 * The operation is determined by cmd. fcntl() can take an optional third argument.
	 * Whether or not this argument is required is determined by cmd. The required  argument
	 * type is indicated in parentheses after each cmd name (in most cases, the required type is long,
	 * and we identify the argument using the name arg), or void is specified if the argument is not required.
	 */
	//SYS_REC0(fcntl64)
	case SYS_fcntl64:
	{
		int cmd = regs.ecx;
		switch (cmd) {
		case F_DUPFD:
		case F_GETFD:
		case F_GETFL:
		case F_SETFL:
		case F_SETFD:
		case F_SETOWN:
		{
			break;
		}

		case F_SETLKW64:
		case F_SETLK64:
		case F_GETLK64:
		case F_GETLK:
		case F_SETLK:
		{
			record_child_data(ctx, syscall, sizeof(struct flock64), regs.edx);
			break;
		}

		default:
		printf("unknown command: %d -- bailing out\n", cmd);
		sys_exit();
		}
		break;
	}

	/**
	 * int fdatasync(int fd)
	 *
	 * fdatasync() is similar to fsync(), but does not flush modified metadata unless that metadata is needed in order
	 * to allow a subsequent data retrieval to be correctly handled.  For example, changes to st_atime or st_mtime (respectively,
	 * time of last access and time of last modification; see stat(2)) do not require flushing because they are not necessary
	 * for a subsequent data read to be handled correctly.  On  the other hand, a change to the file size (st_size, as made by
	 * say ftruncate(2)), would require a metadata flush
	 */
	SYS_REC0(fdatasync)

	/**
	 * int fstatfs(int fd, struct statfs *buf)
	 *
	 * The  function  statfs()  returns  information  about  a mounted file system.
	 * path is the pathname of any file within the get_time(GET_TID(thread_id));mounted file system.  buf is a pointer to a
	 * statfs structure defined approximately as follows:
	 *
	 * FIXXME: we use edx here, although according to man pages this system call has only
	 * 2 paramaters. However, strace tells another story...
	 *
	 */
	SYS_REC1(fstatfs64, sizeof(struct statfs64), regs.edx)

	/**
	 * int ftruncate(int fd, off_t length)
	 *
	 * The  truncate() and ftruncate() functions cause the regular file named by path or referenced by fd
	 * to be truncated to a size of precisely length bytes.
	 *
	 */
	SYS_REC0(ftruncate64)
	SYS_REC0(ftruncate)

	/**
	 * int fsync(int fd)
	 *
	 * fsync()  transfers ("flushes") all modified in-core data of (i.e., modified buffer cache pages for)
	 * the file referred to by the file descriptor fd to the disk device (or other permanent storage device)
	 * where that file  resides.   The  call  blocks until  the  device  reports that the transfer has
	 * completed.  It also flushes metadata information associated with the file (see stat(2))
	 */
	SYS_REC0(fsync)

	/**
	 * char *getwd(char *buf);
	 *
	 * These  functions  return  a  null-terminated  string containing an absolute pathname
	 * that is the current working directory of the calling process.  The pathname is returned as the function result and via the argument buf, if
	 * present.
	 */
	SYS_REC1_STR(getcwd, regs.ebx)

	/**
	 * int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
	 *
	 * The system call getdents() reads several linux_dirent structures from the directory referred
	 * to by the open  file  descriptor fd into the buffer pointed to by dirp.  The argument count
	 * specifies the size of that buffer.
	 *
	 */
	SYS_REC1(getdents64, regs.edx, regs.ecx)
	SYS_REC1(getdents, regs.edx, regs.ecx)

	/**
	 * gid_t getgid(void);
	 *
	 * getgid() returns the real group ID of the calling process.
	 */
	SYS_REC0(getgid32)

	/**
	 * gid_t getegid(void);
	 *
	 * getegid() returns the effective group ID of the calling process.
	 */
	SYS_REC0(getegid32)

	/**
	 * pid_t getpid(void);
	 *
	 * getpid() returns the process ID of the calling process.
	 * (This is often used by routines that generate unique temporary filenames.)
	 *
	 */
	SYS_REC0(getpid)

	/**
	 * int getgroups(int size, gid_t list[]);
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
	case SYS_getgroups32:
	{
		int i;
		/* record all elements of the list array */
		for (i = 0; i < regs.ebx; i++) {
			record_child_data(ctx, syscall, sizeof(gid_t), regs.ecx + i * sizeof(gid_t*));
		}
		break;
	}

	/**
	 * uid_t getuid(void);
	 *
	 *  getuid() returns the real user ID of the calling process
	 */
	SYS_REC0(getuid32)

	/**
	 * uid_t geteuid(void);
	 *
	 * geteuid() returns the effective user ID of the calling process.
	 */
	SYS_REC0(geteuid32)

	/**
	 * pid_t getpgid(pid_t pid);
	 *
	 * getpgid() returns the PGID of the process specified by pid.  If pid is zero,
	 * getpgid() the process ID of the calling process is used.int getrusage(int who, struct rusage *usage);
	 */
	SYS_REC0(getpgid)

	/**
	 * pid_t getppid(void);
	 *
	 * getppid() returns the process ID of the parent of the calling process.
	 */
	SYS_REC0(getppid)

	/**
	 * pid_t gettid(void);
	 *
	 * gettid()  returns  the caller's thread ID (TID).
	 */
	SYS_REC0(gettid)

	/**
	 * int getrusage(int who, struct rusage *usage)
	 *
	 * getrusage() returns resource usage measures for who, which can be one of the following..
	 */
	SYS_REC1(getrusage, sizeof(struct rusage), regs.ecx)

	/**
	 * int gettimeofday(struct timeval *tv, struct timezone *tz);
	 *
	 * The functions gettimeofday() and settimget_timeofday() can get and set the time as
	 * well as a timezone.  The tv argument is a struct timeval (as specified in <sys/time.h>):
	 *
	 */
	SYS_REC2(gettimeofday, sizeof(struct timeval), regs.ebx, sizeof(struct timezone), regs.ecx)

	/**
	 * int inotify_rm_watch(int fd, uint32_t wd)
	 *
	 * inotify_rm_watch()  removes the watch associated with the watch descriptor wd from the
	 * inotify instance associated with the file descriptor fd.
	 */
	SYS_REC0(inotify_rm_watch)

	/**
	 *  int ioctl(int d, int request, ...)
	 *
	 * The ioctl()  function  manipulates the underlying device parameters of
	 * special files.  In particular, many operating characteristics of  char‐
	 * acter  special  files  (e.g., terminals) may be controlled with ioctl()
	 * requests.  The argument d must be an open file descriptor.
	 *
	 * bits    meaning
	 *	31-30	00 - no parameters: uses _IO macro
	 *			10 - read: _IOR
	 *			01 - write: _IOW
	 *			11 - read/write: _IOWR
	 *
	 * 			29-16	size of arguments
	 *
	 * 			15-8	ascii character supposedly
	 *				unique to each driver
	 *
	 * 			7-0	function #
	 * */
	case SYS_ioctl:
	{
		handle_ioctl_request(ctx, regs.ecx);
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
		int call = regs.ebx;

		switch (call) {

		/* int shmget(key_t key, size_t size, int shmflg); */
		case SHMGET:
		/* void *shmat(int shmid, const void *shmaddr, int shmflg); */
		case SHMAT:
		/* int shmdt(const void *shmaddr); */
		case SHMDT:
		{
			break;
		}

		/* int shmctl(int shmid, int cmd, struct shmid_ds *buf); */
		case SHMCTL:
		{
			int cmd = regs.edx;
			assert(cmd != IPC_INFO);
			assert(cmd != SHM_INFO);
			assert(cmd != SHM_STAT);
			record_child_data(ctx, syscall, sizeof(struct shmid_ds), regs.esi);
			break;
		}

		/* ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg); */
		case MSGRCV:
		{
			record_child_data(ctx, syscall, sizeof(long) + regs.esi, regs.edx);
			break;
		}

		default:
		printf("unknown call in ipc: %d -- bailing out\n", call);
		sys_exit();
		}

		break;
	}

	/**
	 * off_t lseek(int fd, off_t offset, int whence)
	 * The  lseek()  function  repositions the offset of the open file associated with the file
	 descriptor fd to the argument offset according to the directive whence as follows:
	 */
	SYS_REC0(lseek)

	/**
	 * int lstat(const char *path, struct stat *buf);
	 *
	 * lstat() is identical to stat(), except that if path is a symbolic link, then
	 * the link itself is stat-ed, not the file that it refers to.
	 */
	SYS_REC1(lstat64, sizeof(struct stat64), regs.ecx)

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
		record_child_data(ctx, syscall, sizeof(int), regs.ebx);
		int op = regs.ecx & FUTEX_CMD_MASK;

		switch (op) {

		case FUTEX_WAKE:
		case FUTEX_WAIT_BITSET:
		case FUTEX_WAIT:
		case FUTEX_LOCK_PI:
		case FUTEX_UNLOCK_PI:
		case FUTEX_WAIT_REQUEUE_PI:
			break;

		case FUTEX_CMP_REQUEUE:
		case FUTEX_WAKE_OP:
		case FUTEX_CMP_REQUEUE_PI:
		{
			record_child_data(ctx, syscall, sizeof(int), regs.edi);
			break;
		}

		default:
		{
			printf("op: %d unknown futex op\n", op);
			assert(1==0);
		}

		}
		break;
	}

	/**
	 * void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
	 *
	 * mmap()  creates  a  new  mapping in the virtual address space of the calling process.
	 * The starting address for the new mapping is specified in addr.  The length argument specifies
	 * the length of the mapping.
	 */
	SYS_REC0(munmap)

	/**
	 * pid_t getpgrp(void)
	 *
	 * The POSIX.1 getpgrp() always returns the PGID of the caller
	 */
	SYS_REC0(getpgrp)

	/**
	 * int inotify_init(void)
	 *
	 * inotify_init()  initializes  a  new inotify instance and returns a file
	 * descriptor associated with a new inotify event queue.
	 */
	SYS_REC0(inotify_init1)

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
	SYS_REC0(inotify_add_watch)

	/* int kill(pid_t pid, int sig)
	 *
	 * The kill() system call can be used to send any signal to any process group or process.
	 */
	SYS_REC0(kill)

	/**
	 * long set_robust_list(struct robust_list_head *head, size_t len)
	 *
	 * The robust futex implementation needs to maintain per-thread lists of robust futexes
	 * which are unlocked when the thread exits. These lists are managed in user space, the
	 * kernel is only notified about the location of the head of the list.

	 * set_robust_list sets the head of the list of robust futexes owned by the current thread to head.
	 * len is the size of *head.
	 */
	SYS_REC0(set_robust_list)

	/* int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
	 *
	 * getresuid()  returns  the  real  UID,  the effective UID, and the saved set-user-ID of
	 * the calling process, in the arguments ruid, euid, and suid, respectively.  getresgid()
	 * performs the analogous task  for  the  process's  group IDs.
	 * @return:  On success, zero is returned.  On error, -1 is returned, and errno is set appropriately.
	 */
	SYS_REC3(getresgid32, sizeof(uid_t), regs.ebx, sizeof(uid_t), regs.ecx, sizeof(uid_t), regs.edx)

	/**
	 * int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
	 *
	 * getresuid() returns the real UID, the effective UID, and the saved set-
	 * user-ID of the calling process, in the arguments ruid, euid, and  suid,
	 * respectively.    getresgid()   performs  the  analogous  task  for  the
	 * process's group IDs.
	 */
	SYS_REC3(getresuid32, sizeof(uid_t), regs.ebx, sizeof(uid_t), regs.ecx, sizeof(uid_t), regs.edx)

	/*
	 * int _llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low,
	 * loff_t *result, unsigned int whence);
	 *
	 * The  _llseek()  function  repositions  the offset of the open file associated with the file descriptor fd to (off‐
	 * set_high<<32) | offset_low bytes relative to the beginning of the file, the current position in the file,  or  the
	 * end  of  the  file,  depending on whether whence is SEEK_SET, SEEK_CUR, or SEEK_END, respectively.  It returns the
	 * resulting file position in the argument result.
	 */

	SYS_REC1(_llseek, sizeof(loff_t), regs.esi)

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
	SYS_REC0(madvise)

	/**
	 * int mkdir(const char *pathname, mode_t mode);
	 *
	 * mkdir() attempts to create a directory named pathname.
	 */
	SYS_REC0(mkdir)

	/**
	 * int mprotect(const void *addr, size_t len, int prot)
	 *
	 * mprotect()  changes  protection for the calling process's memory page(s) containing any
	 * part of the address range in the interval [addr, addr+len-1].  addr must be aligned to a
	 *  page boundary.

	 * If the calling process tries to access memory in a manner that violates the  protection,  then  the
	 * kernel generates a SIGSEGV signal for the process
	 */
	SYS_REC0(mprotect)

	/**
	 * int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
	 *
	 * select()  and  pselect() allow a program to monitor multiple file descriptors, waiting until one or
	 * more of the file descriptors become "ready" for some class of I/O operation (e.g., input possible).
	 * A file descriptor is considered ready if  it  is possible to perform the corresponding I/O operation
	 * (e.g., read(2)) without blocking.
	 *
	 * We also need to record edi, since the return value of the time struct is not defined
	 */

	SYS_REC4(_newselect, sizeof(fd_set), regs.ecx, sizeof(fd_set), regs.edx, sizeof(fd_set), regs.esi, sizeof(struct timeval), regs.edi)

	/* this class of system calls has a char* as argument 0; we log this argument */

	/*
	 * int open(const char *pathname, int flags)
	 * int open(const char *pathname, int flags, mode_t mode)
	 */
	SYS_REC0(open)

	/**
	 *  int pipe(int pipefd[2]);
	 *
	 * pipe()  creates  a  pipe, a unidirectional data channel that can be used for
	 * interprocess communiinotify_init1cation.  The array pipefd is used  to  return  two  file
	 * descriptors referring to the ends of the pipe.  pipefd[0] refers to the read
	 * end of the pipe.  pipefd[1] refers to the write end of the pipe.  Data writ‐
	 * ten  to the write end of the pipe is buffered by the kernel until it is read
	 * from the read end of the pipe.  For further details, see pipe(7).
	 */
	SYS_REC2(pipe, sizeof(int), regs.ebx, sizeof(int), regs.ebx+sizeof(int*))

	/**
	 * int pipe2(int pipefd[2], int flags)
	 *
	 * If flags is 0, then pipe2() is the same as pipe().  The following values can be bitwise
	 * ORed in flags to obtain different behavior...
	 */
	SYS_REC2(pipe2, sizeof(int), regs.ebx, sizeof(int), regs.ebx+sizeof(int*))

	/**
	 * int poll(struct pollfd *fds, nfds_t nfds, int timeout)
	 *
	 * poll() performs a similar task to select(2): it waits for one of a set of file descriptors to
	 * become ready to perform I/O.
	 *
	 * Potentially blocking
	 */
	case SYS_poll:
	{
		int i;
		for (i = 0; i < regs.ecx; i++) {
			record_child_data(ctx, syscall, sizeof(struct pollfd), regs.ebx + (i * sizeof(struct pollfd)));
		}
		break;
	}

	/**
	 * int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
	 *
	 *  prctl() is called with a first argument describing what to do (with values defined in <linux/prctl.h>), and
	 *  further arguments with a significance depending on the first one.
	 *
	 * FIXXME: check if there is some output in the variable parameters
	 */
	SYS_REC0(prctl)

	/**
	 * ssize_t pread(int fd, void *buf, size_t count, off_t offset);
	 *
	 * pread, pwrite - read from or write to a file descriptor at a given off‐
	 * set
	 */
	SYS_REC1(pread64, regs.edx, regs.ecx)

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
	SYS_REC1(prlimit64, sizeof(struct rlimit64), regs.esi)

	/**
	 * int quotactl(int cmd, const char *special, int id, caddr_t addr);
	 *
	 * The  quotactl()  call  manipulates disk quotas.  The cmd argument indi‐
	 * cates a command to be applied to the user or group ID specified in  id.
	 * To  initialize the cmd argument, use the QCMD(subcmd, type) macro.  The
	 * type value is either USRQUOTA, for user quotas, or GRPQUOTA, for  group
	 * quotas.  The subcmd value is described below.
	 */
	case SYS_quotactl:
	{
		assert(1==0);
		break;
	}

	/**
	 * ssize_t readlink(const char *path, char *buf, size_t bufsiz);
	 *
	 * readlink() places the contents of the symbolic link path in the buffer
	 * buf, which has size bufsiz. readlink() does not append a null byte to buf.
	 * It will truncate the contents (to a length of bufsiz characters), in case
	 * the buffer is too small to hold all of the contents.
	 */
	SYS_REC1(readlink, regs.edx, regs.ecx)

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
	SYS_REC1(rt_sigaction, sizeof(struct sigaction), regs.edx)

	/**
	 *  int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
	 *
	 *  sigprocmask() is used to fetch and/or change the signal mask of the calling
	 *  thread.  The signal mask is the set of signals whose delivery is currently
	 *   blocked for the caller (see also signal(7) for more details).
	 */
	SYS_REC1(rt_sigprocmask, sizeof(sigset_t), regs.edx)

	/**
	 * int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
	 *
	 * sched_getaffinity()  writes  the affinity mask of the process whose ID is pid into the cpu_set_t structure
	 * pointed to by mask.  The cpusetsize argument specifies the
	 *  size (in bytes) of mask.  If pid is zero, then the mask of the calling process is returned.
	 */
	SYS_REC1(sched_getaffinity, sizeof(cpu_set_t), regs.edx)

	/**
	 * int sched_getparam(pid_t pid, struct sched_param *param)
	 *
	 * sched_getparam()  retrieves  the  scheduling  parameters  for  the  process  i
	 * dentified  by  pid.  If pid is zero, then the parameters of the calling process
	 * are retrieved.
	 */
	SYS_REC1(sched_getparam, sizeof(struct sched_param), regs.ecx)

	/**
	 *  int sched_get_priority_max(int policy)
	 *
	 * sched_get_priority_max() returns the maximum priority value that can be
	 * used    with   the   scheduling   algorithm   identified   by   policy.
	 */
	SYS_REC0(sched_get_priority_max)

	/**
	 * int sched_get_priority_min(int policy)
	 *
	 * sched_get_priority_min() returns the minimint fdatasync(int fd);um priority value that can be used
	 * with the scheduling algorithm identified by  policy.
	 */
	SYS_REC0(sched_get_priority_min)

	/**
	 * int sched_getscheduler(pid_t pid);
	 *
	 * sched_getscheduler() queries the scheduling policy currently applied to the
	 * process identified by pid.  If pid equals zero, the policy  of  the  calling
	 * process will be retrieved.
	 */
	SYS_REC0(sched_getscheduler)

	/**
	 * int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param);
	 *
	 * sched_setscheduler()  sets  both the scheduling policy and the associated parameters
	 * for the process whose ID is specified in pid.  If pid equals zero, the scheduling policy
	 * and parameters of the calling process will be set.  The interpretation of the argument
	 * param depends on the selected policy.
	 */
	SYS_REC0(sched_setscheduler)

	/**
	 * int sched_yield(void)
	 *
	 * sched_yield() causes the calling thread to relinquish the CPU.  The thread is moved to the end of
	 * the queue for its static priority and a new thread gets to run.
	 */
	SYS_REC0(sched_yield)

	/**
	 * int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value);
	 *
	 */
	SYS_REC1(setitimer, sizeof(struct itimerval), regs.edx);

	/**
	 * int setregid(gid_t rgid, gid_t egid)
	 *
	 * setreuid() sets real and effective user IDs of the calling process
	 */
	SYS_REC0(setregid32)

	/**
	 * pid_t setsid(void);
	 *
	 * setsid() creates a new session if the calling process is not a process group leader.
	 */
	SYS_REC0(setsid)

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
	SYS_REC0(set_thread_area)

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
	SYS_REC1(set_tid_address, sizeof(int), regs.ebx)

	/**
	 * int sigaltstack(const stack_t *ss, stack_t *oss)
	 *
	 * sigaltstack()  allows a process to define a new alternate signal stack and/or retrieve the state of
	 * an existing alternate signal stack.  An alternate signal stack is used during the execution of a signal
	 * handler if the establishment of that handler (see sigaction(2)) requested it.
	 */
	SYS_REC0(sigaltstack)

	/**
	 * int sigreturn(unsigned long __unused)
	 *
	 * When  the Linux kernel creates the stack frame for a signal handler, a call to sigreturn()
	 * is inserted into the stack frame so that upon return from the signal handler, sigreturn() will
	 * be called.
	 */
	SYS_REC0(sigreturn)

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
		int call = regs.ebx;
		uintptr_t base_addr = regs.ecx;

		debug_print("socket call: %d\n", call);
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
		{
			break;
		}
		/* int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */
		case SYS_GETPEERNAME:
		/* int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */
		case SYS_GETSOCKNAME:
		{

			long int* addr = read_child_data(ctx, sizeof(void*), base_addr + 2 * sizeof(int));
			socklen_t *addrlen = read_child_data(ctx, sizeof(socklen_t), *addr);
			record_child_data(ctx, syscall, sizeof(socklen_t), *addr);
			sys_free((void**) &addr);

			addr = read_child_data(ctx, sizeof(void*), base_addr + sizeof(int));
			record_child_data(ctx, syscall, *addrlen, *addr);
			sys_free((void**) &addr);
			sys_free((void**) &addrlen);
			break;
		}

		/* ssize_t recv(int sockfd, void *buf, size_t len, int flags) */
		case SYS_RECV:
		{
			uintptr_t* buf;
			size_t* len;

			buf = read_child_data(ctx, sizeof(void*), base_addr + 4);
			len = read_child_data(ctx, sizeof(void*), base_addr + 8);
			record_child_data(ctx, syscall, *len, *buf);
			sys_free((void**) &len);
			sys_free((void**) &buf);
			break;
		}

		/* ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags); */
		case SYS_RECVMSG:
		{
			struct msghdr** ptr = read_child_data(ctx, sizeof(void*), base_addr + sizeof(int));
			struct msghdr* msg = read_child_data(ctx, sizeof(struct msghdr), (long int) *ptr);

			assert(msg->msg_iovlen == 1);
			record_child_data(ctx, syscall, sizeof(struct msghdr), (long int) *ptr);
			record_child_data(ctx, syscall, sizeof(struct iovec), (long int) (msg->msg_iov));
			struct iovec *iov = read_child_data(ctx, sizeof(struct iovec), (long int) msg->msg_iov);
			record_child_data(ctx, syscall, iov->iov_len, (long int) iov->iov_base);
			record_child_data(ctx, syscall, msg->msg_controllen, (long int) msg->msg_control);

			sys_free((void**) &iov);
			sys_free((void**) &msg);
			sys_free((void**) &ptr);
			break;
		}

		/* ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen); */
		case SYS_RECVFROM:
		{
			uintptr_t* buf;
			size_t* len;
			socklen_t** addrlen_ptr;
			socklen_t *addrlen;
			struct sockaddr** src_addr_ptr;

			buf = read_child_data(ctx, sizeof(void*), base_addr + 4);
			len = read_child_data(ctx, sizeof(void*), base_addr + 8);
			src_addr_ptr = read_child_data(ctx, sizeof(struct sockaddr), base_addr + 16);
			addrlen_ptr = read_child_data(ctx, sizeof(socklen_t), (long int) base_addr + 20);
			addrlen = read_child_data(ctx, sizeof(socklen_t), (long int) *addrlen_ptr);

			record_child_data(ctx, syscall, *len, *buf);
			record_child_data(ctx, syscall, sizeof(socklen_t), (long int) *addrlen_ptr);
			record_child_data(ctx, syscall, *addrlen, (long int) *src_addr_ptr);

			sys_free((void**) &buf);
			sys_free((void**) &len);
			sys_free((void**) &addrlen_ptr);
			sys_free((void**) &addrlen);
			sys_free((void**) &src_addr_ptr);
			break;
		}

		/**
		 *  int getsockopt(int sockfd, int level, int optname, const void *optval, socklen_t* optlen);
		 */
		case SYS_GETSOCKOPT:
		{
			socklen_t** len_ptr = read_child_data(ctx, sizeof(socklen_t*), regs.ecx + 3 * sizeof(int) + sizeof(void*));
			socklen_t* len = read_child_data(ctx, sizeof(socklen_t), (long int) *len_ptr);
			unsigned long** optval = read_child_data(ctx, sizeof(void*), regs.ecx + 3 * sizeof(int));
			record_child_data(ctx, syscall, *len, (long int) *optval);
			sys_free((void**) &len_ptr);
			sys_free((void**) &len);
			sys_free((void**) &optval);
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
			socklen_t *addrlen = read_child_data(ctx, sizeof(socklen_t), regs.ecx + (sizeof(int) + sizeof(struct sockaddr*)));
			struct sockaddr **addr_ptr = read_child_data(ctx, sizeof(struct sockaddr*), regs.ecx + sizeof(int));
			record_child_data(ctx, syscall, sizeof(struct sockaddr), (long int) *addr_ptr);
			record_child_data(ctx, syscall, sizeof(socklen_t), *addrlen);
			sys_free((void**) &addr_ptr);
			sys_free((void**) &addrlen);
			break;
		}

		/* int socketpair(int domain, int type, int protocol, int sv[2]);
		 *
		 * values returned in sv
		 */
		case SYS_SOCKETPAIR:
		{
			unsigned long* addr = read_child_data(ctx, sizeof(int*), (long int) regs.ecx + (3 * sizeof(int)));
			record_child_data(ctx, syscall, 2 * sizeof(int), *addr);
			sys_free((void**) &addr);
			break;
		}

		default:
		fprintf(stderr, "unknwon socket call: %d -- baling out\n", call);
		sys_exit();
		}
		break;
	}

	/**
	 *  int stat(const char *path, struct stat *buf);
	 *
	 *  stat() stats the file pointed to by path and fills in buf.
	 */
	SYS_REC1(stat64, sizeof(struct stat64), regs.ecx)

	/**
	 * int statfs(const char *path, struct statfs *buf)
	 *
	 * The function statfs() returns information about a mounted file system.  path is the pathname of any file within the mounted
	 * file system.  buf is a pointer to a statfs structure defined approximately as follows:
	 */
	SYS_REC1(statfs, sizeof(struct statfs), regs.ecx)

	/**
	 * int statfs(const char *path, struct statfs *buf)
	 *
	 * The  function  statfs() returns information about a mounted file system.
	 * path is the pathname of any file within the mounted file system.  buf is a
	 * pointer to a statfs structure defined approximately as follows:
	 *
	 * FIXXME: we use edx here, although according to man pages this system call has only
	 * 2 paramaters. However, strace tells another story...
	 */
	SYS_REC1(statfs64, sizeof(struct statfs64), regs.edx)

	/**
	 * int symlink(const char *oldpath, const char *newpath)
	 *
	 * symlink() creates a symbolic link named newpath which contains the string oldpath.
	 */
	SYS_REC0(symlink)

	/**
	 * int sysinfo(struct sysinfo *info)
	 *
	 * sysinfo() provides a simple way of getting overall system statistics.
	 */
	SYS_REC1(sysinfo, sizeof(struct sysinfo), regs.ebx)

	/**
	 * int tgkill(int tgid, int tid, int sig)
	 * tgkill()  sends  the  signal sig to the thread with the thread ID tid in the thread group tgid.  (By contrast, kill(2) can only be used to send a
	 * signal to a process (i.e., thread group) as a whole, and the signal will be delivered to an arbitrary thread within that process.)
	 */
	case SYS_tgkill:
	{
		//printf("%d:tgkill: send sig: %d to %d    ret: %ld\n", ctx->child_tid, regs.edx, regs.ecx, regs.eax);
		break;
	}

	/**
	 * time_t time(time_t *t);
	 *
	 * time() returns the time since the Epoch (00:00:00 UTC, January 1, 1970), measured
	 *  in seconds. If t is non-NULL, the return value is also stored in the memory pointed
	 *  to by t.
	 */
	SYS_REC1(time, sizeof(time_t), regs.ebx)

	/**
	 * clock_t times(struct tms *buf)
	 *
	 * times()  stores  the  current  process  times in the struct tms that buf points to.  The
	 *  struct tms is as defined in <sys/times.h>:
	 */
	SYS_REC1(times, sizeof(struct tms), regs.ebx)

	/**
	 * int getrlimit(int resource, struct rlimit *rlim)
	 *
	 * getrlimit()  and  setrlimit()  get and set resource limits respectively.
	 * Each resource has an associated soft and hard limit, as defined by the rlimit structure
	 * (the rlim argument to both getrlimit() and setrlimit()):
	 */
	SYS_REC1(ugetrlimit, sizeof(struct rlimit), regs.ecx)

	/**
	 * int uname(struct utsname *buf)
	 *
	 * uname() returns system information in the structure pointed to by buf. The utsname
	 * struct is defined in <sys/utsname.h>:
	 */
	SYS_REC1(uname, sizeof(struct utsname), regs.ebx)

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
	 */
	SYS_REC0(utime)

	/* signature:
	 * int execve(const char *filename, char *const argv[], char *const envp[]);
	 *
	 */
	case SYS_execve:
	{
		unsigned int* stack_ptr = (unsigned int*) read_child_esp(tid);
		print_register_file_tid(tid);

		/* esp[0] points to argc - iterate over argv pointers*/
		int* argc = read_child_data(ctx, 100, (long int) (stack_ptr));

		stack_ptr += *argc + 1;
		sys_free((void**) &argc);

		unsigned long* null_ptr = read_child_data(ctx, sizeof(void*), (long int) stack_ptr);
		assert(*null_ptr == 0);
		sys_free((void**) &null_ptr);

		/* should now point to envp (pointer to environment strings) */
		stack_ptr++;

		unsigned long* tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);

		while (*tmp != 0) {
			sys_free((void**) &tmp);
			stack_ptr++;
			tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		}
		sys_free((void**) &tmp);
		stack_ptr++;
		/* should now point to ELF Auxiliary Table */

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0x20);
		/* AT_SYSINFO */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0x21);
		/* AT_SYSINFO_EHDR */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0x10);
		/* AT_HWCAP */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0x6);
		/* AT_PAGESZ */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0x11);
		/* AT_CLKTCK */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0x3);
		/* AT_PHDR */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0x4);
		/* AT_PHENT */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0x5);
		/* AT_PHNUM */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0x7);
		/* AT_BASE */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0x8);
		/* AT_FLAGS */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0x9);
		/* AT_ENTRY */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0xb);
		/* AT_UID */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0xc);
		/* AT_EUID */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0xd);
		/* AT_GID */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0xe);
		/* AT_EGID */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0x17);
		/* AT_SECURE */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(ctx, sizeof(unsigned long*), (long int) stack_ptr);
		assert(*tmp == 0x19);
		/* AT_RANDOM */
		unsigned long* rand_addr = read_child_data(ctx, sizeof(unsigned long*), (long int) (stack_ptr + 1));
		record_child_data(ctx, syscall, 16, (long int) *rand_addr);
		sys_free((void**) &rand_addr);
		sys_free((void**) &tmp);
		break;
	}

	/**
	 * int fstat(int fd, struct stat *buf)
	 *
	 * fstat()  is  identical  to  stat(),  except  that  the  file to be stat-ed is specified
	 * by the file descriptor fd.
	 *
	 */

	SYS_REC1(fstat64, sizeof(struct stat64), regs.ecx)

	/**
	 * pid_t fork(void)
	 *
	 * fork()  creates  a new process by duplicating the calling process.  The new process, referred to as
	 * the child, is an exact duplicate of the calling process, referred to as the parent, except for the
	 * following points...
	 *
	 */
	SYS_REC0(fork)

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
		print_register_file_tid(tid);
		/* inspect mmap arguments */
		long int flags = regs.esi;
		/* Anonymous mappings are fine - the allocated space is initialized with '0'.
		 * For non-anonymous mappings we record the mapped memory region and inject the
		 * recorded content in the replayer.
		 */
		if (!(flags & MAP_ANONYMOUS)) {
			assert((flags & MAP_GROWSDOWN) == 0);
			record_child_data(ctx, syscall, regs.ecx, regs.eax);
		}
		break;
	}

	/*
	 * void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... ( void *new_address ));
	 *
	 *  mremap()  expands  (or  shrinks) an existing memory mapping, potentially moving it at the same time
	 *  (controlled by the flags argument and the available virtual address space).
	 */
	SYS_REC0(mremap)

	/**
	 * int rmdir(const char *pathname)
	 *
	 * rmdir() deletes a directory, which must be empty.
	 */
	SYS_REC0(rmdir)

	/**
	 * ssize_t write(int fd, const void *buf, size_t count)
	 *
	 * write() writes up to count bytes to the file referenced by the file descriptor fd
	 * write()  from the buffer starting at buf. POSIX requires that a read() which can be
	 * proved to occur after a write() has returned returns the new data. Note that not all file
	 *  systems are POSIX conforming.
	 */
	SYS_REC0(write)

	/*
	 * ssize_t read(int fd, void *buf, size_t count);
	 *
	 * read() attempts to read up to count bytes from file descriptor fd into the buffer starting at buf.
	 */
	SYS_REC1(read, regs.edx, regs.ecx)

	/**
	 * int rename(const char *oldpath, const char *newpath)
	 *
	 * rename() renames a file, moving it between directories if required.
	 */
	SYS_REC0(rename)

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
	SYS_REC0(setpgid)

	/**
	 * int setrlimit(int resource, const struct rlimit *rlim)
	 *
	 *  getrlimit() and setrlimit() get and set resource limits respectively.  Each resource has an associated soft and hard limit, as
	 defined by the rlimit structure (the rlim argument to both getrlimit() and setrlimit()):

	 struct rlimit {
	 rlim_t rlim_cur;  // Soft limit
	 rlim_t rlim_max;  // Hard limit (ceiling for rlim_cur)
	 };

	 The soft limit is the value that the kernel enforces for the corresponding resource.  The hard limit acts as a ceiling for the
	 soft  limit:  an  unprivileged  process  may  only set its soft limit to a value in the range from 0 up to the hard limit, and
	 (irreversibly) lower its hard limit.  A privileged process (under Linux: one with the CAP_SYS_RESOURCE  capability)  may  make
	 arbitrary changes to either limit value.
	 */
	SYS_REC1(setrlimit, sizeof(struct rlimit), regs.ecx)

	/**
	 * mode_t umask(mode_t mask);
	 * umask()  sets  the  calling  process's file mode creation mask (umask) to mask & 0777
	 * (i.e., only the file permission bits of mask are used), and returns the previous value of the mask.
	 *
	 */
	SYS_REC0(umask)

	/**
	 * int unlink(const char *path);
	 *
	 * The unlink() function shall remove a link to a file. If path names a symbolic link, unlink()
	 * shall remove the symbolic link named by path and shall not affect any file or directory named
	 * by the contents of the symbolic link. Otherwise, unlink() shall remove the link named by the
	 * pathname pointed to by path and shall decrement the link count of the file referenced by the link.
	 *
	 */
	SYS_REC0(unlink)

	/**
	 * pid_t vfork(void);
	 *
	 * vfork - create a child process and block parent
	 */
	SYS_REC0(vfork)

	/**
	 * pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
	 *
	 * The  wait3()  and wait4() system calls are similar to waitpid(2), but
	 * additionally return resource usage information about the child in the
	 * structure pointed to by rusage.
	 */
	SYS_REC2(wait4, sizeof(int), regs.ecx, sizeof(struct rusage), regs.esi)

	/**
	 * pid_t waitpid(pid_t pid, int *status, int options);
	 *
	 * The waitpid() system call suspends execution of the calling process until
	 * a child specified by pid argument has changed state.  By default, waitpid()
	 * waits only for terminated children, but this behavior  is  modifiable  via
	 * the options argument, as described below....
	 *
	 */
	SYS_REC1(waitpid, sizeof(int), regs.ecx)

	/**
	 * ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
	 * The writev() function writes iovcnt buffers of data described by iov
	 * to the file associated with the file descriptor fd ("gather output").
	 */
	SYS_REC0(writev)

	default:

	printf("recorder: unknown syscall %ld -- bailing out\n", syscall);
	printf("execuction state: %x sig %d\n", ctx->exec_state,signal_pending(ctx->exec_state));
	print_register_file_tid(tid);
//	get_eip_info(tid);
	sys_exit();
	break;
	}
}
