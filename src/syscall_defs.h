/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

/**
 * Each known syscall is written as
 *
 *   SYSCALL_DEF*(name[, ...])
 *
 * These definitions comprise the syscalls known to rr.  The includer
 * should define SYSCALL_DEF*() macros, in the format described below,
 * that will do something with each syscall definition.  The
 * SYSCALL_DEF*() formats are
 *
 *   DEF[N](name, semantics[, type, reg...]) -> the syscall has N
 *   pairs of (type, register) args.  For example,
 *   |SYSCALL_DEF1(gettimeofday, EMU, struct timeval, arg1)| has one
 *   outparam arg in |arg1()| of size |sizeof(struct timeval)|.
 *
 *   DEF[N]_DYNSIZE(name, semantics[, dynamic-size, reg...]) -> like
 *   above, except that the N pairs are (dynamic-size, register) args.
 *   An arbitrary expression of the relevant Task |t| can be used to
 *   specify the size of each argument, for example |t->regs().syscall_result() *
 *   sizeof(int)|.
 *
 *   DEF_IRREG(name, irreg_semantics) -> the syscall doesn't fit a
 *   regular pattern; hand-written code is needed to process the
 *   syscall args.
 *
 *   DEF_UNSUPPORTED(name) -> the syscall is not yet supported by rr.
 *   rr will abort when seeing such a syscall (if the kernel does not return
 *   ENOSYS).
 *
 * |name| is the short syscall descriptor, e.g. "close".  For syscalls
 * other than DEF_IRREG(), replay |semantics| is one of
 *
 *   EMU: fully emulated syscall
 *   EXEC: fully executed syscall
 *   EXEC_RET_EMU: syscall is executed, but retval is emulated
 *   IRREGULAR: doesn't adhere to regular format (e.g. meta-syscalls
 *     like socketcall)
 *
 * For DEF_IRREG(), the replay |irreg_semantics| is one of
 *
 *   MAY_EXEC: syscall may be fully executed
 *   EMU: syscall will always be emulated
 *
 * System calls are ordered by system call number.
 * Use SYSCALLNO_X86(N) macro to set the system call number of the next system
 * call to N for x86.
 * By default the system call number is the number of the previous system call
 * plus one.
 */

SYSCALLNO_X86(1)
/**
 *  void exit(int status)
 *
 * The exit() function causes normal process termination and the value
 * of status & 0377 is returned to the parent (see wait(2)).
 */
SYSCALL_DEF_IRREG(exit, MAY_EXEC)

// Obsolete. glibc calls clone() instead.
SYSCALL_DEF_UNSUPPORTED(fork)

/**
 *  ssize_t read(int fd, void *buf, size_t count);
 *
 * read() attempts to read up to count bytes from file descriptor fd
 * into the buffer starting at buf.
 *
 * CHECKED: (trace->recorded_regs.eax > 0)
 */
SYSCALL_DEF_IRREG(read, EMU)

/**
 *  ssize_t write(int fd, const void *buf, size_t count);
 *
 * write() writes up to count bytes to the file referenced by the file
 * descriptor fd from the buffer starting at buf. POSIX requires that
 * a read() which can be proved to occur after a write() has returned
 * returns the new data. Note that not all file systems are POSIX
 * conforming.
 *
 * Note: write isn't irregular per se; we hook it to redirect output
 * to stdout/stderr during replay.
 */
SYSCALL_DEF_IRREG(write, EMU)

/**
 *  int open(const char *pathname, int flags)
 *  int open(const char *pathname, int flags, mode_t mode)
 *
 * Given a pathname for a file, open() returns a file descriptor, a
 * small, nonnegative integer for use in subsequent system calls
 * (read(2), write(2), lseek(2), fcntl(2), etc.).  The file descriptor
 * returned by a successful call will be the lowest-numbered file
 * descriptor not currently open for the process.
 */
SYSCALL_DEF_IRREG(open, EMU)

/**
 *  int close(int fd)
 *
 * close() closes a file descriptor, so that it no longer refers to
 * any file and may be reused.  Any record locks (see fcntl(2)) held
 * on the file it was associated with, and owned by the process, are
 * removed (regardless of the file descriptor that was used to obtain
 * the lock).
 */
SYSCALL_DEF0(close, EMU)

/**
 *  pid_t waitpid(pid_t pid, int *status, int options);
 *
 * The waitpid() system call suspends execution of the calling process
 * until a child specified by pid argument has changed state.  By
 * default, waitpid() waits only for terminated children, but this
 * behavior is modifiable via the options argument, as described
 * below....
 */
SYSCALL_DEF_IRREG(waitpid, EMU)

/**
 *  int creat(const char *pathname, mode_t mode);
 *
 * creat() is equivalent to open() with flags equal to
 * O_CREAT|O_WRONLY|O_TRUNC.
 */
SYSCALL_DEF0(creat, EMU)

/**
 *  int link(const char *oldpath, const char *newpath);
 *
 * link() creates a new link (also known as a hard link) to an
 * existing file.
 */
SYSCALL_DEF0(link, EMU)

/**
 *  int unlink(const char *path);
 *
 * The unlink() function shall remove a link to a file. If path names
 * a symbolic link, unlink() shall remove the symbolic link named by
 * path and shall not affect any file or directory named by the
 * contents of the symbolic link. Otherwise, unlink() shall remove the
 * link named by the pathname pointed to by path and shall decrement
 * the link count of the file referenced by the link.
 */
SYSCALL_DEF0(unlink, EMU)

/**
 *  int execve(const char *filename, char *const argv[], char *const envp[]);
 *
 * execve() executes the program pointed to by filename.
 */
SYSCALL_DEF_IRREG(execve, MAY_EXEC)

/**
 *  int chdir(const char *path);
 *
 * chdir() changes the current working directory of the calling
 * process to the directory specified in path.
 */
SYSCALL_DEF0(chdir, EMU)

/**
 *  time_t time(time_t *t);
 *
 * time() returns the time since the Epoch (00:00:00 UTC, January 1,
 * 1970), measured in seconds. If t is non-NULL, the return value is
 * also stored in the memory pointed to by t.
 */
SYSCALL_DEF1(time, EMU, time_t, arg1)

SYSCALL_DEF_UNSUPPORTED(mknod)

/**
 *  int chmod(const char *path, mode_t mode)
 *
 * The mode of the file given by path or referenced by fildes is
 * changed.
 */
SYSCALL_DEF0(chmod, EMU)

SYSCALL_DEF_UNSUPPORTED(lchown)
SYSCALL_DEF_UNSUPPORTED(_break)
SYSCALL_DEF_UNSUPPORTED(oldstat)

/**
 *  off_t lseek(int fd, off_t offset, int whence)
 *
 * The lseek() function repositions the offset of the open file
 * associated with the file descriptor fd to the argument offset
 * according to the directive whence as follows:
 */
SYSCALL_DEF0(lseek, EMU)

/**
 *  pid_t getpid(void);
 *
 * getpid() returns the process ID of the calling process.  (This is
 * often used by routines that generate unique temporary
 * filenames.)
 */
SYSCALL_DEF0(getpid, EMU)

SYSCALL_DEF_UNSUPPORTED(mount)
SYSCALL_DEF_UNSUPPORTED(umount)
SYSCALL_DEF_UNSUPPORTED(setuid)
SYSCALL_DEF_UNSUPPORTED(getuid)
SYSCALL_DEF_UNSUPPORTED(stime)

/**
 *  long ptrace(enum __ptrace_request request, pid_t pid,
 *              void *addr, void *data);
 *
 * The ptrace() system call provides a means by which one process (the
 * "tracer") may observe and control the execution of another process
 * (the "tracee"), and examine and change the tracee's memory and
 * registers.  It is primarily used to implement breakpoint debugging
 * and system call tracing.
 */
SYSCALL_DEF_IRREG(ptrace, EMU)

/**
 *  unsigned int alarm(unsigned int seconds)
 *
 * The alarm() system call schedules an alarm. The process will get a
 * SIGALRM after the requested amount of seconds.
 */
SYSCALL_DEF0(alarm, EMU)

SYSCALL_DEF_UNSUPPORTED(oldfstat)

/**
 *  int pause(void);
 *
 * pause() causes the calling process (or thread) to sleep until a
 * signal is delivered that either terminates the process or causes
 * the invocation of a signal-catching function.
 */
SYSCALL_DEF0(pause, EMU)

/**
 *  int utime(const char *filename, const struct utimbuf *times)
 *
 * The utime() system call changes the access and modification times
 * of the inode specified by filename to the actime and modtime fields
 * of times respectively.
 *
 * If times is NULL, then the access and modification times of the
 * file are set to the current time.
 *
 * Changing timestamps is permitted when: either the process has
 * appropriate privileges, or the effective user ID equals the user ID
 * of the file, or times is NULL and the process has write permission
 * for the file.
 *
 * FIXME: is mod_time set by the kernel?
 */
SYSCALL_DEF0(utime, EMU)

SYSCALL_DEF_UNSUPPORTED(stty)
SYSCALL_DEF_UNSUPPORTED(gtty)

/**
 *  int access(const char *pathname, int mode);
 *
 * access() checks whether the calling process can access the file
 * pathname.  If pathname is a symbolic link, it is dereferenced.
 */
SYSCALL_DEF0(access, EMU)

SYSCALL_DEF_UNSUPPORTED(nice)
SYSCALL_DEF_UNSUPPORTED(ftime)
SYSCALL_DEF_UNSUPPORTED(sync)

/**
 *  int kill(pid_t pid, int sig)
 *
 * The kill() system call can be used to send any signal to any
 * process group or process.
 */
SYSCALL_DEF0(kill, EMU)

/**
 *  int rename(const char *oldpath, const char *newpath)
 *
 * rename() renames a file, moving it between directories if required.
 */
SYSCALL_DEF0(rename, EMU)

/**
 *  int mkdir(const char *pathname, mode_t mode);
 *
 * mkdir() attempts to create a directory named pathname.
 */
SYSCALL_DEF0(mkdir, EMU)

/**
 *  int rmdir(const char *pathname)
 *
 * rmdir() deletes a directory, which must be empty.
 */
SYSCALL_DEF0(rmdir, EMU)

/**
 *  int dup(int oldfd)
 *
 * dup() uses the lowest-numbered unused descriptor for the new
 * descriptor.
 */
SYSCALL_DEF0(dup, EMU)

/**
 *  int pipe(int pipefd[2]);
 *
 * pipe() creates a pipe, a unidirectional data channel that can be
 * used for interprocess communication.  The array pipefd is used to
 * return two file descriptors referring to the ends of the pipe.
 * pipefd[0] refers to the read end of the pipe.  pipefd[1] refers to
 * the write end of the pipe.  Data writ‐ ten to the write end of the
 * pipe is buffered by the kernel until it is read from the reoad end
 * of the pipe.  For further details, see pipe(7).
 */
SYSCALL_DEF1(pipe, EMU, int[2], arg1)

/**
 *  clock_t times(struct tms *buf)
 *
 * times() stores the current process times in the struct tms that buf
 *  points to.  The struct tms is as defined in <sys/times.h>:
 */
SYSCALL_DEF1(times, EMU, struct tms, arg1)

SYSCALL_DEF_UNSUPPORTED(prof)

/**
 *  int brk(void *addr)
 *
 * brk() and sbrk() change the location of the program break, which
 * defines the end of the process's data segment (i.e., theprogram
 * break is the first location after the end of the uninitialized data
 * segment).  Increasing the program break has the effect of
 * allocating memory to the process; decreasing the break deallocates
 * memory.
 *
 * brk() sets the end of the data segment to the value specified by
 * addr, when that value is reasonable, the system has enough memory,
 * and the process does not exceed its maximum data size (see
 * setrlimit(2)).
 */
SYSCALL_DEF0(brk, EXEC)

SYSCALL_DEF_UNSUPPORTED(setgid)
SYSCALL_DEF_UNSUPPORTED(getgid)
SYSCALL_DEF_UNSUPPORTED(signal)
SYSCALL_DEF_UNSUPPORTED(geteuid)
SYSCALL_DEF_UNSUPPORTED(getegid)
SYSCALL_DEF_UNSUPPORTED(acct)
SYSCALL_DEF_UNSUPPORTED(umount2)
SYSCALL_DEF_UNSUPPORTED(lock)

/**
 *  int ioctl(int d, int request, ...)
 *
 * The ioctl() function manipulates the underlying device parameters
 * of special files.  In particular, many operating characteristics of
 * character special files (e.g., terminals) may be controlled with
 * ioctl() requests.  The argument d must be an open file descriptor.
 *
 */
SYSCALL_DEF_IRREG(ioctl, EMU)

SYSCALL_DEF_UNSUPPORTED(fcntl)
SYSCALL_DEF_UNSUPPORTED(mpx)

/**
 *  int setpgid(pid_t pid, pid_t pgid);
 *
 * setpgid() sets the PGID of the process specified by pid to pgid.
 * If pid is zero, then the process ID of the calling process is used.
 * If pgid is zero, then the PGID of the process specified by pid is
 * made the same as its process ID.  If setpgid() is used to move a
 * process from one process group to another (as is done by some
 * shells when creating pipelines), both process groups must be part
 * of the same session (see setsid(2) and credentials(7)).  In this
 * case, the pgid specifies an existing process group to be joined and
 * the session ID of that group must match the session ID of the
 * joining process.
 */
SYSCALL_DEF0(setpgid, EMU)

SYSCALL_DEF_UNSUPPORTED(ulimit)
SYSCALL_DEF_UNSUPPORTED(oldolduname)

/**
 *  mode_t umask(mode_t mask);
 *
 * umask() sets the calling process's file mode creation mask (umask)
 * to mask & 0777 (i.e., only the file permission bits of mask are
 * used), and returns the previous value of the mask.
 */
SYSCALL_DEF0(umask, EMU)

SYSCALL_DEF_UNSUPPORTED(chroot)
SYSCALL_DEF_UNSUPPORTED(ustat)

/**
 *  int dup2(int oldfd, int newfd)
 *
 * dup2() makes newfd be the copy of oldfd, closing newfd first if
 *  necessary, but note the following..
 */
SYSCALL_DEF0(dup2, EMU)

/**
 *  pid_t getppid(void);
 *
 * getppid() returns the process ID of the parent of the calling
 * process.
 */
SYSCALL_DEF0(getppid, EMU)

/**
 *  pid_t getpgrp(void)
 *
 * The POSIX.1 getpgrp() always returns the PGID of the caller.
 */
SYSCALL_DEF0(getpgrp, EMU)

/**
 *  pid_t setsid(void)
 *
 * setsid() is used to start a new session and set the new process
 * group ID.
 */
SYSCALL_DEF0(setsid, EMU)

/**
 *  int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
 *
 * The sigaction() system call is used to change the action taken by a
 * process on receipt of a specific signal.  (See signal(7) for an
 * overview of signals.)
 *
 * signum specifies the signal and can be any valid signal except
 * SIGKILL and SIGSTOP.
 *
 * If act is non-NULL, the new action for signal signum is installed
 * from act.  If oldact is non-NULL, the previous action is saved in
 * oldact.
 */
SYSCALL_DEF1(sigaction, EMU, struct kernel_sigaction, arg3)

SYSCALL_DEF_UNSUPPORTED(sgetmask)
SYSCALL_DEF_UNSUPPORTED(ssetmask)
SYSCALL_DEF_UNSUPPORTED(setreuid)
SYSCALL_DEF_UNSUPPORTED(setregid)
SYSCALL_DEF_UNSUPPORTED(sigsuspend)
SYSCALL_DEF_UNSUPPORTED(sigpending)
SYSCALL_DEF_UNSUPPORTED(sethostname)

/**
 *  int setrlimit(int resource, const struct rlimit *rlim)
 *
 * getrlimit() and setrlimit() get and set resource limits
 * respectively.  Each resource has an associated soft and hard limit,
 * as defined by the rlimit structure (the rlim argument to both
 * getrlimit() and setrlimit()):
 *
 * NOTE: We should execute this system call, since this system call
 * sets a limit on a resource (e.g., the stack size) This bahavior
 * must be the same in the replay as in the recording phase.
 */
SYSCALL_DEF1(setrlimit, EXEC, struct rlimit, arg2)

SYSCALL_DEF_UNSUPPORTED(getrlimit)

/**
 *  int getrusage(int who, struct rusage *usage)
 *
 * getrusage() returns resource usage measures for who, which can be
 * one of the following..
 */
SYSCALL_DEF1(getrusage, EMU, struct rusage, arg2)

/**
 *  int gettimeofday(struct timeval *tv, struct timezone *tz);
 *
 * The functions gettimeofday() and settimeofday() can get and set the
 * time as well as a timezone.  The tv argument is a struct timeval
 * (as specified in <sys/time.h>):
 */
SYSCALL_DEF2(gettimeofday, EMU, struct timeval, arg1, struct timezone, arg2)

SYSCALL_DEF_UNSUPPORTED(settimeofday)
SYSCALL_DEF_UNSUPPORTED(getgroups)
SYSCALL_DEF_UNSUPPORTED(setgroups)
SYSCALL_DEF_UNSUPPORTED(select)

/**
 *  int symlink(const char *oldpath, const char *newpath)
 *
 * symlink() creates a symbolic link named newpath which contains the
 * string oldpath.
 *
 * FIXME: Why was this disabled?
 */
SYSCALL_DEF0(symlink, EMU)

SYSCALL_DEF_UNSUPPORTED(oldlstat)

/**
 *  ssize_t readlink(const char *path, char *buf, size_t bufsiz);
 *
 * readlink() places the contents of the symbolic link path in the
 * buffer buf, which has size bufsiz. readlink() does not append a
 * null byte to buf.  It will truncate the contents (to a length of
 * bufsiz characters), in case the buffer is too small to hold all of
 * the contents.
 */
SYSCALL_DEF1_DYNSIZE(readlink, EMU, (size_t)t->regs().arg3(), arg2)

SYSCALL_DEF_UNSUPPORTED(uselib)
SYSCALL_DEF_UNSUPPORTED(swapon)
SYSCALL_DEF_UNSUPPORTED(reboot)
SYSCALL_DEF_UNSUPPORTED(readdir)

/**
 *  void *mmap2(void *addr, size_t length, int prot,int flags, int fd, off_t pgoffset);
 *
 * The mmap2() system call operates in exactly the same way as
 * mmap(2), except that the final argument specifies the offset into
 * the file in 4096-byte units (instead of bytes, as is done by
 * mmap(2)).  This enables applications that use a 32-bit off_t to map
 * large files (up to 2^44 bytes).
 */
SYSCALL_DEF_IRREG(mmap, MAY_EXEC)

/**
 *  int munmap(void *addr, size_t length)
 *
 * The munmap() system call deletes the mappings for the specified
 * address range, and causes further references to addresses within
 * the range to generate invalid memory references.  The region is
 * also automatically unmapped when the process is terminated.  On the
 * other hand, closing the file descriptor does not unmap the region.
 */
SYSCALL_DEF0(munmap, EXEC)

/**
 *  int truncate(const char *path, off_t length);
 *  int ftruncate(int fd, off_t length)
 *
 * The truncate() and ftruncate() functions cause the regular file
 * named by path or referenced by fd to be truncated to a size of
 * precisely length bytes.
 */
SYSCALL_DEF0(truncate, EMU)

SYSCALL_DEF0(ftruncate, EMU)

/**
 *  int fchmod(int fd, mode_t mode);
 *
 * fchmod() changes the permissions of the file referred to by the
 * open file descriptor fd
 */
SYSCALL_DEF0(fchmod, EMU)

SYSCALL_DEF_UNSUPPORTED(fchown)

/**
 *  int getpriority(int which, int who);
 *
 * The scheduling priority of the process, process group, or user, as
 * indicated by which and who is obtained with the getpriority() call.
 */
SYSCALL_DEF0(getpriority, EMU)

/**
 *  int setpriority(int which, int who, int prio);
 *
 * The scheduling priority of the process, process group, or user, as
 * indicated by which and who is obtained with the getpriority() call
 * and set with the setpriority() call.
 */
SYSCALL_DEF0(setpriority, EMU)

SYSCALL_DEF_UNSUPPORTED(profil)

/**
 *  int statfs(const char *path, struct statfs *buf)
 *
 * The function statfs() returns information about a mounted file
 * system.  path is the pathname of any file within the mounted file
 * system.  buf is a pointer to a statfs structure defined
 * approximately as follows:
 */
SYSCALL_DEF1(statfs, EMU, struct statfs, arg2)

/**
 *  int fstatfs(int fd, struct statfs *buf)
 *
 * The function statfs() returns information about a mounted file
 * system.  path is the pathname of any file within the
 * get_time(GET_TID(thread_id));mounted file system.  buf is a pointer
 * to a statfs structure defined approximately as follows:
 */
SYSCALL_DEF1(fstatfs, EMU, struct statfs, arg2)

SYSCALL_DEF_UNSUPPORTED(ioperm)

/**
 *  int socketcall(int call, unsigned long *args)
 *
 * socketcall() is a common kernel entry point for the socket system
 * calls.  call determines which socket function to invoke.  args
 * points to a block containing the actual arguments, which are passed
 * through to the appropriate call.
 */
SYSCALL_DEF_IRREG(socketcall, EMU)

SYSCALL_DEF_UNSUPPORTED(syslog)

/**
 *  int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value);
 *
 * The function setitimer() sets the specified timer to the value in
 * new_value.  If old_value is non-NULL, the old value of the timer is
 * stored there.
 */
SYSCALL_DEF1(setitimer, EMU, struct itimerval, arg3)

SYSCALL_DEF_UNSUPPORTED(getitimer)
SYSCALL_DEF_UNSUPPORTED(stat)
SYSCALL_DEF_UNSUPPORTED(lstat)
SYSCALL_DEF_UNSUPPORTED(fstat)
SYSCALL_DEF_UNSUPPORTED(olduname)
SYSCALL_DEF_UNSUPPORTED(iopl)
SYSCALL_DEF_UNSUPPORTED(vhangup)
SYSCALL_DEF_UNSUPPORTED(idle)
SYSCALL_DEF_UNSUPPORTED(vm86old)

/**
 *  pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
 *
 * The wait3() and wait4() system calls are similar to waitpid(2), but
 * additionally return resource usage information about the child in
 * the structure pointed to by rusage.
 */
SYSCALL_DEF_IRREG(wait4, EMU)

SYSCALL_DEF_UNSUPPORTED(swapoff)

/**
 *  int sysinfo(struct sysinfo *info)
 *
 * sysinfo() provides a simple way of getting overall system
 * statistics.
 */
SYSCALL_DEF1(sysinfo, EMU, struct sysinfo, arg1)

/**
 *  int ipc(unsigned int call, int first, int second, int third, void *ptr, long fifth);
 *
 * ipc() is a common kernel entry point for the System V IPC calls for
 * messages, semaphores, and shared memory.  call determines which IPC
 * function to invoke; the other arguments are passed through to the
 * appropriate call.
 */
SYSCALL_DEF_IRREG(ipc, EMU)

/**
 *  int fsync(int fd)
 *
 * fsync() transfers ("flushes") all modified in-core data of (i.e.,
 * modified buffer cache pages for) the file referred to by the file
 * descriptor fd to the disk device (or other permanent storage
 * device) where that file resides.  The call blocks until the device
 * reports that the transfer has completed.  It also flushes metadata
 * information associated with the file (see stat(2))
 */
SYSCALL_DEF0(fsync, EMU)

/**
 *  int sigreturn(unsigned long __unused)
 *
 * When the Linux kernel creates the stack frame for a signal handler,
 * a call to sigreturn() is inserted into the stack frame so that upon
 * return from the signal handler, sigreturn() will be called.
 */
SYSCALL_DEF_IRREG(sigreturn, EMU)

/**
 *  int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, (pid_t *ptid, struct user_desc *tls, pid_t *ctid));
 *
 * clone() creates a new process, in a manner similar to fork(2).  It
 * is actually a library function layered ontrace top of the
 * underlying clone() system call, hereinafter referred to tidas
 * sys_clone.  A description of sys_clone is given towards the end of
 * this page.
 *
 * NOTE: clone is actually implemented by sys_clone which has the
 * following signature:
 *
 *  long sys_clone(unsigned long clone_flags, unsigned long newsp, void __user *parent_tid, void __user *child_tid, struct pt_regs *regs)
 */
SYSCALL_DEF_IRREG(clone, MAY_EXEC)

SYSCALL_DEF_UNSUPPORTED(setdomainname)

/**
 *  int uname(struct utsname *buf)
 *
 * uname() returns system information in the structure pointed to by
 * buf. The utsname struct is defined in <sys/utsname.h>:
 */
SYSCALL_DEF1(uname, EMU, struct utsname, arg1)

SYSCALL_DEF_UNSUPPORTED(modify_ldt)
SYSCALL_DEF_UNSUPPORTED(adjtimex)

/**
 *  int mprotect(const void *addr, size_t len, int prot)
 *
 * mprotect() changes protection for the calling process's memory
 * page(s) containing any part of the address range in the interval
 * [addr, addr+len-1].  addr must be aligned to a page boundary.
 *
 * If the calling process tries to access memory in a manner that
 * violates the protection, then the kernel generates a SIGSEGV signal
 * for the process.
 */
SYSCALL_DEF0(mprotect, EXEC)

/**
 *  int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
 *
 * sigprocmask() is used to fetch and/or change the signal mask of the
 * calling thread.  The signal mask is the set of signals whose
 * delivery is currently blocked for the caller (see also signal(7)
 * for more details).
 */
SYSCALL_DEF1(sigprocmask, EMU, sigset_t, arg3)

SYSCALL_DEF_UNSUPPORTED(create_module)
SYSCALL_DEF_UNSUPPORTED(init_module)
SYSCALL_DEF_UNSUPPORTED(delete_module)
SYSCALL_DEF_UNSUPPORTED(get_kernel_syms)

/**
 *  int quotactl(int cmd, const char *special, int id, caddr_t addr);
 *
 * The quotactl() call manipulates disk quotas.  The cmd argument
 * indicates a command to be applied to the user or group ID
 * specified in id.  To initialize the cmd argument, use the
 * QCMD(subcmd, type) macro.  The type value is either USRQUOTA, for
 * user quotas, or GRPQUOTA, for group quotas.  The subcmd value is
 * described below.
 */
SYSCALL_DEF_IRREG(quotactl, EMU)

/**
 *  pid_t getpgid(pid_t pid);
 *
 * getpgid() returns the PGID of the process specified by pid.  If pid
 * is zero, getpgid() the process ID of the calling process is
 * used.int getrusage(int who, struct rusage *usage);
 */
SYSCALL_DEF0(getpgid, EMU)

/**
 *  int fchdir(int fd);
 *
 * fchdir() is identical to chdir(); the only difference is that the
 * directory is given as an open file descriptor.
 */
SYSCALL_DEF0(fchdir, EMU)

SYSCALL_DEF_UNSUPPORTED(bdflush)
SYSCALL_DEF_UNSUPPORTED(sysfs)
SYSCALL_DEF_UNSUPPORTED(personality)
SYSCALL_DEF_UNSUPPORTED(afs_syscall)
SYSCALL_DEF_UNSUPPORTED(setfsuid)
SYSCALL_DEF_UNSUPPORTED(setfsgid)

/**
 *  int _llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t *result, unsigned int whence);
 *
 * The _llseek() function repositions the offset of the open file
 * associated with the file descriptor fd to (off‐ set_high<<32) |
 * offset_low bytes relative to the beginning of the file, the current
 * position in the file, or the end of the file, depending on whether
 * whence is SEEK_SET, SEEK_CUR, or SEEK_END, respectively.  It
 * returns the resulting file position in the argument result.
 */
SYSCALL_DEF1(_llseek, EMU, loff_t, arg4)

/**
 *  int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
 *
 * The system call getdents() reads several linux_dirent structures
 * from the directory referred to by the open file descriptor fd into
 * the buffer pointed to by dirp.  The argument count specifies the
 * size of that buffer.
 */
SYSCALL_DEF1_DYNSIZE(getdents, EMU, (int)t->regs().syscall_result_signed(), arg2)

/**
 *  int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
 *
 * select() and pselect() allow a program to monitor multiple file
 * descriptors, waiting until one or more of the file descriptors
 * become "ready" for some class of I/O operation (e.g., input
 * possible).  A file descriptor is considered ready if it is possible
 * to perform the corresponding I/O operation (e.g., read(2)) without
 * blocking.
 */
SYSCALL_DEF4(_newselect, EMU, fd_set, arg2, fd_set, arg3,
	     fd_set, arg4, struct timeval, arg5)

SYSCALL_DEF_UNSUPPORTED(flock)

/**
 *  int msync(void *addr, size_t length, int flags);
 *
 * msync() flushes changes made to the in-core copy of a file that was
 * mapped into memory using mmap(2) back to disk.  Without use of this
 * call there is no guarantee that changes are written back before
 * munmap(2) is called.  To be more precise, the part of the file that
 * corresponds to the memory area starting at addr and having length
 * length is updated.
 */
SYSCALL_DEF0(msync, EXEC)

SYSCALL_DEF_UNSUPPORTED(readv)

/**
 *  ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
 *
 * The writev() function writes iovcnt buffers of data described by
 * iov to the file associated with the file descriptor fd ("gather
 * output").
 */
SYSCALL_DEF_IRREG(writev, EMU)

/**
 * pid_t getsid(pid_t pid);
 *
 * getsid(0) returns the session ID of the calling process.  getsid(p)
 * returns the session ID of the process with process ID p.  (The session
 * ID of a process is the process group ID of the session leader.)
 */
SYSCALL_DEF0(getsid, EMU)

/**
 *  int fdatasync(int fd)
 *
 * fdatasync() is similar to fsync(), but does not flush modified
 * metadata unless that metadata is needed in order to allow a
 * subsequent data retrieval to be correctly handled.  For example,
 * changes to st_atime or st_mtime (respectively, time of last access
 * and time of last modification; see stat(2)) do not require flushing
 * because they are not necessary for a subsequent data read to be
 * handled correctly.  On the other hand, a change to the file size
 * (st_size, as made by say ftruncate(2)), would require a metadata
 * flush
 */
SYSCALL_DEF0(fdatasync, EMU)

/**
 *  int _sysctl(struct __syscall_args* args);
 *
 * The _sysctl() call reads and/or writes kernel parameters.  For example,
 * the hostname, or the maximum number of open files.
 *
 * Often not supported in modern kernels, so can return ENOSYS.
 */
SYSCALL_DEF_IRREG(_sysctl, EMU)

SYSCALL_DEF_UNSUPPORTED(mlock)
SYSCALL_DEF_UNSUPPORTED(munlock)
SYSCALL_DEF_UNSUPPORTED(mlockall)
SYSCALL_DEF_UNSUPPORTED(munlockall)
SYSCALL_DEF_UNSUPPORTED(sched_setparam)

/**
 *  int sched_getparam(pid_t pid, struct sched_param *param)
 *
 * sched_getparam() retrieves the scheduling parameters for the
 * process i dentified by pid.  If pid is zero, then the parameters of
 * the calling process are retrieved.
 */
SYSCALL_DEF1(sched_getparam, EMU, struct sched_param, arg2)

/**
 *  int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param);
 *
 * sched_setscheduler() sets both the scheduling policy and the
 * associated parameters for the process whose ID is specified in pid.
 * If pid equals zero, the scheduling policy and parameters of the
 * calling process will be set.  The interpretation of the argument
 * param depends on the selected policy.
 */
SYSCALL_DEF0(sched_setscheduler, EMU)

/**
 *  int sched_getscheduler(pid_t pid);
 *
 * sched_getscheduler() queries the scheduling policy currently
 * applied to the process identified by pid.  If pid equals zero, the
 * policy of the calling process will be retrieved.
 */
SYSCALL_DEF0(sched_getscheduler, EMU)

/**
 *  int sched_yield(void)
 *
 * sched_yield() causes the calling thread to relinquish the CPU.  The
 * thread is moved to the end of the queue for its static priority and
 * a new thread gets to run.
 */
SYSCALL_DEF0(sched_yield, EMU)

/**
 *  int sched_get_priority_max(int policy)
 *
 * sched_get_priority_max() returns the maximum priority value that
 * can be used with the scheduling algorithm identified by policy.
 */
SYSCALL_DEF0(sched_get_priority_max, EMU)

/**
 *  int sched_get_priority_min(int policy)
 *
 * sched_get_priority_min() returns the minimum priority value that
 * can be used with the scheduling algorithm identified by policy.
 */
SYSCALL_DEF0(sched_get_priority_min, EMU)

SYSCALL_DEF_UNSUPPORTED(sched_rr_get_interval)

/**
 *  int nanosleep(const struct timespec *req, struct timespec *rem)
 *
 * nanosleep() suspends the execution of the calling thread until
 * either at least the time specified in *req has elapsed, or the
 * delivery of a signal that triggers the invocation of a handler in
 * the calling thread or that ter- minates the process.
 *
 * CHECKED: trace->recorded_regs.ecx != NULL
 */
SYSCALL_DEF_IRREG(nanosleep, EMU)

/**
 *  void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... ( void *new_address ));
 *
 * mremap() expands (or shrinks) an existing memory mapping,
 * potentially moving it at the same time (controlled by the flags
 * argument and the available virtual address space).
 */
SYSCALL_DEF0(mremap, EXEC)

/**
 *  int setresuid(uid_t ruid, uid_t euid, uid_t suid);
 *
 * setresuid() sets the real user ID, the effective user ID, and the
 * saved set-user-ID of the calling process.
 */
SYSCALL_DEF0(setresuid, EMU)

SYSCALL_DEF_UNSUPPORTED(getresuid)
SYSCALL_DEF_UNSUPPORTED(vm86)
SYSCALL_DEF_UNSUPPORTED(query_module)

/**
 *  int poll(struct pollfd *fds, nfds_t nfds, int timeout)
 *  int ppoll(struct pollfd *fds, nfds_t nfds,
 *            const struct timespec *timeout_ts,
 *            const sigset_t *sigmask);
 *
 * poll() performs a similar task to select(2): it waits for one of a
 * set of file descriptors to become ready to perform I/O.
 *
 * The relationship between poll() and ppoll() is analogous to the
 * relationship between select(2) and pselect(2): like pselect(2),
 * ppoll() allows an application to safely wait until either a file
 * descriptor becomes ready or until a signal is caught.
 *
 * XXX is this irregular?  CHECKED: (trace->recorded_regs.eax > 0)
 */
SYSCALL_DEF_IRREG(poll, EMU)

SYSCALL_DEF_UNSUPPORTED(nfsservctl)

/**
 *  int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
 *
 * setresgid() sets the real GID, effective GID, and saved
 * set-group-ID of the calling process.
 */
SYSCALL_DEF0(setresgid, EMU)

SYSCALL_DEF_UNSUPPORTED(getresgid)

/**
 *  int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
 *
 * prctl() is called with a first argument describing what to do (with
 * values defined in <linux/prctl.h>), and further arguments with a
 * significance depending on the first one.
 *
 */
SYSCALL_DEF_IRREG(prctl, MAY_EXEC)

SYSCALL_DEF_IRREG(rt_sigreturn, EMU)

SYSCALL_DEF1(rt_sigaction, EMU, struct kernel_sigaction, arg3)

SYSCALL_DEF1(rt_sigprocmask, EMU, sigset_t, arg3)

SYSCALL_DEF_UNSUPPORTED(rt_sigpending)
SYSCALL_DEF_UNSUPPORTED(rt_sigtimedwait)
SYSCALL_DEF_UNSUPPORTED(rt_sigqueueinfo)
SYSCALL_DEF_UNSUPPORTED(rt_sigsuspend)

/**
 *  ssize_t pread(int fd, void *buf, size_t count, off_t offset);
 *
 * pread, pwrite - read from or write to a file descriptor at a given
 * offset
 */
SYSCALL_DEF1_DYNSIZE(pread64, EMU, (ssize_t)t->regs().syscall_result_signed(), arg2)

SYSCALL_DEF0(pwrite64, EMU)

SYSCALL_DEF_UNSUPPORTED(chown)

/**
 *  char *getwd(char *buf);
 *
 * These functions return a null-terminated string containing an
 * absolute pathname that is the current working directory of the
 * calling process.  The pathname is returned as the function result
 * and via the argument buf, if present.
 */
SYSCALL_DEF1_STR(getcwd, EMU, arg1)

SYSCALL_DEF_UNSUPPORTED(capget)
SYSCALL_DEF_UNSUPPORTED(capset)

/**
 *  int sigaltstack(const stack_t *ss, stack_t *oss)
 *
 * sigaltstack() allows a process to define a new alternate signal
 * stack and/or retrieve the state of an existing alternate signal
 * stack.  An alternate signal stack is used during the execution of a
 * signal handler if the establishment of that handler (see
 * sigaction(2)) requested it.
 */
SYSCALL_DEF1_DYNSIZE(sigaltstack, EMU,
		     t->regs().arg2() ? sizeof(stack_t) : 0, arg2)

SYSCALL_DEF_UNSUPPORTED(sendfile)
SYSCALL_DEF_UNSUPPORTED(getpmsg)
SYSCALL_DEF_UNSUPPORTED(putpmsg)
SYSCALL_DEF_UNSUPPORTED(vfork)

/**
 *  int getrlimit(int resource, struct rlimit *rlim)
 *
 * getrlimit() and setrlimit() get and set resource limits
 * respectively.  Each resource has an associated soft and hard limit,
 * as defined by the rlimit structure (the rlim argument to both
 * getrlimit() and setrlimit()):
 */
SYSCALL_DEF1(ugetrlimit, EMU, struct rlimit, arg2)

SYSCALL_DEF_IRREG(mmap2, MAY_EXEC)

SYSCALL_DEF0(truncate64, EMU)

SYSCALL_DEF0(ftruncate64, EMU)

/**
 * int stat(const char *path, struct stat *buf);
 *
 * stat() stats the file pointed to by path and fills in buf.
 */
SYSCALL_DEF1(stat64, EMU, struct stat64, arg2)

/**
 *  int lstat(const char *path, struct stat *buf);
 *
 * lstat() is identical to stat(), except that if path is a symbolic
 * link, then the link itself is stat-ed, not the file that it refers
 * to.
 */
SYSCALL_DEF1(lstat64, EMU, struct stat64, arg2)

/**
 *  int fstat(int fd, struct stat *buf)
 *
 * fstat() is identical to stat(), except that the file to be stat-ed
 * is specified by the file descriptor fd.
 */
SYSCALL_DEF1(fstat64, EMU, struct stat64, arg2)

SYSCALL_DEF_UNSUPPORTED(lchown32)

/**
 *  uid_t getuid(void);
 *
 * getuid() returns the real user ID of the calling process
 */
SYSCALL_DEF0(getuid32, EMU)

/**
 *  gid_t getgid(void);
 *
 * getgid() returns the real group ID of the calling process.
 */
SYSCALL_DEF0(getgid32, EMU)

/**
 *  uid_t geteuid(void);
 *
 * geteuid() returns the effective user ID of the calling process.
 */
SYSCALL_DEF0(geteuid32, EMU)

/**
 *  gid_t getegid(void);
 *
 * getegid() returns the effective group ID of the calling process.
 */
SYSCALL_DEF0(getegid32, EMU)

SYSCALL_DEF_UNSUPPORTED(setreuid32)

/**
 *  int setregid(gid_t rgid, gid_t egid)
 *
 * setreuid() sets real and effective user IDs of the calling process
 */
SYSCALL_DEF0(setregid32, EMU)

/**
 *  int getgroups(int size, gid_t list[]);
 *
 * getgroups() returns the supplementary group IDs of the calling
 * process in list.  The argument size should be set to the maximum
 * number of items that can be stored in the buffer pointed to by
 * list. If the calling process is a member of more than size
 * supplementary groups, then an error results.  It is unspecified
 * whether the effective group ID of the calling process is included
 * in the returned list. (Thus, an application should also call
 * getegid(2) and add or remove the resulting value.)
 *
 * If size is zero, list is not modified, but the total number of
 * supplementary group IDs for the process is returned.  This allows
 * the caller to determine the size of a dynamically allocated list to
 * be used in a further call to getgroups().
 */
SYSCALL_DEF1_DYNSIZE(getgroups32, EMU,
	(int)t->regs().syscall_result_signed() * sizeof(gid_t), arg2)

SYSCALL_DEF_UNSUPPORTED(setgroups32)
SYSCALL_DEF_UNSUPPORTED(fchown32)

/**
 *  int setresuid32(uid_t ruid, uid_t euid, uid_t suid);
 *
 * setresuid() sets the real user ID, the effective user ID, and the
 * saved set-user-ID of the calling process.
 */
SYSCALL_DEF0(setresuid32, EMU)

/**
 *  int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
 *
 * getresuid() returns the real UID, the effective UID, and the saved
 * set- user-ID of the calling process, in the arguments ruid, euid,
 * and suid, respectively.  getresgid() performs the analogous task
 * for the process's group IDs.
 */
SYSCALL_DEF3(getresuid32, EMU, uid_t, arg1, uid_t, arg2, uid_t, arg3)

/**
 *  int setresgid32(gid_t rgid, gid_t egid, gid_t sgid);
 *
 * setresgid() sets the real GID, effective GID, and saved
 * set-group-ID of the calling process.
 */
SYSCALL_DEF0(setresgid32, EMU)

/**
 *  int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
 *
 * getresuid() returns the real UID, the effective UID, and the saved
 * set-user-ID of the calling process, in the arguments ruid, euid,
 * and suid, respectively.  getresgid() performs the analogous task
 * for the process's group IDs.  @return: On success, zero is
 * returned.  On error, -1 is returned, and errno is set
 * appropriately.
 */
SYSCALL_DEF3(getresgid32, EMU, uid_t, arg1, uid_t, arg2, uid_t, arg3)

SYSCALL_DEF_UNSUPPORTED(chown32)
SYSCALL_DEF_UNSUPPORTED(setuid32)
SYSCALL_DEF_UNSUPPORTED(setgid32)
SYSCALL_DEF_UNSUPPORTED(setfsuid32)
SYSCALL_DEF_UNSUPPORTED(setfsgid32)
SYSCALL_DEF_UNSUPPORTED(pivot_root)
SYSCALL_DEF_UNSUPPORTED(mincore)

/**
 *  int madvise(void *addr, size_t length, int advice);
 *
 * The madvise() system call advises the kernel about how to handle
 * paging input/output in the address range beginning at address addr
 * and with size length bytes.  It allows an application to tell the
 * kernel how it expects to use some mapped or shared memory areas, so
 * that the kernel can choose appropriate read-ahead and caching
 * techniques.  This call does not influence the semantics of the
 * application (except in the case of MADV_DONTNEED), but may
 * influence its performance.  The kernel is free to ignore the
 * advice.
 */
SYSCALL_DEF0(madvise, EXEC)

SYSCALL_DEF1_DYNSIZE(getdents64, EMU, (int)t->regs().syscall_result_signed(), arg2)

/**
 *  int fcntl(int fd, int cmd, ... ( arg ));
 *
 * fcntl() performs one of the operations described below on the open
 * file descriptor fd.  The operation is determined by cmd. fcntl()
 * can take an optional third argument.  Whether or not this argument
 * is required is determined by cmd. The required argument type is
 * indicated in parentheses after each cmd name (in most cases, the
 * required type is long, and we identify the argument using the name
 * arg), or void is specified if the argument is not required.
 */
SYSCALL_DEF_IRREG(fcntl64, EMU)

SYSCALLNO_X86(224)
/**
 *  pid_t gettid(void);
 *
 * gettid() returns the caller's thread ID (TID).
 */
SYSCALL_DEF0(gettid, EMU)

/**
 *  ssize_t readahead(int fd, off64_t offset, size_t count);
 *
 * readahead() populates the page cache with data from a file so that
 * subsequent reads from that file will not block on disk I/O.  The fd
 * argument is a file descriptor identifying the file which is to be
 * read.  The offset argu- ment specifies the starting point from
 * which data is to be read and count specifies the number of bytes to
 * be read.  I/O is performed in whole pages, so that offset is
 * effectively rounded down to a page boundary and bytes are read up
 * to the next page boundary greater than or equal to (offset+count).
 * readahead() does not read beyond the end of the file.  readahead()
 * blocks until the specified data has been read.  The current file
 * offset of the open file referred to by fd is left unchanged.
 */
SYSCALL_DEF0(readahead, EMU)

SYSCALL_DEF_UNSUPPORTED(setxattr)
SYSCALL_DEF_UNSUPPORTED(lsetxattr)
SYSCALL_DEF_UNSUPPORTED(fsetxattr)

/**
 *  ssize_t getxattr(const char *path, const char *name,
 *                   void *value, size_t size);
 *  ssize_t lgetxattr(const char *path, const char *name,
 *                    void *value, size_t size);
 *  ssize_t fgetxattr(int fd, const char *name,
 *                    void *value, size_t size);
 *
 * getxattr() retrieves the value of the extended attribute identified
 * by name and associated with the given path in the file system. The
 * length of the attribute value is returned.
 */
SYSCALL_DEF_IRREG(getxattr, EMU)

SYSCALL_DEF_IRREG(lgetxattr, EMU)

SYSCALL_DEF_IRREG(fgetxattr, EMU)

SYSCALL_DEF_UNSUPPORTED(listxattr)
SYSCALL_DEF_UNSUPPORTED(llistxattr)
SYSCALL_DEF_UNSUPPORTED(flistxattr)
SYSCALL_DEF_UNSUPPORTED(removexattr)
SYSCALL_DEF_UNSUPPORTED(lremovexattr)
SYSCALL_DEF_UNSUPPORTED(fremovexattr)
SYSCALL_DEF_UNSUPPORTED(tkill)

/**
 * ssize_t sendfile64 (int __out_fd, int __in_fd, __off64_t *__offset, size_t __count);
 *
 * Send up to COUNT bytes from file associated with IN_FD starting at
 * *OFFSET to descriptor OUT_FD.  Set *OFFSET to the IN_FD's file position
 * following the read bytes.  If OFFSET is a null pointer, use the normal
 * file position instead.  Return the number of written bytes, or -1 in
 * case of error.
 */
SYSCALL_DEF_IRREG(sendfile64, EMU)

/**
 *  int futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3);
 *
 * The futex() system call provides a method for a program to wait for
 * a value at a given address to change, and a method to wake up
 * anyone waiting on a particular address (while the addresses for the
 * same memory in separate processes may not be equal, the kernel
 * maps them internally so the same memory mapped in different
 * locations will correspond for futex() calls).  This system call is
 * typically used to implement the contended case of a lock in shared
 * memory, as described in futex(7).
 */
SYSCALL_DEF_IRREG(futex, EMU)

/**
 *  int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
 *
 * sched_setaffinity() sets the CPU affinity mask of the process whose
 * ID is pid to the value specified by mask.  If pid is zero, then the
 * calling process is used.  The argument cpusetsize is the length
 * (in bytes) of the data pointed to by mask.  Normally this argument
 * would be specified as sizeof(cpu_set_t).
 */
SYSCALL_DEF0(sched_setaffinity, EMU)

/**
 *  int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
 *
 * sched_getaffinity() writes the affinity mask of the process whose
 * ID is pid into the cpu_set_t structure pointed to by mask.  The
 * cpusetsize argument specifies the size (in bytes) of mask.  If pid
 * is zero, then the mask of the calling process is returned.
 */
SYSCALL_DEF1(sched_getaffinity, EMU, cpu_set_t, arg3)

/**
 *  int set_thread_area(struct user_desc *u_info)
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
 */
SYSCALL_DEF1(set_thread_area, EXEC, struct user_desc, arg1)

SYSCALL_DEF_UNSUPPORTED(get_thread_area)
SYSCALL_DEF_UNSUPPORTED(io_setup)
SYSCALL_DEF_UNSUPPORTED(io_destroy)
SYSCALL_DEF_UNSUPPORTED(io_getevents)
SYSCALL_DEF_UNSUPPORTED(io_submit)
SYSCALL_DEF_UNSUPPORTED(io_cancel)

/**
 *  int posix_fadvise(int fd, off_t offset, off_t len, int advice);
 *
 * Programs can use posix_fadvise() to announce an intention to access
 * file data in a specific pattern in the future, thus allowing the
 * kernel to perform appropriate optimizations.
 */
SYSCALL_DEF0(fadvise64, EMU)

SYSCALLNO_X86(252)
/**
 *  void exit_group(int status)
 *
 * This system call is equivalent to exit(2) except that it terminates
 * not only the calling thread, but all threads in the calling
 * process's thread group.
 */
SYSCALL_DEF_IRREG(exit_group, MAY_EXEC)

SYSCALL_DEF_UNSUPPORTED(lookup_dcookie)

/**
 *  int epoll_create(int size);
 *
 * epoll_create() creates an epoll "instance", requesting the kernel
 * to allocate an event backing store dimensioned for size
 * descriptors.  The size is not the maximum size of the backing store
 * but just a hint to the kernel about how to dimension internal
 * structures.  When no longer required, the file descriptor returned
 * by epoll_create() should be closed by using close(2).
 */
SYSCALL_DEF0(epoll_create, EMU)

/**
 *  int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
 *
 * This system call performs control operations on the epoll instance
 * referred to by the file descriptor epfd.  It requests that the
 * operation op be performed for the target file descriptor, fd.
 */
SYSCALL_DEF0(epoll_ctl, EMU)

/**
 *  int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
 *
 * The epoll_wait() system call waits for events on the epoll instance
 * referred to by the file descriptor epfd.  The memory area pointed
 * to by events will contain the events that will be available for the
 * caller.  Up to maxevents are returned by epoll_wait().  The
 * maxevents argument must be greater than zero.
 *
 * XXX is this irregular?  CHECKED: (trace->recorded_regs.eax >= 0)
 */
SYSCALL_DEF_IRREG(epoll_wait, EMU)

SYSCALL_DEF_UNSUPPORTED(remap_file_pages)

/**
 *  long set_tid_address(int *tidptr);
 *
 * The kernel keeps for each process two values called set_child_tid
 * and clear_child_tid that are NULL by default.
 *
 * If a process is started using clone(2) with the CLONE_CHILD_SETTID
 * flag, set_child_tid is set to child_tidptr, the fifth argument of
 * that system call.
 *
 * When set_child_tid is set, the very first thing the new process
 * does is writing its PID at this address.
 */
SYSCALL_DEF1(set_tid_address, EXEC_RET_EMU, pid_t, arg1)

SYSCALL_DEF_UNSUPPORTED(timer_create)
SYSCALL_DEF_UNSUPPORTED(timer_settime)
SYSCALL_DEF_UNSUPPORTED(timer_gettime)
SYSCALL_DEF_UNSUPPORTED(timer_getoverrun)
SYSCALL_DEF_UNSUPPORTED(timer_delete)
SYSCALL_DEF_UNSUPPORTED(clock_settime)

/**
 *  int clock_gettime(clockid_t clk_id, struct timespec *tp);
 *
 * The functions clock_gettime() and clock_settime() retrieve and set
 * the time of the specified clock clk_id.
 */
SYSCALL_DEF1(clock_gettime, EMU, struct timespec, arg2)

/**
 *  int clock_getres(clockid_t clk_id, struct timespec *res)
 *
 * The function clock_getres() finds the resolution (precision) of the
 * specified clock clk_id, and, if res is non-NULL, stores it in the
 * struct timespec pointed to by res.  The resolution of clocks
 * depends on the implementation and cannot be configured by a
 * particular process.  If the time value pointed to by the argument
 * tp of clock_settime() is not a multiple of res, then it is
 * truncated to a multiple of res.
 */
SYSCALL_DEF1(clock_getres, EMU, struct timespec, arg2)

SYSCALL_DEF_UNSUPPORTED(clock_nanosleep)

/**
 *  int statfs(const char *path, struct statfs *buf)
 *
 * The function statfs() returns information about a mounted file
 * system.  path is the pathname of any file within the mounted file
 * system.  buf is a pointer to a statfs structure defined
 * approximately as follows...
 *
 * FIXME: we use arg3() here, although according to man pages this system
 * call has only 2 paramaters. However, strace tells another story...
 */
SYSCALL_DEF1(statfs64, EMU, struct statfs64, arg3)

SYSCALL_DEF1(fstatfs64, EMU, struct statfs64, arg3)

/**
 *  int tgkill(int tgid, int tid, int sig)
 *
 * tgkill() sends the signal sig to the thread with the thread ID tid
 * in the thread group tgid.  (By contrast, kill(2) can only be used
 * to send a signal to a process (i.e., thread group) as a whole, and
 * the signal will be delivered to an arbitrary thread within that
 * process.)
 */
SYSCALL_DEF0(tgkill, EMU)

/**
 *  int utimes(const char *filename, const struct timeval times[2])
 *
 * The utime() system call changes the access and modification times
 * of the inode specified by filename to the actime and modtime fields
 * of times respectively.
 *
 */
SYSCALL_DEF1_DYNSIZE(utimes, EMU, 2 * sizeof(struct timeval), arg2)

SYSCALL_DEF0(fadvise64_64, EMU)

SYSCALL_DEF_UNSUPPORTED(vserver)
SYSCALL_DEF_UNSUPPORTED(mbind)
SYSCALL_DEF_UNSUPPORTED(get_mempolicy)
SYSCALL_DEF_UNSUPPORTED(set_mempolicy)
SYSCALL_DEF_UNSUPPORTED(mq_open)
SYSCALL_DEF_UNSUPPORTED(mq_unlink)
SYSCALL_DEF_UNSUPPORTED(mq_timedsend)
SYSCALL_DEF_UNSUPPORTED(mq_timedreceive)
SYSCALL_DEF_UNSUPPORTED(mq_notify)
SYSCALL_DEF_UNSUPPORTED(mq_getsetattr)
SYSCALL_DEF_UNSUPPORTED(kexec_load)

/**
 *  int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
 *
 * If WNOHANG was specified in options and there were no children in a
 * waitable state, then waitid() returns 0 immediately and the state
 * of the siginfo_t structure pointed to by infop is unspecified.  To
 * distinguish this case from that where a child was in a waitable
 * state, zero out the si_pid field before the call and check for a
 * nonzero value in this field after the call returns.
 */
SYSCALL_DEF_IRREG(waitid, EMU)

SYSCALLNO_X86(286)
SYSCALL_DEF_UNSUPPORTED(add_key)
SYSCALL_DEF_UNSUPPORTED(request_key)
SYSCALL_DEF_UNSUPPORTED(keyctl)
SYSCALL_DEF_UNSUPPORTED(ioprio_set)
SYSCALL_DEF_UNSUPPORTED(ioprio_get)

/**
 *  int inotify_init(void)
 *
 * inotify_init() initializes a new inotify instance and returns a
 * file descriptor associated with a new inotify event queue.
 */
SYSCALL_DEF0(inotify_init, EMU)

/**
 *  int inotify_add_watch(int fd, const char *pathname, uint32_t mask)
 *
 * inotify_add_watch() adds a new watch, or modifies an existing
 * watch, for the file whose location is specified in pathname; the
 * caller must have read permission for this file.  The fd argument is
 * a file descrip tor referring to the inotify instance whose watch
 * list is to be modified.  The events to be monitored for pathname
 * are specified in the mask bit-mask argument.  See inotify(7) for a
 * description of the bits that can be set in mask.
 */
SYSCALL_DEF0(inotify_add_watch, EMU)

/**
 *  int inotify_rm_watch(int fd, uint32_t wd)
 *
 * inotify_rm_watch() removes the watch associated with the watch
 * descriptor wd from the inotify instance associated with the file
 * descriptor fd.
 */
SYSCALL_DEF0(inotify_rm_watch, EMU)

SYSCALL_DEF_UNSUPPORTED(migrate_pages)

/**
 *  int openat(int dirfd, const char *pathname, int flags);
 *  int openat(int dirfd, const char *pathname, int flags, mode_t mode);
 *
 * The openat() system call operates in exactly the same way as
 * open(2), except for the differences described in this manual page.
 */
SYSCALL_DEF0(openat, EMU)

/**
 *  int mkdirat(int dirfd, const char *pathname, mode_t mode);
 *
 * The mkdirat() system call operates in exactly the same way as
 * mkdir(2), except for the differences described in this manual
 * page....
 */
SYSCALL_DEF0(mkdirat, EMU)

SYSCALL_DEF_UNSUPPORTED(mknodat)
SYSCALL_DEF_UNSUPPORTED(fchownat)
SYSCALL_DEF_UNSUPPORTED(futimesat)

/**
 *  int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
 *
 * The fstatat() system call operates in exactly the same way as
 * stat(2), except for the differences described in this manual
 * page....
 */
SYSCALL_DEF1(fstatat64, EMU, struct stat64, arg3)

/**
 *  int unlinkat(int dirfd, const char *pathname, int flags)
 *
 * The unlinkat() system call operates in exactly the same way as
 * either unlink(2) or rmdir(2) (depending on whether or not flags
 * includes the AT_REMOVEDIR flag) except for the differences
 * described in this manual page.
 */
SYSCALL_DEF0(unlinkat, EMU)

SYSCALL_DEF_UNSUPPORTED(renameat)
SYSCALL_DEF_UNSUPPORTED(linkat)
SYSCALL_DEF_UNSUPPORTED(symlinkat)
SYSCALL_DEF_UNSUPPORTED(readlinkat)
SYSCALL_DEF_UNSUPPORTED(fchmodat)

/**
 *  int faccessat(int dirfd, const char *pathname, int mode, int flags)
 *
 * The faccessat() system call operates in exactly the same way as
 * access(2), except for the differences described in this manual
 * page....
 */
SYSCALL_DEF0(faccessat, EMU)

SYSCALL_DEF_UNSUPPORTED(pselect6)

SYSCALL_DEF_IRREG(ppoll, EMU)

SYSCALL_DEF_UNSUPPORTED(unshare)

/**
 *  long set_robust_list(struct robust_list_head *head, size_t len)
 *
 * The robust futex implementation needs to maintain per-thread lists
 * of robust futexes which are unlocked when the thread exits. These
 * lists are managed in user space, the kernel is only notified about
 * the location of the head of the list.
 *
 * set_robust_list sets the head of the list of robust futexes owned
 * by the current thread to head.  len is the size of *head.
 */
SYSCALL_DEF0(set_robust_list, EXEC)

SYSCALL_DEF_UNSUPPORTED(get_robust_list)

/**
 *  ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
 *
 * splice() moves data between two file descriptors without copying
 * between kernel address space and user address space.  It transfers
 * up to len bytes of data from the file descriptor fd_in to the file
 * descriptor fd_out, where one of the descriptors must refer to a
 * pipe.
 *
 * NB: the documentation doesn't mention it explicitly, but the |off|
 * params are actually inout params, and are updated with the new file
 * offset on return.
 *
 * NOTE: Technically, the following implementation is unsound for
 * programs that splice with stdin/stdout/stderr and have output
 * redirected during replay.  But, *crickets*.
 */
SYSCALL_DEF_IRREG(splice, EMU)

SYSCALL_DEF_UNSUPPORTED(sync_file_range)
SYSCALL_DEF_UNSUPPORTED(tee)
SYSCALL_DEF_UNSUPPORTED(vmsplice)
SYSCALL_DEF_UNSUPPORTED(move_pages)
SYSCALL_DEF_UNSUPPORTED(getcpu)
SYSCALL_DEF_UNSUPPORTED(epoll_pwait)

/**
 *  int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);
 *
 * utimensat() and futimens() update the timestamps of a file with
 * nanosecond precision.  This contrasts with the historical utime(2)
 * and utimes(2), which permit only second and microsecond precision,
 * respectively, when setting file timestamps.
 */
SYSCALL_DEF0(utimensat, EMU)

SYSCALL_DEF_UNSUPPORTED(signalfd)

/**
 *  int timerfd_create(int clockid, int flags);
 *
 * timerfd_create() creates a new timer object, and returns a file
 * descriptor that refers to that timer.
 */
SYSCALL_DEF0(timerfd_create, EMU)

SYSCALL_DEF_UNSUPPORTED(eventfd)

/**
 * int fallocate(int fd, int mode, off_t offset, off_t len);
 *
 * fallocate() allows the caller to directly manipulate the allocated
 * disk space for the file referred to by fd for the byte range
 * starting at offset and continuing for len bytes
 */
SYSCALL_DEF0(fallocate, EMU)

/**
 *  int timerfd_settime(int fd, int flags,
 *                      const struct itimerspec *new_value,
 *                      struct itimerspec *old_value);
 *
 * timerfd_settime() arms (starts) or disarms (stops) the timer
 * referred to by the file descriptor fd.
 */
SYSCALL_DEF1(timerfd_settime, EMU, struct itimerspec, arg4)

/**
 *  int timerfd_gettime(int fd, struct itimerspec *curr_value);
 *
 * timerfd_gettime() returns, in curr_value, an itimerspec structure
 * that contains the current setting of the timer referred to by the
 * file descriptor fd.
 */
SYSCALL_DEF1(timerfd_gettime, EMU, struct itimerspec, arg2)

SYSCALL_DEF_UNSUPPORTED(signalfd4)

/**
 *  int eventfd(unsigned int initval, int flags);
 *
 * eventfd() creates an "eventfd object" that can be used as an event
 * wait/notify mechanism by userspace applications, and by the kernel
 * to notify userspace applications of events.  The object contains an
 * unsigned 64-bit integer (uint64_t) counter that is maintained by
 * the kernel.  This counter is initialized with the value specified
 * in the argument initval.
 */
SYSCALL_DEF0(eventfd2, EMU)

/**
 *  int epoll_create1(int flags);
 *
 * epoll_create1() is very similar to epoll_create.  They are identical
 * if the passed flag value is 0, they are completely identical.  The
 * flag argument can be used to set the close-on-exec flag on the new
 * file descriptor.
 */
SYSCALL_DEF0(epoll_create1, EMU)

SYSCALL_DEF_UNSUPPORTED(dup3)

/**
 *  int pipe2(int pipefd[2], int flags)
 *
 * If flags is 0, then pipe2() is the same as pipe().  The following
 * values can be bitwise ORed in flags to obtain different behavior...
 */
SYSCALL_DEF1(pipe2, EMU, int[2], arg1)

SYSCALL_DEF0(inotify_init1, EMU)

SYSCALL_DEF_UNSUPPORTED(preadv)
SYSCALL_DEF_UNSUPPORTED(pwritev)
SYSCALL_DEF_UNSUPPORTED(rt_tgsigqueueinfo)

/**
 *  int perf_event_open(struct perf_event_attr *attr,
 *                      pid_t pid, int cpu, int group_fd,
 *                      unsigned long flags);
 *
 * Given a list of parameters, perf_event_open() returns a file
 * descriptor, for use in subsequent system calls (read(2), mmap(2),
 * prctl(2), fcntl(2), etc.).
 */
SYSCALL_DEF0(perf_event_open, EMU)

/**
 *  int recvmmsg(int sockfd, struct mmsghdr *msgvec,
 *               unsigned int vlen, unsigned int flags,
 *               struct timespec *timeout);
 *
 * The recvmmsg() system call is an extension of recvmsg(2) that
 * allows the caller to receive multiple messages from a socket using
 * a single system call.  (This has performance benefits for some
 * applications.)  A further extension over recvmsg(2) is support for
 * a timeout on the receive operation.
 */
SYSCALL_DEF_IRREG(recvmmsg, EMU)

SYSCALL_DEF_UNSUPPORTED(fanotify_init)
SYSCALL_DEF_UNSUPPORTED(fanotify_mark)

/**
 *  int prlimit(pid_t pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit);
 *
 * The Linux-specific prlimit() system call combines and extends the
 * functionality of setrlimit() and getrlimit().  It can be used to
 * both set and get the resource limits of an arbitrary process.
 */
SYSCALL_DEF1(prlimit64, EXEC, struct rlimit64, arg4)

SYSCALL_DEF_UNSUPPORTED(name_to_handle_at)
SYSCALL_DEF_UNSUPPORTED(open_by_handle_at)
SYSCALL_DEF_UNSUPPORTED(clock_adjtime)
SYSCALL_DEF_UNSUPPORTED(syncfs)

/**
 *  int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
 *               unsigned int flags);
 *
 * The sendmmsg() system call is an extension of sendmsg(2) that
 * allows the caller to transmit multiple messages on a socket using a
 * single system call.  (This has performance benefits for some
 * applications.)
 */
SYSCALL_DEF_IRREG(sendmmsg, EMU)

SYSCALL_DEF_UNSUPPORTED(setns)
SYSCALL_DEF_UNSUPPORTED(process_vm_readv)
SYSCALL_DEF_UNSUPPORTED(process_vm_writev)
SYSCALL_DEF_UNSUPPORTED(kcmp)
SYSCALL_DEF_UNSUPPORTED(finit_module)

SYSCALLNO_X86(442)
/**
 *  void* rrcall_init_buffers(struct rrcall_init_buffers_params* args);
 *
 * Do what's necessary to map the shared syscall buffer region in the
 * caller's address space and return the mapped region.  |args| is an
 * inout parameter that's documented in syscall_buffer.h.
 *
 * This is a "magic" syscall implemented by rr.
 */
SYSCALL_DEF_IRREG(rrcall_init_buffers, EMU)

/**
 *  void rrcall_monkeypatch_vdso(void* vdso_hook_trampoline);
 *
 * Monkeypatch |__kernel_vsyscall()| to jump into
 * |vdso_hook_trampoline|.
 *
 * This is a "magic" syscall implemented by rr.
 */
SYSCALL_DEF_IRREG(rrcall_monkeypatch_vdso, EMU)

