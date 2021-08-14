class BaseSyscall(object):
    """A base class for syscalls.

    The constructor accepts specifications for the x86 and x86-64 syscall
    numbers; if one of them does not exist, then the associated syscall is
    assumed to not exist on the corresponding architecture.
    """

    # Take **kwargs and ignore to make life easier on RegularSyscall.
    def __init__(self, x86=None, x64=None, generic=None, **kwargs):
        assert x86 or x64       # Must exist on one architecture.
        self.x86 = x86
        self.x64 = x64
        self.generic = generic
        assert len(kwargs) == 0

class RestartSyscall(BaseSyscall):
    """A special class for the restart_syscall syscall."""
    def __init__(self, **kwargs):
        BaseSyscall.__init__(self, **kwargs)

class UnsupportedSyscall(BaseSyscall):
    """A syscall that is unsupported by rr.

    It is useful to expose these syscalls to the system, so that proper names
    can be displayed in error messages, if nothing else.  They also serve as
    useful documentation.
    """
    def __init__(self, **kwargs):
        BaseSyscall.__init__(self, **kwargs)

class InvalidSyscall(UnsupportedSyscall):
    """A syscall that is unsupported by rr and unimplemented by Linux.

    We distinguish syscalls unimplemented by any version of Linux supported
    by rr from other UnsupportedSyscalls, to help us track the completeness
    of rr's syscall support.
    """
    def __init__(self, **kwargs):
        UnsupportedSyscall.__init__(self, **kwargs)

class RegularSyscall(BaseSyscall):
    """A syscall for which replay information may be recorded automatically.

    The arguments required for rr to record may be specified directly
    through the arg1...arg6 keyword arguments.  The values for these
    arguments determine the size of the associated arguments to the syscall.
    The only allowed type for a given argument is a Python string, in which
    case the size of the argument is sizeof(arg).

    To ensure correct handling for mixed-arch process groups (e.g. a mix of 32
    and 64-bit processes), types should be specified using Arch instead of
    referring directly to the host system types.
    """
    def __init__(self, **kwargs):
        for a in range(1,6):
            arg = 'arg' + str(a)
            if arg in kwargs:
                self.__setattr__(arg, kwargs[arg])
                kwargs.pop(arg)
        BaseSyscall.__init__(self, **kwargs)

class EmulatedSyscall(RegularSyscall):
    """A wrapper for regular syscalls.
    """
    def __init__(self, **kwargs):
        RegularSyscall.__init__(self, **kwargs)

class IrregularEmulatedSyscall(BaseSyscall):
    """A wrapper for irregular syscalls.
    """
    def __init__(self, **kwargs):
        BaseSyscall.__init__(self, **kwargs)

#  void exit(int status)
#
# The exit() function causes normal process termination and the value
# of status & 0377 is returned to the parent (see wait(2)).
exit = IrregularEmulatedSyscall(x86=1, x64=60, generic=93)

# Obsolete, glibc calls clone() instead.
# But Google Breakpad uses it!
fork = IrregularEmulatedSyscall(x86=2, x64=57)

#  ssize_t read(int fd, void *buf, size_t count);
#
# read() attempts to read up to count bytes from file descriptor fd
# into the buffer starting at buf.
#
# CHECKED: (trace->recorded_regs.eax > 0)
read = IrregularEmulatedSyscall(x86=3, x64=0, generic=63)

#  ssize_t write(int fd, const void *buf, size_t count);
#
# write() writes up to count bytes to the file referenced by the file
# descriptor fd from the buffer starting at buf. POSIX requires that
# a read() which can be proved to occur after a write() has returned
# returns the new data. Note that not all file systems are POSIX
# conforming.
#
# Note: write isn't irregular per se; we hook it to redirect output
# to stdout/stderr during replay.
write = IrregularEmulatedSyscall(x86=4, x64=1, generic=64)

#  int open(const char *pathname, int flags)
#  int open(const char *pathname, int flags, mode_t mode)
#
# Given a pathname for a file, open() returns a file descriptor, a
# small, nonnegative integer for use in subsequent system calls
# (read(2), write(2), lseek(2), fcntl(2), etc.).  The file descriptor
# returned by a successful call will be the lowest-numbered file
# descriptor not currently open for the process.
open = IrregularEmulatedSyscall(x86=5, x64=2)

#  int close(int fd)
#
# close() closes a file descriptor, so that it no longer refers to
# any file and may be reused.  Any record locks (see fcntl(2)) held
# on the file it was associated with, and owned by the process, are
# removed (regardless of the file descriptor that was used to obtain
# the lock).
close = IrregularEmulatedSyscall(x86=6, x64=3, generic=57)

#  pid_t waitpid(pid_t pid, int *status, int options);
#
# The waitpid() system call suspends execution of the calling process
# until a child specified by pid argument has changed state.  By
# default, waitpid() waits only for terminated children, but this
# behavior is modifiable via the options argument, as described
# below....
waitpid = IrregularEmulatedSyscall(x86=7)

#  int creat(const char *pathname, mode_t mode);
#
# creat() is equivalent to open() with flags equal to
# O_CREAT|O_WRONLY|O_TRUNC.
creat = EmulatedSyscall(x86=8, x64=85)

#  int link(const char *oldpath, const char *newpath);
#
# link() creates a new link (also known as a hard link) to an
# existing file.
link = EmulatedSyscall(x86=9, x64=86)

#  int unlink(const char *path);
#
# The unlink() function shall remove a link to a file. If path names
# a symbolic link, unlink() shall remove the symbolic link named by
# path and shall not affect any file or directory named by the
# contents of the symbolic link. Otherwise, unlink() shall remove the
# link named by the pathname pointed to by path and shall decrement
# the link count of the file referenced by the link.
unlink = EmulatedSyscall(x86=10, x64=87)

#  int execve(const char *filename, char *const argv[], char *const envp[]);
#
# execve() executes the program pointed to by filename.
execve = IrregularEmulatedSyscall(x86=11, x64=59, generic=221)

#  int chdir(const char *path);
#
# chdir() changes the current working directory of the calling
# process to the directory specified in path.
chdir = EmulatedSyscall(x86=12, x64=80, generic=49)

#  time_t time(time_t *t);
#
# time() returns the time since the Epoch (00:00:00 UTC, January 1,
# 1970), measured in seconds. If t is non-NULL, the return value is
# also stored in the memory pointed to by t.
time = EmulatedSyscall(x86=13, x64=201, arg1="typename Arch::time_t")

mknod = EmulatedSyscall(x86=14, x64=133)

#  int chmod(const char *path, mode_t mode)
#
# The mode of the file given by path or referenced by fildes is
# changed.
chmod = EmulatedSyscall(x86=15, x64=90)
lchown = EmulatedSyscall(x86=16, x64=94)
_break = InvalidSyscall(x86=17)
oldstat = UnsupportedSyscall(x86=18)

#  off_t lseek(int fd, off_t offset, int whence)
#
# The lseek() function repositions the offset of the open file
# associated with the file descriptor fd to the argument offset
# according to the directive whence as follows:
lseek = EmulatedSyscall(x86=19, x64=8, generic=62)

#  pid_t getpid(void);
#
# getpid() returns the process ID of the calling process.  (This is
# often used by routines that generate unique temporary
# filenames.)
getpid = EmulatedSyscall(x86=20, x64=39, generic=172)

mount = EmulatedSyscall(x86=21, x64=165, generic=40)
umount = EmulatedSyscall(x86=22)
setuid = EmulatedSyscall(x86=23, x64=105, generic=146)
getuid = EmulatedSyscall(x86=24, x64=102, generic=174)
stime = UnsupportedSyscall(x86=25)

#  long ptrace(enum __ptrace_request request, pid_t pid,
#              void *addr, void *data);
#
# The ptrace() system call provides a means by which one process (the
# "tracer") may observe and control the execution of another process
# (the "tracee"), and examine and change the tracee's memory and
# registers.  It is primarily used to implement breakpoint debugging
# and system call tracing.
ptrace = IrregularEmulatedSyscall(x86=26, x64=101, generic=117)

#  unsigned int alarm(unsigned int seconds)
#
# The alarm() system call schedules an alarm. The process will get a
# SIGALRM after the requested amount of seconds.
alarm = EmulatedSyscall(x86=27, x64=37)
oldfstat = UnsupportedSyscall(x86=28)

#  int pause(void);
#
# pause() causes the calling process (or thread) to sleep until a
# signal is delivered that either terminates the process or causes
# the invocation of a signal-catching function.
pause = IrregularEmulatedSyscall(x86=29, x64=34)

#  int utime(const char *filename, const struct utimbuf *times)
#
# The utime() system call changes the access and modification times
# of the inode specified by filename to the actime and modtime fields
# of times respectively.
#
# If times is NULL, then the access and modification times of the
# file are set to the current time.
#
# Changing timestamps is permitted when: either the process has
# appropriate privileges, or the effective user ID equals the user ID
# of the file, or times is NULL and the process has write permission
# for the file.
#
# FIXME: is mod_time set by the kernel?
utime = EmulatedSyscall(x86=30, x64=132)

stty = InvalidSyscall(x86=31)
gtty = InvalidSyscall(x86=32)

#  int access(const char *pathname, int mode);
#
# access() checks whether the calling process can access the file
# pathname.  If pathname is a symbolic link, it is dereferenced.
access = EmulatedSyscall(x86=33, x64=21)

nice = UnsupportedSyscall(x86=34)
ftime = InvalidSyscall(x86=35)
sync = IrregularEmulatedSyscall(x86=36, x64=162, generic=81)

#  int kill(pid_t pid, int sig)
#
# The kill() system call can be used to send any signal to any
# process group or process.
kill = EmulatedSyscall(x86=37, x64=62, generic=129)

#  int rename(const char *oldpath, const char *newpath)
#
# rename() renames a file, moving it between directories if required.
rename = EmulatedSyscall(x86=38, x64=82)

#  int mkdir(const char *pathname, mode_t mode);
#
# mkdir() attempts to create a directory named pathname.
mkdir = EmulatedSyscall(x86=39, x64=83)

#  int rmdir(const char *pathname)
#
# rmdir() deletes a directory, which must be empty.
rmdir = EmulatedSyscall(x86=40, x64=84)

#  int dup(int oldfd)
#
# dup() uses the lowest-numbered unused descriptor for the new
# descriptor.
dup = EmulatedSyscall(x86=41, x64=32, generic=23)

#  int pipe(int pipefd[2]);
#
# pipe() creates a pipe, a unidirectional data channel that can be
# used for interprocess communication.  The array pipefd is used to
# return two file descriptors referring to the ends of the pipe.
# pipefd[0] refers to the read end of the pipe.  pipefd[1] refers to
# the write end of the pipe.  Data written to the write end of the
# pipe is buffered by the kernel until it is read from the read end
# of the pipe.  For further details, see pipe(7).
pipe = EmulatedSyscall(x86=42, x64=22, arg1="int[2]")

#  clock_t times(struct tms *buf)
#
# times() stores the current process times in the struct tms that buf
#  points to.  The struct tms is as defined in <sys/times.h>:
times = EmulatedSyscall(x86=43, x64=100, generic=153, arg1="typename Arch::tms")

prof = InvalidSyscall(x86=44)

#  int brk(void *addr)
#
# brk() and sbrk() change the location of the program break, which
# defines the end of the process's data segment (i.e., theprogram
# break is the first location after the end of the uninitialized data
# segment).  Increasing the program break has the effect of
# allocating memory to the process; decreasing the break deallocates
# memory.
#
# brk() sets the end of the data segment to the value specified by
# addr, when that value is reasonable, the system has enough memory,
# and the process does not exceed its maximum data size (see
# setrlimit(2)).
brk = IrregularEmulatedSyscall(x86=45, x64=12, generic=214)

#  int setgid(gid_t gid)
#
# setgid() sets the effective group ID of the calling process.
# If the caller is the superuser, the real GID and saved set-group-ID
# are also set.
#
# Under Linux, setgid() is implemented like the POSIX version with the
# _POSIX_SAVED_IDS feature.  This allows a set-group-ID program that
# is not set-user-ID-root to drop all of its group privileges, do some
# un-privileged work, and then reengage the original effective group
# ID in a secure manner.
#
# setgid will return 0 on success, or if the process already runs
# under the given gid.
setgid = EmulatedSyscall(x86=46, x64=106, generic=144)

getgid = EmulatedSyscall(x86=47, x64=104, generic=176)
signal = UnsupportedSyscall(x86=48)
geteuid = EmulatedSyscall(x86=49, x64=107, generic=175)
getegid = EmulatedSyscall(x86=50, x64=108, generic=177)
acct = EmulatedSyscall(x86=51, x64=163, generic=89)
umount2 = EmulatedSyscall(x86=52, x64=166, generic=39)
lock = InvalidSyscall(x86=53)

#  int ioctl(int d, int request, ...)
#
# The ioctl() function manipulates the underlying device parameters
# of special files.  In particular, many operating characteristics of
# character special files (e.g., terminals) may be controlled with
# ioctl() requests.  The argument d must be an open file descriptor.
#
ioctl = IrregularEmulatedSyscall(x86=54, x64=16, generic=29)

fcntl = IrregularEmulatedSyscall(x86=55, x64=72, generic=25)
mpx = InvalidSyscall(x86=56)

#  int setpgid(pid_t pid, pid_t pgid);
#
# setpgid() sets the PGID of the process specified by pid to pgid.
# If pid is zero, then the process ID of the calling process is used.
# If pgid is zero, then the PGID of the process specified by pid is
# made the same as its process ID.  If setpgid() is used to move a
# process from one process group to another (as is done by some
# shells when creating pipelines), both process groups must be part
# of the same session (see setsid(2) and credentials(7)).  In this
# case, the pgid specifies an existing process group to be joined and
# the session ID of that group must match the session ID of the
# joining process.
setpgid = EmulatedSyscall(x86=57, x64=109, generic=154)

ulimit = InvalidSyscall(x86=58)
oldolduname = UnsupportedSyscall(x86=59)

#  mode_t umask(mode_t mask);
#
# umask() sets the calling process's file mode creation mask (umask)
# to mask & 0777 (i.e., only the file permission bits of mask are
# used), and returns the previous value of the mask.
umask = EmulatedSyscall(x86=60, x64=95, generic=166)

chroot = EmulatedSyscall(x86=61, x64=161, generic=51)
ustat = UnsupportedSyscall(x86=62, x64=136)

#  int dup2(int oldfd, int newfd)
#
# dup2() makes newfd be the copy of oldfd, closing newfd first if
#  necessary, but note the following..
dup2 = IrregularEmulatedSyscall(x86=63, x64=33)

#  pid_t getppid(void);
#
# getppid() returns the process ID of the parent of the calling
# process.
getppid = EmulatedSyscall(x86=64, x64=110, generic=173)

#  pid_t getpgrp(void)
#
# The POSIX.1 getpgrp() always returns the PGID of the caller.
getpgrp = EmulatedSyscall(x86=65, x64=111)

#  pid_t setsid(void)
#
# setsid() is used to start a new session and set the new process
# group ID.
setsid = EmulatedSyscall(x86=66, x64=112, generic=157)

#  int sigaction(int signum, const struct sigaction *act, struct sigaction
#*oldact);
#
# The sigaction() system call is used to change the action taken by a
# process on receipt of a specific signal.  (See signal(7) for an
# overview of signals.)
#
# signum specifies the signal and can be any valid signal except
# SIGKILL and SIGSTOP.
#
# If act is non-NULL, the new action for signal signum is installed
# from act.  If oldact is non-NULL, the previous action is saved in
# oldact.
sigaction = IrregularEmulatedSyscall(x86=67)

sgetmask = UnsupportedSyscall(x86=68)
ssetmask = UnsupportedSyscall(x86=69)
setreuid = EmulatedSyscall(x86=70, x64=113, generic=145)
setregid = EmulatedSyscall(x86=71, x64=114, generic=143)
sigsuspend = IrregularEmulatedSyscall(x86=72)
sigpending = UnsupportedSyscall(x86=73)
sethostname = EmulatedSyscall(x86=74, x64=170, generic=161)

#  int setrlimit(int resource, const struct rlimit *rlim)
#
# getrlimit() and setrlimit() get and set resource limits
# respectively.  Each resource has an associated soft and hard limit,
# as defined by the rlimit structure (the rlim argument to both
# getrlimit() and setrlimit()):
#
# NOTE: This syscall is emulated so the limit does not apply during
# replay. Any signals triggered due to exceeded limits are emulated
# by other means.
setrlimit = EmulatedSyscall(x86=75, x64=160, generic=164)

getrlimit = EmulatedSyscall(x86=76, x64=97, generic=163, arg2="typename Arch::rlimit")

#  int getrusage(int who, struct rusage *usage)
#
# getrusage() returns resource usage measures for who, which can be
# one of the following..
getrusage = EmulatedSyscall(x86=77, x64=98, generic=165, arg2="typename Arch::rusage")

#  int gettimeofday(struct timeval *tv, struct timezone *tz);
#
# The functions gettimeofday() and settimeofday() can get and set the
# time as well as a timezone.  The tv argument is a struct timeval
# (as specified in <sys/time.h>):
gettimeofday = EmulatedSyscall(x86=78, x64=96, generic=169, arg1="typename Arch::timeval", arg2="typename Arch::timezone")

settimeofday = UnsupportedSyscall(x86=79, x64=164, generic=170)
getgroups = IrregularEmulatedSyscall(x86=80, x64=115, generic=158)
setgroups = EmulatedSyscall(x86=81, x64=116, generic=159)
select = IrregularEmulatedSyscall(x86=82, x64=23)

#  int symlink(const char *oldpath, const char *newpath)
#
# symlink() creates a symbolic link named newpath which contains the
# string oldpath.
symlink = EmulatedSyscall(x86=83, x64=88)

oldlstat = UnsupportedSyscall(x86=84)

#  ssize_t readlink(const char *path, char *buf, size_t bufsiz);
#
# readlink() places the contents of the symbolic link path in the
# buffer buf, which has size bufsiz. readlink() does not append a
# null byte to buf.  It will truncate the contents (to a length of
# bufsiz characters), in case the buffer is too small to hold all of
# the contents.
readlink = IrregularEmulatedSyscall(x86=85, x64=89)

uselib = UnsupportedSyscall(x86=86, x64=134)
swapon = UnsupportedSyscall(x86=87, x64=167, generic=224)
reboot = UnsupportedSyscall(x86=88, x64=169, generic=142)
readdir = UnsupportedSyscall(x86=89)

#  void *mmap2(void *addr, size_t length, int prot,int flags, int fd, off_t
#pgoffset);
#
# The mmap2() system call operates in exactly the same way as
# mmap(2), except that the final argument specifies the offset into
# the file in 4096-byte units (instead of bytes, as is done by
# mmap(2)).  This enables applications that use a 32-bit off_t to map
# large files (up to 2^44 bytes).
mmap = IrregularEmulatedSyscall(x86=90, x64=9, generic=222)

#  int munmap(void *addr, size_t length)
#
# The munmap() system call deletes the mappings for the specified
# address range, and causes further references to addresses within
# the range to generate invalid memory references.  The region is
# also automatically unmapped when the process is terminated.  On the
# other hand, closing the file descriptor does not unmap the region.
munmap = IrregularEmulatedSyscall(x86=91, x64=11, generic=215)

#  int truncate(const char *path, off_t length);
#  int ftruncate(int fd, off_t length)
#
# The truncate() and ftruncate() functions cause the regular file
# named by path or referenced by fd to be truncated to a size of
# precisely length bytes.
truncate = EmulatedSyscall(x86=92, x64=76, generic=45)
ftruncate = EmulatedSyscall(x86=93, x64=77, generic=46)

#  int fchmod(int fd, mode_t mode);
#
# fchmod() changes the permissions of the file referred to by the
# open file descriptor fd
fchmod = EmulatedSyscall(x86=94, x64=91, generic=52)

fchown = EmulatedSyscall(x86=95, x64=93, generic=55)

#  int getpriority(int which, int who);
#
# The scheduling priority of the process, process group, or user, as
# indicated by which and who is obtained with the getpriority() call.
getpriority = EmulatedSyscall(x86=96, x64=140, generic=141)

#  int setpriority(int which, int who, int prio);
#
# The scheduling priority of the process, process group, or user, as
# indicated by which and who is obtained with the getpriority() call
# and set with the setpriority() call.
setpriority = IrregularEmulatedSyscall(x86=97, x64=141, generic=140)

profil = InvalidSyscall(x86=98)

#  int statfs(const char *path, struct statfs *buf)
#
# The function statfs() returns information about a mounted file
# system.  path is the pathname of any file within the mounted file
# system.  buf is a pointer to a statfs structure defined
# approximately as follows:
statfs = EmulatedSyscall(x86=99, x64=137, generic=43, arg2="struct Arch::statfs")

#  int fstatfs(int fd, struct statfs *buf)
#
# The function statfs() returns information about a mounted file
# system.  path is the pathname of any file within the
# get_time(GET_TID(thread_id));mounted file system.  buf is a pointer
# to a statfs structure defined approximately as follows:
fstatfs = EmulatedSyscall(x86=100, x64=138, generic=44, arg2="struct Arch::statfs")

ioperm = EmulatedSyscall(x86=101, x64=173)

#  int socketcall(int call, unsigned long *args)
#
# socketcall() is a common kernel entry point for the socket system
# calls.  call determines which socket function to invoke.  args
# points to a block containing the actual arguments, which are passed
# through to the appropriate call.
socketcall = IrregularEmulatedSyscall(x86=102)

syslog = UnsupportedSyscall(x86=103, x64=103, generic=116)

#  int setitimer(int which, const struct itimerval *new_value, struct itimerval
#*old_value);
#
# The function setitimer() sets the specified timer to the value in
# new_value.  If old_value is non-NULL, the old value of the timer is
# stored there.
setitimer = EmulatedSyscall(x86=104, x64=38, generic=103, arg3="typename Arch::itimerval")
getitimer = EmulatedSyscall(x86=105, x64=36, generic=102, arg2="typename Arch::itimerval")
stat = EmulatedSyscall(x86=106, x64=4, arg2="struct Arch::stat")
lstat = EmulatedSyscall(x86=107, x64=6, arg2="struct Arch::stat")
fstat = EmulatedSyscall(x86=108, x64=5, generic=80, arg2="struct Arch::stat")
olduname = UnsupportedSyscall(x86=109)
iopl = EmulatedSyscall(x86=110, x64=172)
vhangup = UnsupportedSyscall(x86=111, x64=153, generic=58)
idle = UnsupportedSyscall(x86=112)
vm86old = UnsupportedSyscall(x86=113)

#  pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
#
# The wait3() and wait4() system calls are similar to waitpid(2), but
# additionally return resource usage information about the child in
# the structure pointed to by rusage.
wait4 = IrregularEmulatedSyscall(x86=114, x64=61, generic=260)

swapoff = UnsupportedSyscall(x86=115, x64=168, generic=225)

#  int sysinfo(struct sysinfo *info)
#
# sysinfo() provides a simple way of getting overall system
# statistics.
sysinfo = EmulatedSyscall(x86=116, x64=99, generic=179, arg1="struct Arch::sysinfo")
#  int ipc(unsigned int call, int first, int second, int third, void *ptr, long
#fifth);
#
# ipc() is a common kernel entry point for the System V IPC calls for
# messages, semaphores, and shared memory.  call determines which IPC
# function to invoke; the other arguments are passed through to the
# appropriate call.
ipc = IrregularEmulatedSyscall(x86=117)

#  int fsync(int fd)
#
# fsync() transfers ("flushes") all modified in-core data of (i.e.,
# modified buffer cache pages for) the file referred to by the file
# descriptor fd to the disk device (or other permanent storage
# device) where that file resides.  The call blocks until the device
# reports that the transfer has completed.  It also flushes metadata
# information associated with the file (see stat(2))
fsync = IrregularEmulatedSyscall(x86=118, x64=74, generic=82)

#  int sigreturn(unsigned long __unused)
#
# When the Linux kernel creates the stack frame for a signal handler,
# a call to sigreturn() is inserted into the stack frame so that upon
# return from the signal handler, sigreturn() will be called.
sigreturn = IrregularEmulatedSyscall(x86=119)

#  int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, (pid_t
#*ptid, struct user_desc *tls, pid_t *ctid));
#
# clone() creates a new process, in a manner similar to fork(2).  It
# is actually a library function layered ontrace top of the
# underlying clone() system call, hereinafter referred to tidas
# sys_clone.  A description of sys_clone is given towards the end of
# this page.
#
# NOTE: clone is actually implemented by sys_clone which has the
# following signature:
#
#  long sys_clone(unsigned long clone_flags, unsigned long newsp, void __user
#*parent_tid, void __user *child_tid, struct pt_regs *regs)
clone = IrregularEmulatedSyscall(x86=120, x64=56, generic=220)

setdomainname = EmulatedSyscall(x86=121, x64=171, generic=162)

#  int uname(struct utsname *buf)
#
# uname() returns system information in the structure pointed to by
# buf. The utsname struct is defined in <sys/utsname.h>:
uname = EmulatedSyscall(x86=122, x64=63, generic=160, arg1="typename Arch::utsname")

modify_ldt = IrregularEmulatedSyscall(x86=123, x64=154)

#  int adjtimex(struct timex *buf);
#
# adjtimex() takes a pointer to a timex structure, reads it, and returns
# the same structure updated with the current kernel values.
adjtimex = EmulatedSyscall(x86=124, x64=159, generic=171, arg1="typename Arch::timex")

#  int mprotect(const void *addr, size_t len, int prot)
#
# mprotect() changes protection for the calling process's memory
# page(s) containing any part of the address range in the interval
# [addr, addr+len-1].  addr must be aligned to a page boundary.
#
# If the calling process tries to access memory in a manner that
# violates the protection, then the kernel generates a SIGSEGV signal
# for the process.
mprotect = IrregularEmulatedSyscall(x86=125, x64=10, generic=226)

#  int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
#
# sigprocmask() is used to fetch and/or change the signal mask of the
# calling thread.  The signal mask is the set of signals whose
# delivery is currently blocked for the caller (see also signal(7)
# for more details).
sigprocmask = IrregularEmulatedSyscall(x86=126)

create_module = UnsupportedSyscall(x86=127, x64=174)
init_module = UnsupportedSyscall(x86=128, x64=175, generic=105)
delete_module = UnsupportedSyscall(x86=129, x64=176, generic=106)
get_kernel_syms = InvalidSyscall(x86=130, x64=177)

#  int quotactl(int cmd, const char *special, int id, caddr_t addr);
#
# The quotactl() call manipulates disk quotas.  The cmd argument
# indicates a command to be applied to the user or group ID
# specified in id.  To initialize the cmd argument, use the
# QCMD(subcmd, type) macro.  The type value is either USRQUOTA, for
# user quotas, or GRPQUOTA, for group quotas.  The subcmd value is
# described below.
quotactl = IrregularEmulatedSyscall(x86=131, x64=179, generic=60)

#  pid_t getpgid(pid_t pid);
#
# getpgid() returns the PGID of the process specified by pid.  If pid
# is zero, getpgid() the process ID of the calling process is
# used.int getrusage(int who, struct rusage *usage);
getpgid = EmulatedSyscall(x86=132, x64=121, generic=155)

#  int fchdir(int fd);
#
# fchdir() is identical to chdir(); the only difference is that the
# directory is given as an open file descriptor.
fchdir = EmulatedSyscall(x86=133, x64=81, generic=50)

bdflush = UnsupportedSyscall(x86=134)
sysfs = IrregularEmulatedSyscall(x86=135, x64=139)
personality = IrregularEmulatedSyscall(x86=136, x64=135, generic=92)
afs_syscall = InvalidSyscall(x86=137, x64=183)
setfsuid = EmulatedSyscall(x86=138, x64=122, generic=151)
setfsgid = EmulatedSyscall(x86=139, x64=123, generic=152)

#  int _llseek(unsigned int fd, unsigned long offset_high, unsigned long
#offset_low, loff_t *result, unsigned int whence);
#
# The _llseek() function repositions the offset of the open file
# associated with the file descriptor fd to (offset_high<<32) |
# offset_low bytes relative to the beginning of the file, the current
# position in the file, or the end of the file, depending on whether
# whence is SEEK_SET, SEEK_CUR, or SEEK_END, respectively.  It
# returns the resulting file position in the argument result.
_llseek = EmulatedSyscall(x86=140, arg4="typename Arch::__kernel_loff_t")

#  int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int
#count);
#
# The system call getdents() reads several linux_dirent structures
# from the directory referred to by the open file descriptor fd into
# the buffer pointed to by dirp.  The argument count specifies the
# size of that buffer.
getdents = IrregularEmulatedSyscall(x86=141, x64=78)

#  int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
#struct timeval *timeout);
#
# select() and pselect() allow a program to monitor multiple file
# descriptors, waiting until one or more of the file descriptors
# become "ready" for some class of I/O operation (e.g., input
# possible).  A file descriptor is considered ready if it is possible
# to perform the corresponding I/O operation (e.g., read(2)) without
# blocking.
_newselect = IrregularEmulatedSyscall(x86=142)

flock = EmulatedSyscall(x86=143, x64=73, generic=32)

#  int msync(void *addr, size_t length, int flags);
#
# msync() flushes changes made to the in-core copy of a file that was
# mapped into memory using mmap(2) back to disk.  Without use of this
# call there is no guarantee that changes are written back before
# munmap(2) is called.  To be more precise, the part of the file that
# corresponds to the memory area starting at addr and having length
# length is updated.
msync = IrregularEmulatedSyscall(x86=144, x64=26, generic=227)

#  ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
#
# The readv() system call reads iovcnt buffers from the file associated
# with the file descriptor fd into the buffers described by iov ("scatter
# input").
readv = IrregularEmulatedSyscall(x86=145, x64=19, generic=65)

#  ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
#
# The writev() function writes iovcnt buffers of data described by
# iov to the file associated with the file descriptor fd ("gather
# output").
writev = IrregularEmulatedSyscall(x86=146, x64=20, generic=66)

# pid_t getsid(pid_t pid);
#
# getsid(0) returns the session ID of the calling process.  getsid(p)
# returns the session ID of the process with process ID p.  (The session
# ID of a process is the process group ID of the session leader.)
getsid = EmulatedSyscall(x86=147, x64=124, generic=156)

#  int fdatasync(int fd)
#
# fdatasync() is similar to fsync(), but does not flush modified
# metadata unless that metadata is needed in order to allow a
# subsequent data retrieval to be correctly handled.  For example,
# changes to st_atime or st_mtime (respectively, time of last access
# and time of last modification; see stat(2)) do not require flushing
# because they are not necessary for a subsequent data read to be
# handled correctly.  On the other hand, a change to the file size
# (st_size, as made by say ftruncate(2)), would require a metadata
# flush
fdatasync = IrregularEmulatedSyscall(x86=148, x64=75, generic=83)

#  int _sysctl(struct __syscall_args* args);
#
# The _sysctl() call reads and/or writes kernel parameters.  For example,
# the hostname, or the maximum number of open files.
#
# Often not supported in modern kernels, so can return ENOSYS.
_sysctl = IrregularEmulatedSyscall(x86=149, x64=156)

mlock = EmulatedSyscall(x86=150, x64=149, generic=228)
munlock = EmulatedSyscall(x86=151, x64=150, generic=229)
mlockall = EmulatedSyscall(x86=152, x64=151, generic=230)
munlockall = EmulatedSyscall(x86=153, x64=152, generic=231)
sched_setparam = EmulatedSyscall(x86=154, x64=142, generic=118)

#  int sched_getparam(pid_t pid, struct sched_param *param)
#
# sched_getparam() retrieves the scheduling parameters for the
# process i dentified by pid.  If pid is zero, then the parameters of
# the calling process are retrieved.
sched_getparam = EmulatedSyscall(x86=155, x64=143, generic=121, arg2="typename Arch::sched_param")

#  int sched_setscheduler(pid_t pid, int policy, const struct sched_param
#*param);
#
# sched_setscheduler() sets both the scheduling policy and the
# associated parameters for the process whose ID is specified in pid.
# If pid equals zero, the scheduling policy and parameters of the
# calling process will be set.  The interpretation of the argument
# param depends on the selected policy.
sched_setscheduler = EmulatedSyscall(x86=156, x64=144, generic=119)

#  int sched_getscheduler(pid_t pid);
#
# sched_getscheduler() queries the scheduling policy currently
# applied to the process identified by pid.  If pid equals zero, the
# policy of the calling process will be retrieved.
sched_getscheduler = EmulatedSyscall(x86=157, x64=145, generic=120)

#  int sched_yield(void)
#
# sched_yield() causes the calling thread to relinquish the CPU.  The
# thread is moved to the end of the queue for its static priority and
# a new thread gets to run.
sched_yield = IrregularEmulatedSyscall(x86=158, x64=24, generic=124)

#  int sched_get_priority_max(int policy)
#
# sched_get_priority_max() returns the maximum priority value that
# can be used with the scheduling algorithm identified by policy.
sched_get_priority_max = EmulatedSyscall(x86=159, x64=146, generic=125)

#  int sched_get_priority_min(int policy)
#
# sched_get_priority_min() returns the minimum priority value that
# can be used with the scheduling algorithm identified by policy.
sched_get_priority_min = EmulatedSyscall(x86=160, x64=147, generic=126)

sched_rr_get_interval = UnsupportedSyscall(x86=161, x64=148, generic=127)

#  int nanosleep(const struct timespec *req, struct timespec *rem)
#
# nanosleep() suspends the execution of the calling thread until
# either at least the time specified in *req has elapsed, or the
# delivery of a signal that triggers the invocation of a handler in
# the calling thread or that ter- minates the process.
#
# CHECKED: trace->recorded_regs.ecx != NULL
nanosleep = IrregularEmulatedSyscall(x86=162, x64=35, generic=101)

#  void *mremap(void *old_address, size_t old_size, size_t new_size, int flags,
#... ( void *new_address ));
#
# mremap() expands (or shrinks) an existing memory mapping,
# potentially moving it at the same time (controlled by the flags
# argument and the available virtual address space).
mremap = IrregularEmulatedSyscall(x86=163, x64=25, generic=216)

#  int setresuid(uid_t ruid, uid_t euid, uid_t suid);
#
# setresuid() sets the real user ID, the effective user ID, and the
# saved set-user-ID of the calling process.
setresuid = EmulatedSyscall(x86=164, x64=117, generic=147)

getresuid = EmulatedSyscall(x86=165, x64=118, generic=148, arg1="typename Arch::legacy_uid_t", arg2="typename Arch::legacy_uid_t", arg3="typename Arch::legacy_uid_t")
vm86 = UnsupportedSyscall(x86=166)
query_module = UnsupportedSyscall(x86=167, x64=178)

#  int poll(struct pollfd *fds, nfds_t nfds, int timeout)
#  int ppoll(struct pollfd *fds, nfds_t nfds,
#            const struct timespec *timeout_ts,
#            const sigset_t *sigmask);
#
# poll() performs a similar task to select(2): it waits for one of a
# set of file descriptors to become ready to perform I/O.
#
# The relationship between poll() and ppoll() is analogous to the
# relationship between select(2) and pselect(2): like pselect(2),
# ppoll() allows an application to safely wait until either a file
# descriptor becomes ready or until a signal is caught.
#
# XXX is this irregular?  CHECKED: (trace->recorded_regs.eax > 0)
poll = IrregularEmulatedSyscall(x86=168, x64=7)

nfsservctl = UnsupportedSyscall(x86=169, x64=180, generic=42)

#  int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
#
# setresgid() sets the real GID, effective GID, and saved
# set-group-ID of the calling process.
setresgid = EmulatedSyscall(x86=170, x64=119, generic=149)

getresgid = EmulatedSyscall(x86=171, x64=120, generic=150, arg1="typename Arch::legacy_gid_t", arg2="typename Arch::legacy_gid_t", arg3="typename Arch::legacy_gid_t")

#  int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long
#arg4, unsigned long arg5);
#
# prctl() is called with a first argument describing what to do (with
# values defined in <linux/prctl.h>), and further arguments with a
# significance depending on the first one.
#
prctl = IrregularEmulatedSyscall(x86=172, x64=157, generic=167)

rt_sigreturn = IrregularEmulatedSyscall(x86=173, x64=15, generic=139)
rt_sigaction = IrregularEmulatedSyscall(x86=174, x64=13, generic=134)
rt_sigprocmask = IrregularEmulatedSyscall(x86=175, x64=14, generic=135)

#  int sigpending(sigset_t *set);
#
# sigpending() returns the set of signals that are pending for
# delivery to the calling thread (i.e., the signals which have been
# raised while blocked).  The mask of pending signals is returned in
# set.
rt_sigpending = IrregularEmulatedSyscall(x86=176, x64=127, generic=136)

#  int sigtimedwait(const sigset_t *set, siginfo_t *info,
#                   const struct timespec *timeout);
#
# sigwaitinfo() suspends execution of the calling thread until one of
# the signals in set is pending (If one of the signals in set is
# already pending for the calling thread, sigwaitinfo() will return
# immedi ately.)
#
# sigtimedwait() operates in exactly the same way as sigwaitinfo()
# except that it has an additional argument, timeout, which specifies
# a minimum interval for which the thread is suspended waiting for a
# signal.
rt_sigtimedwait = IrregularEmulatedSyscall(x86=177, x64=128, generic=137)

#  int sigsuspend(const sigset_t *mask);
#
# sigsuspend() temporarily replaces the signal mask of the calling
# process with the mask given by mask and then suspends the process
# until delivery of a signal whose action is to invoke a signal
# handler or to terminate a process.
rt_sigsuspend = IrregularEmulatedSyscall(x86=179, x64=130, generic=133)

#  ssize_t pread(int fd, void *buf, size_t count, off_t offset);
#
# pread, pwrite - read from or write to a file descriptor at a given
# offset
pread64 = IrregularEmulatedSyscall(x86=180, x64=17, generic=67)
pwrite64 = EmulatedSyscall(x86=181, x64=18, generic=68)

chown = EmulatedSyscall(x86=182, x64=92)

#  char *getwd(char *buf);
#
# These functions return a null-terminated string containing an
# absolute pathname that is the current working directory of the
# calling process.  The pathname is returned as the function result
# and via the argument buf, if present.
getcwd = IrregularEmulatedSyscall(x86=183, x64=79, generic=17)

capget = IrregularEmulatedSyscall(x86=184, x64=125, generic=90)
capset = EmulatedSyscall(x86=185, x64=126, generic=91)

#  int sigaltstack(const stack_t *ss, stack_t *oss)
#
# sigaltstack() allows a process to define a new alternate signal
# stack and/or retrieve the state of an existing alternate signal
# stack.  An alternate signal stack is used during the execution of a
# signal handler if the establishment of that handler (see
# sigaction(2)) requested it.
sigaltstack = EmulatedSyscall(x86=186, x64=131, generic=132, arg2="typename Arch::stack_t")

sendfile = IrregularEmulatedSyscall(x86=187, x64=40, generic=71)
getpmsg = InvalidSyscall(x86=188, x64=181)
putpmsg = InvalidSyscall(x86=189, x64=182)
vfork = IrregularEmulatedSyscall(x86=190, x64=58)

#  int getrlimit(int resource, struct rlimit *rlim)
#
# getrlimit() and setrlimit() get and set resource limits
# respectively.  Each resource has an associated soft and hard limit,
# as defined by the rlimit structure (the rlim argument to both
# getrlimit() and setrlimit()):
ugetrlimit = EmulatedSyscall(x86=191, arg2="typename Arch::rlimit")

mmap2 = IrregularEmulatedSyscall(x86=192)

truncate64 = EmulatedSyscall(x86=193)
ftruncate64 = EmulatedSyscall(x86=194)

# int stat(const char *path, struct stat *buf);
#
# stat() stats the file pointed to by path and fills in buf.
stat64 = EmulatedSyscall(x86=195, arg2="struct Arch::stat64")

#  int lstat(const char *path, struct stat *buf);
#
# lstat() is identical to stat(), except that if path is a symbolic
# link, then the link itself is stat-ed, not the file that it refers
# to.
lstat64 = EmulatedSyscall(x86=196, arg2="struct Arch::stat64")

#  int fstat(int fd, struct stat *buf)
#
# fstat() is identical to stat(), except that the file to be stat-ed
# is specified by the file descriptor fd.
fstat64 = EmulatedSyscall(x86=197, arg2="struct Arch::stat64")

lchown32 = EmulatedSyscall(x86=198)

#  uid_t getuid(void);
#
# getuid() returns the real user ID of the calling process
getuid32 = EmulatedSyscall(x86=199)

#  gid_t getgid(void);
#
# getgid() returns the real group ID of the calling process.
getgid32 = EmulatedSyscall(x86=200)

#  uid_t geteuid(void);
#
# geteuid() returns the effective user ID of the calling process.
geteuid32 = EmulatedSyscall(x86=201)

#  gid_t getegid(void);
#
# getegid() returns the effective group ID of the calling process.
getegid32 = EmulatedSyscall(x86=202)

setreuid32 = EmulatedSyscall(x86=203)

#  int setregid(gid_t rgid, gid_t egid)
#
# setreuid() sets real and effective user IDs of the calling process
setregid32 = EmulatedSyscall(x86=204)

#  int getgroups(int size, gid_t list[]);
#
# getgroups() returns the supplementary group IDs of the calling
# process in list.  The argument size should be set to the maximum
# number of items that can be stored in the buffer pointed to by
# list. If the calling process is a member of more than size
# supplementary groups, then an error results.  It is unspecified
# whether the effective group ID of the calling process is included
# in the returned list. (Thus, an application should also call
# getegid(2) and add or remove the resulting value.)
#
# If size is zero, list is not modified, but the total number of
# supplementary group IDs for the process is returned.  This allows
# the caller to determine the size of a dynamically allocated list to
# be used in a further call to getgroups().
getgroups32 = IrregularEmulatedSyscall(x86=205)

setgroups32 = EmulatedSyscall(x86=206)
fchown32 = EmulatedSyscall(x86=207)

#  int setresuid32(uid_t ruid, uid_t euid, uid_t suid);
#
# setresuid() sets the real user ID, the effective user ID, and the
# saved set-user-ID of the calling process.
setresuid32 = EmulatedSyscall(x86=208)

#  int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
#
# getresuid() returns the real UID, the effective UID, and the saved
# set- user-ID of the calling process, in the arguments ruid, euid,
# and suid, respectively.  getresgid() performs the analogous task
# for the process's group IDs.
getresuid32 = EmulatedSyscall(x86=209, arg1="typename Arch::uid_t", arg2="typename Arch::uid_t", arg3="typename Arch::uid_t")

#  int setresgid32(gid_t rgid, gid_t egid, gid_t sgid);
#
# setresgid() sets the real GID, effective GID, and saved
# set-group-ID of the calling process.
setresgid32 = EmulatedSyscall(x86=210)

#  int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);
#
# getresuid() returns the real UID, the effective UID, and the saved
# set-user-ID of the calling process, in the arguments ruid, euid,
# and suid, respectively.  getresgid() performs the analogous task
# for the process's group IDs.  @return: On success, zero is
# returned.  On error, -1 is returned, and errno is set
# appropriately.
getresgid32 = EmulatedSyscall(x86=211, arg1="typename Arch::gid_t", arg2="typename Arch::gid_t", arg3="typename Arch::gid_t")

chown32 = EmulatedSyscall(x86=212)
setuid32 = EmulatedSyscall(x86=213)
setgid32 = EmulatedSyscall(x86=214)
setfsuid32 = EmulatedSyscall(x86=215)
setfsgid32 = EmulatedSyscall(x86=216)
pivot_root = EmulatedSyscall(x86=217, x64=155, generic=41)
mincore = IrregularEmulatedSyscall(x86=218, x64=27, generic=232)

#  int madvise(void *addr, size_t length, int advice);
#
# The madvise() system call advises the kernel about how to handle
# paging input/output in the address range beginning at address addr
# and with size length bytes.  It allows an application to tell the
# kernel how it expects to use some mapped or shared memory areas, so
# that the kernel can choose appropriate read-ahead and caching
# techniques.
# The man page says "This call does not influence the semantics of the
# application (except in the case of MADV_DONTNEED)", but that is a lie.
madvise = IrregularEmulatedSyscall(x86=219, x64=28, generic=233)

getdents64 = IrregularEmulatedSyscall(x86=220, x64=217, generic=61)

#  int fcntl(int fd, int cmd, ... ( arg ));
#
# fcntl() performs one of the operations described below on the open
# file descriptor fd.  The operation is determined by cmd. fcntl()
# can take an optional third argument.  Whether or not this argument
# is required is determined by cmd. The required argument type is
# indicated in parentheses after each cmd name (in most cases, the
# required type is long, and we identify the argument using the name
# arg), or void is specified if the argument is not required.
fcntl64 = IrregularEmulatedSyscall(x86=221)

#  pid_t gettid(void);
#
# gettid() returns the caller's thread ID (TID).
gettid = EmulatedSyscall(x86=224, x64=186, generic=178)

#  ssize_t readahead(int fd, off64_t offset, size_t count);
#
# readahead() populates the page cache with data from a file so that
# subsequent reads from that file will not block on disk I/O.  The fd
# argument is a file descriptor identifying the file which is to be
# read.  The offset argu- ment specifies the starting point from
# which data is to be read and count specifies the number of bytes to
# be read.  I/O is performed in whole pages, so that offset is
# effectively rounded down to a page boundary and bytes are read up
# to the next page boundary greater than or equal to (offset+count).
# readahead() does not read beyond the end of the file.  readahead()
# blocks until the specified data has been read.  The current file
# offset of the open file referred to by fd is left unchanged.
readahead = EmulatedSyscall(x86=225, x64=187, generic=213)

setxattr = EmulatedSyscall(x86=226, x64=188, generic=5)
lsetxattr = EmulatedSyscall(x86=227, x64=189, generic=6)
fsetxattr = EmulatedSyscall(x86=228, x64=190, generic=7)

#  ssize_t getxattr(const char *path, const char *name,
#                   void *value, size_t size);
#  ssize_t lgetxattr(const char *path, const char *name,
#                    void *value, size_t size);
#  ssize_t fgetxattr(int fd, const char *name,
#                    void *value, size_t size);
#
# getxattr() retrieves the value of the extended attribute identified
# by name and associated with the given path in the file system. The
# length of the attribute value is returned.
getxattr = IrregularEmulatedSyscall(x86=229, x64=191, generic=8)
lgetxattr = IrregularEmulatedSyscall(x86=230, x64=192, generic=9)
fgetxattr = IrregularEmulatedSyscall(x86=231, x64=193, generic=10)

listxattr = IrregularEmulatedSyscall(x86=232, x64=194, generic=11)
llistxattr = IrregularEmulatedSyscall(x86=233, x64=195, generic=12)
flistxattr = IrregularEmulatedSyscall(x86=234, x64=196, generic=13)
removexattr = EmulatedSyscall(x86=235, x64=197, generic=14)
lremovexattr = EmulatedSyscall(x86=236, x64=198, generic=15)
fremovexattr = EmulatedSyscall(x86=237, x64=199, generic=16)
tkill = EmulatedSyscall(x86=238, x64=200, generic=130)

# ssize_t sendfile64 (int __out_fd, int __in_fd, __off64_t *__offset, size_t
#__count);
#
# Send up to COUNT bytes from file associated with IN_FD starting at
# *OFFSET to descriptor OUT_FD.  Set *OFFSET to the IN_FD's file position
# following the read bytes.  If OFFSET is a null pointer, use the normal
# file position instead.  Return the number of written bytes, or -1 in
# case of error.
sendfile64 = IrregularEmulatedSyscall(x86=239)

#  int futex(int *uaddr, int op, int val, const struct timespec *timeout, int
#*uaddr2, int val3);
#
# The futex() system call provides a method for a program to wait for
# a value at a given address to change, and a method to wake up
# anyone waiting on a particular address (while the addresses for the
# same memory in separate processes may not be equal, the kernel
# maps them internally so the same memory mapped in different
# locations will correspond for futex() calls).  This system call is
# typically used to implement the contended case of a lock in shared
# memory, as described in futex(7).
futex = IrregularEmulatedSyscall(x86=240, x64=202, generic=98)

#  int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
#
# sched_setaffinity() sets the CPU affinity mask of the process whose
# ID is pid to the value specified by mask.  If pid is zero, then the
# calling process is used.  The argument cpusetsize is the length
# (in bytes) of the data pointed to by mask.  Normally this argument
# would be specified as sizeof(cpu_set_t).
sched_setaffinity = IrregularEmulatedSyscall(x86=241, x64=203, generic=122)

#  int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
#
# sched_getaffinity() writes the affinity mask of the process whose
# ID is pid into the cpu_set_t structure pointed to by mask.  The
# cpusetsize argument specifies the size (in bytes) of mask.  If pid
# is zero, then the mask of the calling process is returned.
sched_getaffinity = IrregularEmulatedSyscall(x86=242, x64=204, generic=123)

# int sched_setattr(pid_t pid, struct sched_attr *attr,
#                   unsigned int flags);
#
# The sched_setattr() system call sets the scheduling policy and
# associated attributes for the thread whose ID is specified in pid.
# If pid equals zero, the scheduling policy and attributes of the
# calling thread will be set.
#
# XXX Do we want to restrict somehow how this plays with rr's
# scheduling?
sched_setattr = EmulatedSyscall(x86=351, x64=314, generic=274)

# int sched_getattr(pid_t pid, struct sched_attr *attr,
#                   unsigned int size, unsigned int flags);
#
# The sched_getattr() system call fetches the scheduling policy and the
# associated attributes for the thread whose ID is specified in pid.
# If pid equals zero, the scheduling policy and attributes of the call‐
# ing thread will be retrieved.
sched_getattr = IrregularEmulatedSyscall(x86=352, x64=315, generic=275)

#  int set_thread_area(struct user_desc *u_info)
#
# set_thread_area() sets an entry in the current thread's Thread Local
# Storage (TLS) array.  The TLS array entry set by set_thread_area()
# corresponds to the value of u_info->entry_number passed in by the
# user.  If this value is in bounds, set_thread_area() copies the TLS
# descriptor pointed to by u_info into the thread's TLS array.
#
# When  set_thread_area() is passed an entry_number of -1, it uses a free
# TLS entry.  If set_thread_area() finds a free TLS entry, the  value  of
# u_info->entry_number  is  set  upon  return  to  show  which  entry was
# changed.
set_thread_area = IrregularEmulatedSyscall(x86=243, x64=205)

get_thread_area = IrregularEmulatedSyscall(x86=244, x64=211)
io_setup = IrregularEmulatedSyscall(x86=245, x64=206, generic=0)
io_destroy = UnsupportedSyscall(x86=246, x64=207, generic=1)
io_getevents = UnsupportedSyscall(x86=247, x64=208, generic=4)
io_submit = UnsupportedSyscall(x86=248, x64=209, generic=2)
io_cancel = UnsupportedSyscall(x86=249, x64=210, generic=3)

#  int posix_fadvise(int fd, off_t offset, off_t len, int advice);
#
# Programs can use posix_fadvise() to announce an intention to access
# file data in a specific pattern in the future, thus allowing the
# kernel to perform appropriate optimizations.
fadvise64 = EmulatedSyscall(x86=250, x64=221, generic=223)

#  void exit_group(int status)
#
# This system call is equivalent to exit(2) except that it terminates
# not only the calling thread, but all threads in the calling
# process's thread group.
exit_group = IrregularEmulatedSyscall(x86=252, x64=231, generic=94)

lookup_dcookie = UnsupportedSyscall(x86=253, x64=212)

#  int epoll_create(int size);
#
# epoll_create() creates an epoll "instance", requesting the kernel
# to allocate an event backing store dimensioned for size
# descriptors.  The size is not the maximum size of the backing store
# but just a hint to the kernel about how to dimension internal
# structures.  When no longer required, the file descriptor returned
# by epoll_create() should be closed by using close(2).
epoll_create = EmulatedSyscall(x86=254, x64=213)

#  int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
#
# This system call performs control operations on the epoll instance
# referred to by the file descriptor epfd.  It requests that the
# operation op be performed for the target file descriptor, fd.
epoll_ctl = EmulatedSyscall(x86=255, x64=233, generic=21)

#  int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int
#timeout);
#
# The epoll_wait() system call waits for events on the epoll instance
# referred to by the file descriptor epfd.  The memory area pointed
# to by events will contain the events that will be available for the
# caller.  Up to maxevents are returned by epoll_wait().  The
# maxevents argument must be greater than zero.
#
# XXX is this irregular?  CHECKED: (trace->recorded_regs.eax >= 0)
epoll_wait = IrregularEmulatedSyscall(x86=256, x64=232)

remap_file_pages = UnsupportedSyscall(x86=257, x64=216, generic=234)

#  long set_tid_address(int *tidptr);
#
# The kernel keeps for each process two values called set_child_tid
# and clear_child_tid that are NULL by default.
#
# If a process is started using clone(2) with the CLONE_CHILD_SETTID
# flag, set_child_tid is set to child_tidptr, the fifth argument of
# that system call.
#
# When set_child_tid is set, the very first thing the new process
# does is writing its PID at this address.
set_tid_address = EmulatedSyscall(x86=258, x64=218, generic=96)

timer_create = EmulatedSyscall(x86=259, x64=222, generic=107, arg3="typename Arch::__kernel_timer_t")
timer_settime = EmulatedSyscall(x86=260, x64=223, generic=110, arg4="typename Arch::itimerspec")
timer_gettime = EmulatedSyscall(x86=261, x64=224, generic=108, arg2="typename Arch::itimerspec")
timer_getoverrun = EmulatedSyscall(x86=262, x64=225, generic=109)
timer_delete = EmulatedSyscall(x86=263, x64=226, generic=111)
clock_settime = UnsupportedSyscall(x86=264, x64=227, generic=112)

#  int clock_gettime(clockid_t clk_id, struct timespec *tp);
#
# The functions clock_gettime() and clock_settime() retrieve and set
# the time of the specified clock clk_id.
clock_gettime = EmulatedSyscall(x86=265, x64=228, generic=113, arg2="typename Arch::timespec")

#  int clock_getres(clockid_t clk_id, struct timespec *res)
#
# The function clock_getres() finds the resolution (precision) of the
# specified clock clk_id, and, if res is non-NULL, stores it in the
# struct timespec pointed to by res.  The resolution of clocks
# depends on the implementation and cannot be configured by a
# particular process.  If the time value pointed to by the argument
# tp of clock_settime() is not a multiple of res, then it is
# truncated to a multiple of res.
clock_getres = EmulatedSyscall(x86=266, x64=229, generic=114, arg2="typename Arch::timespec")

clock_nanosleep = IrregularEmulatedSyscall(x86=267, x64=230, generic=115)

#  int statfs(const char *path, struct statfs *buf)
#
# The function statfs() returns information about a mounted file
# system.  path is the pathname of any file within the mounted file
# system.  buf is a pointer to a statfs structure defined
# approximately as follows...
#
# FIXME: we use arg3() here, although according to man pages this system
# call has only 2 paramaters. However, strace tells another story...
statfs64 = EmulatedSyscall(x86=268, arg3="struct Arch::statfs64")
fstatfs64 = EmulatedSyscall(x86=269, arg3="struct Arch::statfs64")

#  int tgkill(int tgid, int tid, int sig)
#
# tgkill() sends the signal sig to the thread with the thread ID tid
# in the thread group tgid.  (By contrast, kill(2) can only be used
# to send a signal to a process (i.e., thread group) as a whole, and
# the signal will be delivered to an arbitrary thread within that
# process.)
tgkill = EmulatedSyscall(x86=270, x64=234, generic=131)

#  int utimes(const char *filename, const struct timeval times[2])
#
# The utime() system call changes the access and modification times
# of the inode specified by filename to the actime and modtime fields
# of times respectively.
#
utimes = EmulatedSyscall(x86=271, x64=235)

fadvise64_64 = EmulatedSyscall(x86=272)

vserver = InvalidSyscall(x86=273, x64=236)
mbind = EmulatedSyscall(x86=274, x64=237, generic=235)
get_mempolicy = IrregularEmulatedSyscall(x86=275, x64=239, generic=236)
set_mempolicy = EmulatedSyscall(x86=276, x64=238, generic=237)

mq_open = EmulatedSyscall(x86=277, x64=240, generic=180)
mq_unlink = EmulatedSyscall(x86=278, x64=241, generic=181)
mq_timedsend = EmulatedSyscall(x86=279, x64=242, generic=182)
mq_timedreceive = IrregularEmulatedSyscall(x86=280, x64=243, generic=183)
mq_notify = EmulatedSyscall(x86=281, x64=244, generic=184)
mq_getsetattr = EmulatedSyscall(x86=282, x64=245, generic=185, arg3="struct Arch::mq_attr")

kexec_load = UnsupportedSyscall(x86=283, x64=246, generic=104)

#  int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
#
# If WNOHANG was specified in options and there were no children in a
# waitable state, then waitid() returns 0 immediately and the state
# of the siginfo_t structure pointed to by infop is unspecified.  To
# distinguish this case from that where a child was in a waitable
# state, zero out the si_pid field before the call and check for a
# nonzero value in this field after the call returns.
waitid = IrregularEmulatedSyscall(x86=284, x64=247, generic=95)

add_key = EmulatedSyscall(x86=286, x64=248, generic=217)
request_key = UnsupportedSyscall(x86=287, x64=249, generic=218)
keyctl = IrregularEmulatedSyscall(x86=288, x64=250, generic=219)
ioprio_set = EmulatedSyscall(x86=289, x64=251, generic=30)
ioprio_get = EmulatedSyscall(x86=290, x64=252, generic=31)

#  int inotify_init(void)
#
# inotify_init() initializes a new inotify instance and returns a
# file descriptor associated with a new inotify event queue.
inotify_init = EmulatedSyscall(x86=291, x64=253)

#  int inotify_add_watch(int fd, const char *pathname, uint32_t mask)
#
# inotify_add_watch() adds a new watch, or modifies an existing
# watch, for the file whose location is specified in pathname; the
# caller must have read permission for this file.  The fd argument is
# a file descrip tor referring to the inotify instance whose watch
# list is to be modified.  The events to be monitored for pathname
# are specified in the mask bit-mask argument.  See inotify(7) for a
# description of the bits that can be set in mask.
inotify_add_watch = EmulatedSyscall(x86=292, x64=254, generic=27)

#  int inotify_rm_watch(int fd, uint32_t wd)
#
# inotify_rm_watch() removes the watch associated with the watch
# descriptor wd from the inotify instance associated with the file
# descriptor fd.
inotify_rm_watch = EmulatedSyscall(x86=293, x64=255, generic=28)

migrate_pages = UnsupportedSyscall(x86=294, x64=256, generic=238)

#  int openat(int dirfd, const char *pathname, int flags);
#  int openat(int dirfd, const char *pathname, int flags, mode_t mode);
#
# The openat() system call operates in exactly the same way as
# open(2), except for the differences described in this manual page.
openat = IrregularEmulatedSyscall(x86=295, x64=257, generic=56)

#  int mkdirat(int dirfd, const char *pathname, mode_t mode);
#
# The mkdirat() system call operates in exactly the same way as
# mkdir(2), except for the differences described in this manual
# page....
mkdirat = EmulatedSyscall(x86=296, x64=258, generic=34)

mknodat = EmulatedSyscall(x86=297, x64=259, generic=33)
fchownat = EmulatedSyscall(x86=298, x64=260, generic=54)
futimesat = UnsupportedSyscall(x86=299, x64=261)

#  int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
#
# The fstatat() system call operates in exactly the same way as
# stat(2), except for the differences described in this manual
# page....
fstatat = EmulatedSyscall(x64=262, generic=79, arg3="struct Arch::stat")
fstatat64 = EmulatedSyscall(x86=300, arg3="struct Arch::stat64")

#  int unlinkat(int dirfd, const char *pathname, int flags)
#
# The unlinkat() system call operates in exactly the same way as
# either unlink(2) or rmdir(2) (depending on whether or not flags
# includes the AT_REMOVEDIR flag) except for the differences
# described in this manual page.
unlinkat = EmulatedSyscall(x86=301, x64=263, generic=35)

renameat = EmulatedSyscall(x86=302, x64=264, generic=38)
linkat = EmulatedSyscall(x86=303, x64=265, generic=37)
symlinkat = EmulatedSyscall(x86=304, x64=266, generic=36)
readlinkat = IrregularEmulatedSyscall(x86=305, x64=267, generic=78)
fchmodat = EmulatedSyscall(x86=306, x64=268, generic=53)

#  int faccessat(int dirfd, const char *pathname, int mode, int flags)
#
# The faccessat() system call operates in exactly the same way as
# access(2), except for the differences described in this manual
# page....
faccessat = EmulatedSyscall(x86=307, x64=269, generic=48)

#  int faccessat2(int dirfd, const char *pathname, int mode, int flags)
#
# The faccessat2() system call operates in exactly the same way as
# access(2), except for the differences described in this manual
# page...
faccessat2 = EmulatedSyscall(x86=439, x64=439, generic=439)

pselect6 = IrregularEmulatedSyscall(x86=308, x64=270, generic=72)

ppoll = IrregularEmulatedSyscall(x86=309, x64=271, generic=73)

unshare = EmulatedSyscall(x86=310, x64=272, generic=97)

#  long set_robust_list(struct robust_list_head *head, size_t len)
#
# The robust futex implementation needs to maintain per-thread lists
# of robust futexes which are unlocked when the thread exits. These
# lists are managed in user space, the kernel is only notified about
# the location of the head of the list.
#
# set_robust_list sets the head of the list of robust futexes owned
# by the current thread to head.  len is the size of *head.
set_robust_list = EmulatedSyscall(x86=311, x64=273, generic=99)

get_robust_list = EmulatedSyscall(x86=312, x64=274, generic=100, arg2="typename Arch::unsigned_word", arg3="typename Arch::size_t")

#  ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
#size_t len, unsigned int flags);
#
# splice() moves data between two file descriptors without copying
# between kernel address space and user address space.  It transfers
# up to len bytes of data from the file descriptor fd_in to the file
# descriptor fd_out, where one of the descriptors must refer to a
# pipe.
#
# NB: the documentation doesn't mention it explicitly, but the |off|
# params are actually inout params, and are updated with the new file
# offset on return.
#
# NOTE: Technically, the following implementation is unsound for
# programs that splice with stdin/stdout/stderr and have output
# redirected during replay.  But, *crickets*.
splice = IrregularEmulatedSyscall(x86=313, x64=275, generic=76)

sync_file_range = IrregularEmulatedSyscall(x86=314, x64=277, generic=84)
tee = UnsupportedSyscall(x86=315, x64=276, generic=77)
vmsplice = UnsupportedSyscall(x86=316, x64=278, generic=75)
move_pages = UnsupportedSyscall(x86=317, x64=279, generic=239)
getcpu = EmulatedSyscall(x86=318, x64=309, generic=168, arg1="unsigned int", arg2="unsigned int")
epoll_pwait = IrregularEmulatedSyscall(x86=319, x64=281, generic=22)

#  int utimensat(int dirfd, const char *pathname, const struct timespec
#times[2], int flags);
#
# utimensat() and futimens() update the timestamps of a file with
# nanosecond precision.  This contrasts with the historical utime(2)
# and utimes(2), which permit only second and microsecond precision,
# respectively, when setting file timestamps.
utimensat = EmulatedSyscall(x86=320, x64=280, generic=88)

#  int signalfd(int fd, const sigset_t *mask, int flags);
# There are two underlying Linux system calls: signalfd() and the more
# recent signalfd4(). The former system call does not implement a flags
# argument. The latter system call implements the flags values described
# above. Starting with glibc 2.9, the signalfd() wrapper function will
# use signalfd4() where it is available.
signalfd = EmulatedSyscall(x86=321, x64=282)

#  int timerfd_create(int clockid, int flags);
#
# timerfd_create() creates a new timer object, and returns a file
# descriptor that refers to that timer.
timerfd_create = EmulatedSyscall(x86=322, x64=283, generic=85)

eventfd = EmulatedSyscall(x86=323, x64=284)

# int fallocate(int fd, int mode, off_t offset, off_t len);
#
# fallocate() allows the caller to directly manipulate the allocated
# disk space for the file referred to by fd for the byte range
# starting at offset and continuing for len bytes
fallocate = EmulatedSyscall(x86=324, x64=285, generic=47)

#  int timerfd_settime(int fd, int flags,
#                      const struct itimerspec *new_value,
#                      struct itimerspec *old_value);
#
# timerfd_settime() arms (starts) or disarms (stops) the timer
# referred to by the file descriptor fd.
timerfd_settime = EmulatedSyscall(x86=325, x64=286, generic=86, arg4="typename Arch::itimerspec")

#  int timerfd_gettime(int fd, struct itimerspec *curr_value);
#
# timerfd_gettime() returns, in curr_value, an itimerspec structure
# that contains the current setting of the timer referred to by the
# file descriptor fd.
timerfd_gettime = EmulatedSyscall(x86=326, x64=287, generic=87, arg2="typename Arch::itimerspec")

#  int signalfd(int fd, const sigset_t *mask, int flags);
# There are two underlying Linux system calls: signalfd() and the more
# recent signalfd4(). The former system call does not implement a flags
# argument. The latter system call implements the flags values described
# above. Starting with glibc 2.9, the signalfd() wrapper function will
# use signalfd4() where it is available.
signalfd4 = EmulatedSyscall(x86=327, x64=289, generic=74)

#  int eventfd(unsigned int initval, int flags);
#
# eventfd() creates an "eventfd object" that can be used as an event
# wait/notify mechanism by userspace applications, and by the kernel
# to notify userspace applications of events.  The object contains an
# unsigned 64-bit integer (uint64_t) counter that is maintained by
# the kernel.  This counter is initialized with the value specified
# in the argument initval.
eventfd2 = EmulatedSyscall(x86=328, x64=290, generic=19)

#  int epoll_create1(int flags);
#
# epoll_create1() is very similar to epoll_create.  They are identical
# if the passed flag value is 0, they are completely identical.  The
# flag argument can be used to set the close-on-exec flag on the new
# file descriptor.
epoll_create1 = EmulatedSyscall(x86=329, x64=291, generic=20)

dup3 = IrregularEmulatedSyscall(x86=330, x64=292, generic=24)

#  int pipe2(int pipefd[2], int flags)
#
# If flags is 0, then pipe2() is the same as pipe().  The following
# values can be bitwise ORed in flags to obtain different behavior...
pipe2 = EmulatedSyscall(x86=331, x64=293, generic=59, arg1="int[2]")

inotify_init1 = EmulatedSyscall(x86=332, x64=294, generic=26)

preadv = IrregularEmulatedSyscall(x86=333, x64=295, generic=69)
pwritev = EmulatedSyscall(x86=334, x64=296, generic=70)

#  int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *uinfo);
#  int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig,
#                        siginfo_t *uinfo);
#
# The rt_sigqueueinfo() and rt_tgsigqueueinfo() system calls are the
# low-level interfaces used to send a signal plus data to a process
# or thread.  The receiver of the signal can obtain the accompanying
# data by establishing a signal handler with the sigaction(2)
# SA_SIGINFO flag.
rt_sigqueueinfo = EmulatedSyscall(x86=178, x64=129, generic=138)
rt_tgsigqueueinfo = EmulatedSyscall(x86=335, x64=297, generic=240)

#  int perf_event_open(struct perf_event_attr *attr,
#                      pid_t pid, int cpu, int group_fd,
#                      unsigned long flags);
#
# Given a list of parameters, perf_event_open() returns a file
# descriptor, for use in subsequent system calls (read(2), mmap(2),
# prctl(2), fcntl(2), etc.).
perf_event_open = IrregularEmulatedSyscall(x86=336, x64=298, generic=241)

#  int recvmmsg(int sockfd, struct mmsghdr *msgvec,
#               unsigned int vlen, unsigned int flags,
#               struct timespec *timeout);
#
# The recvmmsg() system call is an extension of recvmsg(2) that
# allows the caller to receive multiple messages from a socket using
# a single system call.  (This has performance benefits for some
# applications.)  A further extension over recvmsg(2) is support for
# a timeout on the receive operation.
recvmmsg = IrregularEmulatedSyscall(x86=337, x64=299, generic=243)

fanotify_init = EmulatedSyscall(x86=338, x64=300, generic=262)
fanotify_mark = EmulatedSyscall(x86=339, x64=301, generic=263)

#  int prlimit(pid_t pid, int resource, const struct rlimit *new_limit, struct
#rlimit *old_limit);
#
# The Linux-specific prlimit() system call combines and extends the
# functionality of setrlimit() and getrlimit().  It can be used to
# both set and get the resource limits of an arbitrary process.
#
# NOTE: We should execute this system call, since this system call
# can set a limit on the stack size that will trigger a synchronous SIGSEGV,
# and we expect synchronous SIGSEGVs to be triggered by the kernel
# during replay.
prlimit64 = EmulatedSyscall(x86=340, x64=302, generic=261, arg4="typename Arch::rlimit64")

name_to_handle_at = IrregularEmulatedSyscall(x86=341, x64=303, generic=264)
open_by_handle_at = EmulatedSyscall(x86=342, x64=304, generic=265)
clock_adjtime = EmulatedSyscall(x86=343, x64=305, generic=266, arg2="typename Arch::timex")
syncfs = IrregularEmulatedSyscall(x86=344, x64=306, generic=267)

#  int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
#               unsigned int flags);
#
# The sendmmsg() system call is an extension of sendmsg(2) that
# allows the caller to transmit multiple messages on a socket using a
# single system call.  (This has performance benefits for some
# applications.)
sendmmsg = IrregularEmulatedSyscall(x86=345, x64=307, generic=269)

setns = EmulatedSyscall(x86=346, x64=308, generic=268)
process_vm_readv = IrregularEmulatedSyscall(x86=347, x64=310, generic=270)
process_vm_writev = IrregularEmulatedSyscall(x86=348, x64=311, generic=271)
kcmp = EmulatedSyscall(x86=349, x64=312, generic=272)
finit_module = UnsupportedSyscall(x86=350, x64=313, generic=273)
renameat2 = EmulatedSyscall(x86=353, x64=316, generic=276)
seccomp = IrregularEmulatedSyscall(x86=354, x64=317, generic=277)
getrandom = IrregularEmulatedSyscall(x86=355, x64=318, generic=278)
memfd_create = IrregularEmulatedSyscall(x86=356, x64=319, generic=279)
arch_prctl = IrregularEmulatedSyscall(x86=384, x64=158)

bpf = IrregularEmulatedSyscall(x86=357, x64=321, generic=280)
execveat = UnsupportedSyscall(x86=358, x64=322, generic=281)
userfaultfd = IrregularEmulatedSyscall(x86=374, x64=323, generic=282)
membarrier = EmulatedSyscall(x86=375, x64=324, generic=283)
mlock2 = UnsupportedSyscall(x86=376, x64=325, generic=284)
copy_file_range = IrregularEmulatedSyscall(x86=377, x64=326, generic=285)
preadv2 = UnsupportedSyscall(x86=378, x64=327, generic=286)
pwritev2 = UnsupportedSyscall(x86=379, x64=328, generic=287)
pkey_mprotect = IrregularEmulatedSyscall(x86=380, x64=329, generic=288)
pkey_alloc = EmulatedSyscall(x86=381, x64=330, generic=289)
pkey_free = EmulatedSyscall(x86=382, x64=331, generic=290)
statx = EmulatedSyscall(x86=383, x64=332, generic=291, arg5="typename Arch::statx_struct")
io_pgetevents = UnsupportedSyscall(x86=385, x64=333, generic=292)
rseq = IrregularEmulatedSyscall(x86=386, x64=334, generic=293)

clock_gettime64 = EmulatedSyscall(x86=403, arg2="typename Arch::Arch64::timespec")
clock_settime64 = UnsupportedSyscall(x86=404)
clock_adjtime64 = EmulatedSyscall(x86=405, arg2="typename Arch::Arch64::timex")
clock_getres_time64 = EmulatedSyscall(x86=406, arg2="typename Arch::Arch64::timespec")
clock_nanosleep_time64 = IrregularEmulatedSyscall(x86=407)
timer_gettime64 = EmulatedSyscall(x86=408, arg2="typename Arch::Arch64::itimerspec")
timer_settime64 = EmulatedSyscall(x86=409, arg4="typename Arch::Arch64::itimerspec")
timerfd_gettime64 = EmulatedSyscall(x86=410, arg2="typename Arch::Arch64::itimerspec")
timerfd_settime64 = EmulatedSyscall(x86=411, arg4="typename Arch::Arch64::itimerspec")
utimensat_time64 = EmulatedSyscall(x86=412)
pselect6_time64 = IrregularEmulatedSyscall(x86=413)
ppoll_time64 = IrregularEmulatedSyscall(x86=414)
io_pgetevents_time64 = UnsupportedSyscall(x86=416)
recvmmsg_time64 = IrregularEmulatedSyscall(x86=417)
mq_timedsend_time64 = EmulatedSyscall(x86=418)
mq_timedreceive_time64 = IrregularEmulatedSyscall(x86=419)
semtimedop_time64 = IrregularEmulatedSyscall(x86=420)
rt_sigtimedwait_time64 = IrregularEmulatedSyscall(x86=421)
futex_time64 = IrregularEmulatedSyscall(x86=422)
sched_rr_get_interval_time64 = UnsupportedSyscall(x86=423)

# x86-64 decided to skip ahead here to catchup
pidfd_send_signal = UnsupportedSyscall(x86=424, x64=424, generic=424)
io_uring_setup = IrregularEmulatedSyscall(x86=425, x64=425, generic=425)
io_uring_enter = UnsupportedSyscall(x86=426, x64=426, generic=426)
io_uring_register = UnsupportedSyscall(x86=427, x64=427, generic=427)
open_tree = UnsupportedSyscall(x86=428, x64=428, generic=428)
move_mount = UnsupportedSyscall(x86=429, x64=429, generic=429)
fsopen = UnsupportedSyscall(x86=430, x64=430, generic=430)
fsconfig = UnsupportedSyscall(x86=431, x64=431, generic=431)
fsmount = UnsupportedSyscall(x86=432, x64=432, generic=432)
fspick = UnsupportedSyscall(x86=433, x64=433, generic=433)
pidfd_open = EmulatedSyscall(x86=434, x64=434, generic=434)
clone3 = UnsupportedSyscall(x86=435, x64=435, generic=435)
openat2 = UnsupportedSyscall(x86=437, x64=437, generic=437)
pidfd_getfd = UnsupportedSyscall(x86=438, x64=438, generic=438)
process_madvise = UnsupportedSyscall(x86=440, x64=440, generic=440)
epoll_pwait2 = UnsupportedSyscall(x86=441, x64=441, generic=441)
mount_setattr = UnsupportedSyscall(x86=442, x64=442, generic=442)
quotactl_fd = UnsupportedSyscall(x86=443, x64=443, generic=443)
landlock_create_ruleset = UnsupportedSyscall(x86=444, x64=444, generic=444)
landlock_add_rule = UnsupportedSyscall(x86=445, x64=445, generic=445)
landlock_restrict_self = UnsupportedSyscall(x86=446, x64=446, generic=446)
memfd_secret = UnsupportedSyscall(x86=447, x64=447, generic=447)

# restart_syscall is a little special.
restart_syscall = RestartSyscall(x86=0, x64=219, generic=128)

# Internal rr syscall numbers.
# These syscall numbers must be the same across all architectures.
rrcall_init_preload = IrregularEmulatedSyscall(x86=1000, x64=1000, generic=1000)
rrcall_init_buffers = IrregularEmulatedSyscall(x86=1001, x64=1001, generic=1001)
rrcall_notify_syscall_hook_exit = IrregularEmulatedSyscall(x86=1002, x64=1002, generic=1002)
rrcall_notify_control_msg = IrregularEmulatedSyscall(x86=1003, x64=1003, generic=1003)
rrcall_reload_auxv = IrregularEmulatedSyscall(x86=1004, x64=1004, generic=1004)
rrcall_mprotect_record = IrregularEmulatedSyscall(x86=1005, x64=1005, generic=1005)
rrcall_notify_stap_semaphore_added = IrregularEmulatedSyscall(x86=1006, x64=1006, generic=1006)
rrcall_notify_stap_semaphore_removed = IrregularEmulatedSyscall(x86=1007, x64=1007, generic=1007)
rrcall_check_presence = IrregularEmulatedSyscall(x86=1008, x64=1008, generic=1008)
rrcall_detach_teleport = IrregularEmulatedSyscall(x86=1009, x64=1009, generic=1009)

# These syscalls also appear under `socketcall` on x86.
socket = EmulatedSyscall(x86=359, x64=41, generic=198)
connect = IrregularEmulatedSyscall(x86=362, x64=42, generic=203)
accept = IrregularEmulatedSyscall(x64=43, generic=202)
sendto = IrregularEmulatedSyscall(x86=369, x64=44, generic=206)
recvfrom = IrregularEmulatedSyscall(x86=371, x64=45, generic=207)
sendmsg = IrregularEmulatedSyscall(x86=370, x64=46, generic=211)
recvmsg = IrregularEmulatedSyscall(x86=372, x64=47, generic=212)
shutdown = EmulatedSyscall(x86=373, x64=48, generic=210)
bind = EmulatedSyscall(x86=361, x64=49, generic=200)
listen = EmulatedSyscall(x86=363, x64=50, generic=201)
getsockname = IrregularEmulatedSyscall(x86=367, x64=51, generic=204)
getpeername = IrregularEmulatedSyscall(x86=368, x64=52, generic=205)
socketpair = EmulatedSyscall(x86=360, x64=53, generic=199, arg4="int[2]")
setsockopt = IrregularEmulatedSyscall(x86=366, x64=54, generic=208)
getsockopt = IrregularEmulatedSyscall(x86=365, x64=55, generic=209)
accept4 = IrregularEmulatedSyscall(x86=364, x64=288, generic=242)

# These syscalls also appear under `ipc` on x86.
shmget = EmulatedSyscall(x64=29, x86=395, generic=194)
shmat = IrregularEmulatedSyscall(x64=30, x86=397, generic=196)
shmctl = IrregularEmulatedSyscall(x64=31, x86=396, generic=195)
semget = EmulatedSyscall(x64=64, x86=393, generic=190)
semop = IrregularEmulatedSyscall(x64=65, generic=193)
semctl = IrregularEmulatedSyscall(x64=66, x86=394, generic=191)
shmdt = IrregularEmulatedSyscall(x64=67, x86=398, generic=197)
msgget = EmulatedSyscall(x64=68, x86=399, generic=186)
msgsnd = IrregularEmulatedSyscall(x64=69, x86=400, generic=189)
msgrcv = IrregularEmulatedSyscall(x64=70, x86=401, generic=188)
msgctl = IrregularEmulatedSyscall(x64=71, x86=402, generic=187)
semtimedop = IrregularEmulatedSyscall(x64=220, generic=192)

# These syscalls simply don't exist on x86.
tuxcall = InvalidSyscall(x64=184)
security = InvalidSyscall(x64=185)
epoll_ctl_old = UnsupportedSyscall(x64=214)
epoll_wait_old = UnsupportedSyscall(x64=215)

def _syscalls():
    for name, obj in globals().items():
        if isinstance(obj, BaseSyscall):
            yield name, obj

def all():
    return list(_syscalls())

def for_arch(arch):
    for name, obj in all():
        if getattr(obj, arch) is not None:
            yield name, obj
