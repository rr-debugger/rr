/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#define _GNU_SOURCE

#include "sys.h"

#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
/* This header has to be included after sys/ptrace.h. */
#include <asm/ptrace-abi.h>
#include <sys/time.h>
#include <sys/wait.h>

#include "dbg.h"
#include "ipc.h"
#include "../recorder/rec_sched.h"
#include "task.h"
#include "trace.h"
#include "util.h"

FILE* sys_fopen(const char* path, const char* mode)
{
	FILE* file = fopen(path, mode);

	if (file == NULL) {
		log_err("error while opening file: %s -- bailing out!\n", path);
		sys_exit();
	}

	return file;
}

int sys_open(const char* path, int flags, mode_t mode)
{
	int file = (mode < 0) ? open(path, flags) : open(path, flags, mode);

	if (file < 0) {
		log_err("error while opening file: %s -- bailing out!\n", path);
		sys_exit();
	}

	return file;
}

void sys_fclose(FILE* file)
{
	if (fclose(file) < 0) {
		log_err("error while closing file -- bailing out\n");
		sys_exit();
	}
}

void sys_close(int filedes)
{
	if (close(filedes) < 0) {
		log_err("error while closing file -- bailing out\n");
		sys_exit();
	}
}

int sys_open_child_mem(pid_t tid)
{
	char path[64];
	bzero(path, 64);
	int fd;

	sprintf(path, "/proc/%d/mem", tid);
	if ((fd = open(path, O_RDWR)) < 0) {
		log_err("error reading child memory:open-- bailing out\n");
		sys_exit();
	}

	return fd;
}

pid_t sys_fork()
{
	pid_t pid = fork();

	if (pid == -1) {
		log_err("error forking process");
		exit(-1);
	}

	return pid;
}

void sys_kill(int pid, int msg)
{
	int ret;
	if ((ret = kill(pid, msg)) < 0) {
		log_err("error sending signal");
	}
}

void sys_exit()
{
	log_err("Exiting");
	rec_sched_exit_all();
	close_trace_files();
	abort();
}

/**
 * Prepare this process and its ancestors for recording/replay by
 * preventing direct access to sources of nondeterminism, and ensuring
 * that rr bugs don't adversely affect the underlying system.
 */
static void set_up_process()
{
	int orig_pers;

	if (!rr_flags()->cpu_unbound) {
		cpu_set_t mask;
		/* Bind tracee tasks to exactly one logical CPU, the
		 * same across record/replay.  This prevents tracees
		 * from observing nondeterminism through issuing
		 * 'cpuid' instructions that reveal which HW thread
		 * they're running on. */
		CPU_ZERO(&mask);
		CPU_SET(0, &mask);
		if (0 > sched_setaffinity(0, sizeof(mask), &mask)) {
			fatal("Couldn't bind to CPU 0");
		}
	}

	/* TODO tracees can probably undo some of the setup below
	 * ... */

	/* Disable address space layout randomization, for obvious
	 * reasons, and ensure that the layout is otherwise well-known
	 * ("COMPAT").  For not-understood reasons, "COMPAT" layouts
	 * have been observed in certain recording situations but not
	 * in replay, which causes divergence. */
	if (0 > (orig_pers = personality(0xffffffff))) {
		fatal("error getting personaity");
	}
	if (0 > personality(orig_pers | ADDR_NO_RANDOMIZE |
			    ADDR_COMPAT_LAYOUT)) {
		fatal("error disabling randomization");
	}
	/* Trap to the rr process if a 'rdtsc' instruction is issued.
	 * That allows rr to record the tsc and replay it
	 * deterministically. */
	if (0 > prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0)) {
		fatal("error setting up prctl -- bailing out");
	}
	/* If the rr process dies, prevent runaway tracee processes
	 * from dragging down the underlying system. */
	if (0 > prctl(PR_SET_PDEATHSIG, SIGKILL)) {
		fatal("Couldn't set parent-death signal");
	}

	/* XXX is it faster to mask off a CPU affinity when this
	 * process is the only intensive one in the system? */
}

void sys_start_trace(char* executable, char** argv, char** envp)
{
	set_up_process();
	sys_ptrace_traceme();

	/* signal the parent that the child is ready */
	kill(getpid(), SIGSTOP);

	execvpe(executable, argv, envp);
	fatal("Failed to exec %s", executable);
}

/* ptrace stuff comes here */
long sys_ptrace(int request, pid_t pid, void *addr, void *data)
{
	long ret;
	if ((ret = ptrace(request, pid, addr, data)) == -1) {
		fatal("ptrace_error: request: %d of tid: %d: addr %p, data %p",
		      request, pid, addr, data);
	}
	return ret;
}

void sys_ptrace_syscall(pid_t pid)
{
	sys_ptrace(PTRACE_SYSCALL, pid, 0, 0);
}

void sys_ptrace_cont(pid_t pid)
{
	ptrace(PTRACE_CONT, pid, 0, 0);
}

void sys_ptrace_cont_sig(pid_t pid, int sig)
{
	ptrace(PTRACE_CONT, pid, 0, (void*)sig);
}

/**
 * Detaches the child process from monitoring. This method must only be
 * invoked, if the thread exits. We do not check errors here, since the
 * thread could have already exited.
 */
void sys_ptrace_detach(pid_t pid)
{
	ptrace(PTRACE_DETACH, pid, 0, 0);
}

void sys_ptrace_syscall_sig(pid_t pid, int sig)
{
	sys_ptrace(PTRACE_SYSCALL, pid, 0, (void*)sig);
}

void sys_ptrace_sysemu(pid_t pid)
{
	sys_ptrace(PTRACE_SYSEMU, pid, 0, 0);
}

void sys_ptrace_sysemu_sig(pid_t pid, int sig)
{
	sys_ptrace(PTRACE_SYSEMU, pid, 0, (void*)sig);
}

void sys_ptrace_sysemu_singlestep(pid_t pid)
{
	sys_ptrace(PTRACE_SYSEMU_SINGLESTEP, pid, 0, 0);
}

void sys_ptrace_sysemu_singlestep_sig(pid_t pid, int sig)
{
	sys_ptrace(PTRACE_SYSEMU_SINGLESTEP, pid, 0, (void*)sig);
}

int sys_ptrace_peekdata(pid_t pid, long addr, long* value)
{
	long ret;

	assert(0 == (addr & (sizeof(void*) - 1)));

	errno = 0;
	ret = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
	if (-1 == ret && errno) {
		return -1;
	}
	*value = ret;
	return 0;
}

unsigned long sys_ptrace_getmsg(pid_t pid)
{
	unsigned long tmp;
	sys_ptrace(PTRACE_GETEVENTMSG, pid, 0, &tmp);
	return tmp;
}
void sys_ptrace_getsiginfo(pid_t pid, siginfo_t* sig)
{
	sys_ptrace(PTRACE_GETSIGINFO, pid, 0, sig);
}

void sys_ptrace_setup(pid_t pid)
{
	int flags = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACEEXIT;
	/* First try with seccomp */
	if (ptrace(PTRACE_SETOPTIONS, pid, 0, (void*) (PTRACE_O_TRACESECCOMP | flags)) == -1) {
		/* No seccomp on the system, try without (this has to succeed) */
		sys_ptrace(PTRACE_SETOPTIONS, pid, 0, (void*) flags);
	}
}

void sys_ptrace_singlestep(pid_t pid)
{
	sys_ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
}

void sys_ptrace_singlestep_sig(pid_t pid, int sig)
{
	sys_ptrace(PTRACE_SINGLESTEP, pid, 0, (void*) sig);
}

void sys_ptrace_traceme()
{
	sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
}

void goto_next_event(struct task *t)
{

	if (t->child_sig != 0) {
		printf("sending signal: %d\n",t->child_sig);
	}
	sys_ptrace(PTRACE_SYSCALL, t->tid, 0, (void*) t->child_sig);
	sys_waitpid(t->tid, &t->status);

	t->child_sig = signal_pending(t->status);
	assert_exec(t, t->child_sig != SIGTRAP,
		    "Caught unexpected SIGTRAP while going to next event");

	t->event = read_child_orig_eax(t->tid);
}

long sys_ptrace_peektext_word(pid_t pid, void* addr)
{
	return sys_ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
}

pid_t sys_waitpid(pid_t pid, int *status)
{
	pid_t ret;

	if ((ret = waitpid(pid, status, __WALL)) < 0) {
		log_err("waiting for: %d -- bailing out", pid);
		sys_exit();
	}

	assert(ret == pid);
	return ret;
}

pid_t sys_waitpid_nonblock(pid_t pid, int* status)
{
	pid_t ret;

	if ((ret = waitpid(pid, status, __WALL | __WCLONE | WNOHANG | WSTOPPED )) < 0) {
		log_err("waiting for: %d -- bailing out",pid);
		sys_exit();
	}

	return ret;
}

/*
 * Returns the time difference t2 - t1 in microseconds.
 */
static inline long time_difference(struct timeval *t1, struct timeval *t2) {
	return (t2->tv_sec - t1->tv_sec) * 1000000 + (t2->tv_usec - t1->tv_usec);
}

void sys_fcntl(int fd, int cmd, long arg1)
{
	if (fcntl(fd, cmd, arg1) < 0) {
		fatal("fcntl(%d, %ld) failed", cmd, arg1);
	}
}

void* sys_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void* tmp = mmap(addr, length, prot, flags, fd, offset);
	if (tmp == MAP_FAILED) {
		log_err("cannot memory-map file");
		sys_exit();
	}
	return tmp;
}

void sys_munmap(void* addr, size_t length)
{
	if (munmap(addr, length) == -1) {
		log_err("cannot un-map file");
		sys_exit();
	}
}

void* sys_malloc(int size)
{
	void* tmp;
	errno = 0;
	if ((tmp = malloc(size)) == NULL) {
		log_err("sys_malloc: size is: %d\n",size);
		sys_exit();
	}
	assert(errno == 0);
	return tmp;
}

void* sys_memset(void * block, int c, size_t size)
{
	void* tmp;
	if ((tmp = memset(block,c,size)) == NULL) {
		log_err("malloc failed, size is: %d\n",size);
		sys_exit();
	}
	return tmp;
}

void* sys_malloc_zero(int size)
{
	void* tmp;
	if ((tmp = malloc(size)) == NULL) {
		log_err("failed to malloc memory of size %d -- bailing out",size);
		sys_exit();
	}
	bzero(tmp, size);
	return tmp;
}

void sys_free(void** ptr)
{
	free(*ptr);
	*ptr = NULL;
}

void sys_setpgid(pid_t pid, pid_t pgid)
{
	if (setpgid(pid, pgid) == -1) {
		log_err("error setting group id of child process");
	}
}

int sys_mkdir(const char *path, mode_t mode)
{
    struct stat st;
    int status = 0;

    if (stat(path, &st) != 0)
    {
        // Directory does not exist. EEXIST for race condition
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            status = -1;
    }
    else if (!S_ISDIR(st.st_mode))
    {
        errno = ENOTDIR;
        status = -1;
    }

    return(status);
}

/**
** sys_mkpath - ensure all directories in path exist
** Algorithm takes the pessimistic view and works top-down to ensure
** each directory in path exists, rather than optimistically creating
** the last element and working backwards.
*/
int sys_mkpath(const char *path, mode_t mode)
{
    char           *pp;
    char           *sp;
    int             status;
    char           *copypath = sys_malloc(strlen(path) + 1);

    strcpy(copypath,path);
    status = 0;
    pp = copypath;
    while (status == 0 && (sp = strchr(pp, '/')) != 0)
    {
        if (sp != pp)
        {
            /* Neither root nor double slash in path */
            *sp = '\0';
            status = sys_mkdir(copypath, mode);
            *sp = '/';
        }
        pp = sp + 1;
    }

    sys_free((void**)&copypath);
    assert(status == 0);
    return status;
}
