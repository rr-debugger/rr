/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#define _GNU_SOURCE

#include "sys.h"

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <asm/ptrace-abi.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sched.h>

#include "dbg.h"
#include "ipc.h"
#include "../recorder/rec_sched.h"
#include "../replayer/replayer.h" /* for emergency_debug() */
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

void sys_fstat(int filedes, struct stat * stat_buf)
{
	if (fstat(filedes,stat_buf) < 0) {
		log_err("error while fstating file (fd = %d) -- bailing out\n",filedes);
		sys_exit();
	}
}

void sys_stat(char * pathname, struct stat * stat_buf)
{
	if (stat(pathname,stat_buf) < 0) {
		log_err("error while stating file -- bailing out\n");
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

int sys_open_child_mem(pid_t child_tid)
{
	char path[64];
	bzero(path, 64);
	int fd;

	sprintf(path, "/proc/%d/mem", child_tid);
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

void sys_sched_setaffinity(unsigned long mask)
{
	if (sched_setaffinity(0, sizeof(mask), (cpu_set_t*) &mask) == -1) {
		log_err("error setting affinity -- bailing out");
		sys_exit();
	}
}

/**
 * This function configures the process for recording/replay. In particular:
 * (1) address space randomization is disabled
 * (2) rdtsc is disabled
 */
void sys_setup_process()
{
	/* disable address space randomization */
	int orig_pers;
	if ((orig_pers = personality(0xffffffff)) == -1) {
		fatal("error getting personaity");
	}
	if (-1 == personality(orig_pers | ADDR_NO_RANDOMIZE)) {
		fatal("error disabling randomization");
	}
	if (prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0) == -1) {
		fatal("error setting up prctl -- bailing out");
	}

	/* Pin the child to a specific logical core as we serialize the execution anyway */
	sys_sched_setaffinity(CHILD_LOGICAL_CORE_AFFINITY_MASK);
}

void sys_start_trace(char* executable, char** argv, char** envp)
{

	sys_setup_process();
	sys_ptrace_traceme();

	/* signal the parent that the child is ready */
	kill(getpid(), SIGSTOP);

	execve(executable, argv, envp);
	fatal("Failed to exec %s", executable);
}

/* ptrace stuff comes here */
long sys_ptrace(int request, pid_t pid, void *addr, void *data)
{
	long ret;
	if ((ret = ptrace(request, pid, addr, data)) == -1) {
		log_err("ptrace_error: request: %d of tid: %d: addr %p, data %p", request, pid, addr, data);
		sys_exit();
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
	sys_ptrace(PTRACE_SYSCALL, pid, 0, (void*) sig);
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

void goto_next_event(struct context *ctx)
{

	if (ctx->child_sig != 0) {
		printf("sending signal: %d\n",ctx->child_sig);
	}
	sys_ptrace(PTRACE_SYSCALL, ctx->child_tid, 0, (void*) ctx->child_sig);
	sys_waitpid(ctx->child_tid, &ctx->status);

	ctx->child_sig = signal_pending(ctx->status);
	if (ctx->child_sig == SIGTRAP) {
		log_err("Caught unexpected SIGTRAP while going to next event");
		emergency_debug(ctx);
	}
	ctx->event = read_child_orig_eax(ctx->child_tid);
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

void sys_fcntl(int fd, int option, pid_t pid)
{
	if (fcntl(fd, option, pid) < 0) {
		perror("error when calling fcntl\n");
		exit(-1);
	}
}
void sys_fcntl_f_setown(int fd, pid_t pid)
{
	sys_fcntl(fd, F_SETOWN, pid);
}

void sys_fcntl_f_setfl_o_async(int fd)
{
	sys_fcntl(fd, F_SETFL, O_ASYNC);
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
