/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

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

int sys_open_child_mem(Task* t)
{
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path) - 1, "/proc/%d/mem", t->tid);
	fd = open(path, O_RDWR);
	assert_exec(t, fd >= 0, "Failed to open %s", path);

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
static void set_up_process(void)
{
	int orig_pers;

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

void sys_start_trace(const char* executable, char** argv, char** envp)
{
	set_up_process();
	sys_ptrace_traceme();

	/* signal the parent that the child is ready */
	kill(getpid(), SIGSTOP);

	execvpe(executable, argv, envp);
	fatal("Failed to exec %s", executable);
}

/* ptrace stuff comes here */
void sys_ptrace(Task* t, int request, void *addr, void *data)
{
	pid_t tid = t->tid;
	long ret = ptrace(__ptrace_request(request), tid, addr, data);
	assert_exec(t, 0 == ret,
		    "ptrace_error: request: %d of tid: %d: addr %p, data %p",
		    request, tid, addr, data);
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

unsigned long sys_ptrace_getmsg(Task* t)
{
	unsigned long tmp;
	sys_ptrace(t, PTRACE_GETEVENTMSG, 0, &tmp);
	return tmp;
}
void sys_ptrace_getsiginfo(Task* t, siginfo_t* sig)
{
	sys_ptrace(t, PTRACE_GETSIGINFO, 0, sig);
}

void sys_ptrace_setup(Task* t)
{
	int flags = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACEEXIT;
	if (ptrace(PTRACE_SETOPTIONS, t->tid, 0, (void*) (PTRACE_O_TRACESECCOMP | flags)) == -1) {
		/* No seccomp on the system, try without (this has to succeed) */
		sys_ptrace(t, PTRACE_SETOPTIONS, 0, (void*) flags);
	}
}

void sys_ptrace_traceme()
{
	ptrace(PTRACE_TRACEME, 0, 0, 0);
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

int sys_mkdir(const char *path, mode_t mode)
{
    struct stat st;
    int status = 0;

    if (stat(path, &st) != 0) {
        // Directory does not exist. EEXIST for race condition
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            status = -1;
    } else if (!S_ISDIR(st.st_mode)) {
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
    char           *copypath = (char*)malloc(strlen(path) + 1);

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

    free(copypath);
    assert(status == 0);
    return status;
}
