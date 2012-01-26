#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <asm/ptrace-abi.h>
#include <sys/wait.h>

#include "sys.h"
#include "util.h"
#include "ipc.h"
#include "../recorder/rec_sched.h"

FILE* sys_fopen(const char* path, const char* mode)
{
	FILE* file = fopen(path, mode);

	if (file == NULL) {
		printf("error while opening file: %s -- bailing out!\n", path);
		perror("");
		exit(0);
	}

	return file;
}

void sys_fclose(FILE* file)
{
	if (fclose(file) < 0) {
		perror("error while closing file -- bailing out\n");
		sys_exit();
	}
}

void sys_close(int fd)
{
	if (close(fd) < 0) {
		perror("error while closing file -- bailing out\n");
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
		perror("error reading child memory:open-- bailing out\n");
		sys_exit();
	}

	return fd;
}

pid_t sys_fork()
{
	pid_t pid = fork();

	if (pid == -1) {
		perror("error forking process\n");
		exit(-1);
	}

	return pid;
}

void sys_kill(int pid, int msg)
{
	int ret;
	if ((ret = kill(pid, msg)) < 0) {
		perror("error sending signal\n");
	}
}

void sys_exit()
{
	printf("exiting\n");
	rec_sched_exit_all();
	exit(-1);
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
		perror("Recorder: error setting personaity\n");
		sys_exit();
	}
	if ((orig_pers = personality(orig_pers | ADDR_NO_RANDOMIZE)) == -1) {
		perror("Recorder: error setting personaity\n");
		sys_exit();
	}
	if (prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0) == -1) {
		perror("error setting up prctl -- bailing out\n");
		sys_exit();
	}

	unsigned long mask = 0x4;
	if (sched_setaffinity(0, sizeof(mask), (cpu_set_t*) &mask) == -1) {
		perror("error setting affinity -- bailing out\n");
		sys_exit();
	}
}

void sys_start_trace(char* executable, char** argv, char** envp)
{
	sys_setup_process();
	sys_ptrace_traceme();
	/* signal the parent that the child is ready */
	kill(getpid(), SIGSTOP);
	/* we need to fork another child since we must fake the tid in the replay */
	printf("executable %s\n", executable);
	if (fork() == 0) {
		/* start client application */
		execve(executable, argv, envp);
		/* we should never arriver here */
		assert(1);
	}

	exit(0);
}

/* ptrace stuff comes here */
long sys_ptrace(int request, pid_t pid, void *addr, void *data)
{
	long ret;
	if ((ret = ptrace(request, pid, addr, data)) == -1) {
		perror("");
		printf("ptrace_error: request: %d of tid: %d: addr %p, data %p\n", request, pid, addr, data);
		sys_exit();
	}
	return ret;
}

void sys_ptrace_syscall(pid_t pid)
{
	sys_ptrace(PTRACE_SYSCALL, pid, 0, 0);
}

/**
 * Detaches the child process from monitoring. This method must only be
 * invoked, if the thread exits. We do not check errors here, since the
 * thread could have already exited.
 */
void sys_ptrace_detatch(pid_t pid)
{
	sys_ptrace(PTRACE_DETACH, pid, 0, 0);
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


void sys_ptrace_sysemu_singlestep(pid_t pid, int sig)
{
	sys_ptrace(PTRACE_SYSEMU_SINGLESTEP, pid, 0, (void*)sig);
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
	sys_ptrace(PTRACE_SETOPTIONS, pid, 0,
			(void*) (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACEEXIT));
}

void sys_ptrace_singlestep(pid_t pid, int sig)
{
	sys_ptrace(PTRACE_SINGLESTEP, pid, 0, (void*) sig);
}

void sys_ptrace_traceme()
{
	sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
}

void sys_ptrace_cont(pid_t pid)
{
	sys_ptrace(PTRACE_CONT, pid, 0, 0);
}

void goto_next_event(struct context *ctx)
{

	if (ctx->child_sig != 0) {
		printf("sending signal: %d\n",ctx->child_sig);
	}
	sys_ptrace(PTRACE_SYSCALL, ctx->child_tid, 0, (void*) ctx->child_sig);
	sys_waitpid(ctx->child_tid, &ctx->status);

	ctx->child_sig = signal_pending(ctx->status);
	ctx->event = read_child_orig_eax(ctx->child_tid);
}



long sys_ptrace_peektext_word(pid_t pid, void* addr)
{
	return sys_ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
}

pid_t sys_waitpid(pid_t pid, int *status)
{
	pid_t ret;

	if ((ret = waitpid(pid, status, __WALL | __WCLONE)) < 0) {
		perror("");
		printf("waiting for: %d -- bailing out\n", pid);
		sys_exit();
	}

	assert(ret == pid);
	return ret;
}

pid_t sys_waitpid_nonblock(pid_t pid, int* status)
{
	pid_t ret;

	if ((ret = waitpid(pid, status, __WALL | __WCLONE | WNOHANG | WSTOPPED)) < 0) {
		perror("");
		printf("waiting for: %d -- bailing out\n", pid);
		exit(-1);
	}

	return ret;
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
		fprintf(stderr, "cannot memory-map file\n");
		sys_exit();
	}
	return tmp;
}

void* sys_malloc(int size)
{
	void* tmp;
	if ((tmp = malloc(size)) == NULL) {
		perror("sys_malloc: ");
		printf("size is: %d\n",size);
		sys_exit();
	}
	bzero(tmp,size);
	return tmp;
}

void* sys_malloc_zero(int size)
{
	void* tmp;
	if ((tmp = malloc(size)) == NULL) {
		perror("");
		sys_exit();
	}
	bzero(tmp, size);
	return tmp;
}

void sys_free(void** ptr)
{
	if (*ptr == NULL) {
		fprintf(stderr, "Failed to free memory of size -- bailing out\n");
		sys_exit();
	}
	free(*ptr);
	*ptr = 0;
}

void sys_setpgid(pid_t pid, pid_t pgid)
{
	if (setpgid(pid, pgid) == -1) {
		perror("error setting group id of child process");
	}
}

