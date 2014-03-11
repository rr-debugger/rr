/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static void breakpoint(void) {
	int break_here = 1;
	(void)break_here;
}

static int child(void* arg) {
	sigset_t set;

	sigfillset(&set);
	/* NB: we have to naughtily make the linux assumption that
	 * sigprocmask is per-task, because we're not a real
	 * pthread. */
	test_assert(0 == syscall(SYS_rt_sigprocmask, SIG_UNBLOCK, &set, NULL,
				 _NSIG / 8));
	return 0;
}

int main(int argc, char *argv[]) {
	const size_t stack_size = 1 << 20;
	void* stack = mmap(NULL, stack_size,
			   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			   -1, 0);
	int pid;
	int status;
	int ret;
	sigset_t set;

	sys_gettid();
	/* NB: no syscalls in between the sys_gettid() above and this
	 * clone(). */
	breakpoint();
	pid = clone(child, stack + stack_size,
		    CLONE_FS | CLONE_FILES | CLONE_UNTRACED,
		    NULL, NULL, NULL, NULL);

	atomic_printf("clone()d pid: %d\n", pid);
	test_assert(pid > 0);

	ret = waitpid(pid, &status, __WALL);
	test_assert(ret == pid);

	atomic_printf("child status: 0x%x\n", status);
	test_assert(status == 0);

	sys_gettid();

	sigfillset(&set);
	test_assert(0 == sigprocmask(SIG_BLOCK, &set, NULL));

	/* NB: no syscalls in between the sys_gettid() above and this
	 * clone(). */
	breakpoint();
	pid = clone(child, stack + stack_size,
		    CLONE_SIGHAND /*must also have CLONE_VM*/,
		    NULL, NULL, NULL);

	atomic_printf("clone(CLONE_SIGHAND)'d pid: %d\n", pid);
	test_assert(-1 == pid);

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
