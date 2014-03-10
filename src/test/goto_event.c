/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static void bad_breakpoint(void) {
	int break_here = 1;
	(void)break_here;
}

static void good_breakpoint(void) {
	int break_here = 1;
	(void)break_here;
}

static void child(int num_syscalls) {
	int i;

	bad_breakpoint();

	/* NB: this test assumes that gettid() produces at least one
	 * trace event per syscall. */
	atomic_printf("%d: running %d syscalls ...\n", getpid(), num_syscalls);
	for (i = 0; i < num_syscalls; ++i) {
		(void)sys_gettid();
	}

	good_breakpoint();

	exit(0);
}

int main(int argc, char** argv) {
	int num_syscalls;
	pid_t c;
	int status;

	test_assert(argc == 2);
	num_syscalls = atoi(argv[1]);

	if (0 == (c = fork())) {
		child(num_syscalls);
		test_assert("Not reached" && 0);
	}

	atomic_printf("%d: waiting on %d ...\n", getpid(), c);
	test_assert(c == waitpid(c, &status, 0));
	test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
