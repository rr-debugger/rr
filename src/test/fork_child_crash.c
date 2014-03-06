/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static void breakpoint(void) {
	int break_here = 1;
	(void)break_here;
}

int main(int argc, char *argv[]) {
	pid_t child = fork();
	int status;

	if (0 == child) {
		atomic_puts("child: crashing ...");

		breakpoint();

		*(volatile int*)NULL = 0;
		exit(0);	/* not reached */
	}

	test_assert(child == waitpid(child, &status, 0));
	atomic_printf("parent: child %d exited with %#x\n", child, status);
	test_assert(WIFSIGNALED(status) && SIGSEGV == WTERMSIG(status));

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
