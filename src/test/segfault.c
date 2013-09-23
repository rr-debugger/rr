/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"


static void sighandler(int sig) {
	atomic_printf("caught signal %d, exiting\n", sig);
	_exit(0);
}

static void breakpoint() {
	int break_here = 1;
	(void)break_here;
}

int main(int argc, char *argv[]) {
	signal(SIGSEGV, sighandler);

	breakpoint();
	/* NO SYSCALLS BETWEEN HERE AND SEGFAULT BELOW: next event to
	 * replay must be the signal. */

	*((volatile int*)0) = 0;
	return 0;
}
