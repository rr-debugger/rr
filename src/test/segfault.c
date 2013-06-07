/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static void sighandler(int sig) {
	printf("caught signal %d, exiting\n", sig);
	_exit(0);
}

static void breakpoint() {
	int break_here = 1;
}

int main(int argc, char *argv[]) {
	signal(SIGSEGV, sighandler);

	breakpoint();
	/* NO SYSCALLS BETWEEN HERE AND SEGFAULT BELOW: next event to
	 * replay must be the signal. */

	*((volatile int*)0) = 0;
	return 0;
}
