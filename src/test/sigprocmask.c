/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

static int signals_unblocked;

static void handle_usr1(int sig) {
	puts("Caught usr1");
	test_assert(signals_unblocked);
}

int main(int argc, char *argv[]) {
	sigset_t mask, oldmask;
	int i, dummy;

	signal(SIGUSR1, handle_usr1);

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	/* The libc function invokes rt_sigprocmask. */
	sigprocmask(SIG_BLOCK, &mask, &oldmask);

	raise(SIGUSR1);

	for (i = 0; i < 1 << 25; ++i) {
		dummy += (dummy + i) % 9735;
	}

	signals_unblocked = 1;
	syscall(SYS_sigprocmask, SIG_SETMASK, &oldmask, NULL);

	puts("EXIT-SUCCESS");
	return 0;
}
