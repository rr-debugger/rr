/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

static int num_signals_caught;

static void handle_sigrt(int sig) {
	printf("Caught signal %d\n", sig);
	fflush(stdout);

	++num_signals_caught;
}

int main(int argc, char *argv[]) {
	int i;

	for (i = SIGRTMIN; i <= SIGRTMAX; ++i) {
		signal(i, handle_sigrt);
		raise(i);
	}

	printf("caught %d signals; expected %d\n", num_signals_caught,
	       SIGRTMAX - SIGRTMIN);
	test_assert(1 + SIGRTMAX - SIGRTMIN == num_signals_caught);

	puts("EXIT-SUCCESS");
	return 0;
}
