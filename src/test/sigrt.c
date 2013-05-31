/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

static void handle_sigrt(int sig) {
	printf("Caught signal %d\n", sig);
	fflush(stdout);
}

int main(int argc, char *argv[]) {
	int i;

	for (i = SIGRTMIN; i <= SIGRTMAX; ++i) {
		signal(i, handle_sigrt);
		raise(i);
	}

	return 0;
}
