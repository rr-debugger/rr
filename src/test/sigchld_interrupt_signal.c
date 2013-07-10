/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

int main(int argc, char *argv[]) {
	pid_t c;
	int dummy, i;
	int status;

	puts("forking child");

	if (0 == (c = fork())) {
		usleep(10000);
		puts("child exiting");
		exit(0);
	}

	/* NO SYSCALLS AFTER HERE!  (Up to the test_asserts.) */
	for (i = 1; i < (1 << 28); ++i) {
		dummy += (dummy + i) % 9735;
	}

	test_assert(c == waitpid(c, &status, 0));
	test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

	puts("EXIT-SUCCESS");
	return 0;
}
