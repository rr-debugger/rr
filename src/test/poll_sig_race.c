/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

#define NUM_ITERATIONS 10

int main(int argc, char *argv[]) {
	int fds[2];
	struct pollfd pfd;
	int i;

	pipe2(fds, O_NONBLOCK);

	pfd.fd = fds[0];
	pfd.events = POLLIN;
	for (i = 0; i < NUM_ITERATIONS; ++i) {
		char c;

		atomic_printf("iteration %d\n", i);

		if (0 == fork()) {
			usleep(250000);
			write(fds[1], "x", 1);
			return 0;
		}

		test_assert(1 == poll(&pfd, 1, -1));
		test_assert(POLLIN & pfd.revents);
		test_assert(1 == read(pfd.fd, &c, 1));
	}

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
