/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

int main(int argc, char** argv) {
	int num_syscalls;
	const char* exe_image;
	int child;
	int i;

	test_assert(argc == 3);
	num_syscalls = atoi(argv[1]);
	exe_image = argv[2];

	atomic_printf("%d: running %d syscalls ...\n", getpid(), num_syscalls);
	for (i = 0; i < num_syscalls; ++i) {
		sys_gettid();
	}

	atomic_printf("%d: forking and exec'ing %s...\n", getpid(), exe_image);
	if (0 == (child = fork())) {
		execl(exe_image, exe_image, NULL);
		test_assert("Not reached; execl() failed.");
	}

	atomic_printf("child %d\n", child);

	waitpid(child, NULL, 0);

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
