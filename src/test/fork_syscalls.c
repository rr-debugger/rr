/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static void syscalls(int num) {
	struct timespec ts;
	struct timeval tv;
	int i;

	for (i = 0; i < num; ++i) {
		clock_gettime(CLOCK_MONOTONIC, &ts);
		gettimeofday(&tv, NULL);
	}
}

int main(void) {
	int child;

	syscalls(10);

	if (0 == (child = fork())) {
		syscalls(10);
		atomic_printf("CHILD-EXIT ");
		exit(0);
	}

	syscalls(10);

	waitpid(child, NULL, 0);

	atomic_puts("PARENT-EXIT");
	return 0;
}
