/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

static void syscalls(int num) {
	struct timespec ts;
	struct timeval tv;
	int i;

	for (i = 0; i < num; ++i) {
		clock_gettime(CLOCK_MONOTONIC, &ts);
		gettimeofday(&tv, NULL);
	}
}

int main() {
	syscalls(10);

	if (0 == fork()) {
		syscalls(10);
		puts("child done");
		exit(0);
	}

	syscalls(10);

	puts("EXIT-SUCCESS");
	return 0;
}
