/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <stdio.h>

#define NUM_ITERATIONS (1 << 30)

void halfway_done() {
	int break_here = 0;
}

int spin() {
	int i, dummy = 0;

	puts("spinning");
	/* NO SYSCALLS AFTER HERE: the point of this test is to hit
	 * hpc interrupts to exercise the nonvoluntary interrupt
	 * scheduler. */
	for (i = 1; i < NUM_ITERATIONS; ++i) {
		dummy += i % (1 << 20);
		dummy += i % (79 * (1 << 20));
		if (i == NUM_ITERATIONS / 2) {
			halfway_done();
		}
	}
	return dummy;
}

int main(int argc, char *argv[]) {
	setvbuf(stdout, NULL, _IONBF, 0);

	printf("done: dummy=%d\n", spin());
	return 0;
}
