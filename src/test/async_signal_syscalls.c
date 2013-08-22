/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

static sig_atomic_t caught_usr1;

static void handle_usr1(int sig) {
	test_assert(SIGUSR1 == sig);
	caught_usr1 = 1;
	atomic_puts("caught usr1");
}

int main() {
	struct timespec ts;
	struct timeval tv;
	int i;

	signal(SIGUSR1, handle_usr1);

	/* XXX arbitrarily chosen to take ~3s on a fast machine */
	for (i = 0; i < 1 << 17; ++i) {
		/* The odds of the signal being caught in the library
		 * implementing these syscalls is very high.  But even
		 * if it's not caught there, this test will pass. */
		clock_gettime(CLOCK_MONOTONIC, &ts);
		gettimeofday(&tv, NULL);
		clock_gettime(CLOCK_MONOTONIC, &ts);
		gettimeofday(&tv, NULL);
		clock_gettime(CLOCK_MONOTONIC, &ts);
		gettimeofday(&tv, NULL);
		clock_gettime(CLOCK_MONOTONIC, &ts);
		gettimeofday(&tv, NULL);
	}

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
