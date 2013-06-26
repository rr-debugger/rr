/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

int main() {
	struct timespec ts;
	struct timeval tv;
	int i;

	clock_getres(CLOCK_MONOTONIC, &ts);
	printf("Clock resolution is >= %g us\n", ((double) ts.tv_nsec) / 1.0e3);

	memset(&ts, 0, sizeof(ts));
	memset(&tv, 0, sizeof(tv));

	for (i = 0; i < 100; ++i) {
		struct timespec ts_now;
		struct timeval tv_now;

		clock_gettime(CLOCK_MONOTONIC, &ts_now);
		test_assert(ts.tv_sec < ts_now.tv_sec
			    || (ts.tv_sec == ts_now.tv_sec
				&& ts.tv_nsec <= ts_now.tv_nsec));
		ts = ts_now;

		/* technically gettimeofday() isn't monotonic, but the
		 * value of this check is higher than the remote
		 * possibility of a spurious failure */
		gettimeofday(&tv_now, NULL);
		test_assert(tv.tv_sec < tv_now.tv_sec
			    || (tv.tv_sec == tv_now.tv_sec
				&& tv.tv_usec <= tv_now.tv_usec));
		tv = tv_now;

		printf("cg: %g %llu, gtod: %g %llu\n",
		       (double) ts.tv_sec, (long long int) ts.tv_nsec,
		       (double) tv.tv_sec, (long long int) tv.tv_usec);
	}

	puts("EXIT-SUCCESS");
	return 0;
}
