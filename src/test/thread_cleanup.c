/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static void* thread(void* unused) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return NULL;
}

int main(int argc, char *argv[]) {
	int i;

	/* Chosen so that |3MB * nthreads| exhausts a 32-bit address
	 * space. */
	for (i = 0; i < 1500; ++i) {
		pthread_t t;
		pthread_create(&t, NULL, thread, NULL);
		pthread_join(t, NULL);
	}

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
