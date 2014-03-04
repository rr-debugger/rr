/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static void* thread(void* unused) {
	sleep(-1);
	return NULL;
}

int main(int argc, char *argv[]) {
	pthread_t t;

	pthread_create(&t, NULL, thread, NULL);
	/* Don't join |t|. */

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
