/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

#include <signal.h>
#include <sys/types.h>

static void* kill_thread(void* dontcare) {
	kill(getpid(), SIGTERM);
	atomic_puts("FAILED: kill() didn't work");
	return NULL;		/* not reached */
}

int main(int argc, char *argv[]) {
	pthread_t t;

	pthread_create(&t, NULL, kill_thread, NULL);
	pthread_join(t, NULL);
	atomic_puts("FAILED: joined thread that should have died");
	return 0;
}
