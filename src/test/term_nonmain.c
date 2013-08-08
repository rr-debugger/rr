/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

static void* kill_thread(void* dontcare) {
	kill(getpid(), SIGTERM);
	puts("FAILED: kill() didn't work");
	return NULL;		/* not reached */
}

int main(int argc, char *argv[]) {
	pthread_t t;

	setvbuf(stdout, NULL, _IONBF, 0);

	pthread_create(&t, NULL, kill_thread, NULL);
	pthread_join(t, NULL);
	puts("FAILED: joined thread that should have died");
	return 0;
}
