/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <pthread.h>
#include <unistd.h>

pthread_barrier_t bar;

static void* thread(void* unused) {
	pthread_barrier_wait(&bar);

	sleep(-1);
	return NULL;
}

int main(int argc, char *argv[]) {
	pthread_t t;

	pthread_barrier_init(&bar, NULL, 2);

	pthread_create(&t, NULL, thread, NULL);

	pthread_barrier_wait(&bar);

	_exit(0);
	return 0;		/* not reached */
}
