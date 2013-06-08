/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <pthread.h>

#define ALEN(_a) (sizeof(_a) / sizeof(_a[0]))

static void breakpoint() {
	int break_here = 1;
}

static void hit_barrier() {
	int break_here = 1;
}

static void* thread(void* barp) {
	pthread_barrier_t* bar = barp;

	puts("thread launched");
	breakpoint();
	pthread_barrier_wait(bar);
	pthread_barrier_wait(bar);
	puts("thread done");
	return NULL;
}

int main(int argc, char *argv[]) {
	pthread_barrier_t bar;
	pthread_t threads[10];
	int i;

	pthread_barrier_init(&bar, NULL, 1 + ALEN(threads));

	for (i = 0; i < ALEN(threads); ++i) {
		pthread_create(&threads[i], NULL, thread, &bar);
	}

	pthread_barrier_wait(&bar);

	hit_barrier();

	pthread_barrier_wait(&bar);
	puts("main done");

	for (i = 0; i < ALEN(threads); ++i) {
		pthread_join(threads[i], NULL);
	}

	return 0;
}
