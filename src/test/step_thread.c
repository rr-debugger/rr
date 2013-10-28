/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"


pthread_barrier_t bar;

/* NB: these must *not* be macros so that debugger step-next works as
 * expected per the program source. */
void A(void) {
	atomic_puts("entered A");
	pthread_barrier_wait(&bar);
	pthread_barrier_wait(&bar);
}
void B(void) {
	atomic_puts("entered B");
	pthread_barrier_wait(&bar);
	pthread_barrier_wait(&bar);
}

void* threadA(void* unused) {
	A();
	return NULL;
}
void* threadB(void* unused) {
	B();
	return NULL;
}

void C(void) {
	atomic_puts("entered C");
	pthread_barrier_wait(&bar);
}

void hit_barrier(void) {
	atomic_puts("hit barrier");
}

int main(void) {
	pthread_t a, b;

	pthread_barrier_init(&bar, NULL, 3);

	pthread_create(&a, NULL, threadA, NULL);
	pthread_create(&b, NULL, threadB, NULL);

	C();
	hit_barrier();

	pthread_barrier_wait(&bar);

	pthread_join(a, NULL);
	pthread_join(b, NULL);

	return 0;
}
