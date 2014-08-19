/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static void* start_thread(void* p)
{
	sleep(1000);
	return NULL;
}

int main(int argc, char** argv) {
	pthread_t thread;

	pthread_create(&thread, NULL, start_thread, NULL);
	atomic_puts("EXIT-SUCCESS");
	while (1) {
	}
	return 0;
}
