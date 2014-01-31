/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

int main(void) {
	cpu_set_t cpus;

	CPU_ZERO(&cpus);
	CPU_SET(0, &cpus);
	sched_setaffinity(0, sizeof(cpus), &cpus);

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
