/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>

int main() {
	printf("Current process priority: %d\n", getpriority(PRIO_PROCESS, 0));
	return 0;
}
