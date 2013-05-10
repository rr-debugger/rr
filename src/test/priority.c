/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>

int main() {
	int prio;
	prio = getpriority(PRIO_PROCESS, 0);
	printf("Current process priority: %d\n", prio);
	if (prio < 19) {
		/* If it's less than 19, we can decrease the
		 * priority. */
		++prio;
	}
	setpriority(PRIO_PROCESS, 0, prio);
	printf("Now priority is: %d\n", getpriority(PRIO_PROCESS, 0));
	return 0;
}
