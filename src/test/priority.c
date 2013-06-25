/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>

int main() {
	int prio1, prio2;

	prio1 = getpriority(PRIO_PROCESS, 0);
	printf("Current process priority: %d\n", prio1);
	if (prio1 < 19) {
		/* If it's less than 19, we can decrease the
		 * priority. */
		++prio1;
	}

	setpriority(PRIO_PROCESS, 0, prio1);

	prio2 = getpriority(PRIO_PROCESS, 0);
	assert(prio1 == prio2);
	printf("Now priority is: %d\n", prio2);
	puts("EXIT-SUCCESS");
	return 0;
}
