/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <stdio.h>
#include <sys/shm.h>

#include "../share/sys.h"


#define SHMEM_MAXKEYS		10

static int shmem_keys[SHMEM_MAXKEYS][2];


/**
 * TODO: Replace this with a decent hasmap. It's a simple
 * list right now, since it will not have a noticeable impact
 * on performance.
 */
void shmem_store_key(int key, int val)
{
	int i;
	for (i = 0; i < SHMEM_MAXKEYS; i++) {
		if (shmem_keys[i][0] == 0) {
			shmem_keys[i][0] = key;
			shmem_keys[i][1] = val;
			return;
		}
	}

	/* too many keys */
	fprintf(stderr,"too many shared keys -- bailing out\n");
	sys_exit();
}

int shmem_get_key(int key)
{
	int i;
	for (i = 0; i < SHMEM_MAXKEYS; i++) {
		if (shmem_keys[i][0] == key) {
			return shmem_keys[i][1];
		}
	}

	/* too many keys */
	fprintf(stderr,"shmem key not found -- bailing out\n");
	sys_exit();

	return -1;
}
