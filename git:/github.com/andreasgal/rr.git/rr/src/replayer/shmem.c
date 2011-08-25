#include <sys/shm.h>




#define SHMEM_MAXKEYS		10

static int shmem_keys[SHMEM_MAXKEYS][2];

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
	printf("too many shared keys -- bailing out\n");
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
	printf("shmem key not found -- bailing out\n");
	sys_exit();

	return -1;
}
