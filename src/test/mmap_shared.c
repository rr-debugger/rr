/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

static int create_segment(size_t num_bytes) {
	char filename[] = "/dev/shm/rr-test-XXXXXX";
	int fd = mkstemp(filename);
	unlink(filename);
	test_assert(fd >= 0);
	ftruncate(fd, num_bytes);
	return fd;
}

int main(int argc, char *argv[]) {
	size_t num_bytes = sysconf(_SC_PAGESIZE);
	int fd = create_segment(num_bytes);
	int* wpage = mmap(NULL, num_bytes, PROT_WRITE, MAP_SHARED, fd, 0);
	int* rpage = mmap(NULL, num_bytes, PROT_READ, MAP_SHARED, fd, 0);
	int i;

	test_assert(wpage != (void*)-1 && rpage != (void*)-1
		    && rpage != wpage);

	for (i = 0; i < num_bytes / sizeof(int); ++i) {
		wpage[i] = i;
		test_assert(rpage[i] == i);
		printf("%d,", rpage[i]);
	}

	puts(" done");

	return 0;
}
