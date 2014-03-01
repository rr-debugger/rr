/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

int main(int argc, char *argv[]) {
	ssize_t pagesize = sysconf(_SC_PAGESIZE);
	ssize_t two_pages_size = 2 * pagesize;
	void* two_pages = mmap(NULL, two_pages_size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	void* two_pages_end = two_pages + two_pages_size;
	char* cwd;
	char *expected_cwd;

	test_assert(argc == 2);
	expected_cwd = argv[1];

	test_assert(two_pages != (void*)-1);
	/* Make the value returned into |path| overlap two physical
	 * pages. */
	cwd = two_pages + pagesize - 3;
	test_assert(cwd == getcwd(cwd, two_pages_end - (void*)cwd));
	atomic_printf("current working directory is %s; should be %s\n",
		      cwd, expected_cwd);
	test_assert(!strcmp(cwd, expected_cwd));

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
