/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

int main(int argc, char *argv[]) {
	size_t page_size = sysconf(_SC_PAGESIZE);
	byte* pages = mmap(NULL, 7 * page_size,
			   PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	test_assert(pages != (void*)-1);

	/* Unmap first page. */
	munmap(pages, page_size);
	/* Unmap third page. */
	munmap(pages + 2 * page_size, page_size);
	/* Unmap fifth page. */
	munmap(pages + 4 * page_size, page_size);

#if 0
	{
		char cmd[4096];
		snprintf(cmd, sizeof(cmd) - 1, "cat /proc/%d/maps", getpid());
		system(cmd);
	}
#endif

	/* Unmap first 6 page locations, leave 7th. */
	munmap(pages, 6 * page_size);

	atomic_puts(" done");

	return 0;
}
