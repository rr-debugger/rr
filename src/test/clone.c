/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static int child(void* arg) {
	return 0;
}

int main(int argc, char *argv[]) {
	const size_t stack_size = 1 << 20;
	void* stack = mmap(NULL, stack_size,
			   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			   -1, 0);
	int pid = clone(child, stack + stack_size,
			CLONE_FS | CLONE_FILES | CLONE_UNTRACED,
			NULL, NULL, NULL);
	int status;
	int ret;

	atomic_printf("clone()d pid: %d\n", pid);
	test_assert(pid > 0);

	ret = waitpid(pid, &status, __WALL);
	test_assert(ret == pid);

	atomic_printf("child status: 0x%x\n", status);
	test_assert(status == 0);

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
