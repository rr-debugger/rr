/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

static void breakpoint() {
	int break_here = 1;
}

int main(int argc, char *argv[]) {
	breakpoint();
	/* NO SYSCALLS BETWEEN HERE AND SEGFAULT BELOW: next event to
	 * replay must be the signal. */

	*((volatile int*)0) = 0;
	return 0;
}
