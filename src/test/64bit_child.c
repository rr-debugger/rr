/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

int main(int argc, char *argv[]) {
	/* Fork-and-exec 'echo'.
	   The exec may fail if 'bash' is 64-bit and rr doesn't support
	   64-bit processes. That's fine; the test should still pass. We're
	   testing that rr doesn't abort.
	 */
	FILE* f = popen("echo -n", "r");
	while (1) {
		int ch = fgetc(f);
		if (ch < 0) {
			break;
		}
		putchar(ch);
	}
	atomic_puts("EXIT-SUCCESS");
	return 0;
}
