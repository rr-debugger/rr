/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <signal.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
	int dummy, i;

	/* NB: since we're masking out the signal, there's no way for
	 * us to tell whether or not it was actually delivered.  This
	 * test can spuriously pass if it's never sent SIGUSR1. */

	signal(SIGUSR1, SIG_IGN);
	for (i = 1; i < (1 << 27); ++i) {
		dummy += (dummy + i) % 9735;
	}

	puts("EXIT-SUCCESS");
	return 0;
}
