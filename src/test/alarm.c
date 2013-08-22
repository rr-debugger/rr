/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

#include <errno.h>
#include <signal.h>
#include <string.h>

int stop = 0;

void catcher(int signum , siginfo_t *siginfo_ptr, void *ucontext_ptr) {
	stop = 1;
}

int main(int argc, char **argv) {
    struct sigaction sact;
    int counter = 0;

    sigemptyset(&sact.sa_mask);
    sact.sa_flags = 0;
    sact.sa_sigaction = catcher;
    sigaction(SIGALRM, &sact, NULL);

    alarm(1);  /* timer will pop in 1 second */

    for (counter=0; counter >= 0 && !stop; counter++)
	    if (counter % 100000 == 0)
		    write(STDOUT_FILENO, ".", 1);

    atomic_printf("\nSignal caught, Counter is %d\n", counter );

    return 0;
}
