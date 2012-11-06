#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int stop = 0;

void catcher(int signum , siginfo_t *siginfo_ptr, void *ucontext_ptr) {
	stop = 1;
}

int main( int argc, char *argv[] )  {
    struct sigaction sact;
    int counter = 0;

    sigemptyset( &sact.sa_mask );
    sact.sa_flags = 0;
    sact.sa_sigaction = catcher;
    sigaction( SIGALRM, &sact, NULL );

    alarm(1);  /* timer will pop in 1 second */

    for( counter=0; counter >= 0 && !stop ; counter++ )
		if (counter % 100000 == 0)
			write(1,".",1);

    char buf[128];
    sprintf(buf, "\nSignal caught, Counter is %d\n", counter );
    write(1,buf,strlen(buf));

    return( 0 );
}
