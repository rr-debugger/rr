#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int counter = 0;

void catcher( int sig ) {
	 fflush(stdout);
    printf( "Signal caught, Counter is %d\n", counter );
    exit(1);
}

int main( int argc, char *argv[] )  {
    struct sigaction sact;

    sigemptyset( &sact.sa_mask );
    sact.sa_flags = 0;
    sact.sa_handler = catcher;
    sigaction( SIGALRM, &sact, NULL );

    alarm(1);  /* timer will pop in 1 second */

    for( counter=0; 1 ; counter++ )
		printf(".");

    return( 0 );
}
