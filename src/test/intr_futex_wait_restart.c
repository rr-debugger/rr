/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

static const char start_token = '!';
static const char sentinel_token = ' ';

static pthread_t reader;
static pthread_barrier_t barrier;
static pid_t reader_tid;
static int reader_caught_signal;

static int sockfds[2];

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static pid_t sys_gettid() {
	return syscall(SYS_gettid);
}

static void cond_wait(int secs) {
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += secs;

	test_assert(ETIMEDOUT == pthread_cond_timedwait(&cond, &lock, &ts));
}

#define PRINT(_msg) write(STDOUT_FILENO, _msg, sizeof(_msg) - 1)

static void sighandler(int sig) {
	test_assert(sys_gettid() == reader_tid);
	++reader_caught_signal;

	PRINT("r: in sighandler level 1 ...\n");
	cond_wait(1);
	PRINT("r: ... wait done\n");
}

#undef PRINT

static void* reader_thread(void* dontcare) {
	char token = start_token;
	struct sigaction act;
	int readsock = sockfds[1];
	char c = sentinel_token;
	int flags = 0;

	pthread_mutex_lock(&lock);

	reader_tid = sys_gettid();

	flags = SA_RESTART;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sighandler;
	act.sa_flags = flags;
	sigaction(SIGUSR1, &act, NULL);

	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_IGN;
	act.sa_flags = flags;
	sigaction(SIGUSR2, &act, NULL);

	pthread_barrier_wait(&barrier);

	puts("r: blocking on read, awaiting signal ...");

	test_assert(1 == read(readsock, &c, sizeof(c)));
	test_assert(1 == reader_caught_signal);

	printf("r: ... read level 0 '%c'\n", c);
	test_assert(c == token);

	return NULL;
}

int main(int argc, char *argv[]) {
	char token = start_token;
	struct timeval ts;

	setvbuf(stdout, NULL, _IONBF, 0);

	/* (Kick on the syscallbuf if it's enabled.) */
	gettimeofday(&ts, NULL);

	socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds);

	pthread_barrier_init(&barrier, NULL, 2);
	pthread_create(&reader, NULL, reader_thread, NULL);

	pthread_barrier_wait(&barrier);

	/* Force a blocked read() that's interrupted by a SIGUSR1,
	 * which then itself blocks on read() and succeeds. */
	puts("M: sleeping ...");
	usleep(500000);

	puts("M: killing reader ...");
	pthread_kill(reader, SIGUSR1);
	puts("M:   (quick nap)");
	usleep(100000);

	puts("M: killing reader again ...");
	pthread_kill(reader, SIGUSR2);

	usleep(500000);
	printf("M: finishing level 0 reader by writing '%c' to socket ...\n",
		token);
	write(sockfds[0], &token, sizeof(token));
	++token;

	puts("M:   ... done");

	pthread_join(reader, NULL);

	puts("EXIT-SUCCESS");
	return 0;
}
