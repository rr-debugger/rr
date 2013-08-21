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

static int sockfds[2];

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static void fin_intr_sleep(int secs) {
	struct timespec req = { .tv_sec = secs };
	struct timespec rem = { .tv_sec = -1, .tv_nsec = -1 };

	test_assert(0 == nanosleep(&req, &rem));
	/* We would normally assert that the outparam wasn't touched
	 * for this successful sleep, but ptrace-declined signals are
	 * an odd case, the only way a nanosleep can restart.  The
	 * kernel has been observed to write back the outparam at
	 * interrupt time, so we track that semantics here.
	 *
	 *  test_assert(-1 == rem.tv_sec && -1 == rem.tv_nsec);
	 */
}

static void fin_poll(int secs) {
	static int pipefds[2];
	struct pollfd pfd;

	pipe(pipefds);

	pfd.fd = pipefds[0];
	pfd.events = POLLIN;
	pfd.revents = -1;
	errno = 0;
	test_assert(0 == poll(&pfd, 1, 1000 * secs));
	test_assert(0 == pfd.revents);
}

static void cond_wait(int secs) {
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += secs;

	test_assert(ETIMEDOUT == pthread_cond_timedwait(&cond, &lock, &ts));
}

static void* reader_thread(void* dontcare) {
	char token = start_token;
	int readsock = sockfds[1];
	char c = sentinel_token;

	pthread_mutex_lock(&lock);

	pthread_barrier_wait(&barrier);

	puts("r: blocking on sleep, awaiting signal ...");
	fin_intr_sleep(1);

	puts("r: blocking on poll, awaiting signal ...");
	fin_poll(1);

	puts("r: blocking on futex, awaiting signal ...");
	cond_wait(1);

	puts("r: blocking on read, awaiting signal ...");
	test_assert(1 == read(readsock, &c, sizeof(c)));
	printf("r: ... read '%c'\n", c);
	test_assert(c == token);

	return NULL;
}

int main(int argc, char *argv[]) {
	char token = start_token;
	struct timeval ts;
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);

	/* (Kick on the syscallbuf if it's enabled.) */
	gettimeofday(&ts, NULL);

	socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds);

	pthread_barrier_init(&barrier, NULL, 2);
	pthread_create(&reader, NULL, reader_thread, NULL);

	pthread_barrier_wait(&barrier);

	puts("M: sleeping ...");
	usleep(500000);
	for (i = 0; i < 4; ++i) {
		puts("M: killing reader ...");
		pthread_kill(reader, SIGUSR1);
		puts("M: sleeping ...");
		sleep(1);
	}
	printf("M: finishing original reader by writing '%c' to socket ...\n",
		token);
	write(sockfds[0], &token, sizeof(token));
	++token;

	puts("M:   ... done");

	pthread_join(reader, NULL);

	puts("EXIT-SUCCESS");
	return 0;
}
