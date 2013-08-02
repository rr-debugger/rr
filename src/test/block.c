/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

const char token = '?';

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
int sockfds[2];

void* reader_thread(void* dontcare) {
	struct timeval ts;
	struct pollfd pfd;
	char c;

	gettimeofday(&ts, NULL);

	puts("r: acquiring mutex ...");
	pthread_mutex_lock(&lock);
	puts("r:   ... releasing mutex");
	pthread_mutex_unlock(&lock);

	puts("r: polling socket ...");
	pfd.fd = sockfds[1];
	pfd.events = POLLIN;
	poll(&pfd, 1, -1);
	puts("r:   ... done, doing nonblocking read ...");
	test_assert(1 == read(sockfds[1], &c, sizeof(c)));
	printf("r:   ... read '%c'\n", c);
	test_assert(c == token);

	puts("r: reading socket ...");
	test_assert(1 == read(sockfds[1], &c, sizeof(c)));
	printf("r:   ... read '%c'\n", c);
	test_assert(c == token);

	puts("r: recv'ing socket ...");
	test_assert(1 == recv(sockfds[1], &c, sizeof(c), 0));
	printf("r:   ... recv'd '%c'\n", c);
	test_assert(c == token);

	/* Make the main thread wait on our join() */
	puts("r: sleeping ...");
	usleep(500000);

	return NULL;
}

int main(int argc, char *argv[]) {
	struct timeval ts;
	pthread_t reader;

	setvbuf(stdout, NULL, _IONBF, 0);

	gettimeofday(&ts, NULL);

	socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds);

	pthread_mutex_lock(&lock);

	pthread_create(&reader, NULL, reader_thread, NULL);

	/* Make the reader thread wait on its pthread_mutex_lock() */
	puts("M: sleeping ...");
	usleep(500000);
	puts("M: unlocking mutex ...");
	pthread_mutex_unlock(&lock);
	puts("M:   ... done");

	/* Force a wait on poll() */
	puts("M: sleeping again ...");
	usleep(500000);
	printf("M: writing '%c' to socket ...\n", token);
	write(sockfds[0], &token, sizeof(token));
	puts("M:   ... done");

	/* Force a wait on read() */
	puts("M: sleeping again ...");
	usleep(500000);
	printf("M: writing '%c' to socket ...\n", token);
	write(sockfds[0], &token, sizeof(token));
	puts("M:   ... done");

	/* Force a wait on recv() */
	puts("M: sleeping again ...");
	usleep(500000);
	printf("M: sending '%c' to socket ...\n", token);
	send(sockfds[0], &token, sizeof(token), 0);
	puts("M:   ... done");

	pthread_join(reader, NULL);

	puts("EXIT-SUCCESS");
	return 0;
}
