/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int sockfds[2];

void* reader_thread(void* dontcare) {
	char token = '!';
	int readsock = sockfds[1];
	struct timeval ts;
	char c = '\0';

	gettimeofday(&ts, NULL);

	puts("r: acquiring mutex ...");
	pthread_mutex_lock(&lock);
	puts("r:   ... releasing mutex");
	pthread_mutex_unlock(&lock);

	puts("r: reading socket ...");
	gettimeofday(&ts, NULL);
	test_assert(1 == read(readsock, &c, sizeof(c)));
	printf("r:   ... read '%c'\n", c);
	test_assert(c == token);
	++token;

	puts("r: recv'ing socket ...");
	gettimeofday(&ts, NULL);
	test_assert(1 == recv(readsock, &c, sizeof(c), 0));
	printf("r:   ... recv'd '%c'\n", c);
	test_assert(c == token);
	++token;
	{
		struct pollfd pfd;

		puts("r: polling socket ...");
		pfd.fd = readsock;
		pfd.events = POLLIN;
		gettimeofday(&ts, NULL);
		poll(&pfd, 1, -1);
		puts("r:   ... done, doing nonblocking read ...");
		test_assert(1 == read(readsock, &c, sizeof(c)));
		printf("r:   ... read '%c'\n", c);
		test_assert(c == token);
		++token;
	}
	{
		int epfd;
		struct epoll_event ev;

		puts("r: epolling socket ...");
		test_assert(0 <= (epfd = epoll_create(1/*num events*/)));
		ev.events = EPOLLIN;
		ev.data.fd = readsock;
		gettimeofday(&ts, NULL);
		test_assert(0 == epoll_ctl(epfd, EPOLL_CTL_ADD, ev.data.fd,
					   &ev));
		test_assert(1 == epoll_wait(epfd, &ev, 1, -1));
		puts("r:   ... done, doing nonblocking read ...");
		test_assert(readsock == ev.data.fd);
		test_assert(1 == read(readsock, &c, sizeof(c)));
		printf("r:   ... read '%c'\n", c);
		test_assert(c == token);
		++token;

		close(epfd);
	}
	/* Make the main thread wait on our join() */
	puts("r: sleeping ...");
	usleep(500000);

	return NULL;
}

int main(int argc, char *argv[]) {
	char token = '!';
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

	/* Force a wait on read() */
	puts("M: sleeping again ...");
	usleep(500000);
	printf("M: writing '%c' to socket ...\n", token);
	write(sockfds[0], &token, sizeof(token));
	++token;
	puts("M:   ... done");

	/* Force a wait on recv() */
	puts("M: sleeping again ...");
	usleep(500000);
	printf("M: sending '%c' to socket ...\n", token);
	send(sockfds[0], &token, sizeof(token), 0);
	++token;
	puts("M:   ... done");

	/* Force a wait on poll() */
	puts("M: sleeping again ...");
	usleep(500000);
	printf("M: writing '%c' to socket ...\n", token);
	write(sockfds[0], &token, sizeof(token));
	++token;
	puts("M:   ... done");

	/* Force a wait on epoll_wait() */
	puts("M: sleeping again ...");
	usleep(500000);
	printf("M: writing '%c' to socket ...\n", token);
	write(sockfds[0], &token, sizeof(token));
	++token;
	puts("M:   ... done");

	pthread_join(reader, NULL);

	puts("EXIT-SUCCESS");
	return 0;
}
