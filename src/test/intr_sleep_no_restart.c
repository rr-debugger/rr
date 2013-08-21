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

static pthread_t reader;
static pthread_barrier_t barrier;
static pid_t reader_tid;
static int reader_caught_signal;

static pid_t sys_gettid() {
	return syscall(SYS_gettid);
}

static void intr_sleep(int secs) {
	struct timespec req = { .tv_sec = secs };
	struct timespec rem = { 0 };

	test_assert(-1 == nanosleep(&req, &rem) && EINTR == errno);
	test_assert(rem.tv_sec > 0 || rem.tv_nsec > 0);
}

static void fin_sleep(int secs) {
	struct timespec req = { .tv_sec = secs };
	struct timespec rem = { .tv_sec = -1, .tv_nsec = -1 };

	test_assert(0 == nanosleep(&req, &rem));
	test_assert(-1 == rem.tv_sec && -1 == rem.tv_nsec);
}

#define PRINT(_msg) write(STDOUT_FILENO, _msg, sizeof(_msg) - 1)

static void sighandler(int sig) {
	test_assert(sys_gettid() == reader_tid);
	++reader_caught_signal;

	PRINT("r: in sighandler level 1 ...\n");
	intr_sleep(1);
}

static void sighandler2(int sig) {
	test_assert(sys_gettid() == reader_tid);
	++reader_caught_signal;

	PRINT("r: in sighandler level 2 ...\n");
	fin_sleep(1);
}

#undef PRINT

static void* reader_thread(void* dontcare) {
	struct sigaction act;
	int flags = 0;

	reader_tid = sys_gettid();

	memset(&act, 0, sizeof(act));
	act.sa_handler = sighandler;
	act.sa_flags = flags;
	sigaction(SIGUSR1, &act, NULL);

	memset(&act, 0, sizeof(act));
	act.sa_handler = sighandler2;
	act.sa_flags = flags;
	sigaction(SIGUSR2, &act, NULL);

	pthread_barrier_wait(&barrier);

	puts("r: blocking on sleep, awaiting signal ...");
	intr_sleep(1);

	return NULL;
}

int main(int argc, char *argv[]) {
	struct timeval ts;

	setvbuf(stdout, NULL, _IONBF, 0);

	/* (Kick on the syscallbuf if it's enabled.) */
	gettimeofday(&ts, NULL);

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

	puts("M:   ... done");

	pthread_join(reader, NULL);

	puts("EXIT-SUCCESS");
	return 0;
}
