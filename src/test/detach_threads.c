/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "util_internal.h"

#define NUM_THREADS 20

static pid_t my_gettid(void) {
	pid_t pid = syscall(SYS_gettid);
	test_assert(pid > 0);
	return pid;
}

static void* run_thread(__attribute__((unused)) void* p) {
	pid_t tid = my_gettid();
	for (int i = 0; i < 10000; ++i) {
		test_assert(tid == my_gettid());
		if (i % 500 == 0) {
			sched_yield();
		}
	}
  return NULL;
}

static pid_t my_tid;

int main(__attribute__((unused)) int argc,
         __attribute__((unused)) const char** argv) {
	if (fork() == 0) {
		pthread_t threads[NUM_THREADS];
		// Make sure this is patched before the detach
		my_tid = my_gettid();

		if (running_under_rr()) {
			rr_detach_teleport();
			test_assert(my_gettid() != my_tid);
		}

		for (int i = 0; i < NUM_THREADS; ++i) {
			pthread_create(&threads[i], NULL, run_thread, NULL);
		}
		for (int i = 0; i < NUM_THREADS; ++i) {
			pthread_join(threads[i], NULL);
		}
		return 0;
	}

  int status;
  wait(&status);
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
