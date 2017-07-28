/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_ITERATIONS 10
#define NUM_PROCS_PER_ITERATION 10
#define MAGIC_EXIT_CODE 42

static int sockfds[2];

const ssize_t num_sockbuf_bytes = 1 << 20;

static void child_proc(void) { exit(MAGIC_EXIT_CODE); }

static void* writer_thread(__attribute__((unused)) void* dontcare) {
  char token = '!';
  int sock = sockfds[1];
  int i;

  for (i = 0; i < NUM_ITERATIONS; ++i) {
    /* Force a wait on read() */
    atomic_printf("w: iteration %d: sleeping ...\n", i);
    usleep(500000);
    atomic_printf("w: writing '%c' to socket ...\n", token);
    write(sock, &token, sizeof(token));
    ++token;
    atomic_puts("w:   ... done");
  }
  atomic_puts("w:   ... done");
  return NULL;
}

int main(void) {
  char token = '!';
  char c = '\0';
  pthread_t t;
  int sock;
  int i;

  socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds);
  sock = sockfds[0];

  pthread_create(&t, NULL, writer_thread, NULL);

  for (i = 0; i < NUM_ITERATIONS; ++i) {
    pid_t procs[NUM_PROCS_PER_ITERATION];
    int j;

    atomic_printf("M: iteration %d: forking processes before read ...\n", i);
    for (j = 0; j < NUM_PROCS_PER_ITERATION; ++j) {
      if (0 == (procs[j] = fork())) {
        child_proc();
        test_assert("Not reached" && 0);
      }
    }

    atomic_printf("M: sleeping for a bit ...");
    usleep(10000);

    atomic_printf("M: reading socket ...\n");
    test_assert(1 == read(sock, &c, sizeof(c)));
    atomic_printf("M:   ... read '%c'\n", c);
    test_assert(c == token);
    ++token;

    for (j = 0; j < NUM_PROCS_PER_ITERATION; ++j) {
      int status;
      int child = procs[j];
      int pid = waitpid(child, &status, 0);
      int err = errno;
      atomic_printf("M:  waitpid(%d) returns %d(%s) and status %#x\n", child,
                    pid, strerror(err), status);
      test_assert(child == pid);
      test_assert(WIFEXITED(status) && MAGIC_EXIT_CODE == WEXITSTATUS(status));
    }
  }
  atomic_printf("M: ... done\n");

  pthread_join(t, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
