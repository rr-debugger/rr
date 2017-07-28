/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_PACKETS 1000
#define BUF_SIZE 1000

static int fds[2];

static void* do_thread(__attribute__((unused)) void* p) {
  int i;
  char buf[BUF_SIZE];
  for (i = 0; i < NUM_PACKETS; ++i) {
    test_assert(BUF_SIZE == recv(fds[0], buf, sizeof(buf), 0));
  }
  return NULL;
}

int main(void) {
  int i;
  char buf[BUF_SIZE];
  pthread_t thread;

  test_assert(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

  pthread_create(&thread, NULL, do_thread, NULL);

  memset(buf, 'x', BUF_SIZE);
  for (i = 0; i < NUM_PACKETS; ++i) {
    test_assert(BUF_SIZE == send(fds[1], buf, BUF_SIZE, 0));
  }

  pthread_join(thread, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
