/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int stop = 0;

static const char file_name[] = "blahblah.xyz";

static void* opener(__attribute__((unused)) void* p) {
  while (!stop) {
    int fd = open(file_name, O_RDONLY);
    test_assert(fd >= 0);
    close(fd);
  }
  return NULL;
}

static void* do_thread(__attribute__((unused)) void* p) {
  return NULL;
}

int main(void) {
  pthread_t opener_thread;
  int i;
  int fd = open(file_name, O_RDWR | O_CREAT, 0700);
  test_assert(fd >= 0);

  pthread_create(&opener_thread, NULL, opener, NULL);

  for (i = 0; i < 1000; ++i) {
    pthread_t dummy_thread;
    pthread_create(&dummy_thread, NULL, do_thread, NULL);
    pthread_join(dummy_thread, NULL);
  }

  stop = 1;
  pthread_join(opener_thread, NULL);

  unlink(file_name);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
