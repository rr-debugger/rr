/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static int low_priority_thread_scheduled;

static void* low_priority_thread(void* p)
{
  setpriority(PRIO_PROCESS, 0, 4);
  pthread_mutex_lock(&mutex);
  low_priority_thread_scheduled = 1;
  return NULL;
}

int main(void)
{
  pthread_t thread;

  pthread_mutex_lock(&mutex);
  pthread_create(&thread, NULL, low_priority_thread, NULL);
  pthread_mutex_unlock(&mutex);

  sched_yield();

  test_assert(low_priority_thread_scheduled);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
