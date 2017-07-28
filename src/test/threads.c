/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

long int counter = 0;
pthread_barrier_t bar;

void catcher(__attribute__((unused)) int sig) {
  atomic_printf("Signal caught, Counter is %ld\n", counter);
  atomic_puts("EXIT-SUCCESS");
  _exit(0);
}

void* receiver(__attribute__((unused)) void* name) {
  struct sigaction sact;

  sigemptyset(&sact.sa_mask);
  sact.sa_flags = 0;
  sact.sa_handler = catcher;
  sigaction(SIGALRM, &sact, NULL);
  pthread_barrier_wait(&bar);

  while (1) {
    counter++;
    if (counter % 100000 == 0) {
      write(1, ".", 1);
    }
  }
  return NULL;
}

void* sender(void* id) {
  sleep(1);
  pthread_barrier_wait(&bar);
  pthread_kill(*((pthread_t*)id), SIGALRM);
  return NULL;
}

int main(void) {
  struct timeval tv;
  pthread_t thread1, thread2;

  /* (Kick on the syscallbuf lib.) */
  gettimeofday(&tv, NULL);

  /* init barrier */
  pthread_barrier_init(&bar, NULL, 2);
  /* Create independent threads each of which will execute
   * function */
  pthread_create(&thread1, NULL, receiver, NULL);
  pthread_create(&thread2, NULL, sender, &thread1);

  /* Wait till threads are complete before main
   * continues. Unless we wait we run the risk of executing an
   * exit which will terminate the process and all threads
   * before the threads have completed. */
  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);
  return 0;
}
