/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static void hit_barrier(void) {
  int break_here = 1;
  (void)break_here;
}

static void joined_threads(void) {
  int break_here = 1;
  (void)break_here;
}

static void set_thread_name(int id) {
  char name_buf[16];
  snprintf(name_buf, sizeof(name_buf), "BP-THREAD-%d", id);
  prctl(PR_SET_NAME, name_buf);
}

struct thread_data {
  int threadno;
  pthread_barrier_t* bar;
};

static void* thread(void* datap) {
  struct thread_data* data = datap;
  pthread_barrier_t* bar = data->bar;

  set_thread_name(data->threadno);

  atomic_printf("thread %d launched with data %p\n", data->threadno, data);
  breakpoint();
  pthread_barrier_wait(bar);
  pthread_barrier_wait(bar);

  atomic_printf("thread %d done\n", data->threadno);
  free(data);
  return NULL;
}

int main(void) {
  struct timeval tv;
  pthread_barrier_t bar;
  pthread_t threads[10];
  size_t i;

  /* (Kick on the syscallbuf lib.) */
  gettimeofday(&tv, NULL);

  pthread_barrier_init(&bar, NULL, 1 + ALEN(threads));

  set_thread_name(1);

  for (i = 0; i < ALEN(threads); ++i) {
    struct thread_data* data = calloc(1, sizeof(*data));
    data->threadno = i + 2;
    data->bar = &bar;
    pthread_create(&threads[i], NULL, thread, data);
  }

  pthread_barrier_wait(&bar);

  hit_barrier();

  pthread_barrier_wait(&bar);
  atomic_puts("main done");

  for (i = 0; i < ALEN(threads); ++i) {
    pthread_join(threads[i], NULL);
  }

  joined_threads();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
