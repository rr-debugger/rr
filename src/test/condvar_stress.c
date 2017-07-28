/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_THREADS 10
#define NUM_TRIALS 1000

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int last_written;
static int trial;
static int write_locked;
static int done;

static void* thread(void* idp) {
  int id = (intptr_t)idp;
  int num_loops = 0;
  int num_written = 0;

  while (1) {
    int this_write;

    ++num_loops;
    {
      pthread_mutex_lock(&lock);

      while (!done && (last_written == trial || write_locked)) {
        pthread_cond_wait(&cond, &lock);
      }
      if (done) {
        pthread_mutex_unlock(&lock);
        break;
      }

      write_locked = 1;
      this_write = trial;

      pthread_mutex_unlock(&lock);
    }

    atomic_printf("%d:%d(%d)\n", id, this_write, num_loops);
    ++num_written;

    {
      pthread_mutex_lock(&lock);

      last_written = this_write;
      write_locked = 0;
      pthread_cond_broadcast(&cond);

      pthread_mutex_unlock(&lock);
    }
  }

  atomic_printf("  (%d wrote %d)\n", id, num_written);

  pthread_exit((void*)(intptr_t)num_written);
}

int main(void) {
  pthread_t threads[NUM_THREADS];
  int i;
  int threads_num_written = 0;

  for (i = 0; i < NUM_THREADS; ++i) {
    test_assert(0 ==
                pthread_create(&threads[i], NULL, thread, (void*)(intptr_t)i));
  }

  for (i = 0; i < NUM_TRIALS; ++i) {
    {
      pthread_mutex_lock(&lock);

      test_assert(i == trial);
      test_assert(last_written == trial);
      ++trial;
      if (i % 2) {
        pthread_cond_signal(&cond);
      } else {
        pthread_cond_broadcast(&cond);
      }

      pthread_mutex_unlock(&lock);
    }

    {
      pthread_mutex_lock(&lock);

      while (last_written < trial) {
        pthread_cond_wait(&cond, &lock);
      }

      pthread_mutex_unlock(&lock);
    }
  }

  {
    pthread_mutex_lock(&lock);

    done = 1;
    pthread_cond_broadcast(&cond);

    pthread_mutex_unlock(&lock);
  }

  for (i = 0; i < NUM_THREADS; ++i) {
    void* ret = NULL;
    test_assert(0 == pthread_join(threads[i], &ret));
    threads_num_written += (intptr_t)ret;
  }

  atomic_printf(" ...  %d threads completed %d out of %d trials\n", NUM_THREADS,
                threads_num_written, NUM_TRIALS);
  test_assert(threads_num_written == NUM_TRIALS);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
