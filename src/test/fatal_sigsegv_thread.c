#include "util.h"

static void *run_thread(__attribute__((unused)) void* p) {
    crash_null_deref();
    return NULL;
}

static void* no_nothing_thread(__attribute__((unused)) void* p) {
  while (1) {
    sched_yield();
  }
  return NULL;
}

#define NUSELESS 10

int main(__attribute__((unused)) int argc,
         __attribute__((unused)) const char** argv) {

    pid_t child;
    if ((child = fork()) == 0) {
        pthread_t thread;
        pthread_t useless_threads[NUSELESS];
        for (int i = 0; i < NUSELESS; ++i) {
            pthread_create(&useless_threads[i], NULL, no_nothing_thread, NULL);
        }

        pthread_create(&thread, NULL, run_thread, NULL);
        pthread_join(thread, NULL);
        test_assert(0 && "Should not reach here");
    }

    int status;
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);

    atomic_puts("EXIT-SUCCESS");
    return 0;
}

