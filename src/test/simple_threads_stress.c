#include "util.h"

static void* do_thread(__attribute__((unused)) void* p) { return 0; }

int main(void) {
  int i;
  pthread_t thread[100];
  for (i = 0; i < 100; ++i) {
    pthread_create(&thread[i], NULL, do_thread, NULL);
  }
  for (i = 0; i < 100; ++i) {
    pthread_join(thread[i], NULL);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
