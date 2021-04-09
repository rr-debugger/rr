#include "util.h"

static volatile int value = 0;

__attribute__((used)) static int get_value(void) { return value; }

__attribute__((noinline)) static void break_here(void) { __asm__(""); }

static void* thread_func(void* arg) {
  (void)arg;

  value = 1;
  break_here();

  return NULL;
}

int main(void) {
  pthread_t thread_info;
  pthread_create(&thread_info, NULL, &thread_func, NULL);
  pthread_join(thread_info, NULL);
  return 0;
}
