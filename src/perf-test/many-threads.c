#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

static int main_to_child_fds[2];
static int child_to_main_fds[2];

static void* do_thread(__attribute__((unused)) void* p) {
  pause();
  return NULL;
}

static void* do_thread2(__attribute__((unused)) void* p) {
  for (int i = 0; i < 20000; ++i) {
    char ch;
    read(main_to_child_fds[0], &ch, 1);
    write(child_to_main_fds[1], "y", 1);
  }
  return NULL;
}

int main(void) {
  pipe(main_to_child_fds);
  pipe(child_to_main_fds);
  for (int i = 0; i < 5000; ++i) {
    pthread_t th;
    pthread_create(&th, NULL, do_thread, NULL);
  }
  puts("Created ballast threads");
  pthread_t th;
  pthread_create(&th, NULL, do_thread2, NULL);
  for (int i = 0; i < 20000; ++i) {
    char ch;
    write(main_to_child_fds[1], "x", 1);
    read(child_to_main_fds[0], &ch, 1);
  }
  return 0;
}
