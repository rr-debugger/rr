#include <stdint.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <unistd.h>

static volatile uint32_t futex_val;

static void* do_thread(__attribute__((unused)) void* p) {
  if (futex_val == 0) {
    syscall(SYS_futex, &futex_val, FUTEX_WAIT, 0, NULL);
  }
  futex_val = 0;
  syscall(SYS_futex, &futex_val, FUTEX_WAKE, 0, NULL);
  pause();
  return NULL;
}

int main(void) {
  for (int i = 0; i < 5000; ++i) {
    pthread_t th;
    pthread_create(&th, NULL, do_thread, NULL);
    futex_val = 1;
    syscall(SYS_futex, &futex_val, FUTEX_WAKE, 1);
    syscall(SYS_futex, &futex_val, FUTEX_WAIT, 1, NULL);
  }
  return 0;
}
