/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

typedef void* (* SyscallbufPtr)(void);

static SyscallbufPtr syscallbuf_ptr;

static void* syscallbuf;

void* do_thread(__attribute__((unused)) void* p) {
  struct timeval tv;
  /* (Kick on the syscallbuf lib.) */
  gettimeofday(&tv, NULL);
  syscallbuf = syscallbuf_ptr();
  return NULL;
}

int main(void) {
  int i;
  syscallbuf_ptr = (SyscallbufPtr)dlsym(RTLD_DEFAULT, "syscallbuf_ptr");
  if (!syscallbuf_ptr) {
    atomic_puts("Syscallbuf not enabled");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  for (i = 0; i < 100; ++i) {
    pthread_t thread;
    volatile char* p;
    pthread_create(&thread, NULL, do_thread, NULL);
    /* Try to make this mmap() happen between the thread calling exit()
       and actually exiting */
    p = (volatile char*)mmap(syscallbuf, 1, PROT_READ | PROT_WRITE,
                             MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    test_assert(p != MAP_FAILED);
    pthread_join(thread, NULL);
    *p = 1;
    munmap((char*)p, 1);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
