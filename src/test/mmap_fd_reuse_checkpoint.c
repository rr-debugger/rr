/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int fd;

void do_checkpoint(void) {}

static void* le_thread(__attribute__((unused)) void* p) {
  do_checkpoint();
  close(fd);
  return NULL;
}

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  const char kFileName[] = "file";

  fd = open(kFileName, O_CREAT | O_EXCL | O_RDWR, 0600);
  assert(fd >= 0);

  int old = fd;

  char* wpage = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  assert(wpage != MAP_FAILED);

  pthread_t thread;
  pthread_create(&thread, NULL, le_thread, wpage);
  pthread_join(thread, NULL);

  fd = open(kFileName, O_EXCL | O_RDWR, 0600);
  assert(fd == old && "test expects fd reuse");

  munmap(wpage, 0);
  unlink(kFileName);
}
