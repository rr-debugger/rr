/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define SHM_NAME "/my_shared_memory"
#define SHM_SIZE 4096

static void breakpoint(void) {}

int main(void) {
  // Create shared memory
  int shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
  if (shm_fd == -1) {
    perror("shm_open");
    return 1;
  }
  ftruncate(shm_fd, SHM_SIZE);

  // Map shared memory
  const char* ptr =
      (char*)mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
  if (ptr == MAP_FAILED) {
    perror("mmap");
    return 1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return 1;
  }

  const char* parent_msg = "hello parent";
  const char* child_msg = "hello child\0";
  if (pid == 0) {
    sleep(1);
    memcpy((void*)ptr, parent_msg, strlen(parent_msg));
    return 1;
  } else {
    wait(NULL);
    memcpy((void*)(ptr + strlen(parent_msg)), child_msg, strlen(child_msg));
    breakpoint();
  }

  // Cleanup
  munmap((void*)ptr, SHM_SIZE);
  shm_unlink(SHM_NAME);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}