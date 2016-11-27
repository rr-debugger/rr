/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static void* do_thread(__attribute__((unused)) void* p) { return NULL; }

int main(int argc, char** argv) {
  pthread_t thread;
  pid_t child;
  int status;

  if (argc > 1) {
    return 77;
  }

  pthread_create(&thread, NULL, do_thread, NULL);
  pthread_join(thread, NULL);

  child = fork();
  if (!child) {
    char* args[] = { argv[0], "dummy", NULL };
    execve(argv[0], args, environ);
    test_assert(0 && "exec failed");
  }
  test_assert(child == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  /* Test that checksumming doesn't care if we have a mmap
   * that is not backed by a sufficiently long file */
  size_t page_size = sysconf(_SC_PAGESIZE);
  char name[] = "/tmp/rr-checksum-XXXXXX";
  int fd = mkstemp(name);
  /* Have it extend a couple of bytes into the second page */
  test_assert(0 == ftruncate(fd, page_size + 200));
  void* map_addr =
      mmap(NULL, 4 * page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  test_assert(MAP_FAILED != map_addr);
  /* Make the second and third page PROT_NONE */
  test_assert(0 == mprotect(map_addr + page_size, 2 * page_size, PROT_NONE));
  /* Just some syscall to get some additional checksums in */
  (void)geteuid();
  test_assert(0 == unlink(name));

  /* The same again, but this time unmap the two pages in the middle */
  char name2[] = "/tmp/rr-checksum-XXXXXX";
  fd = mkstemp(name2);
  /* Have it extend a couple of bytes into the second page */
  test_assert(0 == ftruncate(fd, page_size + 200));
  map_addr =
      mmap(NULL, 4 * page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  test_assert(MAP_FAILED != map_addr);
  test_assert(0 == munmap(map_addr + page_size, 2 * page_size));
  test_assert(0 == unlink(name2));

  /* Now map two temporary files right next to each other to make sure they're
     not getting coralesced, causing trouble for the checksumming */
  char name3[] = "/tmp/rr-checksum-XXXXXX";
  fd = mkstemp(name3);
  char name4[] = "/tmp/rr-checksum-XXXXXX";
  int fd2 = mkstemp(name4);
  ftruncate(fd, page_size);
  ftruncate(fd2, page_size);

  // Alloc a 2 page region first, then overwrite it.
  map_addr =
      mmap(NULL, 2 * page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  test_assert(MAP_FAILED != map_addr);
  test_assert(MAP_FAILED != mmap(map_addr, page_size, PROT_NONE,
                                 MAP_PRIVATE | MAP_FIXED, fd, 0));
  test_assert(MAP_FAILED != mmap(map_addr + page_size, page_size, PROT_NONE,
                                 MAP_PRIVATE | MAP_FIXED, fd2, 0));
  (void)geteuid();
  test_assert(0 == unlink(name3));
  test_assert(0 == unlink(name4));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
