/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* sendfile() and splice() into a file change what its MAP_SHARED
   mappings read. Each case prints the bytes it reads through the mapping,
   so a replay that reads other bytes produces other output. */

#define FILE_PAGES 2
#define MAP_PAGES 3

static const char data[] = "XYZ";
static size_t page_size;

enum Way {
  /* glibc's sendfile(), which is sendfile64 on x86-32 */
  SENDFILE,
  /* The sendfile syscall itself, with a NULL offset */
  SENDFILE_SYSCALL,
  SPLICE_AT_OFFSET,
  SPLICE_AT_POSITION,
  WAY_COUNT
};

static const char* const way_names[WAY_COUNT] = {
  "sendfile", "sendfile syscall", "splice at offset", "splice at position"
};

/* Writes `data`, without its NUL, at `offset` in `fd`. */
static void send_data(int fd, enum Way way, off_t offset) {
  ssize_t len = sizeof(data) - 1;
  off_t src_offset = 0;
  loff_t off;
  int src_fd;
  int pipe_fds[2];

  switch (way) {
    case SENDFILE:
    case SENDFILE_SYSCALL:
      src_fd = open("temp2", O_CREAT | O_EXCL | O_RDWR, 0600);
      test_assert(src_fd >= 0);
      test_assert(len == write(src_fd, data, len));
      /* sendfile() writes at the output's file position. */
      test_assert(offset == lseek(fd, offset, SEEK_SET));
      if (way == SENDFILE) {
        test_assert(len == sendfile(fd, src_fd, &src_offset, len));
        test_assert(src_offset == len);
      } else {
        test_assert(0 == lseek(src_fd, 0, SEEK_SET));
        test_assert(len == syscall(RR_sendfile, fd, src_fd, NULL, len));
      }
      test_assert(offset + len == lseek(fd, 0, SEEK_CUR));
      test_assert(0 == close(src_fd));
      test_assert(0 == unlink("temp2"));
      break;
    case SPLICE_AT_OFFSET:
    case SPLICE_AT_POSITION:
      test_assert(0 == pipe(pipe_fds));
      test_assert(len == write(pipe_fds[1], data, len));
      if (way == SPLICE_AT_OFFSET) {
        test_assert(0 == lseek(fd, 0, SEEK_SET));
        off = offset;
        test_assert(len == splice(pipe_fds[0], NULL, fd, &off, len, 0));
        test_assert(off == offset + len);
        test_assert(0 == lseek(fd, 0, SEEK_CUR));
      } else {
        test_assert(offset == lseek(fd, offset, SEEK_SET));
        test_assert(len == splice(pipe_fds[0], NULL, fd, NULL, len, 0));
        test_assert(offset + len == lseek(fd, 0, SEEK_CUR));
      }
      test_assert(0 == close(pipe_fds[0]));
      test_assert(0 == close(pipe_fds[1]));
      break;
    default:
      test_assert(0);
  }
}

/* Prints the `len` bytes at `offset` in the mapping `p`, NULs as '_', and
   checks them against `expected`. */
static void check_bytes(const char* name, const char* where, const char* p,
                        size_t offset, const char* expected, size_t len) {
  char buf[16];
  size_t i;

  test_assert(len < sizeof(buf));
  for (i = 0; i < len; ++i) {
    char c = __atomic_load_n(p + offset + i, __ATOMIC_SEQ_CST);
    buf[i] = c ? c : '_';
  }
  buf[len] = 0;
  atomic_printf("%s, %s: %s\n", name, where, buf);
  test_assert(!memcmp(buf, expected, len));
}

static void test_way(enum Way way, int in_child) {
  char name[64];
  char* fill;
  char* p;
  pid_t child;
  int status;
  int fd = open("temp", O_CREAT | O_EXCL | O_RDWR, 0600);

  test_assert(fd >= 0);
  fill = malloc(FILE_PAGES * page_size);
  test_assert(fill != NULL);
  memset(fill, '.', FILE_PAGES * page_size);
  test_assert((ssize_t)(FILE_PAGES * page_size) ==
              write(fd, fill, FILE_PAGES * page_size));
  free(fill);

  p = mmap(NULL, MAP_PAGES * page_size, PROT_READ, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);

  if (in_child) {
    /* Write from a process that doesn't map the file. */
    child = fork();
    test_assert(child >= 0);
    if (!child) {
      test_assert(0 == munmap(p, MAP_PAGES * page_size));
      send_data(fd, way, page_size - 1);
      send_data(fd, way, FILE_PAGES * page_size);
      exit(77);
    }
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  } else {
    /* Across the boundary between the first two pages, and at the end of
       the file, which grows into the last page of the mapping. */
    send_data(fd, way, page_size - 1);
    send_data(fd, way, FILE_PAGES * page_size);
  }

  sprintf(name, "%s%s", way_names[way], in_child ? " in child" : "");
  check_bytes(name, "page boundary", p, page_size - 2, ".XYZ.", 5);
  check_bytes(name, "end of file", p, FILE_PAGES * page_size - 1, ".XYZ_",
              5);

  test_assert(0 == munmap(p, MAP_PAGES * page_size));
  test_assert(0 == close(fd));
  test_assert(0 == unlink("temp"));
}

int main(void) {
  int way;

  page_size = sysconf(_SC_PAGESIZE);

  for (way = 0; way < WAY_COUNT; ++way) {
    test_way(way, 0);
    test_way(way, 1);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
