/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define BUF_SIZE 65536
#define EXTRA 10

static const char file_name[] = "tmp.bin";

/**
 * For benchmarking purposes you can run this with "write" parameter to
 * just generate a (much larger) file and "read" parameter to read it. The
 * normal test uses a much smaller file size.
 */
int main(int argc, char** argv) {
  char buf[BUF_SIZE];
  char buf2[BUF_SIZE];
  int i;
  int fd;
  int buf_count = argc < 2 ? 500 : 20000;

  memset(buf, 1, sizeof(buf));

  if (argc < 2 || !strcmp(argv[1], "write")) {
    fd = open(file_name, O_WRONLY | O_CREAT | O_EXCL, 0600);
    test_assert(fd >= 0);
    for (i = 0; i < buf_count; ++i) {
      test_assert(write(fd, buf, BUF_SIZE) == BUF_SIZE);
    }
    test_assert(write(fd, buf, EXTRA) == EXTRA);
  }

  if (argc < 2 || !strcmp(argv[1], "read")) {
    fd = open(file_name, O_RDONLY);
    test_assert(fd >= 0);
    for (i = 0; i < buf_count; ++i) {
      test_assert(read(fd, buf2, sizeof(buf2)) == sizeof(buf2));
      test_assert(!memcmp(buf, buf2, sizeof(buf)));
    }
    test_assert(read(fd, buf2, sizeof(buf2)) == EXTRA);
    test_assert(read(fd, buf2, sizeof(buf2)) == 0);
  }

  if (argc < 2) {
    fd = open(file_name, O_WRONLY);
    test_assert(fd >= 0);
    memset(buf, 2, sizeof(buf));
    test_assert(write(fd, buf, sizeof(buf)) == sizeof(buf));
    test_assert(0 == close(fd));

    test_assert(0 == unlink(file_name));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
