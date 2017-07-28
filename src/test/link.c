/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  static const char token_file[] = "rr-link-file.txt";
  static const char link_name[] = "rr-link-file.link";
  int fd = open(token_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
  test_assert(fd >= 0);
  test_assert(0 == close(fd));

  test_assert(0 == link(token_file, link_name));
  test_assert(0 == unlink(token_file));
  test_assert(0 == linkat(AT_FDCWD, link_name, AT_FDCWD, token_file, 0));
  test_assert(0 == unlink(token_file));
  test_assert(0 == unlink(link_name));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
