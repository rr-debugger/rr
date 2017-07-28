/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  static const char token_file[] = "rr-link-file.txt";
  static const char link_name[] = "rr-link-file.link";

  test_assert(0 == symlink(token_file, link_name));
  test_assert(0 == unlink(link_name));
  test_assert(0 == symlinkat(token_file, AT_FDCWD, link_name));
  test_assert(0 == unlink(link_name));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
