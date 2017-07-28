/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  DIR* dir = opendir(".");
  struct dirent* ent;

  test_assert(dir != NULL);

  while ((ent = readdir(dir)) != NULL) {
    test_assert(ent->d_reclen >= 8);
    atomic_printf("%s %lld %lld\n", ent->d_name, (long long)ent->d_ino,
                  (long long)ent->d_off);
  }

  test_assert(0 == closedir(dir));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
