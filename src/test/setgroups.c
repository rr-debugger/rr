/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <grp.h>

int main(void) {
  gid_t old_groups[1024];
  gid_t new_groups[1024];
  int i;
  int ret;
  int num_groups = getgroups(ALEN(old_groups), old_groups);
  test_assert(num_groups >= 0);

  /* make sure we have some new groups for setgroups() */
  for (i = 0; i < num_groups; ++i) {
    new_groups[i] = old_groups[i] + 1;
  }
  if (num_groups == 0) {
    new_groups[0] = getegid();
    num_groups = 1;
  }
  ret = setgroups(num_groups, new_groups);
  if (ret == -1) {
    test_assert(errno == EPERM);
    atomic_puts("Test did nothing because process does not have CAP_SETGID?");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  } else {
    test_assert(getgroups(ALEN(old_groups), old_groups) == num_groups);
    for (i = 0; i < num_groups; ++i) {
      test_assert(new_groups[i] == old_groups[i]);
    }
  }
  atomic_puts("EXIT-SUCCESS");

  return 0;
}
