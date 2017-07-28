/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  gid_t groups[1024];
  int num_groups = getgroups(ALEN(groups), groups);
  int i;

  atomic_printf("User %d belongs to %d groups:\n  ", geteuid(), num_groups);
  for (i = 0; i < num_groups; ++i) {
    atomic_printf("%d,", groups[i]);
  }
  atomic_puts("");

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
