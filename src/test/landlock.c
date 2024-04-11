/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define LANDLOCK_RULE_PATH_BENEATH 1

#define LANDLOCK_ACCESS_FS_READ_DIR 8

struct landlock_ruleset_attr {
  uint64_t handled_access_fs;
};

struct landlock_path_beneath_attr {
  uint64_t allowed_access;
  int32_t parent_fd;
} __attribute__((packed));

int main(void) {
  struct landlock_ruleset_attr ruleset = { LANDLOCK_ACCESS_FS_READ_DIR };
  int ruleset_fd = syscall(RR_landlock_create_ruleset,
    &ruleset, sizeof(struct landlock_ruleset_attr),
    0);
  if (ruleset_fd < 0 && errno == ENOSYS) {
    atomic_puts("landlock not supported, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ruleset_fd >= 0);

  int root_fd = open("/", O_PATH);
  test_assert(root_fd >= 0);

  struct landlock_path_beneath_attr rule =
    { LANDLOCK_ACCESS_FS_READ_DIR, root_fd };
  int ret = syscall(RR_landlock_add_rule, ruleset_fd,
    LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
  test_assert(ret == 0);

  ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  test_assert(ret == 0);

  ret = syscall(RR_landlock_restrict_self, ruleset_fd, 0);
  test_assert(ret == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
