/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define DUMMY_FILENAME "foo.txt"

static gid_t get_gid(int fd) {
  struct stat* st;
  gid_t result;

  ALLOCATE_GUARD(st, 'x');
  test_assert(0 == fstat(fd, st));
  result = st->st_gid;
  FREE_GUARD(st);
  return result;
}

static void change_group(const char* path, gid_t new_gid) {
  test_assert(0 == chown(path, geteuid(), new_gid));
}

static void change_group_fd(int fd, gid_t new_gid) {
  test_assert(0 == fchown(fd, geteuid(), new_gid));
}

static void change_group_at(const char* path, gid_t new_gid) {
  test_assert(0 == fchownat(AT_FDCWD, path, geteuid(), new_gid, 0));
}

int main(void) {
  gid_t groups[32];
  int ngroups;
  gid_t this_group, other_group;
  int fd;

  this_group = getegid();
  atomic_printf("Current group is %d\n", this_group);

  ngroups = getgroups(ALEN(groups), groups);
  test_assert(ngroups > 0);

  other_group = groups[0];
  if (this_group == other_group && ngroups > 1) {
    other_group = groups[1];
  }
  if (this_group == other_group) {
    atomic_puts("WARNING: unable to properly test chown()");
  }

  fd = creat(DUMMY_FILENAME, 0600);
  test_assert(fd >= 0);
  atomic_printf("Group owner of %s is %d\n", DUMMY_FILENAME, get_gid(fd));
  test_assert(this_group == get_gid(fd));

  change_group(DUMMY_FILENAME, other_group);
  atomic_printf("  ... now owner is %d\n", get_gid(fd));
  test_assert(other_group == get_gid(fd));

  change_group_fd(fd, this_group);
  atomic_printf("  ... now back to original owner %d\n", get_gid(fd));
  test_assert(this_group == get_gid(fd));

  change_group_at(DUMMY_FILENAME, other_group);
  atomic_printf("  ... now owner is %d\n", get_gid(fd));
  test_assert(other_group == get_gid(fd));

  unlink(DUMMY_FILENAME);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
