/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define DUMMY_FILENAME "foo.txt"

static void dump_statfs(const char* label, const struct statfs* s) {
  atomic_printf("%s: {\n"
                "    type:0x%lx, bsize:%ld, \n"
                "    blocks:%ld, bfree:%ld, bavail:%ld,\n"
                "    files:%lu, ffree:%lu,\n"
                "    fsid: { %d, %d },\n"
                "    namelen:%ld, frsize:%ld,\n"
                "    flags:0x%lx\n"
                "}\n",
                label, (long)s->f_type, (long)s->f_bsize, s->f_blocks,
                s->f_bfree, s->f_bavail, s->f_files, s->f_ffree,
                s->f_fsid.__val[0], s->f_fsid.__val[1], (long)s->f_namelen,
                (long)s->f_frsize, (long)s->f_flags);
}

static int same_statfs_det(const struct statfs* s1, const struct statfs* s2) {
  /* Only compare the ~deterministic members; the free/avail
   * resource members can change in between calls. */
  return (s1->f_type == s2->f_type && s1->f_bsize == s2->f_bsize &&
          s1->f_blocks == s2->f_blocks &&
          s1->f_fsid.__val[0] == s2->f_fsid.__val[0] &&
          s1->f_fsid.__val[1] == s2->f_fsid.__val[1] &&
          s1->f_namelen == s2->f_namelen && s1->f_frsize == s2->f_frsize &&
          s1->f_flags == s2->f_flags);
}

int main(void) {
  int fd;
  struct statfs* sfs1;
  struct statfs* sfs2;

  ALLOCATE_GUARD(sfs1, 0);
  ALLOCATE_GUARD(sfs2, 1);
  fd = creat(DUMMY_FILENAME, 0600);
  test_assert(fd >= 0);
  test_assert(0 == statfs(DUMMY_FILENAME, sfs1));
  test_assert(0 == fstatfs(fd, sfs2));
  VERIFY_GUARD(sfs1);
  VERIFY_GUARD(sfs2);

  dump_statfs("statfs buffer", sfs1);
  dump_statfs("fstatfs buffer", sfs2);

  test_assert(same_statfs_det(sfs1, sfs2));

  unlink(DUMMY_FILENAME);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
