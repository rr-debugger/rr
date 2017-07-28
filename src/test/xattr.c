/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static const char path_name[] = "rr-test-file";
static const char link_name[] = "rr-test-link";
static const char attr_name1[] = "user.testAttr1";
static const char attr_name2[] = "user.testAttr2";
static const char link_attr_name[] = "trusted.testA1";
static const char attr_value1[] = "hello kitty";
static const char attr_value2[] = "hello scarf";

static int list_contains(const char* buf, size_t buf_size, const char* name) {
  const char* end = buf + buf_size;
  while (buf < end) {
    if (strcmp(buf, name) == 0) {
      return 1;
    }
    buf += strlen(buf) + 1;
  }
  return 0;
}

int main(void) {
  int ret;
  int fd;
  size_t buf_size = sizeof(attr_value1) + 1;
  char* buf = allocate_guard(buf_size, '-');
  int test_link = 1;
  size_t file_list_size;
  size_t link_list_size;

  fd = open(path_name, O_RDWR | O_CREAT, 0700);
  test_assert(0 <= fd);

  ret = setxattr(path_name, attr_name1, attr_value1, sizeof(attr_value1),
                 XATTR_CREATE);
  if (ret < 0 && errno == ENOTSUP) {
    test_assert(0 == unlink(path_name));
    atomic_puts("Filesystem does not support xattrs; skipping tests");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == 0);

  test_assert(0 == fsetxattr(fd, attr_name2, attr_value2, sizeof(attr_value2),
                             XATTR_CREATE));

  test_assert(0 == symlink(path_name, link_name));
  ret = lsetxattr(link_name, link_attr_name, attr_value1, sizeof(attr_value1),
                  XATTR_CREATE);
  if (ret < 0 && errno == EPERM) {
    atomic_puts("Not allowed to create xattrs on links; skipping link tests");
    /* Only trusted xattrs can be created on links. Currently Linux does not
       allow non-root users to create trusted xattrs, even if they're
       privileged in a user/fs namespace. If it did, we could run link tests
       in unshare.c... */
    test_link = 0;
  } else {
    test_assert(ret == 0);
  }

  test_assert(-1 ==
              getxattr(path_name, attr_name2, buf, sizeof(attr_value2) - 1));
  verify_guard(buf_size, buf);
  test_assert(errno == ERANGE);
  memset(buf, '-', buf_size);
  test_assert(-1 == fgetxattr(fd, attr_name1, buf, sizeof(attr_value1) - 1));
  verify_guard(buf_size, buf);
  test_assert(errno == ERANGE);
  memset(buf, '-', buf_size);
  if (test_link) {
    test_assert(-1 == lgetxattr(link_name, link_attr_name, buf,
                                sizeof(attr_value1) - 1));
    verify_guard(buf_size, buf);
    test_assert(errno == ERANGE);
    memset(buf, '-', buf_size);
  }

  test_assert(sizeof(attr_value2) ==
              getxattr(path_name, attr_name2, buf, sizeof(attr_value2)));
  verify_guard(buf_size, buf);
  test_assert(0 == memcmp(attr_value2, buf, sizeof(attr_value2)));
  test_assert(buf[sizeof(attr_value2)] == '-');
  memset(buf, '-', buf_size);
  test_assert(sizeof(attr_value1) ==
              fgetxattr(fd, attr_name1, buf, sizeof(attr_value1)));
  verify_guard(buf_size, buf);
  test_assert(0 == memcmp(attr_value1, buf, sizeof(attr_value1)));
  test_assert(buf[sizeof(attr_value1)] == '-');
  memset(buf, '-', buf_size);
  if (test_link) {
    test_assert(sizeof(attr_value2) ==
                lgetxattr(link_name, link_attr_name, buf, sizeof(attr_value1)));
    verify_guard(buf_size, buf);
    test_assert(0 == memcmp(attr_value1, buf, sizeof(attr_value1)));
    test_assert(buf[sizeof(attr_value1)] == '-');
    memset(buf, '-', buf_size);
  }

  test_assert(-1 == listxattr(path_name, buf, sizeof(attr_name1) - 1));
  verify_guard(buf_size, buf);
  test_assert(errno == ERANGE);
  test_assert(buf[0] == '-');
  test_assert(-1 == flistxattr(fd, buf, sizeof(attr_name1) - 1));
  verify_guard(buf_size, buf);
  test_assert(errno == ERANGE);
  test_assert(buf[0] == '-');
  if (test_link) {
    test_assert(-1 == llistxattr(link_name, buf, sizeof(link_attr_name) - 1));
    verify_guard(buf_size, buf);
    test_assert(errno == ERANGE);
    test_assert(buf[0] == '-');
  }

  file_list_size = listxattr(path_name, NULL, 0);
  test_assert(file_list_size >= sizeof(attr_name1) + sizeof(attr_name2));
  if (test_link) {
    link_list_size = llistxattr(link_name, NULL, 0);
    test_assert(link_list_size >= sizeof(link_attr_name));
  } else {
    link_list_size = 0;
  }

  buf_size = file_list_size + 1;
  buf = allocate_guard(buf_size, '-');
  test_assert(file_list_size == (size_t)listxattr(path_name, buf, buf_size));
  verify_guard(buf_size, buf);
  test_assert(list_contains(buf, file_list_size, attr_name1));
  test_assert(list_contains(buf, file_list_size, attr_name2));
  test_assert(buf[file_list_size] == '-');
  memset(buf, '-', buf_size);
  test_assert(file_list_size == (size_t)flistxattr(fd, buf, buf_size));
  verify_guard(buf_size, buf);
  test_assert(list_contains(buf, file_list_size, attr_name1));
  test_assert(list_contains(buf, file_list_size, attr_name2));
  test_assert(buf[file_list_size] == '-');
  memset(buf, '-', buf_size);
  if (test_link) {
    buf_size = link_list_size + 1;
    buf = allocate_guard(buf_size, '-');
    test_assert(link_list_size == (size_t)llistxattr(link_name, buf, buf_size));
    verify_guard(buf_size, buf);
    test_assert(list_contains(buf, link_list_size, link_attr_name));
    test_assert(buf[link_list_size] == '-');
    memset(buf, '-', buf_size);
  }

  test_assert(0 == removexattr(path_name, attr_name2));
  test_assert(-1 == getxattr(path_name, attr_name2, buf, buf_size));
  test_assert(errno == ENODATA);
  test_assert(buf[0] == '-');
  test_assert(0 == fremovexattr(fd, attr_name1));
  test_assert(-1 == getxattr(path_name, attr_name1, buf, buf_size));
  test_assert(errno == ENODATA);
  test_assert(buf[0] == '-');
  if (test_link) {
    test_assert(0 == lremovexattr(link_name, link_attr_name));
    test_assert(-1 == getxattr(link_name, link_attr_name, buf, buf_size));
    test_assert(errno == ENODATA);
    test_assert(buf[0] == '-');
  }

  test_assert(0 == unlink(link_name));
  test_assert(0 == unlink(path_name));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
