/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static const char attr_name[] = "user.testAttr";
static const char attr_value[] = "hello kitty";

int main(void) {
  char path[PATH_MAX];
  const char* home = getenv("HOME");
  int fd;
  int ret;

  snprintf(path, sizeof(path), "%s/rr-xattr-XXXXXX", home ? home : "/tmp");
  path[sizeof(path) - 1] = 0;
  fd = mkstemp(path);
  test_assert(0 <= fd);

  ret = setxattr(path, attr_name, attr_value, sizeof(attr_value), XATTR_CREATE);
  if (ret < 0 && errno == EOPNOTSUPP) {
    atomic_printf("Extended attributes not supported on file %s, "
                  "skipping test\n",
                  path);
  } else {
    char buf[sizeof(attr_value) + 1];

    test_assert(ret == 0);

    memset(buf, '-', sizeof(buf));

    ret = fgetxattr(fd, attr_name, buf, sizeof(buf) - 5);
    test_assert(ret == -1);
    test_assert(errno == ERANGE);
    test_assert(buf[0] == '-');

    ret =
        fsetxattr(fd, attr_name, attr_value, sizeof(attr_value), XATTR_REPLACE);
    test_assert(ret == 0);

    ret = getxattr(path, attr_name, buf, sizeof(buf));
    test_assert(ret == sizeof(attr_value));
    test_assert(0 == memcmp(attr_value, buf, sizeof(attr_value)));
    test_assert(buf[sizeof(attr_value)] == '-');

    ret = fremovexattr(fd, attr_name);
    test_assert(ret == 0);

    memset(buf, '-', sizeof(buf));

    ret = getxattr(path, attr_name, buf, sizeof(buf));
    test_assert(ret == -1);
    test_assert(errno == ENODATA);
    test_assert(buf[0] == '-');
  }

  test_assert(0 == unlink(path));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
