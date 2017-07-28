/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("prw.txt", O_CREAT | O_RDWR, 0600);
  const char content[] = "01234567890\nhello there\n";
  char buf[sizeof(content)];
  ssize_t nr;

  memset(buf, '?', sizeof(buf));
  nr = write(fd, buf, sizeof(buf));
  test_assert(nr == sizeof(buf));
  nr = write(fd, buf, 10);
  test_assert(nr == 10);

  nr = pwrite(fd, content, sizeof(content), 10);
  test_assert(nr == sizeof(content));
  atomic_printf("Wrote ```%s'''\n", content);

  nr = pread(fd, buf, sizeof(buf), 10);
  test_assert(nr == sizeof(content));
  atomic_printf("Read ```%s'''\n", buf);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
