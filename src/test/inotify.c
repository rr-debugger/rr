/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  struct inotify_event* event;
  int desc;
  int file_fd;
  int fd = inotify_init();
  test_assert(fd >= 0);
  test_assert(0 == close(fd));
  fd = inotify_init1(IN_CLOEXEC);
  test_assert(fd >= 0);

  file_fd = open("foo", O_WRONLY | O_CREAT, 0777);
  test_assert(file_fd >= 0);
  test_assert(0 == close(file_fd));

  desc = inotify_add_watch(fd, "foo", IN_ALL_EVENTS);
  if (desc == -1 && errno == ENOSPC) {
    atomic_puts("Hit inotify watch limit");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(desc >= 0);

  test_assert(0 <= open("foo", O_WRONLY | O_CREAT, 0777));
  ALLOCATE_GUARD(event, 'x');
  test_assert(sizeof(*event) == read(fd, event, sizeof(*event)));
  VERIFY_GUARD(event);
  test_assert(event->wd == desc);
  test_assert(event->mask == IN_OPEN);

  test_assert(0 == inotify_rm_watch(fd, desc));

  test_assert(0 == unlink("foo"));

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
