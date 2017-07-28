/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  struct fanotify_event_metadata* event;
  int file_fd;
  int fd = fanotify_init(0, O_RDONLY);

  if (fd == -1 && errno == EPERM) {
    atomic_puts("fanotify requires CAP_SYS_ADMIN (in the root namespace) but "
                "we don't have those privileges; skipping tests");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  if (fd == -1 && errno == ENOSYS) {
    atomic_puts("fanotify is not available in this kernel; skipping tests");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(fd >= 0);

  file_fd = open("foo", O_WRONLY | O_CREAT, 0777);
  test_assert(file_fd >= 0);
  test_assert(0 == close(file_fd));

  test_assert(0 == fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, "foo"));

  file_fd = open("foo", O_WRONLY | O_CREAT, 0777);
  test_assert(file_fd >= 0);
  test_assert(0 == close(file_fd));

  ALLOCATE_GUARD(event, 'x');
  test_assert(sizeof(*event) == read(fd, event, sizeof(*event)));
  VERIFY_GUARD(event);
  test_assert(event->event_len == sizeof(*event));
  test_assert(event->vers == FANOTIFY_METADATA_VERSION);
  test_assert(event->mask == FAN_OPEN);
  test_assert(event->fd >= 0);
  test_assert(event->pid == getpid());

  test_assert(0 == unlink("foo"));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
