/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <linux/dm-ioctl.h>

#define BUF_SIZE 16384

static char dev_name[64];

static struct dm_ioctl* init_buf(char* buf, size_t size, const char* name) {
  struct dm_ioctl* dm = (struct dm_ioctl*)buf;
  memset(buf, 0, size);
  dm->version[0] = DM_VERSION_MAJOR;
  dm->version[1] = 0;
  dm->version[2] = 0;
  dm->data_size = size;
  dm->data_start = sizeof(struct dm_ioctl);
  if (name) {
    strncpy(dm->name, name, sizeof(dm->name) - 1);
  }
  return dm;
}

static void check_version(struct dm_ioctl* dm) {
  atomic_printf("version %u.%u.%u\n", dm->version[0], dm->version[1],
                dm->version[2]);
  test_assert(dm->version[0] == DM_VERSION_MAJOR);
}

int main(void) {
  char* buf;
  struct dm_ioctl* dm;
  struct dm_name_list* names;
  struct dm_target_versions* tv;
  int ret;
  int fd;
  uint32_t event_nr;

  if (geteuid() != 0) {
    atomic_puts("Device-mapper ioctls need root, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  fd = open("/dev/mapper/control", O_RDWR);
  if (fd < 0) {
    if (errno == ENOENT || errno == ENODEV || errno == ENXIO) {
      atomic_puts("Can't find /dev/mapper/control, skipping test");
    } else {
      test_assert(0 && "Unexpected error opening /dev/mapper/control");
    }
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  buf = allocate_guard(BUF_SIZE, 'x');
  /* Use a unique name since tests for different configurations may run
     concurrently. */
  sprintf(dev_name, "rr-ioctl-dm-test-%d", getpid());

  dm = init_buf(buf, BUF_SIZE, NULL);
  ret = ioctl(fd, DM_VERSION, dm);
  test_assert(ret == 0);
  check_version(dm);
  verify_guard(BUF_SIZE, buf);

  /* Buffer too small: the kernel still writes back the version. */
  dm = init_buf(buf, BUF_SIZE, NULL);
  dm->data_size = 0;
  ret = ioctl(fd, DM_LIST_DEVICES, dm);
  test_assert(ret == -1 && errno == EINVAL);
  check_version(dm);
  verify_guard(BUF_SIZE, buf);

  dm = init_buf(buf, BUF_SIZE, NULL);
  ret = ioctl(fd, DM_LIST_VERSIONS, dm);
  test_assert(ret == 0);
  check_version(dm);
  test_assert(dm->data_size <= BUF_SIZE);
  tv = (struct dm_target_versions*)(buf + dm->data_start);
  while (1) {
    atomic_printf("target %s %u.%u.%u\n", tv->name, tv->version[0],
                  tv->version[1], tv->version[2]);
    if (!tv->next) {
      break;
    }
    tv = (struct dm_target_versions*)((char*)tv + tv->next);
  }
  verify_guard(BUF_SIZE, buf);

  dm = init_buf(buf, BUF_SIZE, NULL);
  strcpy(buf + dm->data_start, "linear");
  ret = ioctl(fd, DM_GET_TARGET_VERSION, dm);
  if (ret == 0) {
    tv = (struct dm_target_versions*)(buf + dm->data_start);
    atomic_printf("linear target version %u.%u.%u\n", tv->version[0],
                  tv->version[1], tv->version[2]);
  } else {
    /* DM_GET_TARGET_VERSION was added in Linux 5.7 */
    test_assert(errno == ENOTTY || errno == EINVAL);
  }
  verify_guard(BUF_SIZE, buf);

  /* Create an empty device, query it, then remove it. */
  dm = init_buf(buf, BUF_SIZE, dev_name);
  ret = ioctl(fd, DM_DEV_CREATE, dm);
  test_assert(ret == 0);
  check_version(dm);
  atomic_printf("created dev %llx\n", (unsigned long long)dm->dev);
  verify_guard(BUF_SIZE, buf);

  dm = init_buf(buf, BUF_SIZE, dev_name);
  ret = ioctl(fd, DM_DEV_STATUS, dm);
  test_assert(ret == 0);
  atomic_printf("status: open_count=%d flags=%x event_nr=%u\n",
                dm->open_count, dm->flags, dm->event_nr);
  event_nr = dm->event_nr;
  verify_guard(BUF_SIZE, buf);

  dm = init_buf(buf, BUF_SIZE, dev_name);
  ret = ioctl(fd, DM_TABLE_STATUS, dm);
  test_assert(ret == 0);
  test_assert(dm->target_count == 0);
  verify_guard(BUF_SIZE, buf);

  dm = init_buf(buf, BUF_SIZE, dev_name);
  ret = ioctl(fd, DM_TABLE_DEPS, dm);
  test_assert(ret == 0);
  verify_guard(BUF_SIZE, buf);

  dm = init_buf(buf, BUF_SIZE, dev_name);
  /* DM_DEV_WAIT blocks until the device's event number differs from the one
     passed in, so pass a different one to make it return immediately. */
  dm->event_nr = event_nr + 1;
  ret = ioctl(fd, DM_DEV_WAIT, dm);
  test_assert(ret == 0);
  verify_guard(BUF_SIZE, buf);

  dm = init_buf(buf, BUF_SIZE, NULL);
  ret = ioctl(fd, DM_LIST_DEVICES, dm);
  test_assert(ret == 0);
  check_version(dm);
  test_assert(!(dm->flags & DM_BUFFER_FULL_FLAG));
  test_assert(dm->data_size <= BUF_SIZE);
  {
    int found = 0;
    names = (struct dm_name_list*)(buf + dm->data_start);
    if (names->dev) {
      while (1) {
        atomic_printf("device %s %llx\n", names->name,
                      (unsigned long long)names->dev);
        if (!strcmp(names->name, dev_name)) {
          found = 1;
        }
        if (!names->next) {
          break;
        }
        names = (struct dm_name_list*)((char*)names + names->next);
      }
    }
    test_assert(found);
  }
  verify_guard(BUF_SIZE, buf);

  dm = init_buf(buf, BUF_SIZE, dev_name);
  ret = ioctl(fd, DM_DEV_REMOVE, dm);
  test_assert(ret == 0);
  verify_guard(BUF_SIZE, buf);

  dm = init_buf(buf, BUF_SIZE, dev_name);
  ret = ioctl(fd, DM_DEV_STATUS, dm);
  test_assert(ret == -1 && errno == ENXIO);
  check_version(dm);
  verify_guard(BUF_SIZE, buf);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
