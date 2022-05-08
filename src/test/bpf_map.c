/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#include "util.h"

#include <linux/bpf.h>

int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
  return syscall(__NR_bpf, cmd, attr, size);
}

int main(void) {
  union bpf_attr attr;
  int map_fd;
  uint32_t key = 99;
  uint32_t unknown_key = 0;
  uint32_t* next_key;
  uint64_t value = 1234567;
  uint64_t* value_out;
  int ret;
  memset(&attr, 0, sizeof(attr));

  attr.map_type = BPF_MAP_TYPE_HASH;
  attr.key_size = sizeof(key);
  attr.value_size = sizeof(value);
  attr.max_entries = 10;
  map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
  if (map_fd < 0) {
    if (errno == ENOSYS) {
      atomic_puts("bpf syscall not supported");
      atomic_puts("EXIT-SUCCESS");
      return 0;
    }
    if (errno == EPERM) {
      atomic_puts("Skipping test because it requires CAP_SYS_ADMIN");
      atomic_puts("EXIT-SUCCESS");
      return 0;
    }
  }
  test_assert(map_fd >= 0);

  attr.map_fd = map_fd;
  attr.key = (uintptr_t)&key;
  attr.value = (uintptr_t)&value;
  attr.flags = BPF_ANY;
  ret = bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));

  ALLOCATE_GUARD(value_out, 'a');
  attr.value = (uintptr_t)value_out;
  ret = bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
  test_assert(0 == ret);
  VERIFY_GUARD(value_out);
  test_assert(value == *value_out);

  ALLOCATE_GUARD(next_key, 'b');
  attr.key = (uintptr_t)&unknown_key;
  attr.next_key = (uintptr_t)next_key;
  ret = bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
  test_assert(0 == ret);
  VERIFY_GUARD(next_key);
  test_assert(key == *next_key);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
