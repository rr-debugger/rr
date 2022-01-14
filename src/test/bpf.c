/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#include "util.h"

#include <linux/bpf.h>

int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
  return syscall(__NR_bpf, cmd, attr, size);
}

int main(void) {
  union bpf_attr attr;

  {
    const char* filename = "foo";
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (__u64)(uintptr_t)filename;
    bpf(BPF_OBJ_GET, &attr, 1);
  }

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
