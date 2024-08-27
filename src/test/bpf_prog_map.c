/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#include "util.h"
#include "nsutils.h"

#include <stdint.h>
#include <sched.h>
#include <linux/bpf.h>

#define MAX_PROG_CNT 1
#define ATTACH_TYPE 17 // BPF_FLOW_DISSECTOR
#define PROG_TYPE 22 // BPF_PROG_TYPE_FLOW_DISSECTOR

int bpf(int cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(__NR_bpf, cmd, attr, size);
}

const struct bpf_insn bpf_program[] = {
  // mov r0, 0
  { .code = BPF_ALU | BPF_MOV | BPF_K, .dst_reg = 0, .imm = 0 },
  // exit
  { .code = BPF_JMP | BPF_EXIT },
};

int main(void) {
  if (try_setup_ns(CLONE_NEWNET)) {
    atomic_puts("Skipping test because try_setup_ns failed");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  int netns_fd = open("/proc/self/ns/net", O_RDONLY);
  test_assert(netns_fd > 0);

  // load and add a program to the cgroup
  static char log_buf[4096] = {};
  union bpf_attr prog_attr = {
    .insn_cnt = 2,
    .insns = (uintptr_t)bpf_program,
    .license = (uintptr_t)"MIT",
    .prog_type = PROG_TYPE,
    .log_size = sizeof(log_buf),
    .log_buf = (uintptr_t)log_buf,
    .log_level = 1,
  };
  const int offset_of_attach_prog_fd = 112;
  size_t prog_attr_size = offset_of_attach_prog_fd + sizeof(__u32);
  int prog = bpf(RR_BPF_PROG_LOAD, &prog_attr, prog_attr_size);
  if (prog < 0) {
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
    atomic_puts(log_buf);
    test_assert(0 && "failed to load program");
  }
  test_assert(prog > 0);

  union bpf_attr* map_attr;
  ALLOCATE_GUARD(map_attr, 'a');
  memset(map_attr, 0, sizeof(*map_attr));
  uint32_t key = 99;
  uint64_t value = 1234567;
  map_attr->map_type = BPF_MAP_TYPE_HASH;
  map_attr->key_size = sizeof(key);
  map_attr->value_size = sizeof(value);
  map_attr->max_entries = 10;
  int map_fd = bpf(RR_BPF_MAP_CREATE, map_attr, sizeof(*map_attr));
  test_assert(map_fd >= 0);
  VERIFY_GUARD(map_attr);

  memset(map_attr, 0, sizeof(*map_attr));
  map_attr->prog_bind_map.map_fd = map_fd;
  map_attr->prog_bind_map.prog_fd = prog;
  int ret = bpf(RR_BPF_PROG_BIND_MAP, map_attr, sizeof(*map_attr));
  test_assert(ret == 0 || errno == EINVAL);
  VERIFY_GUARD(map_attr);

  memset(map_attr, 0, sizeof(*map_attr));
  map_attr->map_fd = map_fd;
  ret = bpf(RR_BPF_MAP_FREEZE, map_attr, sizeof(*map_attr));
  test_assert(ret == 0 || errno == EINVAL);
  VERIFY_GUARD(map_attr);

  struct bpf_prog_info* prog_info;
  ALLOCATE_GUARD(prog_info, 'b');
  memset(prog_info, 0, sizeof(*prog_info));
  memset(map_attr, 0, sizeof(*map_attr));
  map_attr->info.bpf_fd = prog;
  map_attr->info.info_len = sizeof(*prog_info);
  map_attr->info.info = (uintptr_t)prog_info;
  ret = bpf(RR_BPF_OBJ_GET_INFO_BY_FD, map_attr, sizeof(*map_attr));
  if (ret == 0) {
    test_assert(prog_info->created_by_uid == getuid());
    atomic_printf("Program: %s run_cnt %lld verified_insns %d\n",
                  prog_info->name, prog_info->run_cnt, prog_info->verified_insns);
  } else {
    sleep(1000);
    test_assert(errno == EINVAL);
  }
  VERIFY_GUARD(prog_info);

  struct bpf_map_info* map_info;
  ALLOCATE_GUARD(map_info, 'c');
  memset(map_info, 0, sizeof(*map_info));
  memset(map_attr, 0, sizeof(*map_attr));
  map_attr->info.bpf_fd = map_fd;
  map_attr->info.info_len = sizeof(*map_info);
  map_attr->info.info = (uintptr_t)map_info;
  ret = bpf(RR_BPF_OBJ_GET_INFO_BY_FD, map_attr, sizeof(*map_attr));
  if (ret == 0) {
    test_assert(map_info->type == BPF_MAP_TYPE_HASH);
    atomic_printf("Map: %s key_size %d value_size %d\n",
                  map_info->name, map_info->key_size, map_info->value_size);
  } else {
    test_assert(errno == EINVAL);
  }
  VERIFY_GUARD(map_info);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
