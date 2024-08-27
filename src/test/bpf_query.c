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
  __u32 prog_ids[MAX_PROG_CNT];

  if (try_setup_ns(CLONE_NEWNET)) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  int netns_fd = open("/proc/self/ns/net", O_RDONLY);
  test_assert(netns_fd > 0);

  union bpf_attr query_attr = {
    .query = {
      .prog_ids = (uintptr_t)&prog_ids,
      .target_fd = netns_fd,
    },
  };


  // query cgroups bpf programs. at first, no programs are attached
  query_attr.query.prog_cnt = 2;
  query_attr.query.attach_type = ATTACH_TYPE;
  if (bpf(RR_BPF_PROG_QUERY, &query_attr, sizeof(query_attr.query)) != 0) {
    if (errno == ENOSYS) {
      atomic_puts("Skipping test because bpf is not supported");
      atomic_puts("EXIT-SUCCESS");
      return 0;
    }
    if (errno == EPERM) {
      // we have to check for EPERM again as a kernel can be built with
      // user namespaces, so unshare can succeed regardless of CAP_SYS_ADMIN
      atomic_puts("Skipping test because it requires CAP_SYS_ADMIN");
      atomic_puts("EXIT-SUCCESS");
      return 0;
    }
    test_assert(0 && "bpf(RR_BPF_PROG_QUERY) failed");
  }
  test_assert(query_attr.query.prog_cnt == 0);

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
    atomic_puts(log_buf);
    test_assert(0 && "failed to load program");
  }
  test_assert(prog > 0);

  union bpf_attr attach_attr = {
    .attach_type = ATTACH_TYPE,
  };
  const int offset_of_replace_bpf_fd = 112;
  size_t attach_attr_size = offset_of_replace_bpf_fd + sizeof(__u32);
  attach_attr.attach_bpf_fd = prog;
  test_assert(bpf(RR_BPF_PROG_ATTACH, &attach_attr, attach_attr_size) == 0);

  // query again
  query_attr.query.prog_cnt = 1;
  query_attr.query.attach_type = ATTACH_TYPE;
  test_assert(bpf(RR_BPF_PROG_QUERY, &query_attr, sizeof(query_attr.query)) == 0);
  test_assert(query_attr.query.prog_cnt == 1); // the kernel sets this field

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
