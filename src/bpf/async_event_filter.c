/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <linux/bpf.h>
#include <linux/bpf_perf_event.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>

const uint32_t REGISTER_COUNT = sizeof(struct pt_regs)/sizeof(uint64_t);

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, REGISTER_COUNT);
  __uint(map_flags, BPF_F_MMAPABLE);
  __type(key, uint32_t);
  __type(value, uint64_t);
} registers SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __uint(map_flags, BPF_F_MMAPABLE);
  __type(key, uint32_t);
  __type(value, uint64_t);
} skips SEC(".maps");

SEC("perf_event")
int match_registers(struct bpf_perf_event_data* event) {
#define CHECK_REG(name)                                                        \
  do {                                                                         \
    const uint32_t i = offsetof(struct pt_regs, name) / sizeof(uint64_t);      \
    uint64_t* reg = bpf_map_lookup_elem(&registers, &i);                       \
    if (!reg) {                                                                \
      return 1;                                                                \
    }                                                                          \
    if (event->regs.name != *reg) {                                            \
      const uint32_t j = 0;                                                    \
      uint64_t* s = bpf_map_lookup_elem(&skips, &j);                           \
      if (s) {                                                                 \
        *s += 1;                                                               \
      }                                                                        \
      return 0;                                                                \
    }                                                                          \
  } while(0)

  CHECK_REG(r15);
  CHECK_REG(r14);
  CHECK_REG(r13);
  CHECK_REG(r12);
  CHECK_REG(rbp);
  CHECK_REG(rbx);
  CHECK_REG(r11);
  CHECK_REG(r10);
  CHECK_REG(r9);
  CHECK_REG(r8);
  CHECK_REG(rax);
  CHECK_REG(rcx);
  CHECK_REG(rdx);
  CHECK_REG(rsi);
  CHECK_REG(rdi);
  CHECK_REG(rsp);

  return 1;
}

char _license[] SEC("license") = "Dual MIT/GPL";
