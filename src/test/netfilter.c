/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include <linux/netfilter_ipv4/ip_tables.h>

#include "nsutils.h"

int main(void) {
  if (-1 == try_setup_ns(CLONE_NEWNET)) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  /*
   * For this test, we'll be manually doing the following:
   * iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j MASQUERADE
   */

  int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  struct ipt_getinfo info;
  memset(&info, 0, sizeof(info));
  strcpy(info.name, "nat");
  uint32_t getinfo_size = sizeof(info);
  int ret = getsockopt(sock_fd, SOL_IP, IPT_SO_GET_INFO, &info, &getinfo_size);
  if (ret < 0) {
    test_assert(errno == ENOPROTOOPT);
    atomic_puts("IPT_SO_GET_INFO not available");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(getinfo_size == sizeof(info));

  atomic_printf("%d existing entries in nat table\n", info.num_entries);

  struct ipt_get_entries* entries =
      malloc(sizeof(struct ipt_get_entries) + info.size);
  strcpy(entries->name, "nat");
  entries->size = info.size;
  uint32_t getentries_size = sizeof(struct ipt_get_entries) + entries->size;
  test_assert(0 == getsockopt(sock_fd, SOL_IP, IPT_SO_GET_ENTRIES, entries,
                              &getentries_size));
  test_assert(getentries_size == sizeof(struct ipt_get_entries) + info.size);

  // matches will be empty
  struct xt_entry_target target;
  const char* target_name = "MASQUERADE";
  target.u.user.target_size = strlen(target_name) - 1;
  memcpy(target.u.user.name, target_name, strlen(target_name) - 1);

  struct ipt_entry entry;
  memset(&entry, 0, sizeof(struct ipt_entry));
  entry.ip.src.s_addr = 0x10;
  entry.ip.smsk.s_addr = 0xffffff;
  entry.target_offset = 0x70;
  entry.next_offset = 0x98;

  // Allocate space to receive counters
  struct xt_counters* counters =
      malloc(sizeof(struct xt_counters) * info.num_entries);
  // We will check for at least some of these bytes being replaced by the kernel
  memset(counters, 0xff, sizeof(struct xt_counters) * info.num_entries);

  struct ipt_replace repl;
  strcpy(repl.name, "nat");
  repl.num_entries = info.num_entries + 1;
  repl.size = info.size + entry.next_offset;
  memcpy(repl.hook_entry, info.hook_entry, sizeof(repl.hook_entry));
  memcpy(repl.underflow, info.underflow, sizeof(repl.underflow));
  repl.num_counters = info.num_entries;
  repl.counters = counters;

  size_t final_size = sizeof(struct ipt_replace) + repl.size;
  char* final = malloc(final_size);

  // Assemble structure
  memcpy(final, &repl, sizeof(struct ipt_replace));

  // Copy over original entries and insert our new one as the second-to-last one
  char* src_ptr = (char*)entries->entrytable;
  char* dest_ptr = (char*)((struct ipt_replace*)final)->entries;
  for (size_t i = 0; i < info.num_entries; ++i) {
    if (i == info.num_entries - 2) {
      memcpy(dest_ptr, &entry, sizeof(struct ipt_entry));
      dest_ptr += sizeof(struct ipt_entry);
      memcpy(dest_ptr, &target, sizeof(struct xt_entry_target));
      dest_ptr += sizeof(struct xt_entry_target);
      size_t npad = entry.next_offset - sizeof(struct xt_entry_target);
      memset(dest_ptr, 0, npad);
      dest_ptr += npad;
    }
    struct ipt_entry* cur_entry = (struct ipt_entry*)src_ptr;
    memcpy(dest_ptr, src_ptr, cur_entry->next_offset);
    dest_ptr += cur_entry->next_offset;
    src_ptr += cur_entry->next_offset;
  }

  // Finally pass this off to the kernel
  test_assert(
      setsockopt(sock_fd, SOL_IP, IPT_SO_SET_REPLACE, final, final_size));

  // Verify that the counters array was overwritten. Since we don't know the
  // exact value here, just make sure some bytes were written. After every byte
  // comparison we also call getuid if they were not the same, which should
  // catch any replay divergence, just from tick mismatch.
  int any_changed = 0;
  for (size_t i = 0; i < sizeof(struct xt_counters) * info.num_entries; ++i) {
    if (((uint8_t*)entries)[i] != 0xff) {
      any_changed = 1;
      (void)getuid();
    }
  }

  test_assert(any_changed);
  atomic_puts("EXIT-SUCCESS");
}
