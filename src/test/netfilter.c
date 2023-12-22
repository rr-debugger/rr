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

  int sock_fd;
  struct ipt_getinfo info;
  memset(&info, 0, sizeof(info));
  strcpy(info.name, "nat");
  uint32_t getinfo_size = sizeof(info);

  sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  test_assert(sock_fd >= 0);

  errno = 0;
  int ret = getsockopt(sock_fd, SOL_IP, IPT_SO_GET_INFO, &info, &getinfo_size);
  if (ret < 0) {
    switch (errno) {
    case ENOPROTOOPT:
      atomic_puts("IPT_SO_GET_INFO not available");
      atomic_puts("EXIT-SUCCESS");
      break;
    case ENOENT:
      atomic_puts("'nat' table missing");
      atomic_puts("EXIT-SUCCESS");
      break;
    default:
      test_assert(errno == 0);
    }
    return 0;
  }
  test_assert(getinfo_size == sizeof(info));

  atomic_printf("%d existing entries in nat table\n", info.num_entries);

  struct ipt_get_entries* entries =
      malloc(sizeof(struct ipt_get_entries) + info.size);
  strcpy(entries->name, "nat");
  entries->size = info.size;
  uint32_t getentries_size = sizeof(struct ipt_get_entries) + entries->size;
  ret = getsockopt(sock_fd, SOL_IP, IPT_SO_GET_ENTRIES, entries,
                   &getentries_size);
  if (ret < 0 && errno == EINVAL && sizeof(void*) == 4) {
    atomic_puts("Kernel may have been built without CONFIG_NETFILTER_XTABLES_COMPAT");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == 0);
  test_assert(getentries_size == sizeof(struct ipt_get_entries) + info.size);

  // Allocate space to receive counters
  struct xt_counters* counters =
      malloc(sizeof(struct xt_counters) * info.num_entries);
  // We will check for at least some of these bytes being replaced by the kernel
  memset(counters, 0xff, sizeof(struct xt_counters) * info.num_entries);

  struct ipt_replace repl;
  strcpy(repl.name, "nat");
  repl.valid_hooks = info.valid_hooks;
  repl.num_entries = info.num_entries;
  repl.size = info.size;
  memcpy(repl.hook_entry, info.hook_entry, sizeof(repl.hook_entry));
  memcpy(repl.underflow, info.underflow, sizeof(repl.underflow));
  repl.num_counters = info.num_entries;
  repl.counters = counters;

  size_t final_size = sizeof(struct ipt_replace) + repl.size;
  char* final = malloc(final_size);

  // Assemble structure
  memcpy(final, &repl, sizeof(struct ipt_replace));

  char* src_ptr = (char*)entries->entrytable;
  char* dest_ptr = (char*)((struct ipt_replace*)final)->entries;
  for (size_t i = 0; i < info.num_entries; ++i) {
    struct ipt_entry* cur_entry = (struct ipt_entry*)src_ptr;
    memcpy(dest_ptr, src_ptr, cur_entry->next_offset);
    dest_ptr += cur_entry->next_offset;
    src_ptr += cur_entry->next_offset;
  }
  test_assert(dest_ptr == final + final_size);

  // Finally pass this off to the kernel
  ret = setsockopt(sock_fd, SOL_IP, IPT_SO_SET_REPLACE, final, final_size);
  test_assert(ret == 0);

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
