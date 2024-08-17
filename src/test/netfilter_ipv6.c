/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include <linux/netfilter_ipv6/ip6_tables.h>

#include "nsutils.h"

int main(void) {
  if (-1 == try_setup_ns(CLONE_NEWNET)) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  int sock_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
  if (sock_fd < 0 && errno == EAFNOSUPPORT) {
    atomic_puts("IPV6 not supported, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(sock_fd >= 0);

  struct ip6t_getinfo* info;
  ALLOCATE_GUARD(info, 'a');
  strcpy(info->name, "nat");
  uint32_t getinfo_size = sizeof(*info);

  errno = 0;
  int ret = getsockopt(sock_fd, SOL_IPV6, IP6T_SO_GET_INFO, info, &getinfo_size);
  if (ret < 0) {
    switch (errno) {
    case ENOPROTOOPT:
      atomic_puts("IPV6T_SO_GET_INFO not available");
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
  test_assert(getinfo_size == sizeof(*info));
  VERIFY_GUARD(info);

  atomic_printf("%d existing entries in nat table\n", info->num_entries);

  uint32_t getentries_size = sizeof(struct ip6t_get_entries) + info->size;
  struct ip6t_get_entries* entries = allocate_guard(getentries_size, 'b');
  strcpy(entries->name, "nat");
  entries->size = info->size;
  ret = getsockopt(sock_fd, SOL_IPV6, IP6T_SO_GET_ENTRIES, entries,
                   &getentries_size);
  if (ret < 0 && errno == EINVAL && sizeof(void*) == 4) {
    atomic_puts("Kernel may have been built without CONFIG_NETFILTER_XTABLES_COMPAT");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == 0);
  VERIFY_GUARD(entries);

  size_t final_size = sizeof(struct ip6t_replace) + info->size;
  struct ip6t_replace* final = allocate_guard(final_size, 'c');

  strcpy(final->name, "nat");
  final->valid_hooks = info->valid_hooks;
  final->num_entries = info->num_entries;
  final->size = info->size;
  memcpy(final->hook_entry, info->hook_entry, sizeof(final->hook_entry));
  memcpy(final->underflow, info->underflow, sizeof(final->underflow));
  final->num_counters = info->num_entries;
  // Allocate space to receive counters
  // We will check for at least some of these bytes being replaced by the kernel
  struct xt_counters* counters =
      allocate_guard(sizeof(struct xt_counters) * info->num_entries, 0xff);
  final->counters = counters;

  char* src_ptr = (char*)entries->entrytable;
  char* dest_ptr = (char*)final->entries;
  for (size_t i = 0; i < info->num_entries; ++i) {
    struct ip6t_entry* cur_entry = (struct ip6t_entry*)src_ptr;
    memcpy(dest_ptr, src_ptr, cur_entry->next_offset);
    dest_ptr += cur_entry->next_offset;
    src_ptr += cur_entry->next_offset;
  }
  test_assert(dest_ptr == (char*)final + final_size);

  // Finally pass this off to the kernel
  ret = setsockopt(sock_fd, SOL_IPV6, IP6T_SO_SET_REPLACE, final, final_size);
  test_assert(ret == 0);
  VERIFY_GUARD(final);
  VERIFY_GUARD(final->counters);

  // Verify that the counters array was overwritten. Since we don't know the
  // exact value here, just make sure some bytes were written. After every byte
  // comparison we also call getuid if they were not the same, which should
  // catch any replay divergence, just from tick mismatch.
  int any_changed = 0;
  for (size_t i = 0; i < sizeof(struct xt_counters) * info->num_entries; ++i) {
    if (((uint8_t*)counters)[i] != 0xff) {
      any_changed = 1;
      (void)getuid();
    }
  }

  test_assert(any_changed);
  atomic_puts("EXIT-SUCCESS");
}
