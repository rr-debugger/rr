/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"
#include <linux/netfilter_ipv4/ip_tables.h>

static int open_proc_file(pid_t pid, const char* file, int mode) {
  char path[100];
  ssize_t n = snprintf(path, sizeof(path), "/proc/%d/%s", pid, file);
  test_assert(n >= 0 && n < (ssize_t)sizeof(path));
  int fd = open(path, mode);
  test_assert(fd != -1);
  return fd;
}

int main(void) {
  int err = unshare(CLONE_NEWNET);
  if (err == -1) {
    // Try again using user namespace functionality
    test_assert(errno == EPERM);

    int child_block[2], parent_block[2];
    pipe(child_block);
    pipe(parent_block);

    pid_t pid = getpid();
    if (fork() == 0) {
      close(child_block[1]);
      close(parent_block[0]);

      // This will block until the parent closes fds[1]
      test_assert(0 == read(child_block[0], NULL, 1));
      close(child_block[0]);

      // Deny setgroups
      int setgroups_fd = open_proc_file(pid, "setgroups", O_WRONLY);
      char deny[] = "deny";
      test_assert(write(setgroups_fd, deny, sizeof(deny)) == sizeof(deny));
      close(setgroups_fd);

      // Make us root
      ssize_t nbytes;
      int uidmap_fd = open_proc_file(pid, "uid_map", O_WRONLY);
      test_assert(uidmap_fd != -1);
      char uidmap[100];
      nbytes = snprintf(uidmap, (ssize_t)sizeof(uidmap), "0\t%d\t1", getuid());
      test_assert(nbytes > 0 && nbytes <= (ssize_t)sizeof(uidmap));
      test_assert(write(uidmap_fd, uidmap, nbytes) == nbytes);
      test_assert(uidmap_fd);

      int gidmap_fd = open_proc_file(pid, "gid_map", O_WRONLY);
      test_assert(gidmap_fd != -1);
      char gidmap[100];
      nbytes = snprintf(gidmap, (ssize_t)sizeof(gidmap), "0\t%d\t1", getgid());
      test_assert(nbytes > 0 && nbytes <= (ssize_t)sizeof(gidmap));
      test_assert(write(gidmap_fd, gidmap, nbytes) == nbytes);

      close(parent_block[1]);

      return 0;
    }
    close(child_block[0]);
    close(parent_block[1]);

    err = unshare(CLONE_NEWNET | CLONE_NEWUSER);

    if (err == -1) {
      test_assert(errno == EPERM);
      atomic_printf("Skipping test because network namespaces are\n"
                    "not available at this privilege level");
      atomic_printf("EXIT-SUCCESS");
      return 0;
    }

    close(child_block[1]);
    // Wait until our child has made us root in this namespace;
    test_assert(0 == read(parent_block[0], NULL, 1));
    close(parent_block[0]);
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
  test_assert(
      0 == getsockopt(sock_fd, SOL_IP, IPT_SO_GET_INFO, &info, &getinfo_size));
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
  atomic_printf("EXIT-SUCCESS");
}
