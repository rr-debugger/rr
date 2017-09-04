/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include <asm/ldt.h>

int main(void) {
  uint32_t limit = 0x1234;
  struct user_desc desc = {.entry_number = 0,
                           .base_addr = 0x0,
                           .limit = limit,
                           .seg_32bit = 1,
                           .contents = 2,
                           .read_exec_only = 0,
                           .seg_not_present = 0,
                           .useable = 1 };
  test_assert(0 == syscall(SYS_modify_ldt, 0x11, &desc, sizeof(desc)));
  uint32_t new_limit = 0, has_limit = 0;
  uint32_t selector = (desc.entry_number << 3) | 0x4 /* LDT */ | 0x3 /* RPL */;
  asm("lsl %[selector], %[the_limit]\n\t"
      "jnz 1f\n\tmovl $1, %[has_limit]\n\t1:"
      : [the_limit] "=r"(new_limit), [has_limit] "+rm"(has_limit)
      : [selector] "r"(selector));
  test_assert(has_limit && new_limit == limit);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
