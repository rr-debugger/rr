/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <asm/ldt.h>

int main(void) {

#if defined(__x86_64__)
  size_t page_size = sysconf(_SC_PAGESIZE);
  void* stack_limit = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, 0, 0);
  uint32_t stack32 = (uint32_t)((uint64_t)stack_limit + page_size);
  uint32_t result_eax = 0;
  uint32_t result_entry = 0;

  struct user_desc* parent_desc = (struct user_desc*)(uint64_t)(stack32 - 0x20);
  parent_desc->entry_number = -1;
  parent_desc->base_addr = stack32; /* ? */
  parent_desc->limit = -1;
  parent_desc->seg_32bit = 1;
  parent_desc->contents = 0;
  parent_desc->read_exec_only = 0;
  parent_desc->limit_in_pages = 0;
  parent_desc->seg_not_present = 0;
  parent_desc->useable = 1;

  asm volatile(
               /* set random value to $rcx */
               "mov $0xdeadbeefdeadbeef,%%rcx\n"

               /* prepare and switch to a 32-bit stack */
               "pushq %%rbx\n"
               "pushq %%r12\n"
               "movq %%rsp,%%r12\n"
               "movl %2,%%esp\n"
               "subl $0x20,%%esp\n"

               /* call SYS_set_thread_area and save results */
               "movl %%esp,%%ebx\n"
               "movl $0xf3,%%eax\n"
               "int $0x80\n"
               "movl %%eax,%0\n"
               "movl (%%rsp),%1\n"

               /* switch back to regular stack */
               "movq %%r12,%%rsp\n"
               "popq %%r12\n"
               "popq %%rbx\n"
               : "=r"(result_eax),"=r"(result_entry) : "r"(stack32) : "eax","rcx");

  atomic_printf("result_eax=%x result_entry=%x\n", result_eax, result_entry);

#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

