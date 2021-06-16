/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifdef __x86_64__
static int found_dyn(Elf64_Dyn* dyn, Elf64_Sxword tag) {
  while (dyn->d_tag != DT_NULL) {
    if (dyn->d_tag == tag) {
      return 1;
    }
    ++dyn;
  }
  return 0;
}
#endif

int main(void) {
#ifdef __x86_64__
  char* vdso = (char*)getauxval(AT_SYSINFO_EHDR);
  Elf64_Ehdr* ehdr = (Elf64_Ehdr*)vdso;
  Elf64_Phdr* dynamic = NULL;
  for (int i = 0; i < ehdr->e_phnum; ++i) {
    Elf64_Phdr* phdr = (Elf64_Phdr*)(vdso + ehdr->e_phoff + i*ehdr->e_phentsize);
    if (phdr->p_type == PT_DYNAMIC) {
      dynamic = phdr;
      break;
    }
  }
  if (!dynamic) {
    atomic_puts("PT_DYNAMIC not found in VDSO");
    return 1;
  }
  Elf64_Dyn* dyn = (Elf64_Dyn*)(vdso + dynamic->p_offset);
  test_assert(found_dyn(dyn, DT_HASH));
  test_assert(found_dyn(dyn, DT_SYMTAB));
  test_assert(found_dyn(dyn, DT_STRTAB));
  test_assert(found_dyn(dyn, DT_VERSYM));
  test_assert(found_dyn(dyn, DT_VERDEF));
  test_assert(found_dyn(dyn, DT_VERDEFNUM));
  test_assert(found_dyn(dyn, DT_STRSZ));
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
