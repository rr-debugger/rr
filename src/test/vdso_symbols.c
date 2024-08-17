/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#if defined(__x86_64__) || defined(__aarch64__)
typedef Elf64_Ehdr Ehdr;
typedef Elf64_Shdr Shdr;
typedef Elf64_Sym Sym;
#else
typedef Elf32_Ehdr Ehdr;
typedef Elf32_Shdr Shdr;
typedef Elf32_Sym Sym;
#endif

static const char* find_string(Ehdr* ehdr, uintptr_t offset) {
  Shdr* strings = (Shdr*)((char*)ehdr + ehdr->e_shoff + ehdr->e_shstrndx*ehdr->e_shentsize);
  return (char*)ehdr + strings->sh_offset + offset;
}

static Shdr* find_section(Ehdr* ehdr, const char* name) {
  for (int i = 0; i < ehdr->e_shnum; ++i) {
    Shdr* hdr = (Shdr*)((char*)ehdr + ehdr->e_shoff + i*ehdr->e_shentsize);
    if (!strcmp(find_string(ehdr, hdr->sh_name), name)) {
      return hdr;
    }
  }
  return NULL;
}

#ifdef __aarch64__
#define PRELOAD_LIBRARY_PAGE_SIZE 65536
#else
#define PRELOAD_LIBRARY_PAGE_SIZE 4096
#endif

int main(void) {
  char* vdso = (char*)getauxval(AT_SYSINFO_EHDR);
  Ehdr* ehdr = (Ehdr*)vdso;
  Shdr* dynsym = find_section(ehdr, ".dynsym");
  if (!dynsym) {
    atomic_puts("dynsym not found in VDSO");
    return 1;
  }

  for (int si = 0; si*dynsym->sh_entsize < dynsym->sh_size; ++si) {
    Sym* sym = (Sym*)(vdso + dynsym->sh_offset) + si;
    // All symbols must be within the VDSO size, i.e. not the
    // absolute address. We assume the VDSO is less than 4 pages.
    test_assert(sym->st_value < 4*PRELOAD_LIBRARY_PAGE_SIZE);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
