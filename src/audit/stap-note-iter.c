#include "stap-note-iter.h"
#include "rtld-audit.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

/* For more information about what's going on in here, see
 * https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation */

#define ALIGN_UP(x, p2) \
  (((x) & ((p2) - 1)) == 0 ? (x) : ((x) + (p2)) & ~((p2) - 1))

/* rtld doesn't mark itself as initialised until after it's loaded all the
 * initially required objects. dladdr() checks this flag, and when not set it
 * delegates functionality to dlfcn_hook; in our case no such hook is
 * installed, so it segfaults trying.
 *
 * This is the function dladdr() normally calls into. The signature doesn't
 * seem to have changed since at least 2007, so redeclaring it here is probably
 * relatively safe. */
extern int _dl_addr(const void* address, Dl_info* info,
                    struct link_map** mapp, const ElfW(Sym)** symbolp);

static void* stap_note_iter_map(StapNoteIter* self,
                                size_t offset, size_t size) {
  void* map;
  size_t requested_offset = offset;
  size_t slack;

  if (self->fd == -1) {
    const char* path = self->map->l_name;

    if (*path == '\0') {
      path = "/proc/self/exe";
    }

    if ((self->fd = open(path, O_RDONLY)) == -1) {
      if (rr_audit_debug) {
        fprintf(stderr, "Failed to open '%s': %s\n", path, strerror(errno));
      }
      return NULL;
    }
  }

  offset &= ~(sysconf(_SC_PAGE_SIZE) - 1);
  slack = requested_offset - offset;
  size += slack;
  map = mmap(NULL, size, PROT_READ, MAP_SHARED, self->fd, offset);
  if (map == MAP_FAILED) {
    if (rr_audit_debug) {
      fprintf(stderr,
              "Failed to map 0x%" PRIxELFADDR "+0x%" PRIxELFADDR
                " from '%s': %s\n",
              offset, size,
              self->map->l_name,
              strerror(errno));
    }
    return NULL;
  }

  return (char*) map + slack;
}

static void stap_note_iter_unmap(StapNoteIter* self __attribute__((unused)),
                                 void* data, size_t size) {
  uintptr_t data_addr = (uintptr_t) data;
  void* page = (void*) (data_addr & ~(sysconf(_SC_PAGE_SIZE) - 1));
  size += (char*) data - (char*) page;
  munmap(page, size);
}

void stap_note_iter_init(StapNoteIter* self, const struct link_map* map) {
  const ElfW(Ehdr)* ehdr;
  const ElfW(Shdr) *shstrtab_hdr, *shdr_iter;
  const char* shstrtab;

  memset(self, '\0', sizeof(*self));
  self->fd = -1;

  self->map = map;

  {
    /* We want the image base address. Kind of round-about, but it works.
     *
     * A warning about anyone thinking about alternate approaches: The initial
     * implementation of this used dl_phdr_info::dlpi_addr[0], but this
     * approach was changed since the documentation of the field doesn't appear
     * to be correct[1].
     *
     * [0]: dl_iterate_phdr(3)
     * [1]: https://bugzilla.kernel.org/show_bug.cgi?id=205837 */
    Dl_info info;
    if (!_dl_addr((void*) map->l_ld, &info, NULL, NULL)) {
      if (rr_audit_debug) {
        fprintf(stderr, "Base address lookup for '%s' failed\n", map->l_name);
      }
      return;
    }
    self->base = info.dli_fbase;
  }

  ehdr = self->base;

  assert(ehdr->e_shentsize == sizeof(ElfW(Shdr)));

  self->shdrs = stap_note_iter_map(self,
                                   ehdr->e_shoff,
                                   ehdr->e_shnum * sizeof(ElfW(Shdr)));
  if (!self->shdrs) {
    if (rr_audit_debug) {
      fprintf(stderr, "Mapping section headers for '%s' failed\n", map->l_name);
    }
    return;
  }

  self->shdr_iter = self->shdrs;
  self->shdr_end = self->shdrs + ehdr->e_shnum;

  assert(ehdr->e_shstrndx < ehdr->e_shnum);
  shstrtab_hdr = self->shdrs + ehdr->e_shstrndx;
  shstrtab = stap_note_iter_map(self,
                                shstrtab_hdr->sh_offset,
                                shstrtab_hdr->sh_size);
  if (!shstrtab) {
    if (rr_audit_debug) {
      fprintf(stderr,
              "Mapping section string table for '%s' failed\n",
              map->l_name);
    }
    return;
  }

  /* STap notes store the link-time memory address of the .stapsdt.base section
   * within the note, allowing us to relocate addresses in the note by finding
   * the difference between this value and the real run-time address of the
   * section. */
  for (shdr_iter = self->shdrs; shdr_iter < self->shdr_end; shdr_iter++) {
    if (strcmp(shstrtab + shdr_iter->sh_name, ".stapsdt.base") == 0) {
      break;
    }
  }

  if (shdr_iter < self->shdr_end) {
    self->stapbase = self->map->l_addr + shdr_iter->sh_addr;
  }

  stap_note_iter_unmap(self, (void*) shstrtab, shstrtab_hdr->sh_size);
}

bool stap_note_iter_next(StapNoteIter* self, ElfStapNote* out_note) {
  /* did the initialisation fail? */
  if (!self->stapbase) {
    return false;
  }

  if (!self->note_data) {
    /* ran out of note data, mmap the next note section */
    for (; self->shdr_iter < self->shdr_end; self->shdr_iter++) {
      if (self->shdr_iter->sh_type == SHT_NOTE) {
        break;
      }
    }

    if (self->shdr_iter == self->shdr_end) {
      return false;
    }
    assert(self->shdr_iter < self->shdr_end);
    assert(self->shdr_iter->sh_type == SHT_NOTE);

    self->note_data = stap_note_iter_map(self,
                                         self->shdr_iter->sh_offset,
                                         self->shdr_iter->sh_size);
    if (!self->note_data) {
      if (rr_audit_debug) {
        fprintf(stderr, "Mapping note data failed\n");
      }
      return false;
    }
  }

  while (self->note_data_offset + sizeof(ElfW(Nhdr))
          < self->shdr_iter->sh_size) {
    const ElfW(Nhdr)* nhdr;
    const char* name = NULL;
    const void* desc = NULL;

    nhdr = (void*) ((char*) self->note_data + self->note_data_offset);
    self->note_data_offset += sizeof(*nhdr);

    if (nhdr->n_namesz) {
      name = (char*) self->note_data + self->note_data_offset;
      self->note_data_offset += ALIGN_UP(nhdr->n_namesz, 4);
    }

    if (nhdr->n_descsz) {
      desc = (char*) self->note_data + self->note_data_offset;
      self->note_data_offset += ALIGN_UP(nhdr->n_descsz, 4);
    }

    if (!name || strcmp(name, "stapsdt") != 0 || nhdr->n_type != 3) {
      continue;
    }

    out_note->probe_address = *(ElfW(Addr)*) desc;
    desc = (char*) desc + sizeof (ElfW(Addr));
    out_note->base_address = *(ElfW(Addr)*) desc;
    desc = (char*) desc + sizeof (ElfW(Addr));
    out_note->semaphore_address = *(ElfW(Addr)*) desc;
    desc = (char*) desc + sizeof (ElfW(Addr));

    /* relocate addresses */
    out_note->probe_address += self->stapbase - out_note->base_address;
    if (out_note->semaphore_address) {
      out_note->semaphore_address += self->stapbase - out_note->base_address;
    }

    out_note->provider_name = desc;
    desc = out_note->provider_name + strlen(out_note->provider_name) + 1;
    out_note->probe_name = desc;
    desc = out_note->probe_name + strlen(out_note->probe_name) + 1;
    out_note->argument_format = desc;

    return true;
  }

  /* We've exhausted the note data in the currently mapped section. Unmap it
   * and try again with the next note section. */
  stap_note_iter_unmap(self, self->note_data, self->shdr_iter->sh_size);
  self->shdr_iter++;
  self->note_data = NULL;
  self->note_data_offset = 0;
  return stap_note_iter_next(self, out_note);
}

void stap_note_iter_release(StapNoteIter* self) {
  if (self->note_data) {
    stap_note_iter_unmap(self, self->note_data, self->shdr_iter->sh_size);
  }
  if (self->shdrs) {
    stap_note_iter_unmap(self,
                         (void*) self->shdrs,
                         (char*) self->shdr_end - (char*) self->shdrs);
  }
  if (self->fd != -1) {
    close(self->fd);
  }
  memset(self, '\0', sizeof(*self));
  self->fd = -1;
}
