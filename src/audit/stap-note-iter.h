#ifndef __RR_STAP_NOTE_ITER_H__
#define __RR_STAP_NOTE_ITER_H__

#define _GNU_SOURCE
#include <stdbool.h>
#include <link.h>

typedef struct {
  ElfW(Addr) probe_address;
  ElfW(Addr) base_address;
  ElfW(Addr) semaphore_address;
  const char* provider_name;
  const char* probe_name;
  const char* argument_format;
} ElfStapNote;

typedef struct {
  /*< private >*/
  const struct link_map* map;
  const void* base;
  int fd;
  uintptr_t stapbase;
  const ElfW(Shdr) *shdrs, *shdr_iter, *shdr_end;
  void* note_data;
  size_t note_data_offset;
} StapNoteIter;

void stap_note_iter_init(StapNoteIter* iter, const struct link_map* map);

bool stap_note_iter_next(StapNoteIter* iter, ElfStapNote* out_note);

void stap_note_iter_release(StapNoteIter* iter);

#endif
