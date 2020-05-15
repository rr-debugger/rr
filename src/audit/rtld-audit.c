#include "stap-note-iter.h"
#include "rtld-audit.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#define RR_IMPLEMENT_AUDIT
#include "../preload/preload_interface.h"

/* Some notes about audit libraries:
 *
 * Due to some libpthread bugs[0][1] (and probably others in other libraries)
 * not everything is safe to call from here. In particular, anything that calls
 * _dlerror_run or __dlerror (i.e., most/all of the public dlfcn functions)
 * will cause a TLS slot to be allocated more than once. Make sure nothing
 * calls pthread_key_create() outside of the main link namespace.
 *
 * Since gdb lacks support for multiple link namespaces[2], no debugging
 * information is available for audit libraries in gdb sessions by default. To
 * avoid debugging unannotated disassembly, we have to inform gdb about the
 * other libraries:
 *  - Run rr-record with '-v LD_DEBUG=files'. This will present output in the form
 *      <pid>:      file=libfoo.so [<link map id>];  needed by bar [<link map id>]
 *      <pid>:      file=libfoo.so [<link map id>];  generating link map
 *      <pid>:        dynamic: 0xxxxxxxxxxxxxxxxx  base: 0xxxxxxxxxxxxxxxxx  size:  0xxxxxxxxxxxxxxxxx
 *      <pid>:        entry:   0xxxxxxxxxxxxxxxxx  phdr: 0xxxxxxxxxxxxxxxxx  phnum:                 XX
 *    We're interested in entries with link map ID 1, assuming librraudit is
 *    first in the audit library list.
 *  - Load the library into gdb:
 *      (rr) add-symbol-file /path/to/libfoo.so -o <base address>
 *    Where <base address> is the value labelled 'base' above.
 *
 * [0]: https://sourceware.org/bugzilla/show_bug.cgi?id=24773#c1
 * [1]: https://sourceware.org/bugzilla/show_bug.cgi?id=24776
 * [2]: https://sourceware.org/bugzilla/show_bug.cgi?id=15971
 */

typedef struct {
  uintptr_t start, end;
} SemaphoreAddrRange;

extern __attribute__((visibility("hidden")))
long _raw_syscall(int syscallno, long a0, long a1, long a2,
                  long a3, long a4, long a5,
                  void* syscall_instruction,
                  long stack_param_1, long stack_param_2);

bool rr_audit_debug;

unsigned la_version(unsigned version) {
  rr_audit_debug = !!getenv("RR_AUDIT_DEBUG");
  return version;
}

static void semaphore_addr_range_init(SemaphoreAddrRange* range) {
  range->start = 0;
  range->end = 0;
}

static void semaphore_addr_range_init_single(SemaphoreAddrRange* range,
                                             uintptr_t addr) {
  range->start = addr;
  range->end = addr + sizeof(uint16_t);
}

static bool semaphore_addr_range_is_valid(const SemaphoreAddrRange* range) {
  return range->end > range->start;
}

static bool semaphore_addr_range_contains(const SemaphoreAddrRange* range,
                                          uintptr_t addr) {
  return addr >= range->start && addr < range->end;
}

static bool semaphore_addr_range_contiguous(const SemaphoreAddrRange* range,
                                            uintptr_t addr) {
  return addr + sizeof(uint16_t) == range->start || addr == range->end;
}

static void semaphore_addr_range_expand(SemaphoreAddrRange* range,
                                        uintptr_t addr) {
  if (addr < range->start) {
    range->start = addr;
  }
  if (addr + sizeof(uint16_t) > range->end) {
    range->end = addr + sizeof(uint16_t);
  }
}

static void semaphore_addr_range_submit(const SemaphoreAddrRange* range,
                                        int syscallno) {
  if (rr_audit_debug) {
    fprintf(stderr,
            "Submitting STap semaphore range: "
              "0x%" PRIxELFADDR "-0x%" PRIxELFADDR "\n",
            range->start, range->end);
  }
  _raw_syscall(syscallno,
               range->start, range->end,
               0, 0, 0, 0,
               RR_PAGE_SYSCALL_TRACED,
               0, 0);
}

static void semaphore_addr_range_handle_add(SemaphoreAddrRange* range,
                                            ElfW(Addr) address,
                                            int submit_syscallno) {
  if (semaphore_addr_range_contiguous(range, address)) {
    semaphore_addr_range_expand(range, address);
  } else {
    if (semaphore_addr_range_is_valid(range)) {
      semaphore_addr_range_submit(range, submit_syscallno);
    }
    semaphore_addr_range_init_single(range, address);
  }
}

unsigned la_objopen(struct link_map* map,
                    Lmid_t lmid,
                    uintptr_t* cookie __attribute__((unused))) {
  StapNoteIter iter;
  ElfStapNote note;
  SemaphoreAddrRange range;

  if (lmid != LM_ID_BASE) {
    return 0;
  }

  if (rr_audit_debug) {
    fprintf(stderr,
            "Processing STap semaphores for loaded object: %s\n",
            map->l_name);
  }

  semaphore_addr_range_init(&range);
  stap_note_iter_init(&iter, map);
  while (stap_note_iter_next(&iter, &note)) {
    if (note.semaphore_address &&
        !semaphore_addr_range_contains(&range, note.semaphore_address)) {
      uint16_t* semaphore = (void*) note.semaphore_address;
      if (rr_audit_debug) {
        fprintf(stderr,
                "Incrementing STap semaphore for %s:%s at "
                  "0x%" PRIxELFADDR " (was: %u)\n",
                note.provider_name, note.probe_name,
                note.semaphore_address,
                *semaphore);
      }
      (*semaphore)++;
      semaphore_addr_range_handle_add(&range,
                                      note.semaphore_address,
                                      SYS_rrcall_notify_stap_semaphore_added);
    }
  }
  stap_note_iter_release(&iter);

  if (semaphore_addr_range_is_valid(&range)) {
    semaphore_addr_range_submit(&range, SYS_rrcall_notify_stap_semaphore_added);
  }

  return 0;
}

unsigned la_objclose(uintptr_t* cookie) {
  StapNoteIter iter;
  ElfStapNote note;
  SemaphoreAddrRange range;

  /* The default value of cookie is the address of the link_map structure.
   * Since we don't modify the value in la_objopen, this should still be its
   * value. */
  const struct link_map* map = (void*) *cookie;

  /* ld.so never has its cookie value initialised, so map will be NULL.
   * However, none of its probes have associated semaphores so we can just
   * ignore it. */
  if (!map) {
    return 0;
  }

  if (rr_audit_debug) {
    fprintf(stderr,
            "Processing STap semaphores for closing object: %s\n",
            map->l_name);
  }

  semaphore_addr_range_init(&range);
  stap_note_iter_init(&iter, map);
  while (stap_note_iter_next(&iter, &note)) {
    if (note.semaphore_address &&
        !semaphore_addr_range_contains(&range, note.semaphore_address)) {
      uint16_t* semaphore = (void*) note.semaphore_address;
      if (rr_audit_debug) {
        fprintf(stderr,
                "Decrementing STap semaphore for %s:%s at "
                  "0x%" PRIxELFADDR " (was: %u)\n",
                note.provider_name, note.probe_name,
                note.semaphore_address,
                *semaphore);
      }
      assert(*semaphore != 0);
      (*semaphore)--;
      semaphore_addr_range_handle_add(&range,
                                      note.semaphore_address,
                                      SYS_rrcall_notify_stap_semaphore_removed);
    }
  }
  stap_note_iter_release(&iter);

  if (semaphore_addr_range_is_valid(&range)) {
    semaphore_addr_range_submit(&range,
                                SYS_rrcall_notify_stap_semaphore_removed);
  }

  return 0;
}
