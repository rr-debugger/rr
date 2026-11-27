/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TRANSLATION_H_
#define RR_TRANSLATION_H_

#include <new>
#include <stdint.h>
#include <stdlib.h>
#include <sys/user.h>

#include "dr_api.h"

#include "Assembler.h"
#include "fragment_stubs.h"

typedef GeneratedCode* Fragment;

struct InvalidateTranslatedCodeParam;
class Translation;

extern "C" {
extern Translation** pc_hash;
extern void** return_address_rsp;
}

struct WriteProtectionRemovedRange {
  app_pc start, end;
};

/**
 * A Translation represents a translation of application code in the range
 * [pc_start(), pc_end()) to generated code starting at translation_start().
 *
 * We support mapping from a range in application memory to all the Translations
 * overlapping that range, and a faster map from a specific PC value to
 * the Translation (if any) starting at that PC.
 *
 * Keep in sync with indirect_jump_stub_slow_path!
 */
class Translation {
public:
  static void init();

  // This can be called by tools "when it's safe to change engine state".
  // Translations with different modes are independent. Only translations in
  // mode 0 represent normal replay! Only translations in mode 0 update the
  // rcb counter.
  static void switch_to_translation_mode(uint8_t mode);

  static uint8_t translation_mode();

  static Translation* insert(app_pc pc, uint8_t pc_len, Fragment translation);

  static Fragment lookup(app_pc pc) {
    Translation* t = pc_hash[hash(pc)];
    while (t) {
      if (t->pc == pc) {
        return t->translation;
      }
      t = t->next_by_pc;
    }
    return nullptr;
  }

  /**
   * Deletes all the Translations that overlap [start,end).
   * If `param` is null then the `invalidate_translated_code` is not called.
   */
  static void delete_overlapping(app_pc start, app_pc end, InvalidateTranslatedCodeParam* param);

  /**
   * We maintain a record of all the mapped regions with their prot bits
   * (though we don't distinguish unmapped from mapped-with-PROT_NONE).
   * Call this whenever a system call has changed the protection of a region.
   * This can invalidate Translations.
   * |start| and |end| must be page-aligned.
   */
  static void notify_prot(app_pc start, app_pc end, int prot, InvalidateTranslatedCodeParam* param);

  /* Return the prot bits from the application's perspective. */
  static uint8_t get_prot(app_pc pc);
  /* Return the prot bits actually in use at the kernel/hardware level. */
  static uint8_t get_hw_prot(app_pc pc);

  /**
   * Called when we have a SIGSEGV for the given address and the
   * page is logically PROT_WRITE | PROT_EXEC. Since we don't execute
   * code from application pages, this must be a write to a PROT_WRITE_PROTECTED
   * page. We remove PROT_WRITE_PROTECTION, making the page writeable again,
   * and invalidating all associated translations.
   */
  static WriteProtectionRemovedRange remove_write_protection(app_pc fault_address, InvalidateTranslatedCodeParam* param);
  /**
   * Called before the module is unloaded. Unprotect all PROT_WRITE_PROTECTED pages.
   */
  static void remove_all_write_protection();
  /**
   * Does not delete prot data.
   */
  static void delete_all();

  /**
   * Dump translation chain lengths.
   */
  static void dump_translation_chain_lengths();

  /**
   * Returns count of current non-invalidated translations.
   */
  static uint64_t translations_count();

  static void refill_indirect_jump_cache(app_pc pc, GeneratedCode* code);

  app_pc pc_start() const { return pc; }
  app_pc pc_end() const { return pc + pc_len; }
  uint8_t pc_length() const { return pc_len; }

  GeneratedCode* translation_start() const { return translation; }

  enum { MAX_APP_LEN = 255 };

  static uint32_t hash(app_pc pc) {
    return (uintptr_t(pc) * PC_HASH_MULTIPLICAND >> PC_HASH_SHIFT) &
           (PC_HASH_SIZE - 1);
  }

  // The offsets of these fields are hardcoded in fragment_stubs.S as
  // Translation_*.
  // Put all the fields indirect_jump_slow_path cares about together.
  app_pc pc;
  Fragment translation;
  Translation* next_by_pc;
  // When this is set, we must return to the control loop before executing
  // this fragment.
  uint8_t is_visited_pc;

  uint8_t pc_len;
  uint8_t mode;
  Translation* next_by_pc_page;
};

#endif /* RR_TRANSLATION_H_ */
