/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#include "Translation.h"

#include <string.h>
#include <sys/mman.h>

#include <algorithm>

#include "engine.h"
#include "remix.h"
#include "remix_util.h"

REMIX_TARGET_BEGIN

using namespace std;

Translation** pc_hash;

static Translation** pc_hashes_by_mode[TRANSLATION_MODES];
static uint8_t current_mode;

extern "C" {
// Each entry is 2*sizeof(byte*) so we have 4K entries */
struct IndirectJumpEntry {
  app_pc pc;
  Fragment translation;
};
IndirectJumpEntry indirect_jump_cache_0[INDIRECT_JUMP_CACHE_SIZE /
                                        sizeof(IndirectJumpEntry)] = {
  { (app_pc)0xdeadbeef, (Fragment)0xdeadbeef }
};
IndirectJumpEntry indirect_jump_cache_1[INDIRECT_JUMP_CACHE_SIZE /
                                        sizeof(IndirectJumpEntry)] = {
  { (app_pc)0xdeadbeef, (Fragment)0xdeadbeef }
};
IndirectJumpEntry* indirect_jump_cache;

// Return-address prediction stack.
// There are 16 entries. Each entry consists of two (quad)words:
// the app_pc return address, followed by the translated-code
// return address.
// The buffer is circular and entries start at odd elements!
void* return_address_stack_0[256/8] __attribute__((aligned(256)));
void* return_address_stack_1[256/8] __attribute__((aligned(256)));
void* return_address_stack[256/8] __attribute__((aligned(256)));
// Points to the end of the next entry to use for a call, so a "call"
// instruction would push on the correct translated-code return address.
// These all point within `return_address_stack`.
void** return_address_rsp_0;
void** return_address_rsp_1;
void** return_address_rsp;
}

static const int page_trie_fanout_bits = 4;
static const int page_trie_fanout = 1 << page_trie_fanout_bits;

/**
 * When this is set on a page, we have removed its PROT_WRITE permission
 * internally while the application thinks it's PROT_WRITE.
 * We maintain the invariant that no translation overlaps a page that's PROT_WRITE
 * and not PROT_WRITE_PROTECTED.
 */
static const uint8_t PROT_WRITE_PROTECTED = 0x80;

struct PageTrieNode {
  union {
    PageTrieNode* children[page_trie_fanout];
    Translation* translations[page_trie_fanout];
  };
  // prot[i] is valid if this is a leaf node or if !children[i]
  uint8_t prot[page_trie_fanout];
};
static PageTrieNode page_map;
// Pages are really 12 bits, but we treat them as 8 bits so that the maximum
// number of fragments starting in a page is 256.
// Consequently the last-level PageTrieNode covers 16 entries that all belong to the same hardware page.
static const int page_bits = 8;
// actually only 47 but we want the division below to not truncate
static const int trie_address_space_bits = 48;
// Nine levels is quite deep but we don't use the page trie in hot code,
// hopefully.
static const int page_trie_levels =
    (trie_address_space_bits - page_bits) / page_trie_fanout_bits;
static uint64_t translations_count_;

static PageTrieNode* alloc_page_trie_node(int prot) {
  PageTrieNode* node = new PageTrieNode();
  memset(node, 0, sizeof(PageTrieNode));
  memset(node->prot, prot, page_trie_fanout);
  return node;
}

static Translation** find_page_trie_entry_for_insert(uintptr_t pc_page) {
  PageTrieNode* node = &page_map;
  for (int level = page_trie_levels - 1; level >= 1; --level) {
    int index =
        (pc_page >> (level * page_trie_fanout_bits)) & (page_trie_fanout - 1);
    PageTrieNode** n = &node->children[index];
    if (!*n) {
      *n = alloc_page_trie_node(node->prot[index]);
    }
    node = *n;
  }
  int index = pc_page & (page_trie_fanout - 1);
  uint8_t prot = node->prot[index];
  if (!(prot & PROT_EXEC)) {
    remix_abort("Running code in a non-executable page");
  }
  if ((prot & PROT_WRITE) && !(prot & PROT_WRITE_PROTECTED)) {
    mprotect((void*)((pc_page << page_bits) & ~(uint64_t)(PAGE_SIZE - 1)), PAGE_SIZE, prot & ~PROT_WRITE);
    // *ALL* these entries are write-protected
    for (int i = 0; i < page_trie_fanout; ++i) {
      node->prot[i] |= PROT_WRITE_PROTECTED;
    }
  }
  return &node->translations[index];
}

static uint8_t get_page_prot(uintptr_t pc_page) {
  PageTrieNode* node = &page_map;
  for (int level = page_trie_levels - 1; level >= 1; --level) {
    int index =
        (pc_page >> (level * page_trie_fanout_bits)) & (page_trie_fanout - 1);
    PageTrieNode* n = node->children[index];
    if (!n) {
      return node->prot[index];
    }
    node = n;
  }
  int index = pc_page & (page_trie_fanout - 1);
  return node->prot[index];
}

uint8_t Translation::get_prot(app_pc pc) {
  return get_page_prot(uintptr_t(pc) >> page_bits) & ~PROT_WRITE_PROTECTED;
}

uint8_t Translation::get_hw_prot(app_pc pc) {
  uint8_t prot = get_page_prot(uintptr_t(pc) >> page_bits);
  if (prot & PROT_WRITE_PROTECTED) {
    prot &= ~(PROT_WRITE | PROT_WRITE_PROTECTED);
  }
  return prot;
}

void Translation::switch_to_translation_mode(uint8_t mode) {
  remix_assert(mode < TRANSLATION_MODES);

  if (return_address_rsp) {
    switch (current_mode) {
      case 0:
        memcpy(return_address_stack_0, return_address_stack, sizeof(return_address_stack));
        return_address_rsp_0 = return_address_rsp;
        break;
      case 1:
        memcpy(return_address_stack_1, return_address_stack, sizeof(return_address_stack));
        return_address_rsp_1 = return_address_rsp;
        break;
      default:
        remix_abort("invalid mode");
        break;
    }
  }

  current_mode = mode;

  pc_hash = pc_hashes_by_mode[mode];
  if (!pc_hash) {
    Translation** tp = static_cast<Translation**>(
        mmap(nullptr, sizeof(Translation*) * PC_HASH_SIZE,
             PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    if (tp == MAP_FAILED) {
      remix_abort("mmap failed");
    }
    pc_hash = pc_hashes_by_mode[mode] = tp;
  }

  switch (mode) {
    case 0:
      indirect_jump_cache = indirect_jump_cache_0;
      memcpy(return_address_stack, return_address_stack_0, sizeof(return_address_stack));
      return_address_rsp = return_address_rsp_0;
      break;
    case 1:
      indirect_jump_cache = indirect_jump_cache_1;
      memcpy(return_address_stack, return_address_stack_1, sizeof(return_address_stack));
      return_address_rsp = return_address_rsp_1;
      break;
    default:
      remix_abort("invalid mode");
      break;
  }
}

uint64_t Translation::translations_count() { return translations_count_; }

uint8_t Translation::translation_mode() { return current_mode; }

Translation* Translation::insert(app_pc pc, uint8_t pc_len,
                                 Fragment translation) {
  Translation* t = new Translation();
  ++translations_count_;
  t->pc = pc;
  t->pc_len = pc_len;
  t->translation = translation;
  t->mode = current_mode;
  t->is_visited_pc = ::is_visited_pc(pc);

  Translation** ptr = &pc_hash[hash(pc)];
  t->next_by_pc = *ptr;
  remix_assert(!*ptr || (*ptr)->pc != pc);
  *ptr = t;

  ptr = find_page_trie_entry_for_insert(uintptr_t(pc) >> page_bits);
  t->next_by_pc_page = *ptr;
  *ptr = t;

  app_pc last_byte = pc + pc_len - 1;
  if (floor_page_size(last_byte) != floor_page_size(pc)) {
    // fragment crosses page boundary. Make sure page is properly protected.
    find_page_trie_entry_for_insert(uintptr_t(last_byte) >> page_bits);
  }
  return t;
}

struct BaseParams {
  // Translations overlapping this range are deleted.
  app_pc start_pc;
  app_pc end_pc;
  InvalidateTranslatedCodeParam* param;
};

struct UpdateProtParams {
  BaseParams base;
  int prot;
};

static void delete_translation_chain(Translation** node_translations,
                                     const BaseParams& params) {
  Translation** ptr = node_translations;
  while (*ptr) {
    Translation* t = *ptr;
    if (max(t->pc_start(), params.start_pc) < min(t->pc_end(), params.end_pc)) {
      if (params.param) {
        invalidate_translated_code(t, params.param);
      }

      *ptr = t->next_by_pc_page;

      Translation** hptr =
          &pc_hashes_by_mode[t->mode][Translation::hash(t->pc_start())];
      while (*hptr != t) {
        hptr = &(*hptr)->next_by_pc;
      }
      *hptr = t->next_by_pc;
      delete t;
      --translations_count_;
    } else {
      ptr = &(*ptr)->next_by_pc_page;
    }
    // This does not delete the translation from the indirect branch
    // cache. That's OK since it's just a two-jump penalty every time
    // that cache entry is used, and hopefully it will eventually get
    // replaced.
  }
}

static bool update_prot_page_trie(PageTrieNode* node, int level,
                                  uintptr_t start_page, uintptr_t end_page,
                                  UpdateProtParams& params) {
  uintptr_t level_bits = level * page_trie_fanout_bits;
  bool occupied = false;
  for (int i = 0; i < page_trie_fanout; ++i) {
    uintptr_t entry_start = uintptr_t(i) << level_bits;
    uintptr_t entry_end = uintptr_t(i + 1) << level_bits;
    if (max(entry_start, start_page) < min(entry_end, end_page)) {
      if (level == 0) {
        if (params.prot & PROT_WRITE) {
          delete_translation_chain(&node->translations[i], params.base);
        }
        node->prot[i] = params.prot & (PROT_READ | PROT_WRITE | PROT_EXEC);
      } else {
        PageTrieNode* n = node->children[i];
        uintptr_t in_node_start = max(start_page, entry_start) - entry_start;
        uintptr_t in_node_end = min(end_page, entry_end) - entry_start;
        if (n) {
          if (!update_prot_page_trie(n, level - 1, in_node_start, in_node_end,
                                     params)) {
            node->prot[i] = params.prot & (PROT_READ | PROT_WRITE | PROT_EXEC);
            delete n;
            node->children[i] = nullptr;
          }
        } else if (node->prot[i] != params.prot) {
          if (in_node_start > 0 || in_node_end < (uintptr_t(1) << level_bits)) {
            n = node->children[i] = alloc_page_trie_node(node->prot[i]);
            update_prot_page_trie(n, level - 1, in_node_start, in_node_end,
                                  params);
          } else {
            node->prot[i] = params.prot & (PROT_READ | PROT_WRITE | PROT_EXEC);
          }
        }
      }
    }
    if ((level == 0 ? (void*)node->translations[i]
                    : (void*)node->children[i]) ||
        node->prot[i] != node->prot[0] ||
        node->prot[i] & PROT_WRITE_PROTECTED) {
      occupied = true;
    }
  }
  return occupied;
}

void Translation::notify_prot(app_pc start, app_pc end, int prot, InvalidateTranslatedCodeParam* param) {
  UpdateProtParams params = { { start, end, param }, prot };
  update_prot_page_trie(
      &page_map, page_trie_levels - 1, uintptr_t(start) >> page_bits,
      min(uintptr_t(1) << trie_address_space_bits, uintptr_t(end)) >> page_bits,
      params);

  if (prot & PROT_WRITE) {
    // Any translations starting in the previous page and extending into |start|
    // must be invalidated.
    delete_overlapping(start, start + 1, param);
  }
}

/* Returns true if |node| is still occupied */
static bool delete_overlapping_via_page_trie(PageTrieNode* node, int level,
                                             uintptr_t start_page,
                                             uintptr_t end_page,
                                             const BaseParams& params) {
  uintptr_t level_bits = level * page_trie_fanout_bits;
  bool occupied = false;
  for (int i = 0; i < page_trie_fanout; ++i) {
    uintptr_t entry_start = uintptr_t(i) << level_bits;
    uintptr_t entry_end = uintptr_t(i + 1) << level_bits;
    if (max(entry_start, start_page) < min(entry_end, end_page)) {
      if (level == 0) {
        delete_translation_chain(&node->translations[i], params);
      } else {
        PageTrieNode* n = node->children[i];
        if (n) {
          if (!delete_overlapping_via_page_trie(
                  n, level - 1, max(start_page, entry_start) - entry_start,
                  min(end_page, entry_end) - entry_start, params)) {
            node->prot[i] = n->prot[0];
            delete n;
            node->children[i] = nullptr;
          }
        }
      }
    }
    if ((level == 0 ? (void*)node->translations[i]
                    : (void*)node->children[i]) ||
        node->prot[i] != node->prot[0] ||
        node->prot[i] & PROT_WRITE_PROTECTED) {
      occupied = true;
    }
  }
  return occupied;
}

void Translation::delete_overlapping(app_pc start, app_pc end, InvalidateTranslatedCodeParam* param) {
  BaseParams params = { start, end, param };
  delete_overlapping_via_page_trie(
      &page_map, page_trie_levels - 1,
      // May need to look one page earlier to find translations that start
      // in the earlier page and extend into our page
      (max<uintptr_t>(uintptr_t(start), MAX_BYTES_PER_FRAGMENT - 1) -
       (MAX_BYTES_PER_FRAGMENT - 1)) >>
          page_bits,
      min(uintptr_t(1) << trie_address_space_bits,
          uintptr_t(end) + ((1 << page_bits) - 1)) >>
          page_bits,
      params);
}

static void remove_write_protection_internal(uintptr_t pc_page) {
  PageTrieNode* node = &page_map;
  // All pages we write-protected have last-level entries in the trie.
  for (int level = page_trie_levels - 1; level >= 1; --level) {
    int index =
        (pc_page >> (level * page_trie_fanout_bits)) & (page_trie_fanout - 1);
    PageTrieNode** n = &node->children[index];
    remix_assert(n && *n);
    node = *n;
  }
  uint8_t prot = node->prot[0];
  remix_assert((prot & (PROT_WRITE | PROT_EXEC | PROT_WRITE_PROTECTED)) ==
               (PROT_WRITE | PROT_EXEC | PROT_WRITE_PROTECTED));
  for (int i = 0; i < page_trie_fanout; ++i) {
    // All "pages" in the last level node belong to the same hardware page so
    // must have the same protection.
    remix_assert(prot == node->prot[i]);
    node->prot[i] &= ~PROT_WRITE_PROTECTED;
  }
  prot &= ~PROT_WRITE_PROTECTED;
  mprotect((void*)((pc_page << page_bits) & ~(uint64_t)(PAGE_SIZE - 1)), PAGE_SIZE, prot);
}

WriteProtectionRemovedRange Translation::remove_write_protection(app_pc fault_address, InvalidateTranslatedCodeParam* param) {
  app_pc start = floor_page_size(fault_address);
  // Invalidate instructions and unprotect the page
  remove_write_protection_internal(uintptr_t(start) >> page_bits);
  delete_overlapping(start, start + PAGE_SIZE, param);
  return WriteProtectionRemovedRange {
    start, start + PAGE_SIZE,
  };
}

static void remove_all_write_protection_via_trie(PageTrieNode* node, int level,
                                                 uintptr_t node_addr) {
  if (level == 0) {
    // All "pages" in the last level node belong to the same hardware page so
    // must have the same protection.
    uint8_t prot = node->prot[0];
    for (int i = 0; i < page_trie_fanout; ++i) {
      remix_assert(prot == node->prot[i]);
      node->prot[i] &= ~PROT_WRITE_PROTECTED;
    }
    if (prot & PROT_WRITE_PROTECTED) {
      prot &= ~PROT_WRITE_PROTECTED;
      mprotect((void*)node_addr, PAGE_SIZE, prot);
    }
    return;
  }
  uintptr_t node_bits = level * page_trie_fanout_bits + page_bits;
  for (int i = 0; i < page_trie_fanout; ++i) {
    PageTrieNode* n = node->children[i];
    if (n) {
      remove_all_write_protection_via_trie(n, level - 1,
               node_addr + (uintptr_t(i) << node_bits));
    }
  }
}

void Translation::dump_translation_chain_lengths() {
  if (!(remix_log_modules & REMIX_LOG)) {
    return;
  }

  int max_chain_length = 0;
  int entries = 0;
  long long total_chain_lengths = 0;
  Translation** chains = pc_hashes_by_mode[0];
  for (size_t i = 0; i < PC_HASH_SIZE; ++i) {
    Translation* c = chains[i];
    if (c) {
      int len = 0;
      while (c) {
        ++len;
        total_chain_lengths += len;
        c = c->next_by_pc;
      }
      if (len > max_chain_length) {
        max_chain_length = len;
      }
      entries += len;
    }
  }
  remix_log(REMIX_LOG, "Max chain length = %d, average chain length = %f",
            max_chain_length,
            double(total_chain_lengths)/entries);
}

void Translation::remove_all_write_protection() {
  remove_all_write_protection_via_trie(&page_map, page_trie_levels - 1,
                                       0);
}

static void reset_return_address_stacks() {
  // This is a non-canonical address. A ret instruction can't retire to set the PC
  // to this address, so we will never look it up via a ret instruction in the replay,
  // and thus the return-address-stack entry will never be used.
  void* non_canonical_address = reinterpret_cast<void*>((uint64)1 << 63);
  // Overwrite the app_pc fields with the non-canonical address.
  for (int i = 1; i < 256/8; i += 2) {
    return_address_stack[i] = non_canonical_address;
  }
  memcpy(return_address_stack_0, return_address_stack, sizeof(return_address_stack));
  memcpy(return_address_stack_1, return_address_stack, sizeof(return_address_stack));
}

static void reset_indirect_jump_cache(IndirectJumpEntry* cache) {
  memset(cache, 0, INDIRECT_JUMP_CACHE_SIZE);
  // Prime the null slot with an invalid pointer so 0 doesn't trigger a
  // cache hit.
  cache[0].pc = (app_pc)0xdeadbeef;
  cache[0].translation = (Fragment)0xdeadbeef;
}

void Translation::init() {
  // The first return address pushed by a call will be stored in the bottom half of the last entry.
  return_address_rsp_0 = return_address_stack + 256/8 - 1;
  return_address_rsp_1 = return_address_stack + 256/8 - 1;
  switch_to_translation_mode(0);
  reset_return_address_stacks();
}

void Translation::delete_all() {
  delete_overlapping(nullptr, (app_pc)(uintptr_t(1) << trie_address_space_bits),
                     nullptr);
  reset_indirect_jump_cache(indirect_jump_cache_0);
  reset_indirect_jump_cache(indirect_jump_cache_1);
  reset_return_address_stacks();
}

void Translation::refill_indirect_jump_cache(app_pc pc, GeneratedCode* code) {
  uintptr_t index = uintptr_t(pc) &
                    (INDIRECT_JUMP_CACHE_SIZE / sizeof(IndirectJumpEntry) - 1);
  indirect_jump_cache[index].pc = pc;
  indirect_jump_cache[index].translation = code;
}

REMIX_TARGET_END
