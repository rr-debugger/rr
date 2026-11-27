/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "mmap.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <unistd.h>

#include <algorithm>

#include "remix.h"
#include "remix_util.h"

using namespace std;

static const uint32_t guard_pages = 1;

struct Page {
  char buf[PAGE_SIZE];
};

/**
 * Tools need to use mmap but we need to ensure that those mmaps are allocated entirely within the memory range
 * reserved for remix, otherwise they can collide with later application mappings.
 * This module takes care of that by implementing a simple allocator for virtual address space
 * within the remix module range and overriding mmap() to use it.
 *
 * A Node tracks the memory allocation status of some page range. The address and size of the range are
 * provided in context by `mem` and `pages` parameters.
 */
struct Node {
  // Both pointers are non-null unless max_continuous_free_pages is all the
  // pages for this node or 0.
  // If non-null, the Node for the first half of this range (the first pages/2 pages), or for a free Node,
  // the next free Node.
  Node* left;
  // If non-null, the Node for the rest of the range.
  Node* right;
  // The precise length of the longest range of continuous free pages covered by this Node.
  uint32_t max_continuous_free_pages;

  // The list of free Nodes.
  static Node* free_list;

  // We allocate pages for Nodes one at a time from this range.
  static Page* free_pages_next;
  // End of the range to use for Nodes; big enough to hold all Nodes
  // that might ever be needed.
  static Page* free_pages_end;

  static Node* allocate() {
    if (!free_list) {
      // Allocate another page of Nodes and add them to the free list.
      remix_assert(free_pages_next < free_pages_end);
      void* p = (void*)syscall(SYS_mmap, (long)free_pages_next, PAGE_SIZE,
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
      if (p != free_pages_next) {
        remix_abort("Node mmap failed");
      }
      ++free_pages_next;
      free_list = reinterpret_cast<Node*>(p);
      Node* n = free_list;
      while (reinterpret_cast<char*>(n + 2) <=
             reinterpret_cast<char*>(free_pages_next)) {
        n->left = n + 1;
        ++n;
      }
      n->left = nullptr;
    }
    Node* result = free_list;
    free_list = free_list->left;
    result->left = result->right = nullptr;
    result->max_continuous_free_pages = 0;
    return result;
  }
  void free() {
    left = free_list;
    free_list = this;
  }
};

Node* Node::free_list = nullptr;
Page* Node::free_pages_next = nullptr;
Page* Node::free_pages_end = nullptr;

/**
 * `node` covers `pages` pages starting at `mem`. Find the end of the last mapped page
 * managed by this node (or return the start of the range if there isn't one).
 */
static Page* find_mapped_pages_end(Node* node, Page* mem, uint32_t pages) {
  if (node->max_continuous_free_pages == pages) {
    return mem;
  }
  if (node->max_continuous_free_pages == 0) {
    return mem + pages;
  }
  if (node->right->max_continuous_free_pages < pages - pages / 2) {
    return find_mapped_pages_end(node->right, mem + pages / 2, pages - pages / 2);
  }
  return find_mapped_pages_end(node->left, mem, pages / 2);
}

/**
 * `node` covers `pages` pages starting at `mem`. Find the start of the first mapped page
 * managed by this node (or return the end of the range if there isn't one).
 */
static Page* find_mapped_pages_start(Node* node, Page* mem, uint32_t pages) {
  if (node->max_continuous_free_pages == 0) {
    return mem;
  }
  if (node->max_continuous_free_pages == pages) {
    return mem + pages;
  }
  if (node->left->max_continuous_free_pages < pages / 2) {
    return find_mapped_pages_start(node->left, mem, pages / 2);
  }
  return find_mapped_pages_start(node->right, mem + pages / 2, pages - pages / 2);
}

/**
 * `node` covers `pages` pages starting at `mem`. Compute the size of the
 * free page range that crosses the halfway point.
 */
static uint32_t count_free_pages_across_children(Node* node, Page* mem,
                                                 uint32_t pages) {
  remix_assert(node->left && node->right);
  Page* start = find_mapped_pages_end(node->left, mem, pages / 2);
  Page* end = find_mapped_pages_start(node->right, mem + pages / 2, pages - pages / 2);
  return end - start;
}

/**
 * `node` covers `pages` pages starting at `mem`. Find the start of a range of pages
 * of length `num_pages` (but don't allocate them).
 */
static Page* find_free_pages(Node* node, Page* mem, uint32_t pages,
                             uint32_t num_pages) {
  remix_assert(node->max_continuous_free_pages >= num_pages);
  remix_assert(num_pages > 0);
  if (node->max_continuous_free_pages == pages) {
    return mem;
  }
  if (node->left->max_continuous_free_pages >= num_pages) {
    return find_free_pages(node->left, mem, pages / 2, num_pages);
  }
  if (node->right->max_continuous_free_pages >= num_pages) {
    return find_free_pages(node->right, mem + pages / 2, pages - pages / 2, num_pages);
  }
  // The pages in our max_continuous_free_pages must be split across the node
  // boundary. Therefore, they must start at the end of the last mapped page of the left node.
  return find_mapped_pages_end(node->left, mem, pages / 2);
}

/**
 * `node` covers `pages` pages starting at `mem`. Update Node structures to indicate that
 * the range `start`..`end` is in use. These pages may or may not be currently allocated.
 */
static void allocate_pages(Node* node, Page* mem, uint32_t pages, Page* start,
                           Page* end) {
  if (start >= end || node->max_continuous_free_pages == 0) {
    return;
  }
  Page* mem_end = mem + pages;
  remix_assert(start >= mem && end <= mem_end);
  if (node->left) {
    remix_assert(node->right != nullptr);
  } else {
    remix_assert(!node->right);
    remix_assert(node->max_continuous_free_pages == pages);
    if (start == mem && end == mem_end) {
      node->max_continuous_free_pages = 0;
      return;
    } else {
      node->left = Node::allocate();
      node->left->max_continuous_free_pages = pages / 2;
      node->right = Node::allocate();
      node->right->max_continuous_free_pages = pages - pages / 2;
    }
  }
  allocate_pages(node->left, mem, pages / 2,
                 start, min(end, mem + pages / 2));
  allocate_pages(node->right, mem + pages / 2, pages - pages / 2,
                 max(mem + pages / 2, start), end);
  if (node->left->max_continuous_free_pages == 0 &&
      node->right->max_continuous_free_pages == 0) {
    node->left->free();
    node->right->free();
    node->left = node->right = nullptr;
    node->max_continuous_free_pages = 0;
    return;
  }
  node->max_continuous_free_pages = max(node->left->max_continuous_free_pages,
                                        node->right->max_continuous_free_pages);
  node->max_continuous_free_pages =
      max(node->max_continuous_free_pages,
          count_free_pages_across_children(node, mem, pages));
}

/**
 * `node` covers `pages` pages starting at `mem`. Update Node structures to indicate that
 * the range `start`..`end` is free. These pages may or may not be currently allocated.
 */
static void free_pages(Node* node, Page* mem, uint32_t pages, Page* start,
                       Page* end) {
  if (start >= end || node->max_continuous_free_pages == pages) {
    return;
  }
  Page* mem_end = mem + pages;
  remix_assert(start >= mem && end <= mem_end);
  if (node->left) {
    remix_assert(node->right != nullptr);
  } else {
    remix_assert(!node->right);
    remix_assert(node->max_continuous_free_pages == 0);
    if (start == mem && end == mem_end) {
      node->max_continuous_free_pages = pages;
      return;
    } else {
      node->left = Node::allocate();
      node->left->max_continuous_free_pages = 0;
      node->right = Node::allocate();
      node->right->max_continuous_free_pages = 0;
    }
  }
  free_pages(node->left, mem, pages / 2, start, min(end, mem + pages / 2));
  free_pages(node->right, mem + pages / 2, pages - pages / 2,
             max(mem + pages / 2, start), end);
  if (node->left->max_continuous_free_pages == pages / 2 &&
      node->right->max_continuous_free_pages == pages / 2) {
    node->left->free();
    node->right->free();
    node->left = node->right = nullptr;
    node->max_continuous_free_pages = pages;
    return;
  }
  node->max_continuous_free_pages = max(node->left->max_continuous_free_pages,
                                        node->right->max_continuous_free_pages);
  node->max_continuous_free_pages =
      max(node->max_continuous_free_pages,
          count_free_pages_across_children(node, mem, pages));
}

// The number of pages managed by the root node.
static uint32_t root_pages;
// Start of the memory region we use to service mmaps.
// The root Node manages `root_pages` pages of memory starting
// from here.
static Page* root_base;
// The root Node managing our range.
static Node* root_node;

void mmap_init(void* start, void* end) {
  remix_log(REMIX_LOG, "Initializing mmap region to %p - %p", start, end);

  Page* start_page = static_cast<Page*>(start);
  Page* end_page = static_cast<Page*>(end);
  // Calculate the maximum number of pages we will manage. This overcounts
  // because some of the pages will be Nodes.
  uint64_t max_pages = min<uint64_t>(1U << 31, end_page - start_page);
  // Maximum number of Nodes we might possibly need.
  uint64_t max_nodes_count = 2 * max_pages;
  // Number of pages we need to reserve for allocating Node objects.
  uint32_t nodes_pages = (max_nodes_count * sizeof(Node) + PAGE_SIZE - 1) / PAGE_SIZE;

  // Carve off the start of our range for Node objects.
  Node::free_pages_next = start_page;
  Node::free_pages_end = start_page + nodes_pages;
  root_base = Node::free_pages_end;

  root_node = Node::allocate();
  root_pages = max_pages - nodes_pages;
  root_node->max_continuous_free_pages = root_pages;
}

extern "C" {

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
  uint64_t pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
  if (pages > UINT32_MAX) {
    errno = ENOMEM;
    return MAP_FAILED;
  }
  if (((uintptr_t)addr & (PAGE_SIZE - 1)) || !pages) {
    errno = EINVAL;
    return MAP_FAILED;
  }
  Page* real_addr;
  void* map_end = root_base + root_pages;
  if (flags & MAP_FIXED) {
    if (addr < root_base || static_cast<uint8_t*>(addr) + length > map_end ||
        (uintptr_t)addr & (PAGE_SIZE - 1)) {
      remix_abort("Invalid mmap hint specified");
    }
    real_addr = static_cast<Page*>(addr);
  } else {
    if (pages + guard_pages * 2 > root_node->max_continuous_free_pages) {
      errno = ENOMEM;
      return MAP_FAILED;
    }
    real_addr = find_free_pages(root_node, root_base, root_pages,
                                pages + guard_pages * 2) + guard_pages;
  }
  remix_log(REMIX_LOG, "Allocating region at %p-%p", real_addr, (char*)real_addr + length);
  remix_assert(real_addr >= root_base && (char*)real_addr + length <= map_end);

  void* p = (void*)syscall(SYS_mmap, (long)real_addr, length, prot,
                           flags | MAP_FIXED, fd, offset);
  if (p != real_addr) {
    errno = -(intptr_t)p;
    return MAP_FAILED;
  }

  allocate_pages(root_node, root_base, root_pages, real_addr, real_addr + pages);
  return p;
}

void* mremap(void* old_addr, size_t old_size, size_t new_size, int flags, ...) {
  uint64_t pages = (new_size + PAGE_SIZE - 1) / PAGE_SIZE;
  if (pages > UINT32_MAX) {
    errno = ENOMEM;
    return MAP_FAILED;
  }
  if (((uintptr_t)old_addr & (PAGE_SIZE - 1)) || !pages) {
    errno = EINVAL;
    return MAP_FAILED;
  }
  remix_assert(flags == MREMAP_MAYMOVE);
  if (pages + guard_pages * 2 > root_node->max_continuous_free_pages) {
    errno = ENOMEM;
    return MAP_FAILED;
  }
  Page* new_addr =
      find_free_pages(root_node, root_base, root_pages, pages + guard_pages * 2) + guard_pages;

  void* p = (void*)syscall(SYS_mremap, (long)old_addr, old_size, new_size,
                           flags | MREMAP_FIXED, (long)new_addr);
  if (p != new_addr) {
    errno = -(intptr_t)p;
    return MAP_FAILED;
  }

  free_pages(root_node, root_base, root_pages, static_cast<Page*>(old_addr),
             static_cast<Page*>(old_addr) +
                 (old_size + PAGE_SIZE - 1) / PAGE_SIZE);
  allocate_pages(root_node, root_base, root_pages, new_addr, new_addr + pages);
  return p;
}

int munmap(void* addr, size_t length) {
  void* map_end = root_base + root_pages;
  remix_assert(addr >= root_base &&
               static_cast<uint8_t*>(addr) + length <= map_end);
  int ret = syscall(SYS_munmap, (long)addr, length, 0, 0, 0, 0);
  if (ret < 0) {
    errno = -ret;
    return -1;
  }
  free_pages(root_node, root_base, root_pages, static_cast<Page*>(addr),
             static_cast<Page*>(addr) + (length + PAGE_SIZE - 1) / PAGE_SIZE);
  return ret;
}
}
