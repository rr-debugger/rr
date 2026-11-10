/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Threads exit with robust futex lists of futexes that hold their tids. When
   a task exits, the kernel walks its list: it marks each such futex
   FUTEX_OWNER_DIED (and wakes a waiter), handles list_op_pending last, and
   gives up on the list at an entry or futex it can't access, at a misaligned
   futex and after ROBUST_LIST_LIMIT entries. */

struct entry {
  struct robust_list list;
  uint32_t futex;
};

struct list {
  struct robust_list_head head;
  struct entry pending;
};

static struct list fault_list;
static struct entry fault_entry;
static struct robust_list_head read_only_head;
static struct robust_list_head misaligned_head;
static char misaligned[64] __attribute__((aligned(8)));
static struct robust_list_head long_head;
static struct entry long_entries[ROBUST_LIST_LIMIT + 1];
static struct list wake_list;
static int wake_list_registered;
static pid_t thread_tid;

static uint32_t load(uint32_t* futex) {
  return __atomic_load_n(futex, __ATOMIC_SEQ_CST);
}

static void store(uint32_t* futex, uint32_t value) {
  __atomic_store_n(futex, value, __ATOMIC_SEQ_CST);
}

/* A misaligned futex word, accessed one byte at a time */
static uint32_t load_misaligned(char* p) {
  uint32_t value = 0;
  size_t i;
  for (i = 0; i < sizeof(value); ++i) {
    ((char*)&value)[i] = __atomic_load_n(p + i, __ATOMIC_SEQ_CST);
  }
  return value;
}

static void store_misaligned(char* p, uint32_t value) {
  size_t i;
  for (i = 0; i < sizeof(value); ++i) {
    __atomic_store_n(p + i, ((char*)&value)[i], __ATOMIC_SEQ_CST);
  }
}

static uint32_t start(void) {
  pid_t tid = sys_gettid();
  __atomic_store_n(&thread_tid, tid, __ATOMIC_SEQ_CST);
  return tid;
}

static void register_list(struct robust_list_head* head, void* first,
                          long futex_offset, void* pending) {
  head->list.next = (struct robust_list*)first;
  head->futex_offset = futex_offset;
  head->list_op_pending = (struct robust_list*)pending;
  test_assert(0 == syscall(SYS_set_robust_list, head, sizeof(*head)));
}

/* The entry after the first one is in memory the kernel can't read. */
static void* fault(void* unreadable) {
  uint32_t tid = start();
  fault_entry.list.next = (struct robust_list*)unreadable;
  store(&fault_entry.futex, tid);
  store(&fault_list.pending.futex, tid);
  register_list(&fault_list.head, &fault_entry.list,
                offsetof(struct entry, futex), &fault_list.pending.list);
  return NULL;
}

/* The first futex is on the second page, which the kernel can't write, and
   the second futex on the third page. */
static void* read_only(void* pages) {
  uint32_t tid = start();
  long page_size = sysconf(_SC_PAGESIZE);
  struct robust_list* first = (struct robust_list*)pages;
  struct robust_list* second =
      (struct robust_list*)((char*)pages + page_size + 64);
  first->next = second;
  second->next = &read_only_head.list;
  store((uint32_t*)((char*)first + page_size), tid);
  store((uint32_t*)((char*)second + page_size), tid);
  test_assert(0 == mprotect((char*)pages + page_size, page_size, PROT_READ));
  register_list(&read_only_head, first, page_size, NULL);
  return NULL;
}

/* The first futex is misaligned, the second isn't. */
static void* misaligned_futex(__attribute__((unused)) void* p) {
  uint32_t tid = start();
  struct robust_list* next = &misaligned_head.list;
  ((struct robust_list*)misaligned)->next =
      (struct robust_list*)(misaligned + 35);
  memcpy(misaligned + 35, &next, sizeof(next));
  store_misaligned(misaligned + 17, tid);
  store_misaligned(misaligned + 35 + 17, tid);
  register_list(&misaligned_head, misaligned, 17, NULL);
  return NULL;
}

static void* long_list(__attribute__((unused)) void* p) {
  uint32_t tid = start();
  size_t i;
  for (i = 0; i <= ROBUST_LIST_LIMIT; ++i) {
    long_entries[i].list.next =
        i < ROBUST_LIST_LIMIT ? &long_entries[i + 1].list : &long_head.list;
    store(&long_entries[i].futex, tid);
  }
  register_list(&long_head, &long_entries[0].list,
                offsetof(struct entry, futex), NULL);
  return NULL;
}

/* The main thread waits on the pending futex. */
static void* wake(void* p) {
  pid_t main_tid = (pid_t)(uintptr_t)p;
  uint32_t tid = start();
  test_assert(main_tid > 1);
  store(&wake_list.pending.futex, tid | FUTEX_WAITERS);
  register_list(&wake_list.head, &wake_list.head.list,
                offsetof(struct entry, futex), &wake_list.pending.list);
  __atomic_store_n(&wake_list_registered, 1, __ATOMIC_SEQ_CST);
  /* The main thread sleeps only in its FUTEX_WAIT. */
  while (get_task_state(main_tid) != 'S') {
    sched_yield();
  }
  return NULL;
}

static pthread_t start_thread(void* (*fn)(void*), void* arg) {
  pthread_t thread;
  test_assert(0 == pthread_create(&thread, NULL, fn, arg));
  return thread;
}

static uint32_t join_thread(pthread_t thread) {
  uint32_t tid;
  test_assert(0 == pthread_join(thread, NULL));
  tid = __atomic_load_n(&thread_tid, __ATOMIC_SEQ_CST);
  test_assert(tid > 0);
  return tid;
}

int main(void) {
  long page_size = sysconf(_SC_PAGESIZE);
  char* unreadable;
  char* pages;
  pthread_t thread;
  uint32_t tid;
  uint32_t value;
  size_t i;
  int ret;

  unreadable = (char*)mmap(NULL, page_size, PROT_NONE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(unreadable != MAP_FAILED);
  tid = join_thread(start_thread(fault, unreadable));
  test_assert(load(&fault_entry.futex) == FUTEX_OWNER_DIED);
  test_assert(load(&fault_list.pending.futex) == tid);

  pages = (char*)mmap(NULL, 3 * page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(pages != MAP_FAILED);
  tid = join_thread(start_thread(read_only, pages));
  test_assert(load((uint32_t*)(pages + page_size)) == tid);
  test_assert(load((uint32_t*)(pages + 2 * page_size + 64)) == tid);

  tid = join_thread(start_thread(misaligned_futex, NULL));
  test_assert(load_misaligned(misaligned + 17) == tid);
  test_assert(load_misaligned(misaligned + 35 + 17) == tid);

  tid = join_thread(start_thread(long_list, NULL));
  for (i = 0; i < ROBUST_LIST_LIMIT; ++i) {
    test_assert(load(&long_entries[i].futex) == FUTEX_OWNER_DIED);
  }
  test_assert(load(&long_entries[ROBUST_LIST_LIMIT].futex) == tid);

  thread = start_thread(wake, (void*)(uintptr_t)sys_gettid());
  while (!__atomic_load_n(&wake_list_registered, __ATOMIC_SEQ_CST)) {
    sched_yield();
  }
  value = load(&wake_list.pending.futex);
  ret = syscall(SYS_futex, &wake_list.pending.futex, FUTEX_WAIT, value, NULL,
                NULL, 0);
  test_assert(ret == 0 || (ret == -1 && errno == EAGAIN));
  join_thread(thread);
  test_assert(load(&wake_list.pending.futex) ==
              (FUTEX_WAITERS | FUTEX_OWNER_DIED));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
