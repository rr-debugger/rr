/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define SIZE 10 * 1024 * 1024

#define FORWARD 1
#define BACKWARD -1

static char* p;
static char* q;
static char* r;

static uintptr_t to_uintptr(char* val) {
  union {
    char buf[9];
    uintptr_t p;
  } u;
  memset(u.buf, 0, sizeof(u.buf));
  strcpy(u.buf, val);
  return u.p;
}

static inline void set_dir(int dir) {
#if defined(__i386__) || defined(__x86_64__)
  if (dir < 0) {
    __asm__("std\n\t");
  } else {
    __asm__("cld\n\t");
  }
#endif
}

static void string_store(char* dest, uintptr_t a, uintptr_t size, int unit,
                         int dir) {
  set_dir(dir);
#if defined(__i386__) || defined(__x86_64__)
  switch (unit) {
    case 1:
      __asm__("rep stosb\n\t" ::"a"(a), "c"(size), "D"(dest));
      break;
    case 2:
      __asm__("rep stosw\n\t" ::"a"(a), "c"(size), "D"(dest));
      break;
    case 4:
      __asm__("rep stosl\n\t" ::"a"(a), "c"(size), "D"(dest));
      break;
#ifdef __x86_64__
    case 8:
      __asm__("rep stosq\n\t" ::"a"(a), "c"(size), "D"(dest));
      break;
#endif
  }
#else
  int i;
  for (i = 0; i < size; i += unit) {
    memcpy(dest, &a, unit);
    dest += dir;
  }
#endif
  set_dir(1);
}

static void string_copy(char* dest, char* src, uintptr_t size, int unit,
                        int dir) {
  set_dir(dir);
#if defined(__i386__) || defined(__x86_64__)
  switch (unit) {
    case 1:
      __asm__("rep movsb\n\t" ::"S"(src), "c"(size), "D"(dest));
      break;
    case 2:
      __asm__("rep movsw\n\t" ::"S"(src), "c"(size), "D"(dest));
      break;
    case 4:
      __asm__("rep movsl\n\t" ::"S"(src), "c"(size), "D"(dest));
      break;
#ifdef __x86_64__
    case 8:
      __asm__("rep movsq\n\t" ::"S"(src), "c"(size), "D"(dest));
      break;
#endif
  }
#else
  int i;
  for (i = 0; i < size; i += unit) {
    memcpy(dest, src, unit);
    dest += dir;
    src += dir;
  }
#endif
  set_dir(1);
}

static int string_scan_equal(char* s, uintptr_t a, uintptr_t size, int unit,
                             int dir) {
  char* end = s;
  set_dir(dir);
#if defined(__i386__) || defined(__x86_64__)
  switch (unit) {
    case 1:
      __asm__("repe scasb\n\t" : "=D"(end) : "a"(a), "D"(s), "c"(size));
      break;
    case 2:
      __asm__("repe scasw\n\t" : "=D"(end) : "a"(a), "D"(s), "c"(size));
      break;
    case 4:
      __asm__("repe scasl\n\t" : "=D"(end) : "a"(a), "D"(s), "c"(size));
      break;
#ifdef __x86_64__
    case 8:
      __asm__("repe scasq\n\t" : "=D"(end) : "a"(a), "D"(s), "c"(size));
      break;
#endif
  }
#else
  int i;
  for (i = 0; i < size; i += unit) {
    end += dir;
    if (memcmp(end - dir, &a, unit) != 0) {
      break;
    }
  }
#endif
  set_dir(1);
  return (end - s - dir) / dir;
}

static int string_scan_not_equal(char* s, uintptr_t a, uintptr_t size, int unit,
                                 int dir) {
  char* end = s;
  set_dir(dir);
#if defined(__i386__) || defined(__x86_64__)
  switch (unit) {
    case 1:
      __asm__("repne scasb\n\t" : "=D"(end) : "a"(a), "D"(s), "c"(size));
      break;
    case 2:
      __asm__("repne scasw\n\t" : "=D"(end) : "a"(a), "D"(s), "c"(size));
      break;
    case 4:
      __asm__("repne scasl\n\t" : "=D"(end) : "a"(a), "D"(s), "c"(size));
      break;
#ifdef __x86_64__
    case 8:
      __asm__("repne scasq\n\t" : "=D"(end) : "a"(a), "D"(s), "c"(size));
      break;
#endif
  }
#else
  int i;
  for (i = 0; i < size; i += unit) {
    end += dir;
    if (memcmp(end - dir, &a, unit) == 0) {
      break;
    }
  }
#endif
  set_dir(1);
  return (end - s - dir) / dir;
}

static int string_cmp_equal(char* s, char* t, uintptr_t size, int unit,
                            int dir) {
  char* sp = s;
  char* tp = t;
  set_dir(dir);
#if defined(__i386__) || defined(__x86_64__)
  switch (unit) {
    case 1:
      __asm__("repe cmpsb\n\t" : "=D"(sp) : "S"(tp), "D"(s), "c"(size));
      break;
    case 2:
      __asm__("repe cmpsw\n\t" : "=D"(sp) : "S"(tp), "D"(s), "c"(size));
      break;
    case 4:
      __asm__("repe cmpsl\n\t" : "=D"(sp) : "S"(tp), "D"(s), "c"(size));
      break;
#ifdef __x86_64__
    case 8:
      __asm__("repe cmpsq\n\t" : "=D"(sp) : "S"(tp), "D"(s), "c"(size));
      break;
#endif
  }
#else
  int i;
  for (i = 0; i < size; i += unit) {
    sp += dir;
    tp += dir;
    if (memcmp(sp - dir, tp - dir, unit) != 0) {
      break;
    }
  }
#endif
  set_dir(1);
  return (sp - s - dir) / dir;
}

static int string_cmp_not_equal(char* s, char* t, uintptr_t size, int unit,
                                int dir) {
  char* sp = s;
  char* tp = t;
  set_dir(dir);
#if defined(__i386__) || defined(__x86_64__)
  switch (unit) {
    case 1:
      __asm__("repne cmpsb\n\t" : "=D"(sp) : "S"(tp), "D"(s), "c"(size));
      break;
    case 2:
      __asm__("repne cmpsw\n\t" : "=D"(sp) : "S"(tp), "D"(s), "c"(size));
      break;
    case 4:
      __asm__("repne cmpsl\n\t" : "=D"(sp) : "S"(tp), "D"(s), "c"(size));
      break;
#ifdef __x86_64__
    case 8:
      __asm__("repne cmpsq\n\t" : "=D"(sp) : "S"(tp), "D"(s), "c"(size));
      break;
#endif
  }
#else
  int i;
  for (i = 0; i < size; i += unit) {
    sp += dir;
    tp += dir;
    if (memcmp(sp - dir, tp - dir, unit) == 0) {
      break;
    }
  }
#endif
  set_dir(1);
  return (sp - s - dir) / dir;
}

int main(void) {
  int u;
  uintptr_t pattern = to_uintptr("aaaaaaaa");
  uintptr_t pattern2 = to_uintptr("bbbbbbbb");

  p = xmalloc(SIZE);
  q = xmalloc(SIZE);
  r = xmalloc(SIZE);

  for (u = 0; u < (sizeof(void*) == 8 ? 4 : 3); ++u) {
    int unit = 1 << u;
    int dir = FORWARD * unit;
    int size_units = SIZE / unit;
    int ret;

    memset(p, 0, SIZE);
    memset(q, 0, SIZE);
    memset(r, 0, SIZE);

    string_store(p, pattern, size_units, unit, dir);
    test_assert(memcmp(&p[SIZE - unit], &pattern, unit) == 0);

    string_copy(q, p, size_units, unit, dir);
    test_assert(memcmp(&q[SIZE - unit], &pattern, unit) == 0);

    memcpy(&p[SIZE - unit], &pattern2, unit);
    ret = string_scan_equal(p, pattern, size_units, unit, dir);
    test_assert(ret == size_units - 1);

    ret = string_scan_not_equal(p, pattern2, size_units, unit, dir);
    test_assert(ret == size_units - 1);

    ret = string_cmp_equal(p, q, size_units, unit, dir);
    test_assert(ret == size_units - 1);

    memset(&p[SIZE - unit], 0, unit);
    ret = string_cmp_not_equal(p, r, size_units, unit, dir);
    test_assert(ret == size_units - 1);

    dir = BACKWARD * unit;

    string_store(p + SIZE - unit, pattern2, size_units, unit, dir);
    test_assert(memcmp(&p[0], &pattern2, unit) == 0);

    string_copy(q + SIZE - unit, p + SIZE - unit, size_units, unit, dir);
    test_assert(memcmp(&q[0], &pattern2, unit) == 0);

    memcpy(&p[0], &pattern, unit);
    ret = string_scan_equal(p + SIZE - unit, pattern2, size_units, unit, dir);
    test_assert(ret == size_units - 1);

    ret =
        string_scan_not_equal(p + SIZE - unit, pattern, size_units, unit, dir);
    test_assert(ret == size_units - 1);

    ret = string_cmp_equal(p + SIZE - unit, q + SIZE - unit, size_units, unit,
                           dir);
    test_assert(ret == size_units - 1);

    memset(&p[0], 0, unit);
    ret = string_cmp_not_equal(p + SIZE - unit, r + SIZE - unit, size_units,
                               unit, dir);
    test_assert(ret == size_units - 1);
  }

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
