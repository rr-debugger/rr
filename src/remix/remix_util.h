/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REMIX_UTIL_H_
#define RR_REMIX_UTIL_H_

#include <stdint.h>
#include <sys/user.h>

#ifdef __clang__
#define REMIX_TARGET_BEGIN _Pragma("clang attribute push (__attribute__((target(\"no-sse\"))), apply_to=function)")
#define REMIX_TARGET_END   _Pragma("clang attribute pop")
#elif defined(__GNUC__)
#define REMIX_TARGET_BEGIN _Pragma("GCC push_options") \
    _Pragma("GCC target(\"no-sse\")")
#define REMIX_TARGET_END   _Pragma("GCC pop_options")
#else
#error Unknown compiler
#endif

#ifdef __cplusplus
const int address_space_bits = 47;
const int page_size_bits = 12;

inline uintptr_t floor_page_size(uintptr_t size) {
  return size & ~uintptr_t(PAGE_SIZE - 1);
}

inline uint8_t* floor_page_size(void* pc) {
  return (uint8_t*)(uintptr_t(pc) & ~uintptr_t(PAGE_SIZE - 1));
}

inline uintptr_t ceil_page_size(uintptr_t v) {
  return (v + PAGE_SIZE - 1) & ~uintptr_t(PAGE_SIZE - 1);
}

inline uint8_t* ceil_page_size(void* pc) {
  return reinterpret_cast<uint8_t*>(ceil_page_size(uintptr_t(pc)));
}

/* Like memcpy, but ensures app_src is readable by mprotecting if necessary.
 * These regions can't overlap. */
void memcpy_from_app(uint8_t* dest, uint8_t* app_src, size_t size);

/* Like memcpy, but ensures app_dest is writeable by mprotecting if necessary.
 * These regions can't overlap. */
void memcpy_to_app(uint8_t* app_dest, uint8_t* src, size_t size);

/* Swaps app bytes with p. mprotects app area if necessary. These regions
 * can't overlap. */
void swap_app_bytes(uint8_t* app, uint8_t* p, size_t size);

extern "C" {
#endif

void remix_abort(const char* format, ...) __attribute__ ((noreturn));

inline void remix_assert_check(int cond, const char* cond_str, const char* file,
                               int line) {
  if (__builtin_expect(!cond, 0)) {
    remix_abort("remix assertion failed: %s at %s:%d", cond_str, file, line);
  }
}

#define REMIX_STRING(s) #s
#define remix_assert(cond)                                                     \
  remix_assert_check(cond, REMIX_STRING(cond), __FILE__, __LINE__)

void remix_log(uint32_t module, const char* format, ...);

void remix_update_uid();

struct CPUIDData {
  uint32_t eax, ebx, ecx, edx;
};

CPUIDData cpuid(uint32_t code, uint32_t subrequest);

#ifdef __cplusplus
}
#endif

#endif /* RR_REMIX_UTIL_H_ */
