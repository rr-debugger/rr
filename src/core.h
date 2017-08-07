/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_CORE_H_
#define RR_CORE_H_

#include <assert.h>
#include <string.h>

#include <array>

/* This file depends on nothing in rr and can be included anywhere */

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif
#ifndef __has_cpp_attribute
#define __has_cpp_attribute(x) 0
#endif

/* RR_FALLTHROUGH - Mark fallthrough cases in switch statements. */
#if defined(__cplusplus) && __cplusplus > 201402L &&                           \
    __has_cpp_attribute(fallthrough)
#define RR_FALLTHROUGH [[fallthrough]]
#elif !__cplusplus
/* Workaround for llvm.org/PR23435, since clang 3.6 and below emit a spurious
   error when __has_cpp_attribute is given a scoped attribute in C mode. */
#define RR_FALLTHROUGH
#elif __has_cpp_attribute(clang::fallthrough)
#define RR_FALLTHROUGH [[clang::fallthrough]]
#elif defined(__GNUC__) && __GNUC__ >= 7
#define RR_FALLTHROUGH __attribute__((fallthrough))
#else
#define RR_FALLTHROUGH
#endif

/* use of assert() causes "unused variable" warnings in non-DEBUG builds
 * when a variable is only used in an assertion. DEBUG_ASSERT fixes that
 * problem. Use DEBUG_ASSERT instead of assert().
 */
#ifdef DEBUG
#define DEBUG_ASSERT(cond) assert(cond)
#else
#define DEBUG_ASSERT(cond)                                                     \
  do {                                                                         \
    size_t s __attribute__((unused)) = sizeof(cond);                           \
  } while (0)
#endif

#ifdef __cplusplus

namespace rr {

template <typename T, size_t N> constexpr size_t array_length(T (&)[N]) {
  return N;
}

template <typename T, size_t N>
constexpr size_t array_length(std::array<T, N>&) {
  return N;
}

template <typename T> T return_dummy_value() {
  T v;
  memset(&v, 1, sizeof(T));
  return v;
}
template <typename T> bool check_type_has_no_holes() {
  T v;
  memset(&v, 2, sizeof(T));
  v = return_dummy_value<T>();
  return memchr(&v, 2, sizeof(T)) == NULL;
}
/**
 * Returns true when type T has no holes. Preferably should not be defined
 * at all otherwise.
 * This is not 100% reliable since the check_type_has_no_holes may be
 * compiled to copy holes. However, it has detected at least two bugs.
 */
template <typename T> bool type_has_no_holes() {
  static bool check = check_type_has_no_holes<T>();
  return check;
}
}

#endif

#endif /* RR_CORE_H_ */
