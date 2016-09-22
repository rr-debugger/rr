/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REMOTE_PTR_H_
#define RR_REMOTE_PTR_H_

#include <cstddef>
#include <iostream>

namespace rr {

/**
 * Number of bytes to use as the element size when doing pointer arithmetic
 * on this type. We specialize 'void' to use 1 byte to make a lot of our
 * calculations easier.
 */
template <typename T> size_t pointer_arithmetic_size() { return sizeof(T); }
template <> inline size_t pointer_arithmetic_size<void>() { return 1; }

/**
 * A pointer to data in some tracee address space.
 * This lets us distinguish between real, usable pointers in rr's address space
 * and pointers that only make sense in a tracee address space.
 */
template <typename T> class remote_ptr {
public:
  remote_ptr() : ptr(0) {}
  remote_ptr(uintptr_t ptr) : ptr(ptr) {}
  remote_ptr(std::nullptr_t) : ptr(0) {}
  template <typename U> remote_ptr(remote_ptr<U> p) : ptr(p.as_int()) {
    consume_dummy(static_cast<typename std::remove_cv<U>::type*>(nullptr));
  }

  uintptr_t as_int() const { return ptr; }

  remote_ptr<T> operator+(intptr_t delta) const {
    return remote_ptr<T>(ptr + delta * arith_size());
  }
  remote_ptr<T> operator-(intptr_t delta) const {
    return remote_ptr<T>(ptr - delta * arith_size());
  }
  remote_ptr<T>& operator+=(intptr_t delta) {
    ptr += delta * arith_size();
    return *this;
  }
  remote_ptr<T>& operator-=(intptr_t delta) {
    ptr -= delta * arith_size();
    return *this;
  }
  intptr_t operator-(remote_ptr<T> other) const {
    return (ptr - other.ptr) / arith_size();
  }
  remote_ptr<T>& operator++() {
    ptr += arith_size();
    return *this;
  }
  remote_ptr<T> operator++(int) {
    uintptr_t p = ptr;
    ptr += arith_size();
    return p;
  }
  remote_ptr<T>& operator--() {
    ptr -= arith_size();
    return *this;
  }
  remote_ptr<T> operator--(int) {
    uintptr_t p = ptr;
    ptr -= arith_size();
    return p;
  }

  template <typename U> remote_ptr<U> cast() const {
    return remote_ptr<U>(ptr);
  }

  explicit operator bool() const { return ptr != 0; }
  bool operator!() const { return !ptr; }
  bool operator<(const remote_ptr<T>& other) const { return ptr < other.ptr; }
  bool operator<=(const remote_ptr<T>& other) const { return ptr <= other.ptr; }
  bool operator==(const remote_ptr<T>& other) const { return ptr == other.ptr; }
  bool operator!=(const remote_ptr<T>& other) const { return ptr != other.ptr; }
  bool operator>(const remote_ptr<T>& other) const { return ptr > other.ptr; }
  bool operator>=(const remote_ptr<T>& other) const { return ptr >= other.ptr; }

  bool is_null() const { return !ptr; }

  template <typename U>
  remote_ptr<typename std::remove_cv<U>::type> field(U*,
                                                     uintptr_t offset) const {
    return remote_ptr<typename std::remove_cv<U>::type>(ptr + offset);
  }
  T* dummy() { return nullptr; }
  const T* dummy() const { return nullptr; }

  size_t referent_size() { return sizeof(T); }

private:
  static void consume_dummy(T*) {}
  static size_t arith_size() { return pointer_arithmetic_size<T>(); }

  uintptr_t ptr;
};

/**
 * returns a remote_ptr pointing to field f of the struct pointed to by
 * remote_ptr p
 */
#define REMOTE_PTR_FIELD(p, f)                                                 \
  ((p).field(                                                                  \
      ((typename std::remove_reference<decltype(                               \
            (p).dummy()->f)>::type*)nullptr),                                  \
      offsetof(typename std::remove_reference<decltype(*(p).dummy())>::type,   \
               f)))

template <typename T>
std::ostream& operator<<(std::ostream& stream, remote_ptr<T> p) {
  stream << (void*)p.as_int();
  return stream;
}

} // namespace rr

#endif /* RR_REMOTE_PTR_H_ */
