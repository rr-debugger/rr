/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_VECTOR_H_
#define RR_VECTOR_H_

#include <stdint.h>

#include <algorithm>

#include "remix_util.h"

REMIX_TARGET_BEGIN

template <typename T> class Vector {
public:
  Vector() : element_count(0), capacity(0), table(nullptr) {}
  Vector(const Vector<T>& other)
      : element_count(other.element_count), capacity(other.element_count) {
    if (capacity) {
      table = new Bucket[capacity];
      for (uint64_t i = 0; i < element_count; ++i) {
        new (table[i].elem) T(other.table[i].t);
      }
    } else {
      table = nullptr;
    }
  }
  ~Vector() {
    while (element_count) {
      pop_back();
    }
    delete[] table;
  }
  T& push_back(const T& val) {
    if (element_count >= capacity) {
      resize(std::max<uint64_t>(4, capacity * 2));
    }
    new (table[element_count].elem) T(val);
    ++element_count;
    return table[element_count - 1].t;
  }
  T& first() {
    remix_assert(element_count);
    return table[0].t;
  }
  T& last() {
    remix_assert(element_count);
    return table[element_count - 1].t;
  }
  T pop_back() {
    remix_assert(element_count);
    T ret = table[element_count - 1].t;
    (&table[element_count - 1].t)->T::~T();
    --element_count;
    return ret;
  }
  uint64_t size() { return element_count; }
  T& operator[](size_t index) {
    return table[index].t;
  }

  T* extend(uint64_t amount) {
    if (element_count + amount > capacity) {
      resize(std::max<uint64_t>(element_count + amount, capacity * 2));
    }
    T* ret = &table[element_count].t;
    element_count += amount;
    return ret;
  }
  T* steal() {
    if (element_count) {
      T* ret = &table[0].t;
      table = nullptr;
      element_count = 0;
      capacity = 0;
      return ret;
    }
    clear();
    return nullptr;
  }
  void clear() {
    while (element_count) {
      pop_back();
    }
    delete[] table;
    table = nullptr;
    element_count = 0;
    capacity = 0;
  }

  class Iterator {
  public:
    Iterator(Vector<T>& vec, uint64_t index) : vec(vec), index(index) {}
    bool operator==(const Iterator& other) const {
      return other.index == index;
    }
    bool operator!=(const Iterator& other) const { return !(*this == other); }
    T& operator*() const { return vec.table[index].t; }
    Iterator& operator++() {
      ++index;
      return *this;
    }

  private:
    Vector<T>& vec;
    uint64_t index;
  };
  friend class Iterator;

  Iterator begin() { return Iterator(*this, 0); }
  Iterator end() { return Iterator(*this, element_count); }

  union alignas(T) Bucket {
    Bucket() {}
    ~Bucket() {}
    char elem[sizeof(T)];
    T t;
  };

private:
  void resize(uint64_t new_capacity) {
    Bucket* old = table;
    capacity = new_capacity;
    table = new Bucket[capacity];
    for (uint64_t i = 0; i < element_count; ++i) {
      new (table[i].elem) T(old[i].t);
    }
    delete[] old;
  }

  uint64_t element_count;
  uint64_t capacity;
  Bucket* table;
};

REMIX_TARGET_END

#endif /* RR_VECTOR_H_ */
