/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_HASHTABLE_H_
#define RR_HASHTABLE_H_

#include <stdint.h>

#include <algorithm>

#include "remix_util.h"

REMIX_TARGET_BEGIN

template <typename T> size_t hash(const T& val);

template <typename T> class Hashtable {
public:
  Hashtable() : element_count(0), capacity(0), table(nullptr) {}
  ~Hashtable() { delete[] table; }
  void clear() {
    element_count = 0;
    capacity = 0;
    delete[] table;
    table = nullptr;
  }
  T* lookup(const T& val) {
    if (!table) {
      return nullptr;
    }
    uint64_t h = hash(val);
    uint64_t r = 0;
    while (true) {
      uint64_t bucket = (h + r) & (capacity - 1);
      if (table[bucket].state == EMPTY) {
        return nullptr;
      }
      if (table[bucket].state == VALID && table[bucket].t == val) {
        return (T*)table[bucket].elem;
      }
      r = advance_r(r);
    }
  }
  bool insert(const T& val) {
    if (element_count >= capacity / 2) {
      rehash(std::max<uint64_t>(4, capacity * 2));
    }
    uint64_t h = hash(val);
    uint64_t r = 0;
    while (true) {
      uint64_t bucket = (h + r) & (capacity - 1);
      if (table[bucket].state != VALID) {
        if (table[bucket].state == DELETED) {
          --deleted_count;
        }
        table[bucket].state = VALID;
        new (table[bucket].elem) T(val);
        ++element_count;
        return true;
      }
      if (table[bucket].t == val) {
        return false;
      }
      r = advance_r(r);
    }
  }
  void remove(const T& val) {
    uint64_t h = hash(val);
    uint64_t r = 0;
    while (true) {
      uint64_t bucket = (h + r) & (capacity - 1);
      if (table[bucket].state == EMPTY) {
        return;
      }
      if (table[bucket].state == VALID && table[bucket].t == val) {
        --element_count;
        table[bucket].state = DELETED;
        ++deleted_count;
        if (deleted_count >= capacity / 2) {
          rehash(capacity);
        }
        return;
      }
      r = advance_r(r);
    }
  }
  uint64_t size() { return element_count; }

  class Iterator {
  public:
    Iterator(Hashtable& hashtable, uint64_t index)
        : hashtable(hashtable), index(index) {
      advance();
    }
    bool operator==(const Iterator& other) const {
      return other.index == index;
    }
    bool operator!=(const Iterator& other) const { return !(*this == other); }
    T& operator*() const { return hashtable.table[index].t; }
    Iterator& operator++() {
      ++index;
      advance();
      return *this;
    }

  private:
    void advance() {
      while (index < hashtable.capacity &&
             hashtable.table[index].state != VALID) {
        ++index;
      }
    }
    Hashtable& hashtable;
    uint64_t index;
  };
  friend class Iterator;

  Iterator begin() { return Iterator(*this, 0); }
  Iterator end() { return Iterator(*this, capacity); }

  enum { EMPTY, VALID, DELETED };
  struct alignas(T) Bucket {
    Bucket() : state(EMPTY) {}
    union {
      char elem[sizeof(T)];
      T t;
    };
    uint8_t state;
  };

private:
  static uint64_t advance_r(uint64_t r) { return r + 1; }
  void rehash(uint64_t new_capacity) {
    Bucket* old = table;
    uint64_t old_capacity = capacity;
    capacity = std::min(uint64_t(1024)*1024*1024*1024, new_capacity);
    table = new Bucket[capacity];
    for (uint64_t i = 0; i < old_capacity; ++i) {
      if (old[i].state == VALID) {
        insert(old[i].t);
      }
    }
    deleted_count = 0;
    delete[] old;
  }

  uint64_t element_count;
  uint64_t deleted_count;
  uint64_t capacity;
  Bucket* table;
};

REMIX_TARGET_END

#endif /* RR_HASHTABLE_H_ */
