/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REMOTE_PTR_H_
#define RR_REMOTE_PTR_H_

/**
 * A pointer in some tracee address space.
 * This lets us distinguish between real, usable pointers in rr's address space
 * and pointers that only make sense in a tracee address space.
 */
template <typename T> class remote_ptr {
public:
  remote_ptr() : ptr(0) {}
  remote_ptr(T* ptr) : ptr(reinterpret_cast<uintptr_t>(ptr)) {}
  operator T*() const { return reinterpret_cast<T*>(ptr); }

private:
  uintptr_t ptr;
};

#endif /* RR_REMOTE_PTR_H_ */
