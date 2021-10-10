#ifndef RR_REMOTE_CODE_PTR_H_
#define RR_REMOTE_CODE_PTR_H_

#include <cstddef>
#include <iostream>

#include "kernel_abi.h"

namespace rr {

/*
 * A pointer to code in the tracee address space.  Convertible to a
 * remote_ptr<void>.
 */
class remote_code_ptr {
public:
  remote_code_ptr() : ptr(0) {}
  remote_code_ptr(uintptr_t ptr) : ptr(ptr) {}
  remote_code_ptr(std::nullptr_t) : ptr(0) {}

  bool operator==(const remote_code_ptr& other) const {
    return ptr == other.ptr;
  }
  bool operator!=(const remote_code_ptr& other) const {
    return ptr != other.ptr;
  }
  bool operator<=(const remote_code_ptr& other) const {
    return ptr <= other.ptr;
  }
  bool operator>=(const remote_code_ptr& other) const {
    return ptr >= other.ptr;
  }
  bool operator<(const remote_code_ptr& other) const { return ptr < other.ptr; }
  bool operator>(const remote_code_ptr& other) const { return ptr > other.ptr; }
  // XXXkhuey this will have to get smarter once we have ARM.
  remote_code_ptr operator+(intptr_t delta) const {
    return remote_code_ptr(ptr + delta);
  }
  remote_code_ptr operator-(intptr_t delta) const {
    return remote_code_ptr(ptr - delta);
  }
  intptr_t operator-(remote_code_ptr other) const { return ptr - other.ptr; }

  remote_code_ptr decrement_by_syscall_insn_length(SupportedArch arch) const {
    return remote_code_ptr(ptr - rr::syscall_instruction_length(arch));
  }
  remote_code_ptr increment_by_syscall_insn_length(SupportedArch arch) const {
    return remote_code_ptr(ptr + rr::syscall_instruction_length(arch));
  }
  remote_code_ptr undo_executed_bkpt(SupportedArch arch) {
    switch (arch) {
      case x86:
      case x86_64:
        return decrement_by_bkpt_insn_length_private(arch);
      default:
        DEBUG_ASSERT(0 && "Unknown architecture");
        RR_FALLTHROUGH;
      case aarch64:
        // On aarch64 executed breakpoint instructions do not increment the pc
        return *this;
    }
  }
  remote_code_ptr increment_by_bkpt_insn_length(SupportedArch arch) const {
    return remote_code_ptr(ptr + rr::bkpt_instruction_length(arch));
  }
  remote_code_ptr increment_by_movrm_insn_length(SupportedArch arch) const {
    return remote_code_ptr(ptr + rr::movrm_instruction_length(arch));
  }
  remote_code_ptr decrement_by_vsyscall_entry_length(SupportedArch arch) const {
    return remote_code_ptr(ptr - rr::vsyscall_entry_length(arch));
  }

  template <typename T> remote_ptr<T> to_data_ptr() const {
    return remote_ptr<T>(to_data_ptr_value());
  }

  // Return the pointer in a form suitable for storing in a register. Only
  // intended for use by Registers and the operator <<
  uintptr_t register_value() const { return ptr; }

  bool is_null() const { return !ptr; }
  explicit operator bool() const { return ptr != 0; }

private:
  // Private to avoid accidentally using this instead of undo_executed_bkpt.
  // You probably want that one.
  remote_code_ptr decrement_by_bkpt_insn_length_private(SupportedArch arch) const {
    return remote_code_ptr(ptr - rr::bkpt_instruction_length(arch));
  }

  // Return the integer value for this pointer viewed as a data pointer.
  // A no-op on Intel architectures, will mask off the thumb bit on ARM.
  uintptr_t to_data_ptr_value() const { return ptr; }

  uintptr_t ptr;
};

std::ostream& operator<<(std::ostream& stream, remote_code_ptr p);

} // namespace rr

namespace std {

template <> struct hash<rr::remote_code_ptr> {
  size_t operator()(const rr::remote_code_ptr& ptr) const {
    return hash<uintptr_t>()(ptr.register_value());
  }
};

} // namespace std

#endif // RR_REMOTE_CODE_PTR_H_
