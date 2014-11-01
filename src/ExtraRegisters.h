/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_EXTRA_REGISTERS_H_
#define RR_EXTRA_REGISTERS_H_

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "GdbRegister.h"

/**
 * An ExtraRegisters object contains values for all user-space-visible
 * registers other than those in Registers.
 *
 * Task is responsible for creating meaningful values of this class.
 *
 * On x86, the data is either an XSAVE area or a user_fpxregs_struct.
 */
class ExtraRegisters {
public:
  // Create empty (uninitialized/unknown registers) value
  ExtraRegisters() : format_(NONE) {}

  enum Format {
    NONE,
    XSAVE,
    FPXREGS,
    XSAVE64,
  };

  // Set values from raw data
  void set_to_raw_data(Format format, std::vector<uint8_t>& consume_data) {
    format_ = format;
    std::swap(data, consume_data);
  }

  Format format() const { return format_; }
  int data_size() const { return data.size(); }
  const uint8_t* data_bytes() const { return data.data(); }
  bool empty() const { return data.empty(); }

  /**
   * Like |Registers::read_register()|, except attempts to read
   * the value of an "extra register" (floating point / vector).
   */
  size_t read_register(uint8_t* buf, GdbRegister regno, bool* defined) const;

private:
  size_t register_size(GdbRegister regno, bool* can_read) const;

  friend class Task;

  Format format_;
  std::vector<uint8_t> data;
};

#endif /* RR_EXTRA_REGISTERS_H_ */
