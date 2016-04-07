/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_ELF_READER_H_
#define RR_ELF_READER_H_

#include <string.h>

#include <memory>
#include <vector>

#include "kernel_abi.h"

namespace rr {

class SymbolTable {
public:
  bool is_name(size_t i, const char* name) const {
    size_t offset = symbols[i].name_index;
    return offset < strtab.size() && strcmp(&strtab[offset], name) == 0;
  }
  uintptr_t file_offset(size_t i) const { return symbols[i].file_offset; }
  size_t size() const { return symbols.size(); }

  struct Symbol {
    Symbol(uintptr_t file_offset, size_t name_index)
        : file_offset(file_offset), name_index(name_index) {}
    Symbol() {}
    uintptr_t file_offset;
    size_t name_index;
  };
  std::vector<Symbol> symbols;
  std::vector<char> strtab;
};

template <typename Arch> class ElfReaderImpl;

class ElfReader {
public:
  virtual ~ElfReader() {}
  virtual bool read(size_t offset, size_t size, void* buf) = 0;
  template <typename T> bool read(size_t offset, T& result) {
    return read(offset, sizeof(result), &result);
  }
  template <typename T> std::vector<T> read(size_t offset, size_t count) {
    std::vector<T> result;
    result.resize(count);
    if (!read(offset, sizeof(T) * count, result.data())) {
      result.clear();
    }
    return result;
  }
  SymbolTable read_symbols(SupportedArch arch, const char* symtab,
                           const char* strtab);
};

} // namespace rr

#endif /* RR_ELF_READER_H_ */
