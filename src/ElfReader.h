/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_ELF_READER_H_
#define RR_ELF_READER_H_

#include <string.h>

#include <memory>
#include <vector>

#include "ScopedFd.h"
#include "kernel_abi.h"

namespace rr {

class ElfReaderImplBase;

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
  // Last character is always null
  std::vector<char> strtab;
};

class DynamicSection {
public:
  struct Entry {
  public:
    Entry(uint64_t tag, uint64_t val) : tag(tag), val(val) {}
    Entry() {}
    uint64_t tag;
    uint64_t val;
  };

  std::vector<Entry> entries;
  // Last character is always null
  std::vector<char> strtab;
};

class ElfReader {
public:
  ElfReader(SupportedArch arch);
  virtual ~ElfReader();
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
  bool ok();
  SymbolTable read_symbols(const char* symtab, const char* strtab);
  DynamicSection read_dynamic();

private:
  ElfReaderImplBase& impl();
  std::unique_ptr<ElfReaderImplBase> impl_;
  SupportedArch arch;
};

class FileReader : public ElfReader {
public:
  FileReader(ScopedFd& fd, SupportedArch arch) : ElfReader(arch), fd(fd) {}
  virtual bool read(size_t offset, size_t size, void* buf) {
    while (size) {
      ssize_t ret = pread(fd.get(), buf, size, offset);
      if (ret <= 0) {
        return false;
      }
      offset += ret;
      size -= ret;
      buf = static_cast<uint8_t*>(buf) + ret;
    }
    return true;
  }
  ScopedFd& fd;
};

} // namespace rr

#endif /* RR_ELF_READER_H_ */
