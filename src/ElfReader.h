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
  uintptr_t addr(size_t i) const { return symbols[i].addr; }
  size_t size() const { return symbols.size(); }

  struct Symbol {
    Symbol(uintptr_t addr, size_t name_index)
        : addr(addr), name_index(name_index) {}
    Symbol() {}
    uintptr_t addr;
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

class Debuglink {
public:
  std::string filename;
  uint32_t crc;
};

struct SectionOffsets {
  uint64_t start;
  uint64_t end;
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
  Debuglink read_debuglink();
  // Returns true and sets file |offset| if ELF address |addr| is mapped from
  // a section in the ELF file.  Returns false if no section maps to
  // |addr|.  |addr| is an address indicated by the ELF file, not its
  // relocated address in memory.
  bool addr_to_offset(uintptr_t addr, uintptr_t& offset);
  SectionOffsets find_section_file_offsets(const char* name);

private:
  ElfReaderImplBase& impl();
  std::unique_ptr<ElfReaderImplBase> impl_;
  SupportedArch arch;
};

class ElfFileReader : public ElfReader {
public:
  ElfFileReader(ScopedFd& fd, SupportedArch arch) : ElfReader(arch), fd(fd) {}
  ElfFileReader(ScopedFd& fd) : ElfReader(identify_arch(fd)), fd(fd) {}
  virtual bool read(size_t offset, size_t size, void* buf);
  // Finds and opens the debug file corresponding to this reader.
  // |elf_file_name| is the name of the file already opened by this reader.
  ScopedFd open_debug_file(const std::string& elf_file_name);
  ScopedFd& fd;

  static SupportedArch identify_arch(ScopedFd& fd);
};

} // namespace rr

#endif /* RR_ELF_READER_H_ */
