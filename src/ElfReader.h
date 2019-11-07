/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_ELF_READER_H_
#define RR_ELF_READER_H_

#include <string.h>

#include <memory>
#include <vector>

#include "Dwarf.h"
#include "ScopedFd.h"
#include "kernel_abi.h"

namespace rr {

class ElfReaderImplBase;

class SymbolTable {
public:
  const char* name(size_t i) const {
    size_t offset = symbols[i].name_index;
    return offset < strtab.size() ? &strtab[offset] : nullptr;
  }
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
  // Last character is always null  map = static_cast<uint8_t*>(fd);

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
  std::string file_name;
  uint32_t crc;
};

class Debugaltlink {
public:
  std::string file_name;
};

struct SectionOffsets {
  uint64_t start;
  uint64_t end;
};

class ElfReader {
public:
  ElfReader(SupportedArch arch);
  virtual ~ElfReader();
  const void* read_bytes(size_t offset, size_t size) {
    if (offset + size > this->size) {
      return nullptr;
    }
    return map + offset;
  }
  template <typename T> const T* read(size_t offset, size_t count = 1) {
    return static_cast<const T*>(read_bytes(offset, sizeof(T)*count));
  }
  template <typename T> bool read_into(size_t offset, T* out) {
    auto r = read<T>(offset);
    if (!r) {
      return false;
    }
    memcpy(out, r, sizeof(*out));
    return true;
  }
  bool ok();
  SymbolTable read_symbols(const char* symtab, const char* strtab);
  DynamicSection read_dynamic();
  Debuglink read_debuglink();
  Debugaltlink read_debugaltlink();
  std::string read_buildid();
  // Returns true and sets file |offset| if ELF address |addr| is mapped from
  // a section in the ELF file.  Returns false if no section maps to
  // |addr|.  |addr| is an address indicated by the ELF file, not its
  // relocated address in memory.
  bool addr_to_offset(uintptr_t addr, uintptr_t& offset);
  SectionOffsets find_section_file_offsets(const char* name);
  DwarfSpan dwarf_section(const char* name);
private:
  ElfReaderImplBase& impl();
  std::unique_ptr<ElfReaderImplBase> impl_;
  SupportedArch arch;
protected:
  uint8_t* map;
  size_t size;
};

class ElfFileReader : public ElfReader {
public:
  ElfFileReader(ScopedFd& fd, SupportedArch arch);
  ElfFileReader(ScopedFd& fd) : ElfFileReader(fd, identify_arch(fd)) {}
  ~ElfFileReader();
  // Finds and opens the debug file corresponding to this reader.
  // |elf_file_name| is the name of the file already opened by this reader.
  ScopedFd open_debug_file(const std::string& elf_file_name);

  static SupportedArch identify_arch(ScopedFd& fd);
};

} // namespace rr

#endif /* RR_ELF_READER_H_ */
