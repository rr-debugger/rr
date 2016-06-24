/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ElfReader.h"

#include <elf.h>

#include "log.h"

using namespace std;

namespace rr {

class ElfReaderImplBase {
public:
  ElfReaderImplBase(ElfReader& r) : r(r), ok_(false) {}
  virtual ~ElfReaderImplBase() {}
  virtual SymbolTable read_symbols(const char* symtab, const char* strtab) = 0;
  bool ok() { return ok_; }

protected:
  ElfReader& r;
  bool ok_;
};

template <typename Arch> class ElfReaderImpl : public ElfReaderImplBase {
public:
  ElfReaderImpl(ElfReader& r);
  virtual SymbolTable read_symbols(const char* symtab, const char* strtab);

private:
  typename Arch::ElfEhdr elfheader;
  vector<typename Arch::ElfShdr> sections;
  vector<char> section_names;
};

template <typename Arch>
unique_ptr<ElfReaderImplBase> elf_reader_impl_arch(ElfReader& r) {
  return unique_ptr<ElfReaderImplBase>(new ElfReaderImpl<Arch>(r));
}

unique_ptr<ElfReaderImplBase> elf_reader_impl(ElfReader& r,
                                              SupportedArch arch) {
  RR_ARCH_FUNCTION(elf_reader_impl_arch, arch, r);
}

template <typename Arch>
ElfReaderImpl<Arch>::ElfReaderImpl(ElfReader& r) : ElfReaderImplBase(r) {
  if (!r.read(0, elfheader) || memcmp(&elfheader, ELFMAG, SELFMAG) != 0 ||
      elfheader.e_ident[EI_CLASS] != Arch::elfclass ||
      elfheader.e_ident[EI_DATA] != Arch::elfendian ||
      elfheader.e_machine != Arch::elfmachine ||
      elfheader.e_shentsize != sizeof(typename Arch::ElfShdr) ||
      elfheader.e_shstrndx >= elfheader.e_shnum) {
    LOG(debug) << "Invalid ELF file: invalid header";
    return;
  }

  sections =
      r.read<typename Arch::ElfShdr>(elfheader.e_shoff, elfheader.e_shnum);
  if (sections.empty()) {
    LOG(debug) << "Invalid ELF file: no sections";
    return;
  }

  auto& section_names_section = sections[elfheader.e_shstrndx];
  section_names = r.read<char>(section_names_section.sh_offset,
                               section_names_section.sh_size);
  if (section_names.empty()) {
    LOG(debug) << "Invalid ELF file: can't read section names";
    return;
  }
  section_names[section_names.size() - 1] = 0;

  ok_ = true;
}

template <typename Arch>
SymbolTable ElfReaderImpl<Arch>::read_symbols(const char* symtab,
                                              const char* strtab) {
  SymbolTable result;
  if (!ok()) {
    return result;
  }

  typename Arch::ElfShdr* symbols = nullptr;
  typename Arch::ElfShdr* strings = nullptr;
  for (size_t i = 0; i < elfheader.e_shnum; ++i) {
    auto& s = sections[i];
    if (s.sh_name >= section_names.size()) {
      LOG(debug) << "Invalid ELF file: invalid name offset for section " << i;
      return result;
    }
    const char* name = section_names.data() + s.sh_name;
    if (strcmp(name, symtab) == 0) {
      if (symbols) {
        LOG(debug) << "Invalid ELF file: duplicate symbol section " << symtab;
        return result;
      }
      symbols = &s;
    }
    if (strcmp(name, strtab) == 0) {
      if (strings) {
        LOG(debug) << "Invalid ELF file: duplicate string section " << strtab;
        return result;
      }
      strings = &s;
    }
  }

  if (!symbols) {
    LOG(debug) << "Invalid ELF file: missing symbol section " << symtab;
    return result;
  }
  if (!strings) {
    LOG(debug) << "Invalid ELF file: missing string section " << strtab;
    return result;
  }
  if (symbols->sh_entsize != sizeof(typename Arch::ElfSym)) {
    LOG(debug) << "Invalid ELF file: incorrect symbol size "
               << symbols->sh_entsize;
    return result;
  }
  if (symbols->sh_size % symbols->sh_entsize) {
    LOG(debug) << "Invalid ELF file: incorrect symbol section size "
               << symbols->sh_size;
    return result;
  }

  auto symbol_list = r.read<typename Arch::ElfSym>(
      symbols->sh_offset, symbols->sh_size / symbols->sh_entsize);
  if (symbol_list.empty()) {
    LOG(debug) << "Invalid ELF file: can't read symbols " << symtab;
    return result;
  }
  result.strtab = r.read<char>(strings->sh_offset, strings->sh_size);
  if (result.strtab.empty()) {
    LOG(debug) << "Invalid ELF file: can't read strings " << strtab;
  }
  result.symbols.resize(symbol_list.size());
  for (size_t i = 0; i < symbol_list.size(); ++i) {
    auto& s = symbol_list[i];
    if (s.st_shndx >= sections.size()) {
      continue;
    }
    auto& section = sections[s.st_shndx];
    result.symbols[i] = SymbolTable::Symbol(
        s.st_value - section.sh_addr + section.sh_offset, s.st_name);
  }
  return result;
}

ElfReader::ElfReader(SupportedArch arch) : arch(arch) {}

ElfReader::~ElfReader() {}

ElfReaderImplBase& ElfReader::impl() {
  if (!impl_) {
    impl_ = elf_reader_impl(*this, arch);
  }
  return *impl_;
}

SymbolTable ElfReader::read_symbols(const char* symtab, const char* strtab) {
  return impl().read_symbols(symtab, strtab);
}

bool ElfReader::ok() { return impl().ok(); }

} // namespace rr
