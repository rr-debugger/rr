/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ElfReader.h"

#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

class ElfReaderImplBase {
public:
  ElfReaderImplBase(ElfReader& r) : r(r), ok_(false) {}
  virtual ~ElfReaderImplBase() {}
  virtual SymbolTable read_symbols(const char* symtab, const char* strtab) = 0;
  virtual DynamicSection read_dynamic() = 0;
  virtual Debuglink read_debuglink() = 0;
  virtual Debugaltlink read_debugaltlink() = 0;
  virtual string read_buildid() = 0;
  virtual bool addr_to_offset(uintptr_t addr, uintptr_t& offset) = 0;
  virtual SectionOffsets find_section_file_offsets(const char* name) = 0;
  bool ok() { return ok_; }

protected:
  ElfReader& r;
  bool ok_;
};

template <typename Arch> class ElfReaderImpl : public ElfReaderImplBase {
public:
  ElfReaderImpl(ElfReader& r);
  virtual SymbolTable read_symbols(const char* symtab,
                                   const char* strtab) override;
  virtual DynamicSection read_dynamic() override;
  virtual Debuglink read_debuglink() override;
  virtual Debugaltlink read_debugaltlink() override;
  virtual string read_buildid() override;
  virtual bool addr_to_offset(uintptr_t addr, uintptr_t& offset) override;
  virtual SectionOffsets find_section_file_offsets(const char* name) override;

private:
  const typename Arch::ElfShdr* find_section(const char* n);

  const typename Arch::ElfEhdr* elfheader;
  const typename Arch::ElfShdr* sections;
  size_t sections_size;
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
  elfheader = r.read<typename Arch::ElfEhdr>(0);
  if (!elfheader || memcmp(elfheader, ELFMAG, SELFMAG) != 0 ||
      elfheader->e_ident[EI_CLASS] != Arch::elfclass ||
      elfheader->e_ident[EI_DATA] != Arch::elfendian ||
      elfheader->e_machine != Arch::elfmachine ||
      elfheader->e_shentsize != sizeof(typename Arch::ElfShdr) ||
      elfheader->e_shstrndx >= elfheader->e_shnum) {
    LOG(debug) << "Invalid ELF file: invalid header";
    return;
  }

  sections =
      r.read<typename Arch::ElfShdr>(elfheader->e_shoff, elfheader->e_shnum);
  if (!sections || !elfheader->e_shnum) {
    LOG(debug) << "Invalid ELF file: no sections";
    return;
  }
  sections_size = elfheader->e_shnum;

  auto& section_names_section = sections[elfheader->e_shstrndx];
  const char* section_names_ptr = r.read<char>(section_names_section.sh_offset,
                                               section_names_section.sh_size);
  if (!section_names_ptr || !section_names_section.sh_size) {
    LOG(debug) << "Invalid ELF file: can't read section names";
    return;
  }
  // Ensure final 0
  section_names.resize(section_names_section.sh_size);
  memcpy(section_names.data(), section_names_ptr, section_names.size());
  section_names[section_names.size() - 1] = 0;

  ok_ = true;
}

template <typename Arch>
const typename Arch::ElfShdr* ElfReaderImpl<Arch>::find_section(const char* n) {
  const typename Arch::ElfShdr* section = nullptr;

  for (size_t i = 0; i < sections_size; ++i) {
    auto& s = sections[i];
    if (s.sh_name >= section_names.size()) {
      LOG(debug) << "Invalid ELF file: invalid name offset for section " << i;
      continue;
    }
    const char* name = section_names.data() + s.sh_name;
    if (strcmp(name, n) == 0) {
      if (section) {
        LOG(debug) << "Invalid ELF file: duplicate symbol section " << n;
        return nullptr;
      }
      section = &s;
    }
  }

  if (!section) {
    LOG(debug) << "Missing section " << n;
  }
  return section;
}

template <typename Arch>
SectionOffsets ElfReaderImpl<Arch>::find_section_file_offsets(
    const char* name) {
  SectionOffsets offsets = { 0, 0 };
  const typename Arch::ElfShdr* section = find_section(name);
  if (!section) {
    return offsets;
  }
  offsets.start = section->sh_offset;
  offsets.end = section->sh_offset + section->sh_size;
  return offsets;
}

template <typename Arch>
SymbolTable ElfReaderImpl<Arch>::read_symbols(const char* symtab,
                                              const char* strtab) {
  SymbolTable result;
  if (!ok()) {
    return result;
  }

  const typename Arch::ElfShdr* symbols = find_section(symtab);
  if (!symbols) {
    return result;
  }
  const typename Arch::ElfShdr* strings = find_section(strtab);
  if (!strtab) {
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
  if (strings->sh_size == 0) {
    LOG(debug) << "Invalid ELF file: empty string table";
    return result;
  }

  size_t symbol_list_size = symbols->sh_size / symbols->sh_entsize;
  auto symbol_list = r.read<typename Arch::ElfSym>(
      symbols->sh_offset, symbol_list_size);
  if (!symbol_list) {
    LOG(debug) << "Invalid ELF file: can't read symbols " << symtab;
    return result;
  }
  auto strtab_ptr = r.read<char>(strings->sh_offset, strings->sh_size);
  if (!strtab_ptr) {
    LOG(debug) << "Invalid ELF file: can't read strings " << strtab;
  }
  result.strtab.resize(strings->sh_size);
  memcpy(result.strtab.data(), strtab_ptr, result.strtab.size());
  result.strtab[result.strtab.size() - 1] = 0;
  result.symbols.resize(symbol_list_size);
  for (size_t i = 0; i < symbol_list_size; ++i) {
    auto& s = symbol_list[i];
    if (s.st_shndx >= sections_size) {
      // Don't leave this entry uninitialized
      result.symbols[i] = SymbolTable::Symbol(0, 0);
      continue;
    }
    result.symbols[i] = SymbolTable::Symbol(s.st_value, s.st_name);
  }
  return result;
}

template <typename Arch> DynamicSection ElfReaderImpl<Arch>::read_dynamic() {
  DynamicSection result;
  if (!ok()) {
    return result;
  }

  const typename Arch::ElfShdr* dynamic = find_section(".dynamic");
  if (!dynamic) {
    return result;
  }
  const typename Arch::ElfShdr* dynstr = find_section(".dynstr");
  if (!dynstr) {
    return result;
  }

  if (dynamic->sh_entsize != sizeof(typename Arch::ElfDyn)) {
    LOG(debug) << "Invalid ELF file: incorrect .dynamic size "
               << dynamic->sh_entsize;
    return result;
  }
  if (!dynamic->sh_size) {
    return result;
  }
  if (dynamic->sh_size % dynamic->sh_entsize) {
    LOG(debug) << "Invalid ELF file: incorrect .dynamic section size "
               << dynamic->sh_size;
    return result;
  }
  if (dynstr->sh_size == 0) {
    LOG(debug) << "Invalid ELF file: empty string table";
    return result;
  }

  size_t dyn_list_size = dynamic->sh_size / dynamic->sh_entsize;
  auto dyn_list = r.read<typename Arch::ElfDyn>(
      dynamic->sh_offset, dyn_list_size);
  if (!dyn_list) {
    LOG(debug) << "Invalid ELF file: can't read .dynamic";
    return result;
  }
  auto strtab = r.read<char>(dynstr->sh_offset, dynstr->sh_size);
  if (!strtab) {
    LOG(debug) << "Invalid ELF file: can't read .dynstr";
  }
  result.strtab.resize(dynstr->sh_size);
  memcpy(result.strtab.data(), strtab, result.strtab.size());
  result.strtab[result.strtab.size() - 1] = 0;
  result.entries.resize(dyn_list_size);
  for (size_t i = 0; i < dyn_list_size; ++i) {
    auto& s = dyn_list[i];
    result.entries[i] = DynamicSection::Entry(s.d_tag, s.d_val);
  }
  return result;
}

static bool null_terminated(const char* p, size_t size, string& out) {
  size_t len = strnlen(p, size);
  if (len == size) {
    LOG(warn) << "Invalid file name";
    return false;
  }
  out = string(p, len);
  return true;
}

template <typename Arch> Debuglink ElfReaderImpl<Arch>::read_debuglink() {
  Debuglink result;
  if (!ok()) {
    return result;
  }

  const typename Arch::ElfShdr* debuglink = find_section(".gnu_debuglink");
  if (!debuglink) {
    return result;
  }
  if (debuglink->sh_size < 8) {
    LOG(warn) << "Invalid ELF file: unexpected .gnu_debuglink length";
    return result;
  }

  size_t crc_offset = debuglink->sh_size - 4;
  if (!r.read_into(debuglink->sh_offset + crc_offset, &result.crc)) {
    LOG(warn) << "Invalid ELF file: can't read .gnu_debuglink crc checksum";
    return result;
  }

  const char* file_name = r.read<char>(debuglink->sh_offset, crc_offset);
  if (!file_name) {
    LOG(warn) << "Invalid ELF file: can't read .gnu_debuglink file_name";
    return result;
  }

  null_terminated(file_name, crc_offset, result.file_name);
  return result;
}

template <typename Arch> Debugaltlink ElfReaderImpl<Arch>::read_debugaltlink() {
  Debugaltlink result;
  if (!ok()) {
    return result;
  }

  const typename Arch::ElfShdr* debuglink = find_section(".gnu_debugaltlink");
  if (!debuglink) {
    return result;
  }
  // Last 20 bytes are the build ID of the target file. Ignore for now.
  if (debuglink->sh_size < 21) {
    LOG(warn) << "Invalid ELF file: unexpected .gnu_debugaltlink length";
    return result;
  }

  size_t build_id_offset = debuglink->sh_size - 20;
  const char* file_name = r.read<char>(debuglink->sh_offset, build_id_offset);
  if (!file_name) {
    LOG(warn) << "Invalid ELF file: can't read .gnu_debugaltlink file_name";
    return result;
  }

  null_terminated(file_name, build_id_offset, result.file_name);
  return result;
}

template <typename Arch>
string ElfReaderImpl<Arch>::read_buildid() {
  string result;
  if (!ok()) {
    return result;
  }

  for (size_t i = 0; i < sections_size; ++i) {
    auto& s = sections[i];
    if (s.sh_type != SHT_NOTE) {
      continue;
    }

    auto offset = s.sh_offset;
    auto nhdr = r.read<typename Arch::ElfNhdr>(offset);
    if (!nhdr) {
      LOG(error) << "Failed to read ELF note";
      return result;
    }
    offset += sizeof(*nhdr);

    char name[4] = { 0 };
    if (!(nhdr->n_namesz == 4 &&
          r.read_into(offset, &name) &&
          memcmp("GNU", name, 4) == 0 &&
          nhdr->n_descsz > 0)) {
      continue;
    }
    // Note members are 4 byte aligned, twiddle bits to round up if necessary.
    offset += (nhdr->n_namesz + 3) & ~0x3;

    if (nhdr->n_type != NT_GNU_BUILD_ID) {
      continue;
    }

    const uint8_t* id = r.read<uint8_t>(offset, nhdr->n_descsz);
    if (!id) {
      LOG(error) << "Failed to read ELF note contents";
      return result;
    }

    result.reserve(nhdr->n_descsz);
    for (unsigned i = 0; i < nhdr->n_descsz; ++i) {
      char byte[3] = { 0 };
      snprintf(&byte[0], 3, "%02x", id[i]);
      result.append(byte);
    }

    break;
  }

  return result;
}

template <typename Arch>
bool ElfReaderImpl<Arch>::addr_to_offset(uintptr_t addr, uintptr_t& offset) {
  for (size_t i = 0; i < sections_size; ++i) {
    const auto& section = sections[i];
    // Skip the section if it either "occupies no space in the file" or
    // doesn't have a valid address because it does not "occupy memory
    // during process execution".
    if (section.sh_type == SHT_NOBITS || !(section.sh_flags & SHF_ALLOC)) {
      continue;
    }
    if (addr >= section.sh_addr && addr - section.sh_addr < section.sh_size) {
      offset = addr - section.sh_addr + section.sh_offset;
      return true;
    }
  }
  return false;
}

ElfReader::ElfReader(SupportedArch arch) : arch(arch), map(nullptr), size(0) {}

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

DynamicSection ElfReader::read_dynamic() { return impl().read_dynamic(); }

Debuglink ElfReader::read_debuglink() { return impl().read_debuglink(); }

Debugaltlink ElfReader::read_debugaltlink() { return impl().read_debugaltlink(); }

SectionOffsets ElfReader::find_section_file_offsets(const char* name) {
  return impl().find_section_file_offsets(name);
}

DwarfSpan ElfReader::dwarf_section(const char* name) {
  SectionOffsets offsets = impl().find_section_file_offsets(name);
  return DwarfSpan(map + offsets.start, map + offsets.end);
}

string ElfReader::read_buildid() { return impl().read_buildid(); }

bool ElfReader::addr_to_offset(uintptr_t addr, uintptr_t& offset) {
  return impl().addr_to_offset(addr, offset);
}

bool ElfReader::ok() { return impl().ok(); }

ElfFileReader::ElfFileReader(ScopedFd& fd, SupportedArch arch) : ElfReader(arch) {
  struct stat st;
  if (fstat(fd, &st) < 0) {
    FATAL() << "Can't stat fd";
  }
  if (st.st_size > 0) {
    map = static_cast<uint8_t*>(mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0));
    if (map == MAP_FAILED) {
      FATAL() << "Can't map fd";
    }
  }
  size = st.st_size;
}

ElfFileReader::~ElfFileReader() {
  if (map) {
    munmap(map, size);
  }
}

ScopedFd ElfFileReader::open_debug_file(const std::string& elf_file_name) {
  if (elf_file_name.empty() || elf_file_name[0] != '/') {
    return ScopedFd();
  }

  Debuglink debuglink = read_debuglink();
  if (debuglink.file_name.empty()) {
    return ScopedFd();
  }

  size_t last_slash = elf_file_name.find_last_of('/');
  string debug_path = "/usr/lib/debug/";
  debug_path += elf_file_name.substr(0, last_slash) + '/' + debuglink.file_name;
  ScopedFd debug_fd(debug_path.c_str(), O_RDONLY);
  if (!debug_fd.is_open()) {
    return ScopedFd();
  }

  // Verify that the CRC checksum matches, in case the debuginfo and text file
  // are in separate packages that are out of sync.
  uint32_t crc = 0xffffffff;
  while (true) {
    unsigned char buf[4096];
    ssize_t ret = ::read(debug_fd.get(), buf, sizeof(buf));
    if (ret < 0) {
      if (errno != EINTR) {
        LOG(debug) << "Error reading " << debug_path;
        return ScopedFd();
      }
    } else if (ret == 0) {
      break;
    } else {
      crc = crc32(crc, buf, ret);
    }
  }

  if ((crc ^ 0xffffffff) == debuglink.crc) {
    return debug_fd;
  }
  return ScopedFd();
}

SupportedArch ElfFileReader::identify_arch(ScopedFd& fd) {
  /**
   * This code is quite lax. That's OK because this is only used to create
   * a specific ElfReaderImpl, which does much more thorough checking of the
   * header.
   */
  static const int header_prefix_size = 20;
  char buf[header_prefix_size];
  ssize_t ret = read_to_end(fd, 0, buf, sizeof(buf));
  if (ret != (ssize_t)sizeof(buf) || buf[5] != 1) {
    return NativeArch::arch();
  }
  switch (buf[18] | (buf[19] << 8)) {
    case 0x03:
      return x86;
    case 0x3e:
      return x86_64;
    default:
      return NativeArch::arch();
  }
}

} // namespace rr
