/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Dwarf.h"

#include <string.h>

#include "log.h"

using namespace std;

namespace rr {

struct Dwarf32 {
  typedef uint32_t Offset;
  static const uint8_t EntrySize = 4;
  struct CompilationUnitPreamble {
    uint32_t unit_length;
  };
};
struct Dwarf64 {
  typedef uint64_t Offset;
  static const uint8_t EntrySize = 8;
  struct __attribute__((packed)) CompilationUnitPreamble {
    uint32_t magic; /* 0xffffffff */
    uint64_t unit_length;
  };
};

template <typename D> struct  __attribute__((packed)) Dwarf4CompilationUnitHeader {
  typedef D Size;
  typename D::CompilationUnitPreamble preamble;
  uint16_t version;
  typename D::Offset debug_abbrev_offset;
  uint8_t address_size;

  void install_dwo_id(DwarfCompilationUnit* unit) const {
    unit->set_dwo_id(0);
  }
};

template <typename D> struct  __attribute__((packed)) Dwarf5CompilationUnitHeader {
  typedef D Size;
  typename D::CompilationUnitPreamble preamble;
  uint16_t version;
  uint8_t unit_type;
  uint8_t address_size;
  typename D::Offset debug_abbrev_offset;
  uint64_t dwo_id;

  void install_dwo_id(DwarfCompilationUnit* unit) const {
    if (version == 5 && (unit_type == DW_UT_skeleton || unit_type == DW_UT_split_compile)) {
      unit->set_dwo_id(dwo_id);
    } else {
      unit->set_dwo_id(0);
    }
  }
};

template <typename D> struct  __attribute__((packed)) Dwarf2LineNumberTableHeader {
  typedef D Size;
  typename D::CompilationUnitPreamble preamble;
  uint16_t version;
  typename D::Offset header_length;
  uint8_t minimum_instruction_length;
  uint8_t default_is_stmt;
  int8_t line_base;
  uint8_t line_range;
  uint8_t opcode_base;

  bool read_directories(const DwarfCompilationUnit& cu,
                        DwarfSpan span,
                        const DebugStrSpans& debug_str,
                        std::vector<const char*>& directories,
                        std::vector<DwarfSourceFile>& files) const;
};

template <typename D> struct  __attribute__((packed)) Dwarf4LineNumberTableHeader {
  typedef D Size;
  typename D::CompilationUnitPreamble preamble;
  uint16_t version;
  typename D::Offset header_length;
  uint8_t minimum_instruction_length;
  uint8_t maximum_operations_per_instruction;
  uint8_t default_is_stmt;
  int8_t line_base;
  uint8_t line_range;
  uint8_t opcode_base;

  bool read_directories(const DwarfCompilationUnit& cu,
                        DwarfSpan span,
                        const DebugStrSpans& debug_str,
                        std::vector<const char*>& directories,
                        std::vector<DwarfSourceFile>& files) const;
};

template <typename D> struct  __attribute__((packed)) Dwarf5LineNumberTableHeader {
  typedef D Size;
  typename D::CompilationUnitPreamble preamble;
  uint16_t version;
  uint8_t address_size;
  uint8_t segment_selector_size;
  typename D::Offset header_length;
  uint8_t minimum_instruction_length;
  uint8_t maximum_operations_per_instruction;
  uint8_t default_is_stmt;
  int8_t line_base;
  uint8_t line_range;
  uint8_t opcode_base;

  bool read_directories(const DwarfCompilationUnit& cu,
                        DwarfSpan span,
                        const DebugStrSpans& debug_str,
                        std::vector<const char*>& directories,
                        std::vector<DwarfSourceFile>& files) const;
};

uint64_t DwarfSpan::read_uleb(bool* ok) {
  uint64_t ret = 0;
  int shift = 0;
  while (start < end) {
    uint8_t b = *start;
    ++start;
    ret |= (b & 0x7f) << shift;
    if (!(b & 0x80)) {
      return ret;
    }
    shift += 7;
    if (shift >= 64) {
      *ok = false;
      return 0;
    }
  }
  *ok = false;
  return 0;
}

DwarfSpan DwarfSpan::read_leb_ref(bool* ok) {
  DwarfSpan ret(*this);
  while (start < end) {
    if (!(*start & 0x80)) {
      ++start;
      ret.end = start;
      return ret;
    }
    ++start;
  }
  *ok = false;
  return ret;
}

const char* DwarfSpan::read_null_terminated_string(bool* ok) {
  const void* p = memchr(start, 0, size());
  if (!p) {
    LOG(warn) << "String was not null-terminated";
    *ok = false;
    return nullptr;
  }
  const char* ret = reinterpret_cast<const char*>(start);
  start = static_cast<const uint8_t*>(p) + 1;
  return ret;
}

DwarfAbbrev* DwarfAbbrevSet::lookup(uint64_t code) {
  auto it = abbrevs.find(code);
  if (it != abbrevs.end()) {
    return it->second.get();
  }

  while (!remaining_span.empty()) {
    bool ok = true;
    uint64_t abbrev_code = remaining_span.read_uleb(&ok);
    unique_ptr<DwarfAbbrev> abbrev(new DwarfAbbrev);
    abbrev->tag = (DWTag)remaining_span.read_uleb(&ok);
    abbrev->children = (DWChildren)remaining_span.read_value<uint8_t>(&ok);
    auto abbrev_raw = abbrev.get();
    while (true) {
      uint64_t name = remaining_span.read_uleb(&ok);
      DWForm form = (DWForm)remaining_span.read_uleb(&ok);
      if (!name && !form) {
        break;
      }
      DwarfSpan constant;
      if (form == DW_FORM_implicit_const) {
        constant = remaining_span.read_leb_ref(&ok);
      }
      abbrev->attributes.push_back({ name, form, constant });
    }
    if (!ok) {
      LOG(warn) << "Invalid DWARF abbrev table!";
      return nullptr;
    }
    abbrevs.insert(make_pair(abbrev_code, move(abbrev)));
    if (code == abbrev_code) {
      return abbrev_raw;
    }
  }

  return nullptr;
}

DwarfAbbrevSet& DwarfAbbrevs::lookup(uint64_t offset) {
  auto it = abbrevs.find(offset);
  if (it != abbrevs.end()) {
    return *it->second;
  }

  unique_ptr<DwarfAbbrevSet> set(new DwarfAbbrevSet(debug_abbrev.subspan(offset)));
  auto set_raw = set.get();
  abbrevs.insert(make_pair(offset, move(set)));
  return *set_raw;
}

static DwarfAbbrev null_abbrev;

DwarfDIE::DwarfDIE(DwarfSpan span, DwarfAbbrevSet& abbrevs, uint8_t dwarf_size, uint8_t address_size, bool* ok)
  : address_size(address_size), dwarf_size(dwarf_size) {
  uint64_t code = span.read_uleb(ok);
  if (!ok) {
    return;
  }
  if (code == 0) {
    abbrev = &null_abbrev;
    return;
  }
  abbrev = abbrevs.lookup(code);
  if (!abbrev) {
    LOG(warn) << "No abbrev found for DIE";
    *ok = false;
    return;
  }
  attr_span = span;
}

static size_t form_size(DWForm form, size_t address_size, size_t dwarf_size, DwarfSpan* span, bool* ok) {
  if (form == DW_FORM_indirect) {
    form = (DWForm)span->read_uleb(ok);
    if (!ok) {
      return 0;
    }
  }
  if (form == DW_FORM_udata) {
    auto before = span->size();
    DwarfSpan a_span(*span);
    a_span.read_uleb(ok);
    if (!ok) {
      return 0;
    }
    return before - a_span.size();
  }
  switch (form) {
    case DW_FORM_addr: return address_size;
    case DW_FORM_addrx: return dwarf_size;
    case DW_FORM_data1: return 1;
    case DW_FORM_data2: return 2;
    case DW_FORM_data4: return 4;
    case DW_FORM_data8: return 8;
    case DW_FORM_data16: return 16;
    case DW_FORM_flag: return 1;
    case DW_FORM_strp: return dwarf_size;
    case DW_FORM_line_strp: return dwarf_size;
    case DW_FORM_strx: return dwarf_size;
    case DW_FORM_strx1: return 1;
    case DW_FORM_strx2: return 2;
    case DW_FORM_strx3: return 3;
    case DW_FORM_strx4: return 4;
    case DW_FORM_sec_offset: return dwarf_size;
    case DW_FORM_flag_present: return 0;
    case DW_FORM_implicit_const: return 0;
    default:
      LOG(warn) << "form " << form << " not supported!";
      *ok = false;
      return 0;
  }
}

DwarfSpan DwarfDIE::find_attribute(DWAttr attr, DWForm* form, bool* ok) const {
  DwarfSpan span = attr_span;
  for (auto& a : abbrev->attributes) {
    size_t size = form_size(a.form, address_size, dwarf_size, &span, ok);
    DwarfSpan a_span = span.consume(size);
    if (a.name == attr) {
      *form = a.form;
      if (a.form == DW_FORM_implicit_const) {
        a_span = a.constant;
      }
      return a_span;
    }
  }
  return DwarfSpan();
}

static uint64_t decode_unsigned_literal(DwarfSpan span, bool* ok) {
  int shift = 0;
  uint64_t ret = 0;
  while (!span.empty()) {
    if (shift >= 64) {
      LOG(warn) << "Literal too large";
      *ok = false;
      return 0;
    }
    ret |= (uint64_t)span.read_value<uint8_t>(ok) << shift;
    shift += 8;
  }
  return ret;
}

static int64_t decode_section_ptr(DwarfSpan span, DWForm form, bool* ok) {
  switch (form) {
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
    case DW_FORM_sec_offset: {
      uint64_t ret = decode_unsigned_literal(span, ok);
      if (ret > INT64_MAX) {
        LOG(warn) << "section ptr out of range";
        *ok = false;
        return 0;
      }
      return ret;
    }
    default:
      LOG(warn) << "Unknown section ptr form " << form;
      *ok = false;
      return 0;
  }
}

static uint64_t decode_unsigned(DwarfSpan span, DWForm form, bool* ok) {
  switch (form) {
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8: {
      return decode_unsigned_literal(span, ok);
    }
    case DW_FORM_udata: {
      return span.read_uleb(ok);
    }
    default:
      LOG(warn) << "Unknown unsigned form " << form;
      *ok = false;
      return 0;
  }
}

static const char* decode_string(const DwarfCompilationUnit& cu, DwarfSpan span, DWForm form, const DebugStrSpans& debug_strs, bool* ok) {
  switch (form) {
    case DW_FORM_strp: {
      uint64_t offset = decode_unsigned_literal(span, ok);
      if (!*ok) {
        return nullptr;
      }
      return debug_strs.debug_str.subspan(offset).read_null_terminated_string(ok);
    }
    case DW_FORM_line_strp: {
      uint64_t offset = decode_unsigned_literal(span, ok);
      if (!*ok) {
        return nullptr;
      }
      return debug_strs.debug_line_str.subspan(offset).read_null_terminated_string(ok);
    }
    case DW_FORM_strx:
    case DW_FORM_strx1:
    case DW_FORM_strx2:
    case DW_FORM_strx3:
    case DW_FORM_strx4: {
      uint64_t index = decode_unsigned_literal(span, ok) * cu.entry_size() + cu.str_offsets_base();
      if (!*ok) {
        return nullptr;
      }
      uint64_t offset = cu.read_entry_sized_value(debug_strs.debug_str_offsets.subspan(index), ok);
      if (!*ok) {
        return nullptr;
      }
      return debug_strs.debug_str.subspan(offset).read_null_terminated_string(ok);
    }
    default:
      LOG(warn) << "Unknown string form " << form;
      *ok = false;
      return 0;
  }
}

int64_t DwarfDIE::section_ptr_attr(DWAttr attr, bool* ok) const {
  DWForm form;
  auto span = find_attribute(attr, &form, ok);
  if (span.empty() || !ok) {
    return -1;
  }
  return decode_section_ptr(span, form, ok);
}

uint64_t DwarfDIE::unsigned_attr(DWAttr attr, bool* found, bool* ok) const {
  DWForm form;
  auto span = find_attribute(attr, &form, ok);
  if (span.empty() || !ok) {
    *found = false;
    return 0;
  }
  *found = true;
  return decode_unsigned(span, form, ok);
}

const char* DwarfDIE::string_attr(const DwarfCompilationUnit& cu, DWAttr attr, const DebugStrSpans& debug_strs, bool* ok) const {
  DWForm form;
  auto span = find_attribute(attr, &form, ok);
  if (span.empty() || !ok) {
    return nullptr;
  }
  return decode_string(cu, span, form, debug_strs, ok);
}

DwarfCompilationUnit DwarfCompilationUnit::next(DwarfSpan* debug_info, DwarfAbbrevs& abbrevs, bool* ok) {
  DwarfCompilationUnit ret;
  uint32_t word = DwarfSpan(*debug_info).read_value<uint32_t>(ok);
  if (!ok) {
    return ret;
  }
  if (word == 0xFFFFFFFF) {
    ret.init_size<Dwarf64>(debug_info, abbrevs, ok);
  } else {
    ret.init_size<Dwarf32>(debug_info, abbrevs, ok);
  }
  return ret;
}

template <typename D> void DwarfCompilationUnit::init_size(DwarfSpan* debug_info, DwarfAbbrevs& abbrevs, bool* ok) {
  auto h = DwarfSpan(*debug_info).read<Dwarf4CompilationUnitHeader<D>>(ok);
  if (!ok) {
    return;
  }
  if (2 <= h->version && h->version <= 4) {
    init<Dwarf4CompilationUnitHeader<D>>(debug_info, abbrevs, ok);
  } else if (h->version == 5) {
    init<Dwarf5CompilationUnitHeader<D>>(debug_info, abbrevs, ok);
  } else {
    LOG(warn) << "Unknown compilation unit version " << h->version;
    *ok = false;
  }
}

template <typename H> void DwarfCompilationUnit::init(DwarfSpan* debug_info, DwarfAbbrevs& abbrevs, bool* ok) {
  DwarfSpan span(*debug_info);
  auto h = span.read<H>(ok);
  if (!ok) {
    return;
  }
  uint64_t length = h->preamble.unit_length;
  if (length >= UINT64_MAX - 12) {
    LOG(warn) << "Invalid CU length";
    *ok = false;
    return;
  }
  debug_info->consume(length + sizeof(h->preamble));
  DwarfAbbrevSet& abbrev_set = abbrevs.lookup(h->debug_abbrev_offset);
  die_ = make_unique<DwarfDIE>(span, abbrev_set, sizeof(typename H::Size::Offset), h->address_size, ok);
  if (die_->tag() != DW_TAG_compile_unit &&
      die_->tag() != DW_TAG_partial_unit &&
      die_->tag() != DW_TAG_skeleton_unit) {
    LOG(warn) << "CU DIE is not DW_TAG_compilation_unit/DW_TAG_partial_unit/DW_TAG_skeleton_unit!";
    *ok = false;
    return;
  }
  entry_size_ = H::Size::EntrySize;
  h->install_dwo_id(this);
}

uint64_t DwarfCompilationUnit::read_entry_sized_value(DwarfSpan span, bool* ok) const {
  if (entry_size() == 4) {
    return span.read_value<uint32_t>(ok);
  } else if (entry_size() == 8) {
    return span.read_value<uint64_t>(ok);
  } else {
    LOG(warn) << "Unknown entry size " << entry_size();
    *ok = false;
    return 0;
  }
}

DwarfLineNumberTable::DwarfLineNumberTable(const DwarfCompilationUnit& cu, DwarfSpan span, const DebugStrSpans& debug_str, bool* ok) {
  uint32_t word = DwarfSpan(span).read_value<uint32_t>(ok);
  if (!ok) {
    return;
  }
  if (word == 0xFFFFFFFF) {
    init_size<Dwarf64>(cu, span, debug_str, ok);
  } else {
    init_size<Dwarf32>(cu, span, debug_str, ok);
  }
}

template <typename D> void DwarfLineNumberTable::init_size(const DwarfCompilationUnit& cu, DwarfSpan span, const DebugStrSpans& debug_str, bool* ok) {
  auto h = DwarfSpan(span).read<Dwarf2LineNumberTableHeader<D>>(ok);
  if (!ok) {
    return;
  }
  if (2 <= h->version && h->version <= 3) {
    init<Dwarf2LineNumberTableHeader<D>>(cu, span, debug_str, ok);
  } else if (h->version == 4) {
    init<Dwarf4LineNumberTableHeader<D>>(cu, span, debug_str, ok);
  } else if (h->version == 5) {
    init<Dwarf5LineNumberTableHeader<D>>(cu, span, debug_str, ok);
  } else {
    LOG(warn) << "Unknown compilation unit version " << h->version;
    *ok = false;
  }
}

static bool read_dwarf2_directories(DwarfSpan span, std::vector<const char*>& directories, std::vector<DwarfSourceFile>& files) {
  bool ok = true;
  directories.push_back(nullptr);
  while (true) {
    const char* dir = span.read_null_terminated_string(&ok);
    if (!ok) {
      return ok;
    }
    if (!*dir) {
      break;
    }
    directories.push_back(dir);
  }
  files.push_back({ 0, nullptr });
  while (true) {
    const char* file = span.read_null_terminated_string(&ok);
    if (!ok) {
      return ok;
    }
    if (!*file) {
      break;
    }
    uint64_t dir = span.read_uleb(&ok);
    if (dir >= directories.size()) {
      LOG(warn) << "Invalid directory index, bailing";
      return false;
    }
    span.read_uleb(&ok); // timestamp
    span.read_uleb(&ok); // length
    if (!ok) {
      return ok;
    }
    files.push_back({ dir, file });
  }

  return ok;
}

template<typename T>
bool Dwarf2LineNumberTableHeader<T>::read_directories(const DwarfCompilationUnit&,
                                                      DwarfSpan span,
                                                      const DebugStrSpans&,
                                                      std::vector<const char*>& directories,
                                                      std::vector<DwarfSourceFile>& files) const {
  return read_dwarf2_directories(span, directories, files);
}

template<typename T>
bool Dwarf4LineNumberTableHeader<T>::read_directories(const DwarfCompilationUnit&,
                                                      DwarfSpan span,
                                                      const DebugStrSpans&,
                                                      std::vector<const char*>& directories,
                                                      std::vector<DwarfSourceFile>& files) const {
  return read_dwarf2_directories(span, directories, files);
}

struct FileEntryFormat {
  DWLnct content_type;
  DWForm form;
};

template<typename T>
bool Dwarf5LineNumberTableHeader<T>::read_directories(const DwarfCompilationUnit& cu,
                                                      DwarfSpan span,
                                                      const DebugStrSpans& debug_str,
                                                      std::vector<const char*>& directories,
                                                      std::vector<DwarfSourceFile>& files) const {
  bool ok = true;
  uint64_t directory_entry_format_count = span.read_uleb(&ok);
  if (!ok) {
    return ok;
  }

  bool seen_lnct_path = false;
  std::vector<FileEntryFormat> directory_formats;
  for (uint64_t i = 0; i < directory_entry_format_count; ++i) {
    DWLnct content_type = (DWLnct)span.read_uleb(&ok);
    if (!ok) {
      return ok;
    }
    if (content_type == DW_LNCT_path) {
      if (seen_lnct_path) {
        LOG(warn) << "DW_LNCT_path appears twice in directories!";
        return false;
      }
      seen_lnct_path = true;
    }

    DWForm form = (DWForm)span.read_uleb(&ok);
    if (!ok) {
      return ok;
    }
    directory_formats.push_back({ content_type, form });
  }

  if (!seen_lnct_path) {
    LOG(warn) << "DW_LNCT_path does not appear in directories";
    return false;
  }

  uint64_t directories_count = span.read_uleb(&ok);
  if (!ok) {
    return ok;
  }

  for (uint64_t i = 0; i < directories_count; ++i) {
    for (auto format: directory_formats) {
      switch (format.content_type) {
        case DW_LNCT_path: {
          size_t size = form_size(format.form, address_size, Size::EntrySize, &span, &ok);
          DwarfSpan a_span = span.consume(size);
          auto directory = decode_string(cu, a_span, format.form, debug_str, &ok);
          if (!ok) {
            return ok;
          }
          directories.push_back(directory);
          break;
        }
        default:
          LOG(warn) << "Unknown DW_LNCT " << format.content_type << " for directory";
          return false;
      }
    }
  }

  uint64_t file_entry_format_count = span.read_uleb(&ok);
  if (!ok) {
    return ok;
  }

  seen_lnct_path = false;
  std::vector<FileEntryFormat> file_formats;
  for (uint64_t i = 0; i < file_entry_format_count; ++i) {
    DWLnct content_type = (DWLnct)span.read_uleb(&ok);
    if (!ok) {
      return ok;
    }
    if (content_type == DW_LNCT_path) {
      if (seen_lnct_path) {
        LOG(warn) << "DW_LNCT_path appears twice in files!";
        return false;
      }
      seen_lnct_path = true;
    }

    DWForm form = (DWForm)span.read_uleb(&ok);
    if (!ok) {
      return ok;
    }
    file_formats.push_back({ content_type, form });
  }

  if (!seen_lnct_path) {
    LOG(warn) << "DW_LNCT_path does not appear in files";
    return false;
  }

  uint64_t files_count = span.read_uleb(&ok);
  if (!ok) {
    return ok;
  }

  for (uint64_t i = 0; i < files_count; ++i) {
    uint64_t directory_index = 0;
    const char* file_path = NULL;
    for (auto format: file_formats) {
      switch (format.content_type) {
        case DW_LNCT_path: {
          size_t size = form_size(format.form, address_size, Size::EntrySize, &span, &ok);
          DwarfSpan a_span = span.consume(size);
          file_path = decode_string(cu, a_span, format.form, debug_str, &ok);
          if (!ok) {
            return ok;
          }
          break;
        }
        case DW_LNCT_directory_index: {
          size_t size = form_size(format.form, address_size, Size::EntrySize, &span, &ok);
          DwarfSpan a_span = span.consume(size);
          directory_index = decode_unsigned(a_span, format.form, &ok);
          if (!ok) {
            return ok;
          }
          break;
        }
        case DW_LNCT_md5: {
          if (format.form != DW_FORM_data16) {
            LOG(warn) << "md5 has unexpected form " << format.form;
            return false;
          }
          size_t size = form_size(format.form, address_size, Size::EntrySize, &span, &ok);
          span.consume(size);
          break;
        }
        default:
          LOG(warn) << "Unknown DW_LNCT " << format.content_type << " for file";
          return false;
      }
    }

    files.push_back({ directory_index, file_path });
  }

  return true;
}

template <typename H> void DwarfLineNumberTable::init(const DwarfCompilationUnit& cu,
                                                      DwarfSpan span,
                                                      const DebugStrSpans& debug_str,
                                                      bool* ok) {
  auto h = span.read<H>(ok);
  if (!ok) {
    return;
  }
  for (uint8_t i = 1; i < h->opcode_base; ++i) {
    span.read_uleb(ok);
  }
  if (!ok) {
    return;
  }
  *ok = h->read_directories(cu, span, debug_str, directories_, file_names_);
}

} // namespace rr
