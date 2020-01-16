/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Dwarf.h"

#include <string.h>

#include "log.h"

using namespace std;

namespace rr {

struct Dwarf32 {
  typedef uint32_t Offset;
  struct CompilationUnitPreamble {
    uint32_t unit_length;
  };
};
struct Dwarf64 {
  typedef uint64_t Offset;
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
};

template <typename D> struct  __attribute__((packed)) Dwarf5CompilationUnitHeader {
  typedef D Size;
  typename D::CompilationUnitPreamble preamble;
  uint16_t version;
  uint8_t unit_type;
  uint8_t address_size;
  typename D::Offset debug_abbrev_offset;
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

size_t DwarfDIE::form_size(DWForm form, DwarfSpan* span, bool* ok) const {
  if (form == DW_FORM_indirect) {
    form = (DWForm)span->read_uleb(ok);
    if (!ok) {
      return 0;
    }
  }
  switch (form) {
    case DW_FORM_addr: return address_size;
    case DW_FORM_data1: return 1;
    case DW_FORM_data2: return 2;
    case DW_FORM_data4: return 4;
    case DW_FORM_data8: return 8;
    case DW_FORM_flag: return 1;
    case DW_FORM_strp: return dwarf_size;
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
    size_t size = form_size(a.form, &span, ok);
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
    ret |= span.read_value<uint8_t>(ok) << shift;
    shift += 8;
  }
  return ret;
}

static int64_t decode_lineptr(DwarfSpan span, DWForm form, bool* ok) {
  switch (form) {
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
    case DW_FORM_sec_offset: {
      uint64_t ret = decode_unsigned_literal(span, ok);
      if (ret > INT64_MAX) {
        LOG(warn) << "lineptr out of range";
        *ok = false;
        return 0;
      }
      return ret;
    }
    default:
      LOG(warn) << "Unknown lineptr form " << form;
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
    default:
      LOG(warn) << "Unknown unsigned form " << form;
      *ok = false;
      return 0;
  }
}

static const char* decode_string(DwarfSpan span, DWForm form, const DwarfSpan& debug_str, bool* ok) {
  switch (form) {
    case DW_FORM_strp: {
      uint64_t offset = decode_unsigned_literal(span, ok);
      if (!ok) {
        return nullptr;
      }
      return debug_str.subspan(offset).read_null_terminated_string(ok);
    }
    default:
      LOG(warn) << "Unknown string form " << form;
      *ok = false;
      return 0;
  }
}

int64_t DwarfDIE::lineptr_attr(DWAttr attr, bool* ok) const {
  DWForm form;
  auto span = find_attribute(attr, &form, ok);
  if (span.empty() || !ok) {
    return -1;
  }
  return decode_lineptr(span, form, ok);
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

const char* DwarfDIE::string_attr(DWAttr attr, const DwarfSpan& debug_str, bool* ok) const {
  DWForm form;
  auto span = find_attribute(attr, &form, ok);
  if (span.empty() || !ok) {
    return nullptr;
  }
  return decode_string(span, form, debug_str, ok);
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
  if (die_->tag() != DW_TAG_compile_unit && die_->tag() != DW_TAG_partial_unit) {
    LOG(warn) << "CU DIE is not DW_TAG_compilation_unit/DW_TAG_partial_unit!";
    *ok = false;
    return;
  }
}

DwarfLineNumberTable::DwarfLineNumberTable(DwarfSpan span, bool* ok) {
  uint32_t word = DwarfSpan(span).read_value<uint32_t>(ok);
  if (!ok) {
    return;
  }
  if (word == 0xFFFFFFFF) {
    init_size<Dwarf64>(span, ok);
  } else {
    init_size<Dwarf32>(span, ok);
  }
}

template <typename D> void DwarfLineNumberTable::init_size(DwarfSpan span, bool* ok) {
  // Only support DWARF4 for now
  auto h = DwarfSpan(span).read<Dwarf2LineNumberTableHeader<D>>(ok);
  if (!ok) {
    return;
  }
  if (2 <= h->version && h->version <= 3) {
    init<Dwarf2LineNumberTableHeader<D>>(span, ok);
  } else if (h->version == 4) {
    init<Dwarf4LineNumberTableHeader<D>>(span, ok);
  } else {
    LOG(warn) << "Unknown compilation unit version " << h->version;
    *ok = false;
  }
}

template <typename H> void DwarfLineNumberTable::init(DwarfSpan span, bool* ok) {
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
  directories_.push_back(nullptr);
  while (true) {
    const char* dir = span.read_null_terminated_string(ok);
    if (!ok) {
      return;
    }
    if (!*dir) {
      break;
    }
    directories_.push_back(dir);
  }
  file_names_.push_back({ 0, nullptr });
  while (true) {
    const char* file = span.read_null_terminated_string(ok);
    if (!ok) {
      return;
    }
    if (!*file) {
      break;
    }
    uint64_t dir = span.read_uleb(ok);
    if (dir >= directories_.size()) {
      LOG(warn) << "Invalid directory index, bailing";
      *ok = false;
      return;
    }
    span.read_uleb(ok); // timestamp
    span.read_uleb(ok); // length
    if (!ok) {
      return;
    }
    file_names_.push_back({ dir, file });
  }
}

} // namespace rr
