/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DWARF_H_
#define RR_DWARF_H_

#include <stdint.h>

#include <memory>
#include <unordered_map>
#include <vector>

namespace rr {

enum DWTag {
  DW_TAG_null = 0,
  DW_TAG_compile_unit = 0x11,
  DW_TAG_partial_unit = 0x3c,
  DW_TAG_skeleton_unit = 0x4a,
};

enum DWAttr {
  DW_AT_name = 0x03,
  DW_AT_stmt_list = 0x10,
  DW_AT_comp_dir = 0x1b,
  DW_AT_str_offsets_base = 0x72,
  DW_AT_dwo_name = 0x76,
  DW_AT_GNU_dwo_name = 0x2130,
  DW_AT_GNU_dwo_id = 0x2131,
};

enum DWChildren {
  DW_CHILDREN_no = 0x00,
  DW_CHILDREN_yes = 0x01
};

enum DWForm {
  DW_FORM_addr = 0x01,
  DW_FORM_block2 = 0x03,
  DW_FORM_block4 = 0x04,
  DW_FORM_data2 = 0x05,
  DW_FORM_data4 = 0x06,
  DW_FORM_data8 = 0x07,
  DW_FORM_data1 = 0x0b,
  DW_FORM_flag = 0x0c,
  DW_FORM_strp = 0x0e,
  DW_FORM_udata= 0x0f,
  DW_FORM_indirect = 0x16,
  DW_FORM_sec_offset = 0x17,
  DW_FORM_flag_present = 0x19,
  DW_FORM_strx = 0x1a,
  DW_FORM_addrx = 0x1b,
  DW_FORM_data16 = 0x1e,
  DW_FORM_line_strp = 0x1f,
  DW_FORM_implicit_const = 0x21,
  DW_FORM_strx1 = 0x25,
  DW_FORM_strx2 = 0x26,
  DW_FORM_strx3 = 0x27,
  DW_FORM_strx4 = 0x28,
};

enum DWLnct {
  DW_LNCT_path = 0x1,
  DW_LNCT_directory_index = 0x2,
  DW_LNCT_md5 = 0x5,
};

enum DWUt {
  DW_UT_compile = 0x01,
  DW_UT_skeleton = 0x04,
  DW_UT_split_compile = 0x05,
};

class DwarfSpan {
public:
  DwarfSpan(const uint8_t* start, const uint8_t* end) : start(start), end(end) {}
  DwarfSpan(const DwarfSpan& other) = default;
  DwarfSpan() : start(nullptr), end(nullptr) {}
  size_t size() const { return end - start; }
  uint64_t read_uleb(bool* ok);
  DwarfSpan read_leb_ref(bool* ok);
  const char* read_null_terminated_string(bool* ok);
  template <typename T> const T* read(bool *ok) {
    if (size() < sizeof(T)) {
      *ok = false;
      return nullptr;
    }
    auto ret = reinterpret_cast<const T*>(start);
    start += sizeof(T);
    return ret;
  }
  template <typename T> T read_value(bool *ok) {
    const T* r = read<T>(ok);
    return r ? *r : T();
  }
  bool empty() {
    return start == end;
  }
  DwarfSpan subspan(uint64_t offset, uint64_t sz = UINT64_MAX) const {
    DwarfSpan ret(*this);
    if (size() <= offset) {
      ret.start = end;
      return ret;
    }
    ret.start += offset;
    if (ret.size() <= sz) {
      return ret;
    }
    ret.end = ret.start + sz;
    return ret;
  }
  DwarfSpan consume(uint64_t sz) {
    DwarfSpan ret(*this);
    if (size() <= sz) {
      start = end;
      return ret;
    }
    ret.end = ret.start + sz;
    start = ret.end;
    return ret;
  }
private:
  const uint8_t* start;
  const uint8_t* end;
};

struct DebugStrSpans {
  DwarfSpan debug_str;
  DwarfSpan debug_str_offsets;
  DwarfSpan debug_line_str;
};

struct DwarfAbbrevAttribute {
  uint64_t name;
  DWForm form;
  DwarfSpan constant; // DWARF5
};

struct DwarfAbbrev {
  DwarfAbbrev() : tag(DW_TAG_null), children(DW_CHILDREN_no) {}
  std::vector<DwarfAbbrevAttribute> attributes;
  DWTag tag;
  DWChildren children;
};

class DwarfAbbrevSet {
public:
  DwarfAbbrevSet(DwarfSpan span) : remaining_span(span) {}
  DwarfAbbrev* lookup(uint64_t code);
private:
  std::unordered_map<uint64_t, std::unique_ptr<DwarfAbbrev>> abbrevs;
  DwarfSpan remaining_span;
};

class DwarfAbbrevs {
public:
  DwarfAbbrevs(DwarfSpan debug_abbrev) : debug_abbrev(debug_abbrev) {}
  DwarfAbbrevSet& lookup(uint64_t offset);
private:
  DwarfSpan debug_abbrev;
  std::unordered_map<uint64_t, std::unique_ptr<DwarfAbbrevSet>> abbrevs;
};

class DwarfCompilationUnit;

class DwarfDIE {
public:
  DwarfDIE(DwarfSpan span, DwarfAbbrevSet& abbrevs, uint8_t dwarf_size, uint8_t address_size, bool* ok);
  DWTag tag() const { return abbrev->tag; }
  // Returns empty span if not found
  DwarfSpan find_attribute(DWAttr attr, DWForm* form, bool* ok) const;
  // Returns -1 if no attr
  int64_t section_ptr_attr(DWAttr attr, bool* ok) const;
  // Sets *found to false if not found.
  uint64_t unsigned_attr(DWAttr attr, bool* found, bool* ok) const;
  // Returns nullptr if no attr
  const char* string_attr(const DwarfCompilationUnit& unit, DWAttr attr, const DebugStrSpans& debug_str, bool* ok) const;
private:
  DwarfAbbrev* abbrev;
  DwarfSpan attr_span;
  uint8_t address_size;
  uint8_t dwarf_size;
};

class DwarfCompilationUnit {
public:
  // Consumes debug_info span and leaves rest behind
  static DwarfCompilationUnit next(DwarfSpan* debug_info, DwarfAbbrevs& abbrevs, bool* ok);
  const DwarfDIE& die() const { return *die_; }
  uint64_t dwo_id() const { return dwo_id_; }
  void set_dwo_id(uint64_t dwo_id) { dwo_id_ = dwo_id; }
  uint64_t str_offsets_base() const { return str_offsets_base_; }
  void set_str_offsets_base(uint64_t str_offsets_base) { str_offsets_base_ = str_offsets_base; }
  uint8_t entry_size() const { return entry_size_; }
  uint64_t read_entry_sized_value(DwarfSpan span, bool* ok) const;
private:
  DwarfCompilationUnit() {}
  template <typename D> void init_size(DwarfSpan* debug_info, DwarfAbbrevs& abbrevs, bool* ok);
  template <typename H> void init(DwarfSpan* debug_info, DwarfAbbrevs& abbrevs, bool* ok);
  std::unique_ptr<DwarfDIE> die_;
  uint64_t dwo_id_;
  uint64_t str_offsets_base_;
  uint8_t entry_size_;
};

struct DwarfSourceFile {
  uint64_t directory_index;
  const char* file_name;
};

class DwarfLineNumberTable {
public:
  DwarfLineNumberTable(const DwarfCompilationUnit& cu, DwarfSpan span, const DebugStrSpans& debug_strs, bool* ok);
  // Null directory pointer means "compilation dir". The first entry is null.
  const std::vector<const char*>& directories() const { return directories_; }
  // Null file name means "compilation unit name". The first entry is null.
  const std::vector<DwarfSourceFile>& file_names() const { return file_names_; }
private:
  template <typename D> void init_size(const DwarfCompilationUnit& cu, DwarfSpan span, const DebugStrSpans& debug_strs, bool* ok);
  template <typename H> void init(const DwarfCompilationUnit& cu, DwarfSpan span, const DebugStrSpans& debug_strs, bool* ok);
  std::vector<const char*> directories_;
  std::vector<DwarfSourceFile> file_names_;
};

#if __cplusplus == 201103L

/**
 * Implementation of make_unique for C++11 (from https://herbsutter.com/gotw/_102/).
 */
template<typename T, typename ...Args>
std::unique_ptr<T> make_unique( Args&& ...args )
{
    return std::unique_ptr<T>( new T( std::forward<Args>(args)... ) );
}

#endif /* __cplusplus == 201103L */

} // namespace rr

#endif /* RR_DWARF_H_ */
