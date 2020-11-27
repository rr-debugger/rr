/*
Following structure definitions got rewritten with looking at
this (MIT like) "Boost Software License, Version 1.0" licensed file:
    https://github.com/boostorg/dll/blob/develop/include/boost/dll/detail/pe_info.hpp

The actual size informations were retrieved by following gdb session:
  $ cat test.cpp
  #include <boost/dll/detail/pe_info.hpp>
  int main() {
    std::ifstream ifs;
    boost::dll::detail::pe_info32 a; a.parsing_supported(ifs); a.sections(ifs);
    boost::dll::detail::pe_info64 b; b.parsing_supported(ifs); b.sections(ifs);
  }
  $ g++ -g test.cpp
  $ gdb -q --args a.out
      b boost::dll::detail::pe_info32::parsing_supported
      b boost::dll::detail::pe_info64::parsing_supported
      run
      ptype /o dos_t
      ptype /o header_t
      ptype /o section_t

Not used, but another source could be this MIT licensed repository:
    https://github.com/microsoft/xlang/blob/master/src/library/impl/meta_reader/pe.h
*/

#ifndef WINE_H_
#define WINE_H_

struct __attribute__((packed)) IMAGE_DOS_HEADER_ {
    uint16_t e_magic;
    char unused[58];
    uint32_t e_lfanew;
};

struct __attribute__((packed)) IMAGE_FILE_HEADER_ {
    char unused1[2];
    uint16_t NumberOfSections;
    char unused2[12];
    uint16_t SizeOfOptionalHeader;
    char unused3[2];
};

struct __attribute__((packed)) IMAGE_OPTIONAL_HEADER_ {
    uint32_t Magic;
    char unused[236];
};

struct __attribute__((packed)) IMAGE_NT_HEADERS_ {
    uint32_t Signature;
    struct IMAGE_FILE_HEADER_ FileHeader;
    struct IMAGE_OPTIONAL_HEADER_ OptionalHeader;
};

struct __attribute__((packed)) IMAGE_SECTION_HEADER_ {
    char unused1[12];
    uint32_t VirtualAddress;
    char unused2[24];
};

#endif /* WINE_H_ */
