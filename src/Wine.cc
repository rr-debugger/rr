/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <algorithm>
#include <cstdint>
#include <list>
#include <sstream>
#include <string>

#include "AddressSpace.h"
#include "log.h"
#include "PE.h"
#include "Task.h"

using namespace std;

namespace rr {

string create_library_response_from_mappings(Task *t) {

  // create an own list of the current mappings
  list<KernelMapping> mapping_list;
  for (KernelMapIterator it(t); !it.at_end(); ++it) {
    auto km = it.current();
    if (km.fsname().substr(0, 7) == "/memfd:") {
      continue;
    }
    if (km.is_vdso() || km.is_heap() || km.is_stack() || km.is_vvar() || km.is_vsyscall()) {
      continue;
    }
    LOG(debug) << "Possible mapping for GDB reply: " << km;
    mapping_list.push_back(km);
  }

  struct library {
    library() : has_exec(false) {};
    vector<remote_ptr<void>> segments;
    bool has_exec;
  };
  map<string, library> libraries;

  // iterate through the mappings and search for PE libraries
  // see wine, packet_query_libraries_cb
  char buf[0x400];
  for (auto it = mapping_list.begin(); it != mapping_list.end(); it++) {
    auto km = *it;
    bool ok = true;
    t->read_bytes_helper(km.start(), sizeof(buf), buf, &ok);
    if (!ok) {
      continue;
    }

    struct IMAGE_DOS_HEADER_* dosheader = reinterpret_cast<struct IMAGE_DOS_HEADER_*>(buf);
    if (memcmp(&dosheader->e_magic, "MZ", 2) != 0 ||
        dosheader->e_lfanew >= sizeof(buf)-4)
    {
      continue;
    }

    struct IMAGE_NT_HEADERS_* ntheader = reinterpret_cast<struct IMAGE_NT_HEADERS_*>(buf + dosheader->e_lfanew);
    if (memcmp(&ntheader->Signature, "PE\0\0", 4) != 0) {
      continue;
    }

    if (ntheader->OptionalHeader.Magic != 0x10b /*32-bit*/ &&
        ntheader->OptionalHeader.Magic != 0x20b /*64-bit*/)
    {
      continue;
    }

    vector<remote_ptr<void>> segments;
    struct IMAGE_SECTION_HEADER_* sec = reinterpret_cast<struct IMAGE_SECTION_HEADER_*>
        (((char*)&ntheader->OptionalHeader) + ntheader->FileHeader.SizeOfOptionalHeader);
    int number_of_sections = ntheader->FileHeader.NumberOfSections;
    for (int i = 0; sec && i < std::max(number_of_sections, 1); ++i) {
      struct IMAGE_SECTION_HEADER_* seci = sec + i;
      if (reinterpret_cast<char*>(seci) + sizeof(*seci) > buf + sizeof(buf)) {
        break;
      }
      segments.push_back(km.start() + seci->VirtualAddress);
    }

    string name = km.fsname();

    // If the mapping with the PE signature has no name assigned search the other segments for a name.
    for (auto it2 = mapping_list.begin(); name.empty() && it2 != mapping_list.end(); it2++) {
      if (find(segments.begin(), segments.end(), it2->start()) != segments.end()) {
        if (!it2->fsname().empty()) {
          name = it2->fsname();
        }
      }
    }

    // we found no name
    if (name.empty()) {
      continue;
    }

    // e.g. gdi32.so is prepared by wine to be found as PE image, but gdb does not like it.
    if (name.substr(name.length() - 3, 3) == ".so") {
      continue;
    }

    libraries[name].segments = segments;
    libraries[name].has_exec = true;
  }

  // remove mappings related to PE libraries
  for (auto m = mapping_list.begin(); m != mapping_list.end(); ) {
    bool del = false;
    for (auto lib : libraries) {
      if (m->fsname() == lib.first) {
        del = true;
      }
      if (!del) {
        for (auto seg : lib.second.segments) {
          if (seg == m->start()) {
            del = true;
          }
        }
      }
    }
    if (del) {
      m = mapping_list.erase(m);
    } else {
      m++;
    }
  }

  // search remaining for regular shared objects
  for (auto it = mapping_list.begin(); it != mapping_list.end(); it++) {
    auto km = *it;
    string name = km.fsname();
    if (!name.empty()) {
      libraries[name].segments.push_back(km.start());
      if (km.prot() & PROT_EXEC) {
        libraries[name].has_exec = true;
      }
    }
  }

  // now create the output string from what we found
  stringstream sstr;
  sstr << "<library-list>";
  sstr << hex;

  for (auto lib : libraries) {
    if (lib.second.has_exec) {
      sstr << "<library name=\"" << lib.first << "\">";
      for (auto seg : lib.second.segments) {
        sstr << "<segment address=\"" << seg << "\"/>";
      }
      sstr << "</library>";
    }
  }

  sstr << "</library-list>";
  return sstr.str();
}

} // namespace rr
