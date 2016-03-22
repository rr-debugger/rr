/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_STRING_VECTOR_TO_CHAR_ARRAY_H_
#define RR_STRING_VECTOR_TO_CHAR_ARRAY_H_

#include <string>
#include <vector>

namespace rr {

/**
 * Converts a vector of strings to a POSIX-style array of char*s terminated
 * by a nullptr.
 */
class StringVectorToCharArray {
public:
  StringVectorToCharArray(const std::vector<std::string>& vs) {
    for (auto& v : vs) {
      array.push_back(const_cast<char*>(v.c_str()));
    }
    array.push_back(nullptr);
  }
  char** get() { return array.data(); }

private:
  std::vector<char*> array;
};

} // namespace rr

#endif
