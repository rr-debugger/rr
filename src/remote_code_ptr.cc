/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "remote_code_ptr.h"

using namespace std;

namespace rr {

ostream& operator<<(ostream& stream, remote_code_ptr p) {
  stream << (void*)p.register_value();
  return stream;
}

} // namespace rr
