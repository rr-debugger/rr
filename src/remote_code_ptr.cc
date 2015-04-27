#include "remote_code_ptr.h"

std::ostream& operator<<(std::ostream& stream, remote_code_ptr p) {
  stream << (void*)p.register_value();
  return stream;
}
