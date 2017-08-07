/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Flags.h"

namespace rr {

Flags& Flags::get_for_init() { return singleton; }

Flags Flags::singleton;

} // namespace rr
