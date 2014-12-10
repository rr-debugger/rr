/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Flags.h"

#include <assert.h>

Flags& Flags::get_for_init() { return singleton; }

Flags Flags::singleton;
