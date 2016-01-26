/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "GdbCommand"

#include "GdbCommand.h"

RR_CMD("when") {
  return std::string() + "Current event: " +
         std::to_string(t->current_trace_frame().time()) + "\n";
}

RR_CMD("when-ticks") {
  return std::string() + "Current tick: " + std::to_string(t->tick_count()) +
         "\n";
}

RR_CMD("when-tid") {
  return std::string() + "Current tid: " + std::to_string(t->tid) + "\n";
}
