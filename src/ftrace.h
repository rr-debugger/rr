/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_FTRACE_H_
#define RR_FTRACE_H_

#include <unistd.h>

#include <string>

#include "TraceStream.h"

namespace rr {

class Session;

/*
 * API for starting/stopping the Linux ftrace API. This uses the support
 * process 'ftrace_helper'. It's only for debugging rr.
 */

namespace ftrace {

/**
 * Start kernel function-graph tracing. The processes of 'session', plus
 * rr itself, are traced. bin/ftrace_helper must have been started manually
 * before this gets called.
 */
void start_function_graph(const Session& session, const TraceStream& trace);

/**
 * Write a marker to the ftrace file. 'str' should be newline-terminated.
 */
void write(const std::string& str);

/**
 * Stop tracing.
 */
void stop();
}

} // namespace rr

#endif /* RR_FTRACE_H_ */
