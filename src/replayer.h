/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAYER_H_
#define RR_REPLAYER_H_

#include "TraceFrame.h"

/**
 * Replay the trace.  argc, argv, and envp are this process's
 * parameters.
 * Returns an exit code: 0 on success.
 */
int replay(const std::vector<std::string>& args);

bool trace_instructions_up_to_event(TraceFrame::Time event);

#endif /* RR_REPLAYER_H_ */
