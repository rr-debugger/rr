/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAYER_H_
#define RR_REPLAYER_H_

#include <stdint.h>

/**
 * Replay the trace.  argc, argv, and envp are this process's
 * parameters.
 * Returns an exit code: 0 on success.
 */
int replay(int argc, char* argv[], char** envp);

bool trace_instructions_up_to_event(uint64_t event);

#endif /* RR_REPLAYER_H_ */
