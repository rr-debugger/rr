/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RECORDER_H_
#define RR_RECORDER_H_

#include <string>

class Task;

/**
 * Record the execution of the application that will be created by
 * argc, argv, and envp.  |rr_exe| points at rr's image (possibly in
 * the $PATH).
 * Returns an exit code --- if recording terminates normally, the exit code
 * of the recorded process.
 */
int record(const char* rr_exe, int argc, char* argv[], char** envp);

#endif /* RR_RECORDER_H_ */
