/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RECORDER_H_
#define RECORDER_H_

#include <string>

struct flags;
class Task;

/**
 * Record the execution of the application that will be created by
 * argc, argv, and envp.  |rr_exe| points at rr's image (possibly in
 * the $PATH).
 */
void record(const char* rr_exe, int argc, char* argv[], char** envp);

/**
 * Record a trace-termination event, sync the trace files, and shut
 * down.  The |t| argument allows this to give task context to the
 * trace-termination event.  It should be the most-recently-known
 * executed task.
 */
void terminate_recording(Task* t = nullptr);

/**
 * Return the name of the initial exe image.
 */
const std::string& get_exe_image();

#endif /* RECORDER_H_ */
