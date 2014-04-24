/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_HANDLE_SIGNAL_H__
#define RR_HANDLE_SIGNAL_H__

#include <signal.h>

class Task;
struct flags;

/**
 * Handle the pending signal for |t|.  To force delivery/handling of a
 * particular signal, pass a pointer to the siginfo in |si|.
 * Otherwise this function determines the pending signal info.
 */
void handle_signal(Task* t, siginfo_t* si = nullptr);

#endif /* RR_HANDLE_SIGNAL_H__ */
