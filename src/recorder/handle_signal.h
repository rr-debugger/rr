/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef __HANDLE_SIGNAL_H__
#define __HANDLE_SIGNAL_H__

struct context;
struct flags;

void handle_signal(const struct flags* flags, struct context* context);

#endif /* __HANDLE_SIGNAL_H__ */
