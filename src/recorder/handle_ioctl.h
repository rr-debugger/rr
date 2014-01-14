/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef HANDLE_IOCTL_H_
#define HANDLE_IOCTL_H_

struct task;

void handle_ioctl_request(struct task* t, int request);

#endif /* HANDLE_IOCTL_H_ */
