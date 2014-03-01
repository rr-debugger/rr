/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef __IPC_H__
#define __IPC_H__

// NB: this definition is required for pread()/pwrite() to work
// properly when reading memory addresses that happen to be negative
// 2's complement numbers.
// 
// XXX we can't globally define this currently, because some files
// need to see 32-bit definitions (rec_process_event.cc f.e.).  But
// having this here is very bad because files that include this get
// 32-bit or 64-bit definitions depending on how early they include
// this.  The options for fixing this are
//
//  1. Convert all code to explicit stat64() usage and remove this
//
//  2. Globally define this and create rr-local definitions of the
//  required 32-bit symbols.
//
//  3. x64 support to make this problem go away (except for 32-bit
//  tracees ...)
//
// Option (2) is probably best, but option 1 may be less work.
#define _FILE_OFFSET_BITS 64

#include <sys/user.h>

#include "types.h"

class Task;

long read_child_code(pid_t pid, byte* addr);
long read_child_data_word(Task* t, byte* addr);
void* read_child_data(Task *t, size_t size, byte* addr);
/**
 * Directly read |size| bytes from |addr| into |buf|, which must be
 * backed by at least |size| bytes.
 *
 * Don't use this directly.  Use Task::read_bytes() instead.
 */
void read_child_data_direct(Task *t, const byte* addr, size_t size, byte* buf);
void read_child_usr(Task *t, void *dest, void *src, size_t size);
void* read_child_data_checked(Task *t, size_t size, byte* addr, ssize_t *read_bytes);
ssize_t checked_pread(Task* t, byte* buf, size_t size, off_t offset);
void memcpy_child(Task* t, void* dest, void* src, int size);

void write_child_code(Task* t, void* addr, long code);
void write_child_data_n(Task* t, ssize_t size, byte* addr,
			const byte* data);
void write_child_data(Task* t, ssize_t size, byte* addr,
		      const byte* data);

#endif /* __IPC_H__ */
