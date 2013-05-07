/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef CONFIG_H_
#define CONFIG_H_

#include <inttypes.h>
									/* 100m */
//#define MAX_RECORD_INTERVAL		((uint64_t)100000000)
//streamcluster
#define MAX_RECORD_INTERVAL		((uint64_t)1000000)

#define MAX_TRACE_ENTRY_SIZE	8000001
#define MAX_SWITCH_COUNTER 		10000 /* TODO: The amount of events decreases when the filter is on */
/*
 * This is the default value for waiting for a write
 * system call to return. The value was determined by
 * analyzing the average wait times for the write
 * system call in the PARSEC benchmark suite.
 */
#define MAX_WAIT_TIMEOUT_SYS_WRITE_US		800

/* Set the logical core on which the child process will be pinned on */
#define CHILD_LOGICAL_CORE_AFFINITY_MASK (unsigned long) 0x1

#endif /* CONFIG_H_ */
