#ifndef CONFIG_H_
#define CONFIG_H_

#include <inttypes.h>
									/* 100m */
//#define MAX_RECORD_INTERVAL		((uint64_t)100000000)
//streamcluster
#define MAX_RECORD_INTERVAL		((uint64_t)1000000)

#define MAX_TRACE_ENTRY_SIZE	8000001
#define MAX_SWITCH_COUNTER 		10000
/*
 * This is the default value for waiting for a write
 * system call to return. The value was determined by
 * analyzing the average wait times for the write
 * system call in the PARSEC benchmark suite.
 */
#define MAX_WAIT_TIMEOUT_SYS_WRITE_US		800

/*
 * For performance reasons, rr should run on the same
 * physical core as the traced child process but on a different
 * logical core if hyperthreading is available.
 */
#define RR_LOGICAL_CORE_AFFINITY	(unsigned long) 0x1
#define CHILD_LOGICAL_CORE_AFFINITY (unsigned long) 0x2

#endif /* CONFIG_H_ */
