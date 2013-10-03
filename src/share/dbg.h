/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef DEBUG_H
#define DEBUG_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../replayer/replayer.h" /* for emergency_debug() */

#include "task.h"
#include "util.h"

/**
 * Useful debug macros.  Define DEBUGTAG with a "module name" to
 * enable DEBUG-level messages.  For example,
 *
 *  #define DEBUGTAG "Sched"
 *  ...
 *  #include "dbg.h"
 */

#ifdef DEBUGTAG
# define debug(M, ...)							\
	do {								\
		fprintf(stderr, "[" DEBUGTAG "] " M "\n", ##__VA_ARGS__); \
	} while(0)
#else
# define debug(M, ...)				\
	do { } while(0)
#endif

inline static int should_log()
{
#ifdef DEBUGTAG
	return 1;
#else
	return rr_flags()->verbose;
#endif
}

/**
 * Assert a condition of the execution state of |_t|.  Print an error
 * message and enter into an emergency debugging session if the
 * assertion doesn't hold.
 */
#define assert_exec(_t, _cond, _msg, ...)				\
	do {								\
		if (!(_cond)) {						\
			fprintf(stderr,					\
				"[EMERGENCY] (%s:%d:%s: errno: %s) "	\
				"(task %d at trace line %d)\n"		\
				" -> Assertion `"#_cond "' failed to hold: " \
				_msg "\n",				\
				__FILE__, __LINE__, __FUNCTION__,	\
				clean_errno(), _t->tid, get_global_time(), \
				##__VA_ARGS__);				\
			log_pending_events(_t);				\
			emergency_debug(_t);				\
		}							\
	} while(0)

#define clean_errno()				\
	(errno == 0 ? "None" : strerror(errno))

#define fatal(M, ...)							\
	do {								\
		fprintf(stderr, "[FATAL] (%s:%d:%s: errno: %s) "	\
			"(trace line %d)\n"				\
			" -> " M "\n",					\
			__FILE__, __LINE__, __FUNCTION__,		\
			clean_errno(), get_global_time(), ##__VA_ARGS__); \
		abort();						\
	} while (0)

#define log_err(M, ...)						 \
	fprintf(stderr, "[ERROR] (%s:%d:%s: errno: %s) \n"	 \
		" -> " M "\n",					 \
		__FILE__, __LINE__, __FUNCTION__,		 \
		clean_errno(), ##__VA_ARGS__)

#define log_warn(M, ...)						\
	do {								\
		if (should_log()) {					\
			fprintf(stderr, "[WARN] (%s: errno: %s) " M "\n", \
				__FUNCTION__, clean_errno(), ##__VA_ARGS__); \
		}							\
	} while (0)

#define log_info(M, ...)						\
	do {								\
		if (should_log()) {					\
			fprintf(stderr, "[INFO] (%s) " M "\n",		\
				__FUNCTION__, ##__VA_ARGS__);		\
		}							\
	} while (0)

#endif /* DEBUG_H */
