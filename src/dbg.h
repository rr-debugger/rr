/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef DEBUG_H
#define DEBUG_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "replayer.h"		// for emergency_debug()
#include "trace.h"		// for get_global_time()
#include "util.h"

/**
 * Useful debug macros.  Define DEBUGTAG with a "module name" to
 * enable DEBUG-level messages.  For example,
 *
 *  #define DEBUGTAG "Sched"
 *  ...
 *  #include "dbg.h"
 *
 * Also, optionally define LOG_FILE to send output to a non-default
 * file.  This can be useful with highly verbose output, or if the
 * tracee itself is logging data that you don't want interleaved with
 * rr spew.  This is orthogonal to DEBUGTAG.
 *
 *  static FILE* locallog = fopen("/tmp/rr-sched.log", "w");
 *  #define LOG_FILE locallog
 *  ...
 *  #include "dbg.h"
 */

#ifndef LOG_FILE
# define LOG_FILE stderr
#endif

#ifdef DEBUGTAG
# define debug(M, ...)							\
	do {								\
		fprintf(LOG_FILE, "[" DEBUGTAG "] " M "\n", ##__VA_ARGS__); \
		fflush(LOG_FILE);					\
	} while(0)
#else
# define debug(M, ...)				\
	do { } while(0)
#endif

inline static int should_log(void)
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
			fprintf(LOG_FILE,				\
				"[EMERGENCY] (%s:%d:%s: errno: %s) "	\
				"(task %d (rec:%d) at trace line %d)\n"	\
				" -> Assertion `"#_cond "' failed to hold: " \
				_msg "\n",				\
				__FILE__, __LINE__, __FUNCTION__,	\
				clean_errno(), _t->tid, _t->rec_tid,	\
				get_global_time(), ##__VA_ARGS__);	\
			_t->log_pending_events();			\
			emergency_debug(_t);				\
		}							\
	} while(0)

#define clean_errno()				\
	(errno == 0 ? "None" : strerror(errno))

#define fatal(M, ...)							\
	do {								\
		fprintf(LOG_FILE, "[FATAL] (%s:%d:%s: errno: %s) "	\
			"(trace line %d)\n"				\
			" -> " M "\n",					\
			__FILE__, __LINE__, __FUNCTION__,		\
			clean_errno(), get_global_time(), ##__VA_ARGS__); \
		abort();						\
	} while (0)

#define log_err(M, ...)						 \
	fprintf(LOG_FILE, "[ERROR] (%s:%d:%s: errno: %s) \n"	 \
		" -> " M "\n",					 \
		__FILE__, __LINE__, __FUNCTION__,		 \
		clean_errno(), ##__VA_ARGS__)

#define log_warn(M, ...)						\
	do {								\
		if (should_log()) {					\
			fprintf(LOG_FILE, "[WARN] (%s: errno: %s) " M "\n", \
				__FUNCTION__, clean_errno(), ##__VA_ARGS__); \
		}							\
	} while (0)

#define log_info(M, ...)						\
	do {								\
		if (should_log()) {					\
			fprintf(LOG_FILE, "[INFO] (%s) " M "\n",	\
				__FUNCTION__, ##__VA_ARGS__);		\
		}							\
	} while (0)

#endif /* DEBUG_H */
