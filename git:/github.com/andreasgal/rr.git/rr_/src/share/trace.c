#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>

#include "trace.h"
#include "sys.h"

#include "../share/util.h"

static FILE* __trace;

void init_write_trace(const char* path)
{

	char line[1024];

	__trace = (FILE*) sys_fopen(path, "r");

	//skip the first line -- is only meta-information
	if (feof(__trace) || fgets(line, 1024, __trace) == NULL) {
		perror("failed reading meta-information\n");
		exit(-1);
	}
}

void close_trace()
{
	sys_fclose(__trace);
}



