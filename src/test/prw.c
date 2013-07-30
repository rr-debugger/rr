/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	int fd = open("prw.txt", O_CREAT | O_RDWR);
	const char content[] = "01234567890\nhello there\n";
	char buf[sizeof(content)];
	ssize_t nr;

	memset(buf, '?', sizeof(buf));
	nr = write(fd, buf, sizeof(buf));
	assert(nr == sizeof(buf));
	nr = write(fd, buf, 10);
	assert(nr == 10);

	nr = pwrite(fd, content, sizeof(content), 10);
	assert(nr == sizeof(content));
	printf("Wrote ```%s'''\n", content);

	nr = pread(fd, buf, sizeof(buf), 10);
	assert(nr == sizeof(content));
	printf("Read ```%s'''\n", buf);

	puts("EXIT-SUCCESS");
	return 0;
}
