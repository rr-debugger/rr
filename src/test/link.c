/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TOKEN "ABC"
#define TOKEN_SIZE sizeof(TOKEN)

static const char token_file[] = "rr-link-file.txt";
static const char link_name[] = "rr-link-file.link";

void verify_token(int fd) {
	ssize_t len;
	char buf[TOKEN_SIZE];

	len = read(fd, buf, sizeof(buf));
	if (len != TOKEN_SIZE || strcmp(buf, TOKEN)) {
		puts("Internal error: FAILED: splice wrote the wrong data");
		exit(1);
	}
	puts("Got expected token " TOKEN);
}

int main() {
	int fd;

	fd = open(token_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
	write(fd, TOKEN, TOKEN_SIZE);
	close(fd);

	if (link(token_file, link_name)) {
		puts("Internal error: FAILED: link not created");
		exit(1);
	}

	fd = open(link_name, O_RDONLY);
	verify_token(fd);
	close(fd);

	unlink(token_file);

	fd = open(link_name, O_RDONLY);
	verify_token(fd);
	close(fd);

	unlink(link_name);

	puts("EXIT-SUCCESS");
	return 0;
}
