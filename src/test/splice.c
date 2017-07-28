/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define TOKEN "ABC"
#define TOKEN_SIZE sizeof(TOKEN)

static const char token_file[] = "rr-splice-file.txt";

void verify_token(int fd) {
  ssize_t len;
  char buf[TOKEN_SIZE];

  len = read(fd, buf, sizeof(buf));
  if (len != TOKEN_SIZE || strcmp(buf, TOKEN)) {
    atomic_puts("Internal error: FAILED: splice wrote the wrong data");
    exit(1);
  }
  atomic_puts("Got expected token " TOKEN);
}

int main(void) {
  int pipefds[2];
  int filefd;
  loff_t off;
  ssize_t nmoved;

  filefd = open(token_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
  pipe2(pipefds, 0 /*no flags*/);
  write(pipefds[1], TOKEN, TOKEN_SIZE);

  off = 0;
  nmoved = splice(pipefds[0], NULL, filefd, &off, TOKEN_SIZE, 0 /*no flags*/);
  atomic_printf(
      "spliced %zd bytes from %d to %d; off changed from 0 to %" PRId64 "\n",
      nmoved, pipefds[0], filefd, off);

  lseek(filefd, 0, SEEK_SET);
  verify_token(filefd);

  off = 0;
  nmoved = splice(filefd, &off, pipefds[1], NULL, TOKEN_SIZE, 0 /*no flags*/);
  atomic_printf(
      "spliced %zd bytes from %d to %d; off changed from 0 to %" PRId64 "\n",
      nmoved, filefd, pipefds[1], off);

  verify_token(pipefds[0]);

  /* The test driver will clean up after us if the test failed
   * before this. */
  unlink(token_file);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
