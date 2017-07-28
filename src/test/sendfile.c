/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define TOKEN "ABC"
#define TOKEN_SIZE sizeof(TOKEN)

static const char token_file[] = "rr-sendfile-file.txt";
static const char token_file_out[] = "rr-sendfile-file-out.txt";

void verify_token(int fd) {
  ssize_t len;
  char buf[TOKEN_SIZE];

  len = read(fd, buf, sizeof(buf));
  if (len != TOKEN_SIZE || strcmp(buf, TOKEN)) {
    atomic_puts("Internal error: FAILED: sendfile wrote the wrong data");
    exit(1);
  }
  atomic_puts("Got expected token " TOKEN);
}

int main(void) {
  int filefd;
  int filefd_out;
  loff_t off = 0;

  filefd = open(token_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
  filefd_out = open(token_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
  write(filefd, TOKEN, TOKEN_SIZE);

  sendfile64(filefd_out, filefd, &off, TOKEN_SIZE);

  atomic_printf(
      "sendfile %zu bytes from %d to %d; off changed from 0 to %" PRId64 "\n",
      TOKEN_SIZE, filefd, filefd_out, off);
  lseek(filefd_out, 0, SEEK_SET);
  verify_token(filefd_out);

  lseek(filefd, 0, SEEK_SET);
  sendfile64(filefd_out, filefd, NULL, TOKEN_SIZE);

  atomic_printf("sendfile %zu bytes from %d to %d\n", TOKEN_SIZE, filefd,
                filefd_out);
  lseek(filefd_out, 0, SEEK_SET);
  verify_token(filefd_out);

  /* The test driver will clean up after us if the test failed
   * before this. */
  unlink(token_file);
  unlink(token_file_out);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
