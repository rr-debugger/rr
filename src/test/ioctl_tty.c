/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  struct termios tc;
  struct termio tio;
  int ret;
  memset(&tc, 0, sizeof(tc));
  memset(&tio, 0, sizeof(tio));

  ret = ioctl(STDIN_FILENO, TCGETS, &tc);
  test_assert(ret == 0);
  atomic_printf("TCGETS returned %d: { iflag=0x%x, oflag=0x%x, cflag=0x%x, "
                "lflag=0x%x }\n",
                ret, tc.c_iflag, tc.c_oflag, tc.c_cflag, tc.c_lflag);
  ret = ioctl(STDIN_FILENO, TCSETS, &tc);
  test_assert(ret == 0);
  ret = ioctl(STDIN_FILENO, TCSETSW, &tc);
  test_assert(ret == 0);
  ret = ioctl(STDIN_FILENO, TCSETSF, &tc);
  test_assert(ret == 0);

  ret = ioctl(STDIN_FILENO, TCGETA, &tio);
  test_assert(ret == 0);
  atomic_printf("TCGETA returned %d: { iflag=0x%x, oflag=0x%x, cflag=0x%x, "
                "lflag=0x%x }\n",
                ret, tio.c_iflag, tio.c_oflag, tio.c_cflag, tio.c_lflag);
  ret = ioctl(STDIN_FILENO, TCSETA, &tio);
  test_assert(ret == 0);
  ret = ioctl(STDIN_FILENO, TCSETAW, &tio);
  test_assert(ret == 0);
  ret = ioctl(STDIN_FILENO, TCSETAF, &tio);
  test_assert(ret == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
