/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd;
  int ret;
  struct termios* tc;
  struct termio* tio;
  pid_t* pgrp;
  int* navail;
  int* outq;
  struct winsize* w;
  pid_t* sid;

  fd = open("/dev/tty", O_RDWR);
  if (fd < 0) {
    atomic_puts("Can't open tty, aborting test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  ALLOCATE_GUARD(tc, 'a');
  test_assert(0 == ioctl(fd, TCGETS, tc));
  VERIFY_GUARD(tc);
  atomic_printf("TCGETS returned { iflag=0x%x, oflag=0x%x, cflag=0x%x, "
                "lflag=0x%x }\n",
                tc->c_iflag, tc->c_oflag, tc->c_cflag, tc->c_lflag);
  test_assert(0 == ioctl(fd, TCSETS, tc));
  test_assert(0 == ioctl(fd, TCSETSW, tc));
  test_assert(0 == ioctl(fd, TCSETSF, tc));

  ALLOCATE_GUARD(tio, 'b');
  test_assert(0 == ioctl(fd, TCGETA, tio));
  VERIFY_GUARD(tio);
  atomic_printf("TCGETA returned { iflag=0x%x, oflag=0x%x, cflag=0x%x, "
                "lflag=0x%x }\n",
                tio->c_iflag, tio->c_oflag, tio->c_cflag, tio->c_lflag);
  test_assert(0 == ioctl(fd, TCSETA, tio));
  test_assert(0 == ioctl(fd, TCSETAW, tio));
  test_assert(0 == ioctl(fd, TCSETAF, tio));

  test_assert(0 == ioctl(fd, TIOCGLCKTRMIOS, tc));
  VERIFY_GUARD(tc);
  atomic_printf("TIOCGLCKTRMIOS returned { iflag=0x%x, oflag=0x%x, cflag=0x%x, "
                "lflag=0x%x }\n",
                tio->c_iflag, tio->c_oflag, tio->c_cflag, tio->c_lflag);
  ret = ioctl(fd, TIOCSLCKTRMIOS, tc);
  test_assert(ret >= 0 || errno == EPERM);

  test_assert(0 == ioctl(fd, TCSBRK, 0));
  test_assert(0 == ioctl(fd, TCSBRKP, 0));
  test_assert(0 == ioctl(fd, TIOCSBRK, 0));
  test_assert(0 == ioctl(fd, TIOCCBRK, 0));

  ALLOCATE_GUARD(pgrp, 'c');
  test_assert(0 == ioctl(fd, TIOCGPGRP, pgrp));
  VERIFY_GUARD(pgrp);
  atomic_printf("TIOCGPGRP returned process group %d\n", *pgrp);
  test_assert(0 == ioctl(fd, TIOCSPGRP, pgrp));

  ALLOCATE_GUARD(navail, 'd');
  test_assert(0 == ioctl(fd, TIOCINQ, navail));
  VERIFY_GUARD(navail);
  atomic_printf("TIOCINQ returned navail=%d\n", *navail);

  ALLOCATE_GUARD(outq, 'e');
  test_assert(0 == ioctl(fd, TIOCOUTQ, outq));
  VERIFY_GUARD(outq);
  atomic_printf("TIOCOUTQ returned outq=%d\n", *outq);

  ALLOCATE_GUARD(w, 'f');
  test_assert(0 == ioctl(fd, TIOCGWINSZ, w));
  VERIFY_GUARD(w);
  atomic_printf("TIOCGWINSZ returned {row:%d col:%d}\n", w->ws_row, w->ws_col);
  test_assert(0 == ioctl(fd, TIOCSWINSZ, w));

  ALLOCATE_GUARD(sid, 'g');
  test_assert(0 == ioctl(fd, TIOCGSID, sid));
  VERIFY_GUARD(sid);
  atomic_printf("TIOCGSID returned %d\n", *sid);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
