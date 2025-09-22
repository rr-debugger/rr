/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef HAVE_TERMIOS2
/* We have to define termios2 ourselves with glibc. See
 * https://github.com/npat-efault/picocom/blob/1acf1ddabaf3576b4023c4f6f09c5a3e4b086fb8/termios2.txt
 * for the long explanation.
 */
struct termios2 {
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t c_line;
  cc_t c_cc[19];
  speed_t c_ispeed;
  speed_t c_ospeed;
};
#endif

/* glibc 2.42 removed termio:
   https://sourceware.org/git/?p=glibc.git;a=commit;h=e04afb71771710cdc6025fe95908f5f17de7b72d
*/
struct rr_termio {
  unsigned short c_iflag;
  unsigned short c_oflag;
  unsigned short c_cflag;
  unsigned short c_lflag;
  unsigned char c_line;
  unsigned char c_cc[8];
};

int main(void) {
  int fd;
  int ret;
  struct termios* tc;
  struct termios2* tc2;
  struct rr_termio* tio;
  pid_t* pgrp;
  int* navail;
  int* outq;
  struct winsize* w;
  pid_t* sid;
  int* nread;
  int sockets[2];

  signal(SIGTTOU, SIG_IGN);

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
  if (*pgrp != 0) {
    atomic_printf("TIOCGPGRP returned process group %d\n", *pgrp);
    test_assert(0 == ioctl(fd, TIOCSPGRP, pgrp));
  } else {
    atomic_printf("Skipping TIOCSPGRP test - controlling tty outside PID ns.");
  }

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

  socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
  ALLOCATE_GUARD(nread, 'h');
  test_assert(0 == ioctl(sockets[0], FIONREAD, nread));
  VERIFY_GUARD(nread);
  atomic_printf("FIONREAD returned nread=%d\n", *nread);

#ifdef TCGETS2
  ALLOCATE_GUARD(tc2, 'i');
  test_assert(0 == ioctl(fd, TCGETS2, tc));
  VERIFY_GUARD(tc2);
  atomic_printf("TCGETS2 returned { iflag=0x%x, oflag=0x%x, cflag=0x%x, "
                "lflag=0x%x, ispeed=%d, ospeed=%d }\n",
                tc2->c_iflag, tc2->c_oflag, tc2->c_cflag, tc2->c_lflag,
                tc2->c_ispeed, tc2->c_ospeed);
  test_assert(0 == ioctl(fd, TCSETS2, tc2));

  // NB: leaving the TCSETS2 as the last word seems to mess up the terminal,
  // so fix it.
  test_assert(0 == ioctl(fd, TCSETS, tc));
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
