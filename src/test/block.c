/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include <linux/net.h>

#define CTRLMSG_LEN CMSG_LEN(sizeof(int))

struct sendmmsg_arg {
  int sockfd;
  struct mmsghdr* msgvec;
  unsigned int vlen;
  unsigned int flags;
};

struct recvmmsg_arg {
  int sockfd;
  struct mmsghdr* msgvec;
  unsigned int vlen;
  unsigned int flags;
  struct timespec* timeout;
};

struct select_arg {
  int n_fds;
  fd_set* read;
  fd_set* write;
  fd_set* except;
  struct timeval* timeout;
};

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int sockfds[2];

static const int msg_magic = 0x1337beef;
const ssize_t num_sockbuf_bytes = 1 << 20;

static void* reader_thread(__attribute__((unused)) void* dontcare) {
  char token = '!';
  int sock = sockfds[1];
  struct timeval ts;
  char c = '\0';
  int i;

  gettimeofday(&ts, NULL);

  atomic_puts("r: acquiring mutex ...");
  pthread_mutex_lock(&lock);
  atomic_puts("r:   ... releasing mutex");
  pthread_mutex_unlock(&lock);

  for (i = 0; i < 2; ++i) {
    atomic_puts("r: reading socket ...");
    gettimeofday(&ts, NULL);
    test_assert(1 == read(sock, &c, sizeof(c)));
    atomic_printf("r:   ... read '%c'\n", c);
    test_assert(c == token);
    ++token;
  }
  /* TODO: readv() support */

  atomic_puts("r: recv'ing socket ...");
  gettimeofday(&ts, NULL);
  test_assert(1 == recv(sock, &c, sizeof(c), 0));
  atomic_printf("r:   ... recv'd '%c'\n", c);
  test_assert(c == token);
  ++token;

  atomic_puts("r: recvfrom'ing socket ...");
  test_assert(1 == recvfrom(sock, &c, sizeof(c), 0, NULL, NULL));
  atomic_printf("r:   ... recvfrom'd '%c'\n", c);
  test_assert(c == token);
  ++token;
  {
    struct sockaddr_un addr;
    socklen_t addrlen = sizeof(addr);

    atomic_puts("r: recvfrom(&sock)'ing socket ...");
    test_assert(1 == recvfrom(sock, &c, sizeof(c), 0, &addr, &addrlen));
    atomic_printf("r:   ... recvfrom'd '%c' from sock len:%d\n", c, addrlen);
    test_assert(c == token);
    /* socketpair() AF_LOCAL sockets don't identify
     * themselves. */
    test_assert(addrlen == 0);
    ++token;
  }
  {
    struct mmsghdr mmsg;
    struct iovec data;
    int magic = ~msg_magic;
    int err, ret;
#if defined(SYS_socketcall)
    struct recvmmsg_arg arg;
#endif

    memset(&mmsg, 0, sizeof(mmsg));
    memset(&data, 0, sizeof(data));
    data.iov_base = &magic;
    data.iov_len = sizeof(magic);
    mmsg.msg_hdr.msg_iov = &data;
    mmsg.msg_hdr.msg_iovlen = 1;

    struct cmsghdr* cmptr = (struct cmsghdr*)xmalloc(CTRLMSG_LEN);
    mmsg.msg_hdr.msg_control = cmptr;
    mmsg.msg_hdr.msg_controllen = CTRLMSG_LEN;

    atomic_puts("r: recvmsg with DONTWAIT ...");
    ret = recvmsg(sock, &mmsg.msg_hdr, MSG_DONTWAIT);
    err = errno;
    atomic_printf("r:  ... returned %d (%s/%d)\n", ret, strerror(err), err);
    test_assert(-1 == ret);
    test_assert(EWOULDBLOCK == err);
    test_assert(mmsg.msg_hdr.msg_iov == &data);

    atomic_puts("r: recmsg'ing socket ...");

    test_assert(0 < recvmsg(sock, &mmsg.msg_hdr, 0));
    atomic_printf("r:   ... recvmsg'd 0x%x\n", magic);
    test_assert(msg_magic == magic);
    test_assert(mmsg.msg_hdr.msg_iov == &data);

    int fd;
    memcpy(&fd, CMSG_DATA(cmptr), sizeof(fd));
    struct stat fs_new, fs_old;
    fstat(fd, &fs_new);
    fstat(STDERR_FILENO, &fs_old);
    // check if control msg was send successfully
    test_assert(
        fs_old.st_dev == fs_new.st_dev && fs_old.st_ino == fs_new.st_ino &&
        fs_old.st_uid == fs_new.st_uid && fs_old.st_gid == fs_new.st_gid &&
        fs_old.st_rdev == fs_new.st_rdev && fs_old.st_size == fs_new.st_size);

    magic = ~msg_magic;
    atomic_puts("r: recmmsg'ing socket ...");

    breakpoint();
    test_assert(1 == recvmmsg(sock, &mmsg, 1, 0, NULL));
    atomic_printf("r:   ... recvmmsg'd 0x%x (%u bytes)\n", magic, mmsg.msg_len);
    test_assert(msg_magic == magic);
    test_assert(mmsg.msg_hdr.msg_iov == &data);

    magic = ~msg_magic;
#if defined(SYS_socketcall)
    memset(&arg, 0, sizeof(arg));
    arg.sockfd = sock;
    arg.msgvec = &mmsg;
    arg.vlen = 1;
    test_assert(1 == syscall(SYS_socketcall, SYS_RECVMMSG, (void*)&arg));
#elif defined(SYS_recvmmsg)
    test_assert(1 == syscall(SYS_recvmmsg, sock, &mmsg, 1, 0, NULL));
#else
#error unable to call recvmmsg
#endif
    atomic_printf("r:   ... recvmmsg'd(by socketcall) 0x%x (%u bytes)\n", magic,
                  mmsg.msg_len);
    test_assert(msg_magic == magic);

    free(cmptr);
  }
  {
    struct msghdr msg;
    struct iovec iovs[2];
    char c1 = '\0', c2 = '\0';
    memset(&msg, 0, sizeof(msg));

    iovs[0].iov_base = &c1;
    iovs[0].iov_len = sizeof(c1);
    iovs[1].iov_base = &c2;
    iovs[1].iov_len = sizeof(c2);

    msg.msg_iov = iovs;
    msg.msg_iovlen = sizeof(iovs) / sizeof(iovs[0]);

    atomic_puts("r: recmsg'ing socket with two iovs ...");
    test_assert(2 == recvmsg(sock, &msg, 0));
    atomic_printf("r:   ... recvmsg'd '%c' and '%c'\n", c1, c2);

    test_assert(c1 == token);
    token++;
    test_assert(c2 == token);
    token++;
  }
  {
    struct pollfd pfd;

    atomic_puts("r: polling socket ...");
    pfd.fd = sock;
    pfd.events = POLLIN;
    gettimeofday(&ts, NULL);
    poll(&pfd, 1, -1);
    atomic_puts("r:   ... done, doing nonblocking read ...");
    test_assert(1 == read(sock, &c, sizeof(c)));
    atomic_printf("r:   ... read '%c'\n", c);
    test_assert(c == token);
    ++token;
  }
  {
    struct pollfd pfd;

    atomic_puts("r: polling socket ...");
    pfd.fd = sock;
    pfd.events = POLLIN;
    gettimeofday(&ts, NULL);
    ppoll(&pfd, 1, NULL, NULL);
    atomic_puts("r:   ... done, doing nonblocking read ...");
    test_assert(1 == read(sock, &c, sizeof(c)));
    atomic_printf("r:   ... read '%c'\n", c);
    test_assert(c == token);
    ++token;
  }
  {
    fd_set fds;
    const struct timeval infinity = { 1 << 30, 0 };
    struct timeval tv = infinity;
    int ret;
#if defined(__i386__)
    struct select_arg arg;
#endif

    atomic_puts("r: select()ing socket ...");
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
#if defined(__i386__)
    memset(&arg, 0, sizeof(arg));
    arg.n_fds = sock + 1;
    arg.read = &fds;
    arg.write = NULL;
    arg.except = NULL;
    arg.timeout = &tv;
    ret = syscall(SYS_select, &arg);
#else
    ret = syscall(SYS_select, sock + 1, &fds, NULL, NULL, &tv);
#endif
    atomic_printf("r:   ... returned %d; tv { %ld, %ld }\n", ret, tv.tv_sec,
                  tv.tv_usec);
    test_assert(1 == ret);
    test_assert(FD_ISSET(sock, &fds));
    test_assert(0 < tv.tv_sec && tv.tv_sec < infinity.tv_sec);

    atomic_puts("r:   ... done, doing nonblocking read ...");
    test_assert(1 == read(sock, &c, sizeof(c)));
    atomic_printf("r:   ... read '%c'\n", c);
    test_assert(c == token);
    ++token;
  }
  {
    fd_set fds;
    const struct timeval infinity = { 1 << 30, 0 };
    struct timeval tv = infinity;
    int ret;

    atomic_puts("r: select()ing socket ...");
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    ret = select(sock + 1, &fds, NULL, NULL, &tv);
    atomic_printf("r:   ... returned %d; tv { %ld, %ld }\n", ret, tv.tv_sec,
                  tv.tv_usec);
    test_assert(1 == ret);
    test_assert(FD_ISSET(sock, &fds));
    test_assert(0 < tv.tv_sec && tv.tv_sec < infinity.tv_sec);

    atomic_puts("r:   ... done, doing nonblocking read ...");
    test_assert(1 == read(sock, &c, sizeof(c)));
    atomic_printf("r:   ... read '%c'\n", c);
    test_assert(c == token);
    ++token;
  }
  {
    int epfd;
    struct epoll_event ev;
    sigset_t all_sigs;
    sigfillset(&all_sigs);

    atomic_puts("r: epolling socket ...");
    test_assert(0 <= (epfd = epoll_create(1 /*num events*/)));
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    gettimeofday(&ts, NULL);
    test_assert(0 == epoll_ctl(epfd, EPOLL_CTL_ADD, ev.data.fd, &ev));
    test_assert(1 == epoll_wait(epfd, &ev, 1, -1));
    atomic_puts("r:   ... done, doing nonblocking read ...");
    test_assert(sock == ev.data.fd);
    test_assert(1 == epoll_pwait(epfd, &ev, 1, -1, &all_sigs));
    test_assert(1 == read(sock, &c, sizeof(c)));
    atomic_printf("r:   ... read '%c'\n", c);
    test_assert(c == token);
    ++token;

    close(epfd);
  }
  {
    char* buf = (char*)xmalloc(num_sockbuf_bytes);
    ssize_t nwritten = 0;
    struct iovec iov;

    ++token;
    memset(buf, token, num_sockbuf_bytes);

    atomic_printf("r: writing outbuf of size %zd ...\n", num_sockbuf_bytes);
    while (nwritten < num_sockbuf_bytes) {
      ssize_t this_write = write(sock, buf, num_sockbuf_bytes - nwritten);
      atomic_printf("r:   wrote %zd bytes this time\n", this_write);
      nwritten += this_write;
    }

    ++token;
    memset(buf, token, num_sockbuf_bytes);
    iov.iov_base = buf;
    iov.iov_len = num_sockbuf_bytes;
    atomic_printf("r: writev()ing outbuf of size %zd ...\n", num_sockbuf_bytes);
    while (iov.iov_len > 0) {
      ssize_t this_write = writev(sock, &iov, 1);
      atomic_printf("r:   wrote %zd bytes this time\n", this_write);
      iov.iov_len -= this_write;
    }

    free(buf);
  }

  atomic_puts("r: reading socket with masked signals ...");
  {
    sigset_t old_mask, mask;
    sigfillset(&mask);
    test_assert(0 == pthread_sigmask(SIG_BLOCK, &mask, &old_mask));

    test_assert(1 == read(sock, &c, sizeof(c)));

    test_assert(0 == pthread_sigmask(SIG_SETMASK, &old_mask, NULL));
  }
  ++token;
  atomic_printf("r:   ... read '%c'\n", c);
  test_assert(c == token);

  /* Make the main thread wait on our join() */
  atomic_puts("r: sleeping ...");
  usleep(500000);

  return NULL;
}

static void read_all_chunks(int sock, char* buf, ssize_t num_sockbuf_bytes,
                            char token) {
  ssize_t nread = 0;
  while (nread < num_sockbuf_bytes) {
    char* this_buf = buf + nread;
    ssize_t this_read = read(sock, this_buf, num_sockbuf_bytes - nread);
    int i;

    atomic_printf("M:   read %zd bytes this time,\n", this_read);
    test_assert(this_read > 0);
    /* XXX: we would like to assert that the written data
     * was read in more than one chunk, which should imply
     * that at least one write() from the other thread
     * blocked, but it's possible for multiple write()s to
     * complete and fill the read buffer here before the
     * reader returns. */
    /*test_assert(this_read < num_sockbuf_bytes);*/

    for (i = nread; i < nread + this_read; ++i) {
      if (token != buf[i]) {
        atomic_printf("M:   byte %d should be '%c', but is '%c'\n", i, token,
                      buf[i]);
      }
    }
    nread += this_read;
    atomic_printf("M:      %zd total so far\n", nread);
  }
}

int main(void) {
  char token = '!';
  struct timeval ts;
  pthread_t reader;
  int sock;

  gettimeofday(&ts, NULL);

  socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds);
  sock = sockfds[0];

  pthread_mutex_lock(&lock);

  pthread_create(&reader, NULL, reader_thread, NULL);

  /* Make the reader thread wait on its pthread_mutex_lock() */
  atomic_puts("M: sleeping ...");
  usleep(500000);
  atomic_puts("M: unlocking mutex ...");
  pthread_mutex_unlock(&lock);
  atomic_puts("M:   ... done");

  /* Force a wait on read() */
  atomic_puts("M: sleeping again ...");
  usleep(500000);
  atomic_printf("M: writing '%c' to socket ...\n", token);
  test_assert(1 == write(sock, &token, sizeof(token)));
  ++token;
  atomic_puts("M:   ... done");
  /* Force a wait on readv() */
  {
    struct iovec v = {.iov_base = &token, .iov_len = sizeof(token) };

    atomic_puts("M: sleeping again ...");
    usleep(500000);
    atomic_printf("r: writev('%c')'ing socket ...\n", token);
    test_assert(1 == writev(sock, &v, 1));
    ++token;
    atomic_puts("M:   ... done");
  }
  /* Force a wait on recv() */
  atomic_puts("M: sleeping again ...");
  usleep(500000);
  atomic_printf("M: sending '%c' to socket ...\n", token);
  send(sock, &token, sizeof(token), 0);
  ++token;
  atomic_puts("M:   ... done");

  /* Force a wait on recvfrom() */
  atomic_puts("M: sleeping again ...");
  usleep(500000);
  atomic_printf("M: sending '%c' to socket ...\n", token);
  send(sock, &token, sizeof(token), 0);
  ++token;
  atomic_puts("M:   ... done");

  /* Force a wait on recvfrom(&sock) */
  atomic_puts("M: sleeping again ...");
  usleep(500000);
  atomic_printf("M: sending '%c' to socket ...\n", token);
  send(sock, &token, sizeof(token), 0);
  ++token;
  atomic_puts("M:   ... done");
  {
    struct mmsghdr mmsg;
    struct iovec data;
    int magic = msg_magic;
#if defined(SYS_socketcall)
    struct sendmmsg_arg arg;
#endif

    memset(&mmsg, 0, sizeof(mmsg));
    memset(&data, 0, sizeof(data));
    data.iov_base = &magic;
    data.iov_len = sizeof(magic);
    mmsg.msg_hdr.msg_iov = &data;
    mmsg.msg_hdr.msg_iovlen = 1;

    struct cmsghdr* cmptr = (struct cmsghdr*)xmalloc(CTRLMSG_LEN); // send a fd
    cmptr->cmsg_level = SOL_SOCKET;
    cmptr->cmsg_type = SCM_RIGHTS;
    cmptr->cmsg_len = CTRLMSG_LEN;
    mmsg.msg_hdr.msg_control = cmptr;
    mmsg.msg_hdr.msg_controllen = CTRLMSG_LEN;
    {
      const int fd = STDERR_FILENO;
      memcpy(CMSG_DATA(cmptr), &fd, sizeof(fd)); // send stderr as fd
    }

    /* Force a wait on recvmsg() */
    atomic_puts("M: sleeping again ...");
    usleep(500000);
    atomic_printf("M: sendmsg'ing 0x%x to socket ...\n", msg_magic);
    sendmsg(sock, &mmsg.msg_hdr, 0);
    atomic_puts("M:   ... done");

    /* Force a wait on recvmmsg() */
    atomic_puts("M: sleeping again ...");
    usleep(500000);
    atomic_printf("M: sendmmsg'ing 0x%x to socket ...\n", msg_magic);

    breakpoint();

    sendmmsg(sock, &mmsg, 1, 0);
    atomic_printf("M:   ... sent %u bytes\n", mmsg.msg_len);

    /* Force a wait on recvmmsg() */
    atomic_puts("M: sleeping again ...");
    usleep(500000);
    atomic_printf("M: sendmmsg'ing(by socketcall) 0x%x to socket ...\n",
                  msg_magic);

#if defined(SYS_socketcall)
    memset(&arg, 0, sizeof(arg));
    arg.sockfd = sock;
    arg.msgvec = &mmsg;
    arg.vlen = 1;
    syscall(SYS_socketcall, SYS_SENDMMSG, (void*)&arg);
#elif defined(SYS_sendmmsg)
    syscall(SYS_sendmmsg, sock, &mmsg, 1, 0);
#else
#error unable to call sendmmsg
#endif

    free(cmptr);
  }
  {
    struct msghdr msg;
    struct iovec iovs[2];
    char c1 = token++;
    char c2 = token++;
    memset(&msg, 0, sizeof(msg));

    iovs[0].iov_base = &c1;
    iovs[0].iov_len = sizeof(c1);
    iovs[1].iov_base = &c2;
    iovs[1].iov_len = sizeof(c2);

    msg.msg_iov = iovs;
    msg.msg_iovlen = sizeof(iovs) / sizeof(iovs[0]);

    /* Force a wait on recvmsg(). */
    atomic_puts("M: sleeping again ...");
    usleep(500000);
    atomic_printf("M: writing { '%c', '%c' } to socket ...\n", c1, c2);
    test_assert(2 == sendmsg(sock, &msg, 0));
    atomic_puts("M:   ... done");
  }
  /* Force a wait on poll() */
  atomic_puts("M: sleeping again ...");
  usleep(500000);
  atomic_printf("M: writing '%c' to socket ...\n", token);
  write(sock, &token, sizeof(token));
  ++token;
  atomic_puts("M:   ... done");

  /* Force a wait on ppoll() */
  atomic_puts("M: sleeping again ...");
  usleep(500000);
  atomic_printf("M: writing '%c' to socket ...\n", token);
  write(sock, &token, sizeof(token));
  ++token;
  atomic_puts("M:   ... done");

  /* Force a wait on select(), raw syscall */
  atomic_puts("M: sleeping again ...");
  usleep(500000);
  atomic_printf("M: writing '%c' to socket ...\n", token);
  write(sock, &token, sizeof(token));
  ++token;
  atomic_puts("M:   ... done");

  /* Force a wait on select(), library call */
  atomic_puts("M: sleeping again ...");
  usleep(500000);
  atomic_printf("M: writing '%c' to socket ...\n", token);
  write(sock, &token, sizeof(token));
  ++token;
  atomic_puts("M:   ... done");

  /* Force a wait on epoll_wait() */
  atomic_puts("M: sleeping again ...");
  usleep(500000);
  atomic_printf("M: writing '%c' to socket ...\n", token);
  write(sock, &token, sizeof(token));
  ++token;
  atomic_puts("M:   ... done");

  /* Force a wait on write() */
  atomic_puts("M: sleeping again ...");
  usleep(500000);
  atomic_printf("M: reading socket ...\n");
  ++token;
  {
    char* buf = (char*)xmalloc(num_sockbuf_bytes);
    int i;
    for (i = 0; i < 2; ++i) {
      read_all_chunks(sock, buf, num_sockbuf_bytes, token);
      ++token;
    }
    free(buf);
  }
  atomic_puts("M:   ... done");

  /* Force a wait on read() */
  atomic_puts("M: sleeping again ...");
  usleep(500000);
  atomic_printf("M: writing '%c' to socket ...\n", token);
  write(sock, &token, sizeof(token));
  atomic_puts("M:   ... done");

  pthread_join(reader, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
