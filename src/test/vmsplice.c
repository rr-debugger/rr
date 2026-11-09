/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define SIZE (4 * 4096)
#define BLOCKING_ROUNDS 8

static char out[SIZE];

struct helper_args {
  pid_t main_tid;
  int read_fd;
  int write_fd;
  int round;
};

static char pattern_byte(size_t i) { return (char)(i * 7 + 3); }

/* Checks that p holds the bytes from offset to offset + len of the pattern
   that buf is filled with. */
static void check_pattern(const char* p, size_t offset, size_t len) {
  size_t i;
  for (i = 0; i < len; ++i) {
    test_assert(p[i] == pattern_byte(offset + i));
  }
}

static void read_all(int fd, char* buf, size_t size) {
  size_t done = 0;
  while (done < size) {
    ssize_t n = read(fd, buf + done, size - done);
    test_assert(n > 0);
    done += n;
  }
}

static int in_vmsplice(pid_t tid, int fd) {
  char path[PATH_MAX];
  char buf[1024];
  long nr;
  unsigned long arg1;
  int proc_fd;
  ssize_t len;

  sprintf(path, "/proc/self/task/%d/syscall", tid);
  proc_fd = open(path, O_RDONLY);
  test_assert(proc_fd >= 0);
  len = read(proc_fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(proc_fd));
  return sscanf(buf, "%ld 0x%lx", &nr, &arg1) == 2 && nr == SYS_vmsplice &&
         arg1 == (unsigned long)fd;
}

static void wait_for_vmsplice(const struct helper_args* args, int fd) {
  test_assert(args->main_tid > 0);
  while (!in_vmsplice(args->main_tid, fd)) {
    sched_yield();
  }
}

/* Writes to the empty pipe the main thread is reading with vmsplice(), then
   waits until the data shows up in the main thread's buffer. */
static void* do_write(void* p) {
  const struct helper_args* args = (const struct helper_args*)p;
  char data[100];

  memset(data, 'a' + args->round, sizeof(data));
  wait_for_vmsplice(args, args->read_fd);
  test_assert(sizeof(data) == write(args->write_fd, data, sizeof(data)));
  while (__atomic_load_n(&out[sizeof(data) - 1], __ATOMIC_SEQ_CST) !=
         data[0]) {
  }
  return NULL;
}

/* Drains the full pipe the main thread is writing with vmsplice(). */
static void* do_read(void* p) {
  const struct helper_args* args = (const struct helper_args*)p;
  int pipe_size = fcntl(args->read_fd, F_GETPIPE_SZ);
  char* data;

  test_assert(pipe_size > 0);
  data = (char*)malloc(pipe_size + 4096);
  test_assert(data != NULL);
  wait_for_vmsplice(args, args->write_fd);
  read_all(args->read_fd, data, pipe_size + 4096);
  check_pattern(data + pipe_size, 0, 4096);
  free(data);
  return NULL;
}

int main(void) {
  int fds[2];
  int closed_fds[2];
  int rw_fd;
  int null_fd;
  char* buf;
  char* filler;
  char path[PATH_MAX];
  struct iovec iov[3];
  struct helper_args args;
  pthread_t thread;
  ssize_t n;
  size_t i;
  int pipe_size;
  int round;

  buf = (char*)mmap(NULL, SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(buf != MAP_FAILED);
  for (i = 0; i < SIZE; ++i) {
    buf[i] = pattern_byte(i);
  }
  test_assert(0 == pipe(fds));

  /* User memory into the pipe (fd is the write end). vmsplice() must leave
     buf unchanged. */
  iov[0].iov_base = buf;
  iov[0].iov_len = SIZE / 2;
  iov[1].iov_base = buf + SIZE / 2;
  iov[1].iov_len = SIZE / 2;
  n = vmsplice(fds[1], iov, 2, 0);
  test_assert(n == SIZE);
  check_pattern(buf, 0, SIZE);
  read_all(fds[0], out, SIZE);
  check_pattern(out, 0, SIZE);

  /* The same with SPLICE_F_GIFT (whole pages). */
  iov[0].iov_base = buf;
  iov[0].iov_len = SIZE;
  n = vmsplice(fds[1], iov, 1, SPLICE_F_GIFT);
  test_assert(n == SIZE);
  check_pattern(buf, 0, SIZE);
  memset(out, 0, SIZE);
  read_all(fds[0], out, SIZE);
  check_pattern(out, 0, SIZE);

  /* A pipe opened for reading and writing: vmsplice() reads user memory
     into the pipe. */
  sprintf(path, "/proc/self/fd/%d", fds[0]);
  rw_fd = open(path, O_RDWR);
  test_assert(rw_fd >= 0);
  iov[0].iov_base = buf;
  iov[0].iov_len = 4096;
  n = vmsplice(rw_fd, iov, 1, 0);
  test_assert(n == 4096);
  check_pattern(buf, 0, SIZE);
  memset(out, 0, SIZE);
  read_all(fds[0], out, 4096);
  check_pattern(out, 0, 4096);
  test_assert(0 == close(rw_fd));

  /* The pipe into user memory (fd is the read end), scattered over three
     segments; the last is only partly filled. */
  test_assert(1000 == write(fds[1], buf, 1000));
  memset(out, 0, SIZE);
  iov[0].iov_base = out;
  iov[0].iov_len = 300;
  iov[1].iov_base = out + 4096;
  iov[1].iov_len = 500;
  iov[2].iov_base = out + 3 * 4096;
  iov[2].iov_len = 4096;
  n = vmsplice(fds[0], iov, 3, 0);
  test_assert(n == 1000);
  check_pattern(out, 0, 300);
  check_pattern(out + 4096, 300, 500);
  check_pattern(out + 3 * 4096, 800, 200);
  for (i = 0; i < 300; ++i) {
    test_assert(out[3 * 4096 + 200 + i] == 0);
  }
  atomic_printf("checksum %d %d %d\n", out[0] + out[299], out[4096 + 499],
                out[3 * 4096 + 199]);

  /* vmsplice() from the empty pipe blocks until another thread writes. */
  args.main_tid = sys_gettid();
  args.read_fd = fds[0];
  args.write_fd = fds[1];
  for (round = 0; round < BLOCKING_ROUNDS; ++round) {
    memset(out, 0, SIZE);
    args.round = round;
    test_assert(0 == pthread_create(&thread, NULL, do_write, &args));
    iov[0].iov_base = out;
    iov[0].iov_len = SIZE;
    n = vmsplice(fds[0], iov, 1, 0);
    test_assert(n == 100);
    test_assert(0 == pthread_join(thread, NULL));
    for (i = 0; i < 100; ++i) {
      test_assert(out[i] == 'a' + round);
    }
    test_assert(out[100] == 0);
  }

  /* vmsplice() into the full pipe blocks until another thread reads. */
  pipe_size = fcntl(fds[1], F_GETPIPE_SZ);
  test_assert(pipe_size > 0);
  filler = (char*)malloc(pipe_size);
  test_assert(filler != NULL);
  memset(filler, 'f', pipe_size);
  test_assert(pipe_size == write(fds[1], filler, pipe_size));
  free(filler);
  test_assert(0 == pthread_create(&thread, NULL, do_read, &args));
  iov[0].iov_base = buf;
  iov[0].iov_len = 4096;
  n = vmsplice(fds[1], iov, 1, SPLICE_F_GIFT);
  test_assert(n == 4096);
  test_assert(0 == pthread_join(thread, NULL));
  check_pattern(buf, 0, SIZE);

  /* Without writers, vmsplice() from the empty pipe returns 0. */
  test_assert(0 == pipe(closed_fds));
  test_assert(0 == close(closed_fds[1]));
  iov[0].iov_base = out;
  iov[0].iov_len = SIZE;
  test_assert(0 == vmsplice(closed_fds[0], iov, 1, 0));
  test_assert(0 == close(closed_fds[0]));

  /* The kernel takes nr_segs as an unsigned int. */
  test_assert(10 == write(fds[1], buf, 10));
  memset(out, 0, SIZE);
  n = syscall(SYS_vmsplice, fds[0], iov,
              (unsigned long)(((uint64_t)1 << 32) | 1), 0);
  test_assert(n == 10);
  check_pattern(out, 0, 10);

  /* Errors. */
  test_assert(-1 == vmsplice(fds[0], iov, 1, SPLICE_F_NONBLOCK) &&
              errno == EAGAIN);
  test_assert(-1 == vmsplice(-1, iov, 1, 0) && errno == EBADF);
  null_fd = open("/dev/null", O_RDONLY);
  test_assert(null_fd >= 0);
  test_assert(-1 == vmsplice(null_fd, iov, 1, 0) && errno == EBADF);
  test_assert(0 == close(null_fd));
  test_assert(-1 == vmsplice(fds[0], iov, 1, 0x10000) && errno == EINVAL);
  test_assert(-1 == vmsplice(fds[0], iov, IOV_MAX + 1, 0) && errno == EINVAL);
  test_assert(0 == munmap(buf, SIZE));
  test_assert(-1 == vmsplice(fds[0], (struct iovec*)buf, 1, 0) &&
              errno == EFAULT);
  test_assert(0 == vmsplice(fds[0], iov, 0, 0));
  test_assert(0 == vmsplice(fds[1], iov, 0, 0));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
