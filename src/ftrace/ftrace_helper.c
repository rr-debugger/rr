/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/user.h>
#include <unistd.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

/*
 * ftrace_helper is a small server providing an interface to ftrace. It needs
 * to run as root, and lets non-root applications connect to it to control
 * ftracing.
 *
 * 'ftrace_helper <path>' creates an AF_UNIX socket at <path> and makes it
 * world-writable. Only one connection is allowed to this socket, then the
 * socket name is removed.
 * 'trace_helper' without arguments spawns itself with 'sudo' and creates the
 * socket at $HOME/.local/share/rr/ftrace.
 *
 * Over this connection the client can establish a series of sessions. All
 * messages from the client are newline-terminated and acked with a single
 * 'K' character.
 * To start a session the client sends a CPU number which is the only CPU
 * which will be traced (all traced processes must be affinity-bound to this
 * CPU). Then the client sends a series of PIDs, one per line, ending in
 * a blank line; these PIDs are the ones that will be traced. ftrace_helper
 * starts tracing those processes with the function_graph tracer.
 * ftrace_helper then sends the client a single 'F' character with a file
 * descriptor attached using SCM_RIGHTS. This fd is for the trace_marker file.
 * The client sends the string "end" to stop the session.
 *
 * Trace output is dumped to /tmp/ftrace_helper_out, owned by root but
 * world-readable, in trace-cmd raw format. Producing raw output is a bit
 * fiddly but it reduces overhead and lets us use "splice" to move data from
 * the kernel to the output file. On my laptop, at least, this is necessary
 * because saving "trace_pipe" loses events due to ringbuffer overrun and
 * using "trace_pipe_raw" does not.
 *
 * To view the output install trace-cmd and run
 *   trace-cmd report /tmp/ftrace_helper_out|less
 */

inline static int check_cond(int cond) {
  if (!cond) {
    fprintf(stderr, "FAILED: errno=%d (%s)\n", errno, strerror(errno));
  }
  return cond;
}

static void drop_sig(__attribute__((unused)) int sig) {}

#define check(cond) assert("FAILED: !" && check_cond(cond))

static int out_fd;
static void* do_echo(void* arg) {
  int fd = *(int*)arg;
  int pipe_fds[2];
  ssize_t size;
  check(0 == pipe(pipe_fds));
  size = fcntl(pipe_fds[1], F_GETPIPE_SZ);
  check(size > 0);
  while (1) {
    ssize_t ret2;
    ssize_t ret = splice(fd, NULL, pipe_fds[1], NULL, size, SPLICE_F_MOVE);
    if (ret == -1 && (errno == EBADF || errno == EINTR)) {
      break;
    }
    check(ret >= 0);
    ret2 = splice(pipe_fds[0], NULL, out_fd, NULL, ret,
                  SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    if (ret2 == -1 && (errno == EBADF || errno == EINTR)) {
      break;
    }
    check(ret2 == ret);
  }
  return NULL;
}

static void chdir_to_tracing(void) {
  int ret = chdir("/sys/kernel/debug");
  if (ret < 0 && errno == ENOENT) {
    fprintf(stderr, "/sys/kernel/debug not found; debugfs not mounted?\n");
    exit(1);
  }
  if (ret < 0 && errno == EACCES) {
    fprintf(stderr, "Cannot chdir to /sys/kernel/debug; run this as root\n");
    exit(1);
  }
  check(ret == 0);

  ret = chdir("tracing");
  if (ret < 0 && errno == ENOENT) {
    fprintf(stderr,
            "/sys/kernel/debug/tracing not found; tracing not enabled?\n");
    exit(1);
  }
  check(ret == 0);
}

static void copy_file_data(int final_fd, int in_fd) {
  char buf[64 * 1024];
  while (1) {
    ssize_t ret = read(in_fd, buf, sizeof(buf));
    check(ret >= 0);
    if (!ret) {
      break;
    }
    check(ret == write(final_fd, buf, ret));
  }
}

static void copy_trace_file(int final_fd, const char* name, int size_len) {
  char buf[1024];
  int fd = open(name, O_RDONLY);
  check(fd >= 0);
  uint64_t len = 0;
  while (1) {
    ssize_t ret = read(fd, buf, sizeof(buf));
    check(ret >= 0);
    if (!ret) {
      break;
    }
    len += ret;
  }
  check(0 == lseek(fd, 0, SEEK_SET));

  /* XXX assumes little-endian */
  check(size_len == write(final_fd, &len, size_len));
  copy_file_data(final_fd, fd);
  check(0 == close(fd));
}

static void copy_trace_file_with_name(int final_fd, const char* name,
                                      int size_len) {
  const char* bare_name = strrchr(name, '/');
  if (bare_name) {
    ++bare_name;
  } else {
    bare_name = name;
  }
  check((ssize_t)strlen(bare_name) + 1 ==
        write(final_fd, bare_name, strlen(bare_name) + 1));
  copy_trace_file(final_fd, name, size_len);
}

static int iterate_events(int final_fd, const char* dir, int write) {
  int count = 0;
  DIR* d = opendir(dir);
  check(d != NULL);
  while (1) {
    char* buf;
    struct dirent* e = readdir(d);
    if (!e) {
      break;
    }
    int ret = asprintf(&buf, "%s/%s/format", dir, e->d_name);
    if (ret >= 0 && access(buf, F_OK) == 0) {
      if (write) {
        copy_trace_file(final_fd, buf, 8);
      }
      ++count;
    }
    free(buf);
  }
  check(0 == closedir(d));
  return count;
}

static void open_output_fd(void) {
  out_fd = open("/tmp/ftrace_helper_out", O_RDWR | O_TRUNC | O_CREAT, 0644);
  check(out_fd >= 0);
}

static uint64_t file_offset(int fd) {
  off_t offset = lseek(fd, 0, SEEK_CUR);
  check(offset != (off_t)-1);
  return offset;
}

static uint64_t pad_output_to_page_size(int fd) {
  char buf[PAGE_SIZE];
  uint64_t offset = file_offset(fd);
  memset(buf, 0, sizeof(buf));
  ssize_t pad = ((offset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) - offset;
  check(pad == write(fd, buf, pad));
  return offset + pad;
}

static void write_final_output(void) {
  int final_fd;
  static const char magic[] = { 23,          8,   68,  't', 'r', 'a', 'c',
                                'i',         'n', 'g', '6', 0, /* file version
                                                                  */
                                0, /* little-endian */
                                sizeof(long) };
  const uint32_t page_size = PAGE_SIZE;
  uint32_t ftrace_count;
  static const uint32_t zero = 0;
  static const uint32_t cpus = 1;
  static const char options[] = "options  ";
  static const uint16_t options_done = 0;
  static const char fly_record[] = "flyrecord";
  uint64_t cpu_data[2] = { 0, 0 };
  uint64_t cpu_data_offset;

  check(0 == unlink("/tmp/ftrace_helper_out"));
  final_fd = open("/tmp/ftrace_helper_out", O_WRONLY | O_TRUNC | O_CREAT, 0644);
  check(final_fd >= 0);

  check(sizeof(magic) == write(final_fd, magic, sizeof(magic)));
  check(sizeof(page_size) == write(final_fd, &page_size, sizeof(page_size)));

  copy_trace_file_with_name(final_fd, "events/header_page", 8);
  copy_trace_file_with_name(final_fd, "events/header_event", 8);
  ftrace_count = iterate_events(final_fd, "events/ftrace", 0);
  check(sizeof(ftrace_count) ==
        write(final_fd, &ftrace_count, sizeof(ftrace_count)));
  iterate_events(final_fd, "events/ftrace", 1);
  /* Write no events (for now) */
  check(sizeof(zero) == write(final_fd, &zero, sizeof(zero)));
  copy_trace_file(final_fd, "/proc/kallsyms", 4);
  copy_trace_file(final_fd, "printk_formats", 4);
  copy_trace_file(final_fd, "saved_cmdlines", 8);
  check(sizeof(cpus) == write(final_fd, &cpus, sizeof(cpus)));
  check(sizeof(options) == write(final_fd, &options, sizeof(options)));
  check(sizeof(options_done) ==
        write(final_fd, &options_done, sizeof(options_done)));
  check(sizeof(fly_record) == write(final_fd, fly_record, sizeof(fly_record)));
  cpu_data_offset = file_offset(final_fd);
  check(sizeof(cpu_data) == write(final_fd, cpu_data, sizeof(cpu_data)));
  copy_trace_file(final_fd, "trace_clock", 8);
  cpu_data[0] = pad_output_to_page_size(final_fd);
  cpu_data[1] = file_offset(out_fd);
  check(0 == lseek(out_fd, 0, SEEK_SET));
  copy_file_data(final_fd, out_fd);
  check(cpu_data_offset ==
        (uint64_t)lseek(final_fd, cpu_data_offset, SEEK_SET));
  check(sizeof(cpu_data) == write(final_fd, cpu_data, sizeof(cpu_data)));
  check(0 == close(final_fd));
}

static int control_fd = -1;
static char control_buf[1024];
static size_t control_buf_len = 0;

static void open_control_fd(const char* path) {
  struct sockaddr_un addr;
  int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  check(listen_fd >= 0);

  addr.sun_family = AF_UNIX;
  if (strlen(path) + 1 > sizeof(addr.sun_path)) {
    fprintf(stderr, "Socket path %s too long\n", path);
    exit(1);
  }
  strcpy(addr.sun_path, path);
  unlink(path);
  check(0 == bind(listen_fd, &addr, sizeof(addr)));
  check(0 == chmod(path, 0666));
  check(0 == listen(listen_fd, 1));
  control_fd = accept(listen_fd, NULL, NULL);
  check(control_fd >= 0);
  check(0 == close(listen_fd));
  check(0 == unlink(path));
}

static int trace_pipe_fd = -1;
static pthread_t echo_thread;

static void write_file(const char* file, const char* value) {
  int fd = open(file, O_WRONLY | O_TRUNC);
  ssize_t ret;
  check(fd >= 0);
  ret = write(fd, value, strlen(value));
  check((ssize_t)strlen(value) == ret);
  check(0 == close(fd));
}

static void stop_tracing(void) {
  write_file("tracing_on", "0");

  if (trace_pipe_fd >= 0) {
    check(0 == close(trace_pipe_fd));
    trace_pipe_fd = -1;
  }

  if (echo_thread) {
    /* The thread might already have exited */
    pthread_kill(echo_thread, SIGUSR1);
    check(0 == pthread_join(echo_thread, NULL));
    memset(&echo_thread, 0, sizeof(echo_thread));
  }

  /* Do this last; we can't change current_tracer while those files are open */
  write_file("current_tracer", "nop");
}

#define MAX_LINE_SIZE 65536
static void read_control_line(char out[MAX_LINE_SIZE]) {
  size_t out_pos = 0;

  while (1) {
    size_t i;
    if (!control_buf_len) {
      int ret = read(control_fd, control_buf, sizeof(control_buf));
      check(ret >= 0);
      if (!ret) {
        stop_tracing();
        write_final_output();
        exit(2);
      }
      control_buf_len = ret;
    }
    for (i = 0; i < control_buf_len; ++i) {
      check(out_pos < MAX_LINE_SIZE);
      if (control_buf[i] == '\n') {
        out[out_pos] = 0;
        ++i;
        memmove(control_buf, control_buf + i, control_buf_len - i);
        control_buf_len -= i;
        return;
      }
      out[out_pos] = control_buf[i];
      ++out_pos;
    }
  }
}

static void ack_control_message(void) { check(1 == write(control_fd, "K", 1)); }

static void send_marker_fd(void) {
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  struct msghdr msg;
  struct iovec data;
  struct cmsghdr* cmsg = (struct cmsghdr*)cmsgbuf;
  int trace_marker_fd = open("trace_marker", O_WRONLY);
  check(trace_marker_fd >= 0);

  data.iov_base = "F";
  data.iov_len = 1;

  memset(&msg, 0, sizeof(msg));
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);
  msg.msg_iov = &data;
  msg.msg_iovlen = 1;

  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  memcpy(CMSG_DATA(cmsg), &trace_marker_fd, sizeof(int));

  check(1 == sendmsg(control_fd, &msg, 0));
  check(0 == close(trace_marker_fd));
}

static void process_control_session(void) {
  char buf[MAX_LINE_SIZE];
  char path[PATH_MAX];
  int cpu;
  int ftrace_pid_fd;
  char buf_out[65536];
  char* buf_out_ptr = buf_out;

  read_control_line(buf);
  cpu = atoi(buf);

  while (1) {
    read_control_line(buf);
    if (buf[0] == 0) {
      break;
    }

    if (buf_out_ptr + strlen(buf) >= buf_out + sizeof(buf_out)) {
      break;
    }
    buf_out_ptr += sprintf(buf_out_ptr, "%s ", buf);
  }

  ftrace_pid_fd = open("set_ftrace_pid", O_WRONLY);
  check(ftrace_pid_fd >= 0);
  check(buf_out_ptr - buf_out ==
        write(ftrace_pid_fd, buf_out, buf_out_ptr - buf_out));
  check(0 == close(ftrace_pid_fd));

  write_file("current_tracer", "function_graph");

  send_marker_fd();

  sprintf(path, "per_cpu/cpu%d/trace_pipe_raw", cpu);
  trace_pipe_fd = open(path, O_RDONLY);
  check(trace_pipe_fd >= 0);
  check(0 == pthread_create(&echo_thread, NULL, do_echo, &trace_pipe_fd));

  write_file("tracing_on", "1");
  ack_control_message();

  read_control_line(buf);
  check(!strcmp(buf, "end"));

  ack_control_message();
  stop_tracing();
}

int main(int argc, const char** argv) {
  if (argc == 1) {
    char* control_path;
    int ret =
        asprintf(&control_path, "%s/.local/share/rr/ftrace", getenv("HOME"));
    if (ret >= 0) {
      execlp("sudo", "sudo", argv[1], control_path, NULL);
    }
    fprintf(stderr, "Can't exec 'sudo'\n");
    return 1;
  }

  signal(SIGUSR1, drop_sig);

  chdir_to_tracing();
  open_control_fd(argv[1]);
  open_output_fd();
  while (1) {
    process_control_session();
  }
  return 0;
}
