/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static const char device_name[] = "/dev/video0";

struct buffer {
  struct v4l2_buffer vbuf;
  unsigned char* mmap_data;
};
static struct buffer buffers[4];
static size_t buffer_count;

static void no_v4l2(void) {
  atomic_puts("EXIT-SUCCESS");
  exit(0);
}

static int open_device(void) {
  struct v4l2_capability cap;
  int fd = open("/dev/video0", O_RDWR);
  int ret;

  if (fd < 0 && errno == ENOENT) {
    atomic_printf("%s not found; aborting test\n", device_name);
    no_v4l2();
  }
  if (fd < 0 && errno == EACCES) {
    atomic_printf("%s not accessible; aborting test\n", device_name);
    no_v4l2();
  }
  test_assert(fd >= 0);

  ret = ioctl(fd, VIDIOC_QUERYCAP, &cap);
  if (ret < 0 && errno == EINVAL) {
    atomic_printf("%s is not a V4L2 device; aborting test\n", device_name);
    no_v4l2();
  }
  if (ret < 0 && errno == EACCES) {
    atomic_printf("%s is not accessible; aborting test\n", device_name);
    no_v4l2();
  }
  if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE)) {
    atomic_printf("%s is not a V4L2 capture device; aborting test\n",
                  device_name);
    no_v4l2();
  }
  if (!(cap.capabilities & V4L2_CAP_STREAMING)) {
    atomic_printf("%s does not support streaming; aborting test\n",
                  device_name);
    no_v4l2();
  }

  return fd;
}

static void init_device(int fd) {
  struct v4l2_format fmt;
  struct v4l2_requestbuffers req;
  int ret;
  size_t i;
  enum v4l2_buf_type type;

  fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  test_assert(0 == ioctl(fd, VIDIOC_G_FMT, &fmt));
  atomic_printf("%s returning %dx%d frames\n", device_name, fmt.fmt.pix.width,
                fmt.fmt.pix.height);

  req.count = 4;
  req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  req.memory = V4L2_MEMORY_MMAP;
  ret = ioctl(fd, VIDIOC_REQBUFS, &req);
  if (ret < 0 && errno == EINVAL) {
    atomic_printf("%s does not support memory mapping; aborting test\n",
                  device_name);
    no_v4l2();
  }
  if (ret < 0 && errno == EBUSY) {
    atomic_printf("%s is busy; aborting test\n", device_name);
    no_v4l2();
  }
  test_assert(0 == ret);
  if (req.count < 2) {
    atomic_printf("%s only supports one buffer; aborting test\n", device_name);
    no_v4l2();
  }
  buffer_count = req.count;

  for (i = 0; i < buffer_count; ++i) {
    struct buffer* buf = buffers + i;
    buf->vbuf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf->vbuf.memory = V4L2_MEMORY_MMAP;
    buf->vbuf.index = i;
    test_assert(0 == ioctl(fd, VIDIOC_QUERYBUF, &buf->vbuf));
    buf->mmap_data = mmap(NULL, buf->vbuf.length, PROT_READ | PROT_WRITE,
                          MAP_SHARED, fd, buf->vbuf.m.offset);
    test_assert(buf->mmap_data != MAP_FAILED);
    atomic_printf("Buffer %d, addr %p, device offset 0x%llx, device len 0x%llx\n",
                  (int)i, buf->mmap_data, (long long)buf->vbuf.m.offset,
                  (long long)buf->vbuf.length);
    test_assert(0 == ioctl(fd, VIDIOC_QBUF, &buf->vbuf));
  }
  type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  test_assert(0 == ioctl(fd, VIDIOC_STREAMON, &type));
}

static void print_fourcc(int v) {
  union {
    int v;
    char cs[4];
  } u;
  u.v = v;
  atomic_printf("%c%c%c%c", u.cs[0], u.cs[1], u.cs[2], u.cs[3]);
}

static double fract_to_fps(struct v4l2_fract* f) {
  return (double)f->denominator / f->numerator;
}

static void dump_sizes(int fd) {
  struct v4l2_fmtdesc fmt;

  fmt.index = 0;
  fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  while (1) {
    struct v4l2_frmsizeenum size;
    int ret = ioctl(fd, VIDIOC_ENUM_FMT, &fmt);
    if (ret < 0) {
      test_assert(errno == EINVAL);
      break;
    }
    ++fmt.index;

    atomic_printf("Format %d fourcc ", fmt.index);
    print_fourcc(fmt.pixelformat);
    atomic_printf(" name '%s'\n", fmt.description);

    size.index = 0;
    size.pixel_format = fmt.pixelformat;
    while (1) {
      ret = ioctl(fd, VIDIOC_ENUM_FRAMESIZES, &size);
      if (ret < 0) {
        test_assert(errno == EINVAL);
        break;
      }
      ++size.index;

      if (size.type == V4L2_FRMSIZE_TYPE_DISCRETE) {
        struct v4l2_frmivalenum interval;
        atomic_printf("  Frame size %dx%d\n", size.discrete.width,
                      size.discrete.height);
        interval.index = 0;
        interval.pixel_format = fmt.pixelformat;
        interval.width = size.discrete.width;
        interval.height = size.discrete.height;
        while (1) {
          ret = ioctl(fd, VIDIOC_ENUM_FRAMEINTERVALS, &interval);
          if (ret < 0) {
            test_assert(errno == EINVAL);
            break;
          }
          ++interval.index;

          if (interval.type == V4L2_FRMIVAL_TYPE_DISCRETE) {
            atomic_printf("    %f fps\n", fract_to_fps(&interval.discrete));
          } else if (interval.type == V4L2_FRMIVAL_TYPE_CONTINUOUS ||
                     interval.type == V4L2_FRMIVAL_TYPE_STEPWISE) {
            atomic_printf("    %f-%f fps\n",
                          fract_to_fps(&interval.stepwise.min),
                          fract_to_fps(&interval.stepwise.max));
          }
        }
      } else if (size.type == V4L2_FRMSIZE_TYPE_STEPWISE) {
        atomic_printf("  Frame size %dx%d to %dx%d step %dx%d\n",
                      size.stepwise.min_width, size.stepwise.min_height,
                      size.stepwise.max_width, size.stepwise.max_height,
                      size.stepwise.step_width, size.stepwise.step_height);
      }
    }
  }
}

static void read_frames(int fd) {
  size_t i, j;

  for (i = 0; i < buffer_count * 2; ++i) {
    struct v4l2_buffer buf;
    int ret;
    size_t bytes;
    struct buffer* buffer;

    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    ret = ioctl(fd, VIDIOC_DQBUF, &buf);
    test_assert(ret == 0);
    test_assert(buf.index < buffer_count);

    bytes = buf.length < 16 ? buf.length : 16;
    buffer = &buffers[buf.index];
    atomic_printf("Frame %d, buffer %d, addr %p: ", (int)i, (int)buf.index,
                  buffer->mmap_data);
    for (j = 0; j < bytes; ++j) {
      atomic_printf("%2x ", buffer->mmap_data[j]);
    }
    atomic_printf("...\n");

    /* Reallocate the mmap data to check for bugs involving the length
       of the shared memory area */
    munmap(buffer->mmap_data, buffer->vbuf.length);
    buffer->mmap_data =
      mmap(NULL, buffer->vbuf.length, PROT_READ | PROT_WRITE, MAP_SHARED,
           fd, buffer->vbuf.m.offset);
    test_assert(buffer->mmap_data != MAP_FAILED);

    test_assert(0 == ioctl(fd, VIDIOC_QBUF, &buf));
  }
}

static void close_device(int fd) {
  enum v4l2_buf_type type;

  type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  test_assert(0 == ioctl(fd, VIDIOC_STREAMOFF, &type));
}

int main(void) {
  int fd = open_device();
  init_device(fd);
  dump_sizes(fd);
  read_frames(fd);
  close_device(fd);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
