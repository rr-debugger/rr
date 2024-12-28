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
  struct v4l2_capability* cap;
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

  ALLOCATE_GUARD(cap, 'a');
  ret = ioctl(fd, VIDIOC_QUERYCAP, cap);
  VERIFY_GUARD(cap);
  if (ret < 0 && errno == EINVAL) {
    atomic_printf("%s is not a V4L2 device; aborting test\n", device_name);
    no_v4l2();
  }
  if (ret < 0 && errno == EACCES) {
    atomic_printf("%s is not accessible; aborting test\n", device_name);
    no_v4l2();
  }
  if (!(cap->capabilities & V4L2_CAP_VIDEO_CAPTURE)) {
    atomic_printf("%s is not a V4L2 capture device; aborting test\n",
                  device_name);
    no_v4l2();
  }
  if (!(cap->capabilities & V4L2_CAP_STREAMING)) {
    atomic_printf("%s does not support streaming; aborting test\n",
                  device_name);
    no_v4l2();
  }

  uint32_t* input;
  ALLOCATE_GUARD(input, 'b');
  ret = ioctl(fd, VIDIOC_G_INPUT, input);
  VERIFY_GUARD(input);
  if (ret < 0) {
    atomic_printf("%s does not support VIDIOC_G_INPUT\n", device_name);
  } else {
    atomic_printf("%s VIDIOC_G_INPUT returns %d\n", device_name, *input);
  }

#ifdef VIDIOC_QUERY_EXT_CTRL
  struct v4l2_query_ext_ctrl* qec;
  ALLOCATE_GUARD(qec, 'c');
  memset(qec, 0, sizeof(*qec));
  qec->id = V4L2_CTRL_FLAG_NEXT_CTRL | V4L2_CTRL_FLAG_NEXT_COMPOUND;
  ret = ioctl(fd, VIDIOC_QUERY_EXT_CTRL, qec);
  VERIFY_GUARD(qec);
  if (ret < 0) {
    atomic_printf("%s does not support VIDIOC_QUERY_EXT_CTRL\n", device_name);
  } else {
    atomic_printf("%s VIDIOC_QUERY_EXT_CTRL returns id=%d, type=%d, name=%s\n",
                  device_name, qec->id, qec->type, qec->name);
  }
#endif

  enum v4l2_priority* prio;
  ALLOCATE_GUARD(prio, 'd');
  ret = ioctl(fd, VIDIOC_G_PRIORITY, prio);
  VERIFY_GUARD(prio);
  if (ret < 0) {
    atomic_printf("%s does not support VIDIOC_G_PRIORITY\n", device_name);
  } else {
    atomic_printf("%s VIDIOC_G_PRIORITY returns prio=%d\n", device_name, *prio);
  }

  struct v4l2_queryctrl* qc;
  ALLOCATE_GUARD(qc, 'e');
  memset(qc, 0, sizeof(*qc));
  qc->id = V4L2_CTRL_FLAG_NEXT_CTRL;
  ret = ioctl(fd, VIDIOC_QUERYCTRL, qc);
  VERIFY_GUARD(qc);
  if (ret < 0) {
    atomic_printf("%s does not support VIDIOC_QUERYCTRL\n", device_name);
  } else {
    atomic_printf("%s VIDIOC_QUERYCTRL returns id=%d, type=%d, name=%s\n",
                  device_name, qc->id, qc->type, qc->name);
  }

  return fd;
}

static void init_device(int fd) {
  struct v4l2_format* fmt;
  struct v4l2_requestbuffers* req;
  int ret;
  size_t i;
  enum v4l2_buf_type* type;

  ALLOCATE_GUARD(fmt, 'a');
  fmt->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  ret = ioctl(fd, VIDIOC_G_FMT, fmt);
  VERIFY_GUARD(fmt);
  if (ret < 0 && errno == EINVAL) {
    // v4l2_loopback doesn't support G_FMT
    atomic_printf("%s does not support G_FMT; aborting test\n",
                  device_name);
    no_v4l2();
  }
  test_assert(0 == ret);
  atomic_printf("%s returning %dx%d frames\n", device_name, fmt->fmt.pix.width,
                fmt->fmt.pix.height);

  ALLOCATE_GUARD(req, 'b');
  req->count = 4;
  req->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  req->memory = V4L2_MEMORY_MMAP;
  ret = ioctl(fd, VIDIOC_REQBUFS, req);
  VERIFY_GUARD(req);
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
  if (req->count < 2) {
    atomic_printf("%s only supports one buffer; aborting test\n", device_name);
    no_v4l2();
  }
  buffer_count = req->count;

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
  ALLOCATE_GUARD(type, 'c');
  *type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  test_assert(0 == ioctl(fd, VIDIOC_STREAMON, type));
  VERIFY_GUARD(type);
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
  struct v4l2_fmtdesc* fmt;

  ALLOCATE_GUARD(fmt, 'a');
  fmt->index = 0;
  fmt->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  while (1) {
    struct v4l2_frmsizeenum* size;
    int ret = ioctl(fd, VIDIOC_ENUM_FMT, fmt);
    VERIFY_GUARD(fmt);
    if (ret < 0) {
      test_assert(errno == EINVAL);
      break;
    }

    atomic_printf("Format %d fourcc ", fmt->index);
    print_fourcc(fmt->pixelformat);
    ++fmt->index;
    atomic_printf(" name '%s'\n", fmt->description);

    ALLOCATE_GUARD(size, 'b');
    size->index = 0;
    size->pixel_format = fmt->pixelformat;
    while (1) {
      ret = ioctl(fd, VIDIOC_ENUM_FRAMESIZES, size);
      VERIFY_GUARD(size);
      if (ret < 0) {
        test_assert(errno == EINVAL);
        break;
      }
      ++size->index;

      if (size->type == V4L2_FRMSIZE_TYPE_DISCRETE) {
        struct v4l2_frmivalenum* interval;
        ALLOCATE_GUARD(interval, 'c');
        atomic_printf("  Frame size %dx%d\n", size->discrete.width,
                      size->discrete.height);
        interval->index = 0;
        interval->pixel_format = fmt->pixelformat;
        interval->width = size->discrete.width;
        interval->height = size->discrete.height;
        while (1) {
          ret = ioctl(fd, VIDIOC_ENUM_FRAMEINTERVALS, interval);
          VERIFY_GUARD(interval);
          if (ret < 0) {
            test_assert(errno == EINVAL);
            break;
          }
          ++interval->index;

          if (interval->type == V4L2_FRMIVAL_TYPE_DISCRETE) {
            atomic_printf("    %f fps\n", fract_to_fps(&interval->discrete));
          } else if (interval->type == V4L2_FRMIVAL_TYPE_CONTINUOUS ||
                     interval->type == V4L2_FRMIVAL_TYPE_STEPWISE) {
            atomic_printf("    %f-%f fps\n",
                          fract_to_fps(&interval->stepwise.min),
                          fract_to_fps(&interval->stepwise.max));
          }
        }
      } else if (size->type == V4L2_FRMSIZE_TYPE_STEPWISE) {
        atomic_printf("  Frame size %dx%d to %dx%d step %dx%d\n",
                      size->stepwise.min_width, size->stepwise.min_height,
                      size->stepwise.max_width, size->stepwise.max_height,
                      size->stepwise.step_width, size->stepwise.step_height);
      }
    }
  }
}

static void read_frames(int fd) {
  size_t i, j;

  for (i = 0; i < buffer_count * 2; ++i) {
    struct v4l2_buffer* buf;
    int ret;
    size_t bytes;
    struct buffer* buffer;

    ALLOCATE_GUARD(buf, 'a');
    buf->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf->memory = V4L2_MEMORY_MMAP;
    ret = ioctl(fd, VIDIOC_DQBUF, buf);
    VERIFY_GUARD(buf);
    test_assert(ret == 0);
    test_assert(buf->index < buffer_count);

    bytes = buf->length < 16 ? buf->length : 16;
    buffer = &buffers[buf->index];
    atomic_printf("Frame %d, buffer %d, addr %p: ", (int)i, (int)buf->index,
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

    test_assert(0 == ioctl(fd, VIDIOC_QBUF, buf));
    VERIFY_GUARD(buf);
    FREE_GUARD(buf);
  }
}

static void close_device(int fd) {
  enum v4l2_buf_type* type;

  ALLOCATE_GUARD(type, 'a');
  *type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  test_assert(0 == ioctl(fd, VIDIOC_STREAMOFF, type));
  VERIFY_GUARD(type);
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
