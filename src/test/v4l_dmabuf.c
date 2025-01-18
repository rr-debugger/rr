/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <linux/dma-buf.h>

#ifndef DMA_BUF_IOCTL_EXPORT_SYNC_FILE
struct dma_buf_export_sync_file {
  uint32_t flags;
  int32_t fd;
};
#define DMA_BUF_IOCTL_EXPORT_SYNC_FILE _IOWR(DMA_BUF_BASE, 2, struct dma_buf_export_sync_file)
#endif
#ifndef DMA_BUF_IOCTL_IMPORT_SYNC_FILE
struct dma_buf_import_sync_file {
  uint32_t flags;
  int32_t fd;
};
#define DMA_BUF_IOCTL_IMPORT_SYNC_FILE _IOWR(DMA_BUF_BASE, 3, struct dma_buf_import_sync_file)
#endif

static const char device_name[] = "/dev/video0";

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

static int get_dmabuf(int fd) {
  struct v4l2_requestbuffers* req;
  int ret;
  struct v4l2_exportbuffer* exp;

  ALLOCATE_GUARD(req, 'a');
  req->count = 1;
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
  if (req->count < 1) {
    atomic_puts("Got no buffers, aborting test");
    no_v4l2();
  }

  ALLOCATE_GUARD(exp, 'b');
  exp->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  exp->index = 0;
  exp->plane = 0;
  exp->flags = O_RDONLY;
  memset(exp->reserved, 0, sizeof(exp->reserved));
  ret = ioctl(fd, VIDIOC_EXPBUF, exp);
  VERIFY_GUARD(exp);
  test_assert(ret == 0);
  test_assert(exp->fd >= 0);
  return exp->fd;
}

int main(void) {
  int fd = open_device();
  int dmabuf = get_dmabuf(fd);

  struct dma_buf_sync* sync;
  ALLOCATE_GUARD(sync, 'a');
  sync->flags = DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ;
  int ret = ioctl(dmabuf, DMA_BUF_IOCTL_SYNC, sync);
  VERIFY_GUARD(sync);
  test_assert(ret == 0);

  sync->flags = DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ;
  ret = ioctl(dmabuf, DMA_BUF_IOCTL_SYNC, sync);
  VERIFY_GUARD(sync);
  test_assert(ret == 0);

  struct dma_buf_export_sync_file* sync_file;
  ALLOCATE_GUARD(sync_file, 'b');
  sync_file->flags = DMA_BUF_SYNC_READ;
  ret = ioctl(dmabuf, DMA_BUF_IOCTL_EXPORT_SYNC_FILE, sync_file);
  VERIFY_GUARD(sync_file);
  test_assert(ret == 0);
  test_assert(sync_file->fd >= 0);

  struct dma_buf_import_sync_file* import_sync_file;
  ALLOCATE_GUARD(import_sync_file, 'c');
  import_sync_file->flags = DMA_BUF_SYNC_READ;
  import_sync_file->fd = sync_file->fd;
  ret = ioctl(dmabuf, DMA_BUF_IOCTL_IMPORT_SYNC_FILE, import_sync_file);
  VERIFY_GUARD(import_sync_file);
  test_assert(ret == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
