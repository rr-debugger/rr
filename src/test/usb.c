/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

/* Based on https://github.com/ktossell/libuvc/blob/master/src/example.c

Software License Agreement (BSD License)

Copyright (C) 2010-2015 Ken Tossell
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

 * Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above
   copyright notice, this list of conditions and the following
   disclaimer in the documentation and/or other materials provided
   with the distribution.
 * Neither the name of the author nor other contributors may be
   used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

/* Tests a subset of the USBDEVFS ioctls. Requires libuvc to build:
   https://github.com/ktossell/libuvc
   Therefore this test is not built/run by default. */

#include "util.h"

#include "libuvc/libuvc.h"

static int frame_count = 0;

void cb(uvc_frame_t* frame, __attribute__((unused)) void* ptr) {
  uvc_frame_t* bgr;
  uvc_error_t ret;
  bgr = uvc_allocate_frame(frame->width * frame->height * 3);
  test_assert(bgr != NULL);
  ret = uvc_any2bgr(frame, bgr);
  test_assert(ret == 0);
  ++frame_count;
  uvc_free_frame(bgr);
}

int main(void) {
  uvc_context_t* ctx;
  uvc_device_t* dev;
  uvc_device_handle_t* devh;
  uvc_stream_ctrl_t ctrl;
  uvc_error_t res;
  res = uvc_init(&ctx, NULL);
  test_assert(res >= 0);
  atomic_puts("UVC initialized");
  /* Locates the first attached UVC device, stores in dev */
  res = uvc_find_device(ctx, &dev, 0, 0, NULL); /* filter devices: vendor_id,
                                                   product_id, "serial_num" */
  if (res < 0) {
    atomic_puts("No device found");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  atomic_puts("Device found");
  /* Try to open the device: requires exclusive access */
  res = uvc_open(dev, &devh);
  if (res < 0) {
    atomic_puts("Can't open device");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  atomic_puts("Device opened");
  /* Print out a message containing all the information that libuvc
   * knows about the device */
  uvc_print_diag(devh, stdout);
  /* Try to negotiate a 640x480 30 fps YUYV stream profile */
  res = uvc_get_stream_ctrl_format_size(
      devh, &ctrl,           /* result stored in ctrl */
      UVC_FRAME_FORMAT_YUYV, /* YUV 422, aka YUV 4:2:2. try _COMPRESSED */
      640, 480, 30           /* width, height, fps */
      );
  /* Print out the result */
  uvc_print_stream_ctrl(&ctrl, stdout);
  if (res < 0) {
    atomic_puts("No matching stream");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  /* Start the video stream. The library will call user function cb:
   *   cb(frame, (void*) 12345)
   */
  res = uvc_start_streaming(devh, &ctrl, cb, (void*)12345, 0);
  test_assert(res >= 0);
  atomic_puts("Streaming...");
  uvc_set_ae_mode(devh, 1); /* e.g., turn on auto exposure */
  sleep(2);                 /* stream for 2 seconds */
  atomic_puts("Stopping streaming.");
  /* End the stream. Blocks until last callback is serviced */
  uvc_stop_streaming(devh);
  atomic_puts("Done streaming.");
  /* Release our handle on the device */
  uvc_close(devh);
  atomic_puts("Device closed");
  /* Release the device descriptor */
  uvc_unref_device(dev);
  /* Close the UVC context. This closes and cleans up any existing device
   * handles,
   * and it closes the libusb context if one was not provided. */
  uvc_exit(ctx);
  test_assert(frame_count > 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
