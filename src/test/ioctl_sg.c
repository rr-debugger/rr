/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("/dev/sr0", O_NONBLOCK | O_RDONLY);
  if (fd < 0) {
    test_assert(errno == EACCES || errno == ENOENT);
  } else {

    /* https://www.tldp.org/HOWTO/SCSI-Generic-HOWTO/pexample.html */

    int k;
    if ((ioctl(fd, SG_GET_VERSION_NUM, &k) < 0) || (k < 30000)) {
      /* no usable sg device available */
    } else {

      #define INQ_REPLY_LEN 96
      #define INQ_CMD_CODE 0x12
      #define INQ_CMD_LEN 6

      unsigned char inqCmdBlk[INQ_CMD_LEN] = {INQ_CMD_CODE, 0, 0, 0, INQ_REPLY_LEN, 0};
      unsigned char inqBuff[INQ_REPLY_LEN];
      unsigned char sense_buffer[32];
      sg_io_hdr_t io_hdr;

      memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
      io_hdr.interface_id = 'S';
      io_hdr.cmd_len = sizeof(inqCmdBlk);
      io_hdr.iovec_count = 0;
      io_hdr.mx_sb_len = sizeof(sense_buffer);
      io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
      io_hdr.dxfer_len = INQ_REPLY_LEN;
      io_hdr.dxferp = inqBuff;
      io_hdr.cmdp = inqCmdBlk;
      io_hdr.sbp = sense_buffer;
      io_hdr.timeout = 20000;
      io_hdr.flags = 0;
      io_hdr.pack_id = 0;
      io_hdr.usr_ptr = NULL;

      test_assert(0 == ioctl(fd, SG_IO, &io_hdr));
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
