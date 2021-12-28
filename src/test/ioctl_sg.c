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

    int ret;
    struct cdrom_tochdr tochdr;
    memset(&tochdr, 0, sizeof(tochdr));
    ret = ioctl(fd, CDROMREADTOCHDR, &tochdr);
    atomic_printf("CDROMREADTOCHDR returned ret=%d cdth_trk0=%d cdth_trk1=%d\n",
                  ret, tochdr.cdth_trk0, tochdr.cdth_trk1);

    struct cdrom_tocentry tocentry;
    memset(&tocentry, 0, sizeof(tocentry));
    tocentry.cdte_track = tochdr.cdth_trk0;
    tocentry.cdte_format = CDROM_LBA;
    ret = ioctl(fd, CDROMREADTOCENTRY, &tocentry);
    atomic_printf("CDROMREADTOCENTRY returned ret=%d cdte_format=%d lba=%d cdte_datamode=%d\n",
                  ret, tocentry.cdte_format, tocentry.cdte_addr.lba, tocentry.cdte_datamode);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
