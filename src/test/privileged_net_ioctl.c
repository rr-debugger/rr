/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

#include <linux/route.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

/* Utilities for assembling rtnetlink packages */
void buf_put(char** cur_buf_pos, void* data, size_t size) {
  memcpy(*cur_buf_pos, data, size);
  *cur_buf_pos += size;
}

void buf_put_attr_header(char** cur_buf_pos, uint16_t opt, size_t size) {
  struct rtattr attr = {.rta_type = opt,
                        .rta_len = size + sizeof(struct rtattr) };
  buf_put(cur_buf_pos, &attr, sizeof(struct rtattr));
}

void buf_put_attr(char** cur_buf_pos, uint16_t opt, void* data, size_t size) {
  buf_put_attr_header(cur_buf_pos, opt, size);
  buf_put(cur_buf_pos, data, size);
  *cur_buf_pos += RTA_ALIGN(size) - size;
}

#define htonl(x) __bswap_32(x)

int main(void) {
  if (-1 == try_setup_ns(CLONE_NEWNET)) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  int inetfd = socket(AF_INET, SOCK_DGRAM, 0);
  struct iovec iov;
  struct sockaddr_nl kernel_addr;
  memset(&kernel_addr, 0, sizeof(struct sockaddr_nl));
  kernel_addr.nl_family = AF_NETLINK;
  struct msghdr hdr = {.msg_name = &kernel_addr,
                       .msg_namelen = sizeof(struct sockaddr_nl),
                       .msg_iov = &iov,
                       .msg_iovlen = 1,
                       .msg_control = 0,
                       .msg_controllen = 0,
                       .msg_flags = 0 };
  char* cur_buf_p;
  char** cur_buf_pos = &cur_buf_p;
  char* bridge_name = "rrbridge0";
  char* iface0_name = "rreth0";
  char* iface1_name = "rreth1";

  // Create some interfaces to play with. This is the equivalent of:
  // sudo ip link add rreth0 type veth peer name rreth1
  {
    char* interface_kind = "veth";

    ssize_t total_encoded_size =
        5 * sizeof(struct rtattr) + sizeof(struct ifinfomsg) +
        RTA_ALIGN(strlen(interface_kind)) + RTA_ALIGN(strlen(iface1_name) + 1);

    ssize_t msg_len = sizeof(struct nlmsghdr) + sizeof(struct ifinfomsg) +
                      sizeof(struct rtattr) +
                      RTA_ALIGN(strlen(iface0_name) + 1) + total_encoded_size;

    struct nlmsghdr nlhdr;
    memset(&nlhdr, 0, sizeof(struct nlmsghdr));
    nlhdr.nlmsg_type = RTM_NEWLINK;
    nlhdr.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL;
    nlhdr.nlmsg_len = msg_len;
    nlhdr.nlmsg_seq = 1;
    // Reply here please
    nlhdr.nlmsg_pid = getpid();
    struct ifinfomsg msg;
    memset(&msg, 0, sizeof(struct ifinfomsg));
    char* buf = malloc(msg_len);
    cur_buf_p = buf;
    buf_put(cur_buf_pos, &nlhdr, sizeof(nlhdr));
    buf_put(cur_buf_pos, &msg, sizeof(msg));
    buf_put_attr(cur_buf_pos, IFLA_IFNAME, iface0_name,
                 strlen(iface0_name) + 1);

    buf_put_attr_header(cur_buf_pos, IFLA_LINKINFO, total_encoded_size - 4);
    buf_put_attr(cur_buf_pos, IFLA_INFO_KIND, interface_kind,
                 strlen(interface_kind));
    buf_put_attr_header(cur_buf_pos, IFLA_INFO_DATA, total_encoded_size - 16);
    buf_put_attr_header(cur_buf_pos, VETH_INFO_PEER, total_encoded_size - 20);
    buf_put(cur_buf_pos, &msg, sizeof(msg));
    buf_put_attr(cur_buf_pos, IFLA_IFNAME, iface1_name,
                 strlen(iface1_name) + 1);
    iov.iov_base = buf;
    iov.iov_len = msg_len;
    test_assert(msg_len == sendmsg(fd, &hdr, 0));
    test_assert(-1 != recvmsg(fd, &hdr, 0));
    errno = -((struct nlmsgerr*)&(((struct nlmsghdr*)buf)[1]))->error;
    if (((struct nlmsghdr*)buf)->nlmsg_type == NLMSG_ERROR) {
      if (errno == ENOTSUP) {
        atomic_puts("Skipping test because veth device creation\n"
                    "is not supported by this kernel.");
        atomic_puts("EXIT-SUCCESS");
        return 0;
      }
      test_assert(errno == 0);
    }
    free(buf);
  }

  // sudo ifconfig rreth0 0.0.0.0
  {
    struct ifreq req;
    memcpy(&req.ifr_name, iface0_name, strlen(iface0_name) + 1);
    memset(&req.ifr_addr, 0, sizeof(req.ifr_addr));
    req.ifr_addr.sa_family = AF_INET;
    test_assert(0 == ioctl(inetfd, SIOCSIFADDR, &req));
    test_assert(0 == ioctl(inetfd, SIOCGIFFLAGS, &req));
    req.ifr_flags |= IFF_UP | IFF_RUNNING;
    test_assert(0 == ioctl(inetfd, SIOCSIFFLAGS, &req));
  }

  // sudo brctl addbr rrbridge0
  {
    char buf[IFNAMSIZ];
    strncpy(buf, bridge_name, sizeof(buf));
    test_assert(0 == ioctl(inetfd, SIOCBRADDBR, buf));
  }

  // sudo brctl addif rrbridge0 rreth0
  {
    struct ifreq req;
    // Get index by name
    memcpy(&req.ifr_name, iface0_name, strlen(iface0_name) + 1);
    test_assert(0 == ioctl(inetfd, SIOCGIFINDEX, &req));

    // Add to bridge
    memcpy(&req.ifr_name, bridge_name, strlen(bridge_name) + 1);
    test_assert(0 == ioctl(inetfd, SIOCBRADDIF, &req));
  }

  // sudo ifconfig rreth0 10.0.0.2/24
  {
    uint32_t host = htonl((uint32_t)10 << 24 | 0x2);
    uint32_t netmask = htonl(0xffffff00);

    struct ifreq req;
    memcpy(&req.ifr_name, iface1_name, strlen(iface1_name) + 1);
    req.ifr_addr.sa_family = AF_INET;
    memcpy(&((struct sockaddr_in*)&req.ifr_addr)->sin_addr, &host,
           sizeof(uint32_t));
    test_assert(0 == ioctl(inetfd, SIOCSIFADDR, &req));
    memcpy(&((struct sockaddr_in*)&req.ifr_netmask)->sin_addr, &netmask,
           sizeof(uint32_t));
    test_assert(0 == ioctl(inetfd, SIOCSIFNETMASK, &req));
    test_assert(0 == ioctl(inetfd, SIOCGIFFLAGS, &req));
    req.ifr_flags |= IFF_UP | IFF_RUNNING;
    test_assert(0 == ioctl(inetfd, SIOCSIFFLAGS, &req));
  }

  // That will be our default gateway:
  // route add default gw 10.0.0.2
  {
    struct rtentry rm;
    uint32_t gateway = htonl((uint32_t)10 << 24 | 0x2);
    memset(&rm, 0, sizeof(struct rtentry));
    rm.rt_dst.sa_family = rm.rt_genmask.sa_family = rm.rt_gateway.sa_family =
        AF_INET;
    rm.rt_flags |= RTF_GATEWAY;
    memcpy(&((struct sockaddr_in*)&rm.rt_gateway)->sin_addr, &gateway,
           sizeof(uint32_t));
    test_assert(0 == ioctl(inetfd, SIOCADDRT, &rm));
    /* Maybe try to delete it again */
    test_assert(0 == ioctl(inetfd, SIOCDELRT, &rm));
  }

  // sudo brctl delif rrbridge0 rreth0
  {
    struct ifreq req;
    // Get index by name
    memcpy(&req.ifr_name, iface0_name, strlen(iface0_name) + 1);
    test_assert(0 == ioctl(inetfd, SIOCGIFINDEX, &req));

    // Remove from bridge
    memcpy(&req.ifr_name, bridge_name, strlen(bridge_name) + 1);
    test_assert(0 == ioctl(inetfd, SIOCBRDELIF, &req));
  }

  // sudo brctl delbr rrbridge0
  {
    char buf[IFNAMSIZ];
    strncpy(buf, bridge_name, sizeof(buf));
    test_assert(0 == ioctl(inetfd, SIOCBRDELBR, buf));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
