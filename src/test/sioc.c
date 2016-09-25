/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

const char* sockaddr_name(const struct sockaddr* addr) {
  const struct sockaddr_in* sin = (const struct sockaddr_in*)addr;
  static char str[PATH_MAX];
  /* FIXME: add INET6 support (original author didn't
   * have ipv6 iface available to test).  */
  test_assert(AF_INET == addr->sa_family);
  return inet_ntop(AF_INET, (void*)&sin->sin_addr, str, sizeof(str));
}

const char* sockaddr_hw_name(const struct sockaddr* addr) {
  static char str[PATH_MAX];
  const unsigned char* data = (const unsigned char*)addr->sa_data;
  test_assert(AF_LOCAL == addr->sa_family);
  sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", data[0], data[1], data[2],
          data[3], data[4], data[5]);
  return str;
}

/**
 * Fetch and print the ifconfig for this machine.  Fill in
 * |req.ifr_name| with the first non-loopback interface name found, preferring
 * a wireless interface if possible.
 * |eth_req| returns an ethernet interface if possible.
 */
static void get_ifconfig(int sockfd, struct ifreq* req, struct ifreq* eth_req) {
  struct {
    struct ifreq ifaces[100];
  } * ifaces;
  struct ifconf* ifconf;
  int ret;
  ssize_t num_ifaces;
  int i;
  int wireless_index = -1;
  int eth_index = -1;
  int non_loop_index = -1;

  ALLOCATE_GUARD(ifconf, 0xff);
  ALLOCATE_GUARD(ifaces, 'y');
  ifconf->ifc_len = sizeof(*ifaces);
  ifconf->ifc_req = ifaces->ifaces;

  ret = ioctl(sockfd, SIOCGIFCONF, ifconf);
  VERIFY_GUARD(ifconf);
  VERIFY_GUARD(ifaces);
  num_ifaces = ifconf->ifc_len / sizeof(ifaces->ifaces[0]);
  test_assert(num_ifaces < 100);
  atomic_printf("SIOCGIFCONF(ret %d): %zd ifaces (%d bytes of ifreq)\n", ret,
                num_ifaces, ifconf->ifc_len);
  test_assert(0 == ret);
  test_assert(0 == (ifconf->ifc_len % sizeof(ifaces->ifaces[0])));

  if (!num_ifaces) {
    atomic_puts("No interfaces found\n");
    atomic_puts("EXIT-SUCCESS");
    exit(0);
  }

  for (i = 0; i < num_ifaces; ++i) {
    const struct ifreq* ifc = &ifconf->ifc_req[i];
    atomic_printf("  iface %d: name:%s addr:%s\n", i, ifc->ifr_name,
                  sockaddr_name(&ifc->ifr_addr));
    switch (ifc->ifr_name[0]) {
      case 'w':
        wireless_index = i;
        non_loop_index = i;
        break;
      case 'e':
        eth_index = i;
        non_loop_index = i;
        break;
      case 't':
      case 'l':
        break;
      default:
        non_loop_index = i;
        break;
    }
  }

  if (wireless_index >= 0) {
    strcpy(req->ifr_name, ifaces->ifaces[wireless_index].ifr_name);
  } else if (non_loop_index >= 0) {
    strcpy(req->ifr_name, ifaces->ifaces[non_loop_index].ifr_name);
  } else {
    strcpy(req->ifr_name, ifaces->ifaces[0].ifr_name);
  }
  if (eth_index >= 0) {
    strcpy(eth_req->ifr_name, ifaces->ifaces[eth_index].ifr_name);
  } else if (non_loop_index >= 0) {
    strcpy(eth_req->ifr_name, ifaces->ifaces[non_loop_index].ifr_name);
  } else {
    strcpy(eth_req->ifr_name, ifaces->ifaces[0].ifr_name);
  }
}

#define GENERIC_REQUEST_BY_NAME(nr) \
  memset(&req->ifr_ifru, 0xff, sizeof(req->ifr_ifru)); \
  ret = ioctl(sockfd, nr, req); \
  VERIFY_GUARD(req); \
  atomic_printf(#nr "(ret:%d): %s ", ret, req->ifr_name); \
  test_assert(0 == ret)

int main(void) {
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  struct ifreq* req;
  struct ifreq* eth_req;
  char name[PATH_MAX];
  int index;
  struct ethtool_cmd* etc;
  int err, ret;
  struct iwreq* wreq;
  char buf[1024];

  ALLOCATE_GUARD(req, 'a');
  ALLOCATE_GUARD(eth_req, 'a');
  get_ifconfig(sockfd, req, eth_req);
  strcpy(name, req->ifr_name);

  req->ifr_ifindex = -1;
  strcpy(req->ifr_name, name);
  ret = ioctl(sockfd, SIOCGIFINDEX, req);
  VERIFY_GUARD(req);
  atomic_printf("SIOCGIFINDEX(ret:%d): %s index is %d\n", ret, req->ifr_name,
                req->ifr_ifindex);
  test_assert(0 == ret);
  test_assert(req->ifr_ifindex != -1);
  index = req->ifr_ifindex;

  memset(&req->ifr_name, 0xff, sizeof(req->ifr_name));
  req->ifr_ifindex = index;
  ret = ioctl(sockfd, SIOCGIFNAME, req);
  VERIFY_GUARD(req);
  atomic_printf("SIOCGIFNAME(ret:%d): index %d(%s) name is %s\n", ret, index,
                name, req->ifr_name);
  test_assert(0 == ret);
  test_assert(!strcmp(name, req->ifr_name));

  GENERIC_REQUEST_BY_NAME(SIOCGIFFLAGS);
  atomic_printf("flags are %#x\n", req->ifr_flags);

  GENERIC_REQUEST_BY_NAME(SIOCGIFADDR);
  atomic_printf("addr is %s\n", sockaddr_name(&req->ifr_addr));

  GENERIC_REQUEST_BY_NAME(SIOCGIFDSTADDR);
  atomic_printf("addr is %s\n", sockaddr_name(&req->ifr_addr));

  GENERIC_REQUEST_BY_NAME(SIOCGIFBRDADDR);
  atomic_printf("addr is %s\n", sockaddr_name(&req->ifr_addr));

  GENERIC_REQUEST_BY_NAME(SIOCGIFNETMASK);
  atomic_printf("netmask is %s\n", sockaddr_name(&req->ifr_addr));

  GENERIC_REQUEST_BY_NAME(SIOCGIFMETRIC);
  atomic_printf("metric is %d\n", req->ifr_metric);

  memset(&req->ifr_metric, 0xff, sizeof(req->ifr_metric));
  ret = ioctl(sockfd, SIOCGIFMEM, req);
  VERIFY_GUARD(req);
  test_assert(-1 == ret && errno == ENOTTY);

  GENERIC_REQUEST_BY_NAME(SIOCGIFMTU);
  atomic_printf("MTU is %d\n", req->ifr_mtu);

  GENERIC_REQUEST_BY_NAME(SIOCGIFHWADDR);
  atomic_printf("hwaddr %s\n", sockaddr_hw_name(&req->ifr_addr));

  memset(&req->ifr_flags, 0xff, sizeof(req->ifr_flags));
  ret = ioctl(sockfd, SIOCGIFPFLAGS, req);
  VERIFY_GUARD(req);
  if (ret != -1 || errno != EINVAL) {
    test_assert(0 == ret);
    atomic_printf("SIOCGIFPFLAGS(ret:%d): %s flags are", ret, req->ifr_name);
    atomic_printf(" %#x\n", req->ifr_flags);
  }

  GENERIC_REQUEST_BY_NAME(SIOCGIFTXQLEN);
  atomic_printf("qlen is %d\n", req->ifr_qlen);

  ALLOCATE_GUARD(etc, 'b');
  etc->cmd = ETHTOOL_GSET;
  req->ifr_data = (char*)&etc;
  ret = ioctl(sockfd, SIOCETHTOOL, req);
  VERIFY_GUARD(req);
  VERIFY_GUARD(etc);
  err = errno;
  atomic_printf("SIOCETHTOOL(ret:%d): %s ethtool data:\n", ret, req->ifr_name);
  if (-1 == ret) {
    atomic_printf("WARNING: %s doesn't appear to support SIOCETHTOOL\n", name);
    test_assert(EOPNOTSUPP == err || EPERM == err);
  } else {
    atomic_printf("  speed:%#x duplex:%#x port:%#x physaddr:%#x, maxtxpkt:%u "
                  "maxrxpkt:%u ...\n",
                  ethtool_cmd_speed(etc), etc->duplex, etc->port,
                  etc->phy_address, etc->maxtxpkt, etc->maxrxpkt);
  }

  ALLOCATE_GUARD(wreq, 'c');
  strcpy(wreq->ifr_ifrn.ifrn_name, name);
  ret = ioctl(sockfd, SIOCGIWRATE, wreq);
  VERIFY_GUARD(wreq);
  err = errno;
  atomic_printf("SIOCGIWRATE(ret:%d): %s:\n", ret, wreq->ifr_name);
  if (-1 == ret) {
    atomic_printf("WARNING: %s doesn't appear to be a wireless iface\n", name);
    test_assert(EOPNOTSUPP == err || EPERM == err || EINVAL == err);
  } else {
    atomic_printf("  bitrate:%d (fixed? %s; disabled? %s) flags:%#x\n",
                  wreq->u.bitrate.value, wreq->u.bitrate.fixed ? "yes" : "no",
                  wreq->u.bitrate.disabled ? "yes" : "no",
                  wreq->u.bitrate.flags);
  }

  ALLOCATE_GUARD(wreq, 'd');
  strcpy(wreq->ifr_ifrn.ifrn_name, name);
  ret = ioctl(sockfd, SIOCGIWNAME, wreq);
  VERIFY_GUARD(wreq);
  err = errno;
  atomic_printf("SIOCGIWNAME(ret:%d): %s:\n", ret, wreq->ifr_name);
  if (-1 == ret) {
    atomic_printf("WARNING: %s doesn't appear to be a wireless iface\n", name);
    test_assert(EOPNOTSUPP == err || EPERM == err || EINVAL == err);
  } else {
    atomic_printf("  wireless protocol name:%s\n", wreq->u.name);
  }

  ALLOCATE_GUARD(wreq, 'e');
  strcpy(wreq->ifr_ifrn.ifrn_name, name);
  wreq->u.essid.length = sizeof(buf);
  wreq->u.essid.pointer = buf;
  wreq->u.essid.flags = 0;
  ret = ioctl(sockfd, SIOCGIWESSID, wreq);
  VERIFY_GUARD(wreq);
  err = errno;
  atomic_printf("SIOCGIWESSID(ret:%d): %s:\n", ret, wreq->ifr_name);
  if (-1 == ret) {
    atomic_printf("WARNING: %s doesn't appear to be a wireless iface\n", name);
    test_assert(EOPNOTSUPP == err || EPERM == err || EINVAL == err);
  } else {
    atomic_printf("  wireless ESSID:%s\n", buf);
  }

  ALLOCATE_GUARD(wreq, 'f');
  strcpy(wreq->ifr_ifrn.ifrn_name, name);
  ret = ioctl(sockfd, SIOCGIWFREQ, wreq);
  VERIFY_GUARD(wreq);
  err = errno;
  atomic_printf("SIOCGIWFREQ(ret:%d): %s:\n", ret, wreq->ifr_name);
  if (-1 == ret) {
    atomic_printf("WARNING: %s doesn't appear to be a wireless iface\n", name);
    test_assert(EOPNOTSUPP == err || EPERM == err || EINVAL == err);
  } else {
    atomic_printf("  wireless freq m:%d e:%d i:%d flags:%d\n", wreq->u.freq.m,
                  wreq->u.freq.e, wreq->u.freq.i, wreq->u.freq.flags);
  }

  ALLOCATE_GUARD(wreq, 'g');
  strcpy(wreq->ifr_ifrn.ifrn_name, name);
  ret = ioctl(sockfd, SIOCGIWMODE, wreq);
  VERIFY_GUARD(wreq);
  err = errno;
  atomic_printf("SIOCGIWMODE(ret:%d): %s:\n", ret, wreq->ifr_name);
  if (-1 == ret) {
    atomic_printf("WARNING: %s doesn't appear to be a wireless iface\n", name);
    test_assert(EOPNOTSUPP == err || EPERM == err || EINVAL == err);
  } else {
    atomic_printf("  wireless mode:%d\n", wreq->u.mode);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
