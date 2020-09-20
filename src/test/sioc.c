/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

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
  }* ifaces;
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

static void generic_request_by_name(int sockfd, struct ifreq* req, int nr,
                                    const char* nr_str) {
  int ret;
  memset(&req->ifr_ifru, 0xff, sizeof(req->ifr_ifru));
  ret = ioctl(sockfd, nr, req);
  VERIFY_GUARD(req);
  atomic_printf("%s(ret:%d): %s ", nr_str, ret, req->ifr_name);
  if (ret < 0 && errno == EFAULT && nr == SIOCGIFADDR) {
    /* Work around https://bugzilla.kernel.org/show_bug.cgi?id=202273 */
    atomic_puts("Buggy kernel detected; aborting test");
    atomic_puts("EXIT-SUCCESS");
    exit(0);
  }
  test_assert(0 == ret);
}

#define GENERIC_REQUEST_BY_NAME(nr)                                            \
  generic_request_by_name(sockfd, req, nr, #nr)

static int generic_wireless_request_by_name_internal(int sockfd,
                                                     struct iwreq** wreq,
                                                     const char* name, int nr,
                                                     const char* nr_str) {
  int err;
  int ret;
  /* Note that we use sizeof(struct ifreq) here, not iwreq, because of
   * https://bugzilla.kernel.org/show_bug.cgi?id=195869
   */
  *wreq = allocate_guard(sizeof(struct ifreq), 'd');
  strcpy((*wreq)->ifr_ifrn.ifrn_name, name);
  ret = ioctl(sockfd, nr, *wreq);
  VERIFY_GUARD(*wreq);
  err = errno;
  atomic_printf("%s(ret:%d): %s: ", nr_str, ret, (*wreq)->ifr_name);
  if (-1 == ret) {
    atomic_printf("WARNING: %s doesn't support ioctl %s\n", name, nr_str);
    /* "bond" network devices can return ENODEV.
       Some virtual ethernet devices can return ENOTTY. */
    test_assert(EOPNOTSUPP == err || EPERM == err || EINVAL == err || ENODEV == err || ENOTTY == err);
  }
  return ret;
}

#define GENERIC_WIRELESS_REQUEST_BY_NAME_INTERNAL(nr, nr_str, args)            \
  if (generic_wireless_request_by_name_internal(sockfd, &wreq, name, nr,       \
                                                nr_str) == 0) {                \
    atomic_printf args;                                                        \
    atomic_puts("");                                                           \
  }                                                                            \
  while (0)

#define GENERIC_WIRELESS_REQUEST_BY_NAME(nr, args)                             \
  GENERIC_WIRELESS_REQUEST_BY_NAME_INTERNAL(nr, #nr, args)

#define GENERIC_WIRELESS_PARAM_REQUEST_BY_NAME(nr, name)                       \
  GENERIC_WIRELESS_REQUEST_BY_NAME_INTERNAL(                                   \
      nr, #nr, ("wireless %s:%d (fixed? %s; disabled? %s) flags:%#x", #name,   \
                wreq->u.name.value, wreq->u.name.fixed ? "yes" : "no",         \
                wreq->u.name.disabled ? "yes" : "no", wreq->u.name.flags));

#define GENERIC_ETHTOOL_REQUEST_BY_NAME(ptr, nr) \
  (ptr)->cmd = nr; \
  req->ifr_data = (char*)ptr; \
  ret = ioctl(sockfd, SIOCETHTOOL, req); \
  VERIFY_GUARD(req); \
  VERIFY_GUARD(ptr); \
  err = errno; \
  atomic_printf("SIOCETHTOOL(ret:%d) " #nr ": %s ethtool data: ", ret, req->ifr_name); \
  if (-1 == ret) { \
    atomic_printf("WARNING: %s doesn't appear to support SIOCETHTOOL " #nr "\n", req->ifr_name); \
    test_assert(EOPNOTSUPP == err || EPERM == err); \
  }

static void ethtool(int sockfd, struct ifreq* req) {
  struct ethtool_cmd* et_set;
  struct ethtool_drvinfo* et_drvinfo;
  struct ethtool_wolinfo* et_wolinfo;
  struct {
    struct ethtool_regs et;
    uint8_t data[32];
  }* et_regs;
  struct {
    struct ethtool_eeprom et;
    uint8_t data[32];
  }* et_eeprom;
  struct ethtool_eee* et_eee;
  struct ethtool_modinfo* et_modinfo;
  struct ethtool_coalesce* et_coalesce;
  struct ethtool_ringparam* et_ringparam;
  struct ethtool_channels* et_channels;
  struct ethtool_pauseparam* et_pauseparam;
  struct {
    struct ethtool_sset_info et;
    uint32_t data[8];
  }* et_sset_info;
  struct {
    struct ethtool_gfeatures et;
    struct ethtool_get_features_block features[20];
  }* et_gfeatures;
  struct {
    struct ethtool_perm_addr et;
    uint8_t data[32];
  }* et_perm_addr;
  int i;
  int err;
  int ret;

  ALLOCATE_GUARD(et_set, 'b');
  GENERIC_ETHTOOL_REQUEST_BY_NAME(et_set, ETHTOOL_GSET);
  if (-1 == ret) {
    return;
  }
  atomic_printf("speed:%#x duplex:%#x port:%#x physaddr:%#x, maxtxpkt:%u "
                "maxrxpkt:%u ...\n",
                ethtool_cmd_speed(et_set), et_set->duplex, et_set->port,
                et_set->phy_address, et_set->maxtxpkt, et_set->maxrxpkt);

  ALLOCATE_GUARD(et_drvinfo, 'c');
  GENERIC_ETHTOOL_REQUEST_BY_NAME(et_drvinfo, ETHTOOL_GDRVINFO);
  if (-1 != ret) {
    #ifdef ETHTOOL_EROMVERS_LEN
    atomic_printf("driver:%s version:%s fw_version:%s bus_info:%s erom_version:%s\n",
                  et_drvinfo->driver, et_drvinfo->version, et_drvinfo->fw_version,
                  et_drvinfo->bus_info, et_drvinfo->erom_version);
    #else
    atomic_printf("driver:%s version:%s fw_version:%s bus_info:%s\n",
                  et_drvinfo->driver, et_drvinfo->version, et_drvinfo->fw_version,
                  et_drvinfo->bus_info);
    #endif
  }

  ALLOCATE_GUARD(et_wolinfo, 'd');
  GENERIC_ETHTOOL_REQUEST_BY_NAME(et_wolinfo, ETHTOOL_GWOL);

  ALLOCATE_GUARD(et_regs, 'e');
  et_regs->et.len = sizeof(et_regs->data);
  GENERIC_ETHTOOL_REQUEST_BY_NAME(&et_regs->et, ETHTOOL_GREGS);
  if (-1 != ret) {
    uint32_t i;
    for (i = 0; i < et_regs->et.len; ++i) {
      atomic_printf("%02x ", et_regs->data[i]);
    }
    atomic_printf("\n");
  }

  ALLOCATE_GUARD(et_eeprom, 'f');
  et_eeprom->et.offset = 0;
  et_eeprom->et.len = sizeof(et_eeprom->data);
  GENERIC_ETHTOOL_REQUEST_BY_NAME(&et_eeprom->et, ETHTOOL_GEEPROM);
  if (-1 != ret) {
    uint32_t i;
    for (i = 0; i < et_eeprom->et.len; ++i) {
      atomic_printf("%02x ", et_eeprom->data[i]);
    }
    atomic_printf("\n");
  }

  ALLOCATE_GUARD(et_eeprom, 'g');
  et_eeprom->et.offset = 0;
  et_eeprom->et.len = sizeof(et_eeprom->data);
  GENERIC_ETHTOOL_REQUEST_BY_NAME(&et_eeprom->et, ETHTOOL_GMODULEEEPROM);
  if (-1 != ret) {
    uint32_t i;
    for (i = 0; i < et_eeprom->et.len; ++i) {
      atomic_printf("%02x ", et_eeprom->data[i]);
    }
    atomic_printf("\n");
  }

  ALLOCATE_GUARD(et_eee, 'h');
  GENERIC_ETHTOOL_REQUEST_BY_NAME(et_eee, ETHTOOL_GEEE);
  if (-1 != ret) {
    atomic_printf("tx_lpi_timer:%d enabled:%d\n",
                  et_eee->tx_lpi_timer, et_eee->eee_enabled);
  }

  ALLOCATE_GUARD(et_modinfo, 'i');
  GENERIC_ETHTOOL_REQUEST_BY_NAME(et_modinfo, ETHTOOL_GMODULEINFO);

  ALLOCATE_GUARD(et_coalesce, 'j');
  GENERIC_ETHTOOL_REQUEST_BY_NAME(et_coalesce, ETHTOOL_GCOALESCE);
  if (-1 != ret) {
    atomic_printf("rx_coalesce_usecs:%d tx_coalesce_usecs:%d\n",
                  et_coalesce->rx_coalesce_usecs, et_coalesce->tx_coalesce_usecs);
  }

  ALLOCATE_GUARD(et_ringparam, 'k');
  GENERIC_ETHTOOL_REQUEST_BY_NAME(et_ringparam, ETHTOOL_GRINGPARAM);
  if (-1 != ret) {
    atomic_printf("rx_max_pending:%d rx_pending:%d tx_max_pending:%d tx_pending:%d\n",
                  et_ringparam->rx_max_pending, et_ringparam->rx_pending,
                  et_ringparam->rx_pending, et_ringparam->tx_pending);
  }

  ALLOCATE_GUARD(et_channels, 'l');
  GENERIC_ETHTOOL_REQUEST_BY_NAME(et_channels, ETHTOOL_GCHANNELS);
  if (-1 != ret) {
    atomic_printf("max_rx:%d max_tx:%d\n",
                  et_channels->max_rx, et_channels->max_tx);
  }

  ALLOCATE_GUARD(et_pauseparam, 'm');
  GENERIC_ETHTOOL_REQUEST_BY_NAME(et_pauseparam, ETHTOOL_GPAUSEPARAM);
  if (-1 != ret) {
    atomic_printf("rx_pause:%d tx_pause:%d\n",
                  et_pauseparam->rx_pause, et_pauseparam->tx_pause);
  }

  ALLOCATE_GUARD(et_sset_info, 'n');
  et_sset_info->et.sset_mask = 0xff;
  GENERIC_ETHTOOL_REQUEST_BY_NAME(&et_sset_info->et, ETHTOOL_GSSET_INFO);
  if (-1 != ret) {
    int index = 0;
    for (i = 0; i < 8; ++i) {
      if (et_sset_info->et.sset_mask & (1 << i)) {
        uint32_t len = et_sset_info->data[index++];
        size_t size = sizeof(struct ethtool_gstrings) + len*ETH_GSTRING_LEN;
        char* buf = (char*)allocate_guard(size, 'o');
        struct ethtool_gstrings* et_gstrings = (struct ethtool_gstrings*)buf;
        et_gstrings->cmd = ETHTOOL_GSTRINGS;
        et_gstrings->string_set = i;
        req->ifr_data = buf;
        ret = ioctl(sockfd, SIOCETHTOOL, req);
        VERIFY_GUARD(req);
        verify_guard(size, buf);
        err = errno;
        atomic_printf("SIOCETHTOOL(ret:%d) ETHTOOL_GSTRINGS: %s ethtool data: ", ret, req->ifr_name);
        if (-1 == ret) {
          atomic_printf("WARNING: %s doesn't appear to support SIOCETHTOOL ETHTOOL_GSTRINGS\n", req->ifr_name);
          test_assert(EOPNOTSUPP == err || EPERM == err);
        } else {
          uint32_t j;
          for (j = 0; j < len; ++j) {
            atomic_printf("Group %d string %d: %s\n",
                          i, j, buf + sizeof(struct ethtool_gstrings) + j*ETH_GSTRING_LEN);
          }
        }
      }
    }
  }

  ALLOCATE_GUARD(et_gfeatures, 'p');
  et_gfeatures->et.size = 20;
  GENERIC_ETHTOOL_REQUEST_BY_NAME(&et_gfeatures->et, ETHTOOL_GFEATURES);
  if (-1 != ret) {
    int n = et_gfeatures->et.size;
    if (n > 20) {
      n = 20;
    }
    for (i = 0; i < n; ++i) {
      atomic_printf("Feature %d available:%x requested:%x\n",
        i, et_gfeatures->features[i].available, et_gfeatures->features[i].requested);
    }
  }

  ALLOCATE_GUARD(et_perm_addr, 'q');
  et_perm_addr->et.size = sizeof(et_perm_addr->data);
  GENERIC_ETHTOOL_REQUEST_BY_NAME(&et_perm_addr->et, ETHTOOL_GPERMADDR);
  if (-1 != ret) {
    uint32_t i;
    for (i = 0; i < et_perm_addr->et.size; ++i) {
      atomic_printf("%02x ", et_perm_addr->data[i]);
    }
    atomic_printf("\n");
  }
}

int main(void) {
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  struct ifreq* req;
  struct ifreq* eth_req;
  char name[PATH_MAX];
  int index;
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
  if (ret < 0 && errno == EFAULT) {
    /* Work around https://bugzilla.kernel.org/show_bug.cgi?id=199469 */
    atomic_puts("Buggy kernel detected; aborting test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
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
  if (ret < 0 && errno == EFAULT) {
    /* Work around https://bugzilla.kernel.org/show_bug.cgi?id=202273 */
    atomic_puts("Buggy kernel detected; aborting test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  GENERIC_REQUEST_BY_NAME(SIOCGIFMETRIC);
  atomic_printf("metric is %d\n", req->ifr_metric);

  GENERIC_REQUEST_BY_NAME(SIOCGIFMAP);
  atomic_printf("map is %llu,%llu,%u,%d,%d,%d\n",
                (unsigned long long)req->ifr_map.mem_start,
                (unsigned long long)req->ifr_map.mem_end,
                req->ifr_map.base_addr, req->ifr_map.irq, req->ifr_map.dma,
                req->ifr_map.port);

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

  ethtool(sockfd, eth_req);

  GENERIC_WIRELESS_REQUEST_BY_NAME(SIOCGIWNAME,
                                   ("wireless protocol name:%s", wreq->u.name));

  GENERIC_WIRELESS_REQUEST_BY_NAME(SIOCGIWMODE,
                                   (" wireless mode:%d", wreq->u.mode));

  GENERIC_WIRELESS_PARAM_REQUEST_BY_NAME(SIOCGIWSENS, sens);

  GENERIC_WIRELESS_PARAM_REQUEST_BY_NAME(SIOCGIWRATE, bitrate);

  /* Note that we use sizeof(struct ifreq) here, not iwreq, because of
   * https://bugzilla.kernel.org/show_bug.cgi?id=195869
   */
  wreq = allocate_guard(sizeof(struct ifreq), 'e');
  strcpy(wreq->ifr_ifrn.ifrn_name, name);
  wreq->u.essid.length = sizeof(buf);
  wreq->u.essid.pointer = buf;
  wreq->u.essid.flags = 0;
  ret = ioctl(sockfd, SIOCGIWESSID, wreq);
  VERIFY_GUARD(wreq);
  err = errno;
  atomic_printf("SIOCGIWESSID(ret:%d): %s: ", ret, wreq->ifr_name);
  if (-1 == ret) {
    atomic_printf("WARNING: %s doesn't appear to be a wireless iface\n", name);
    /* "bond" network devices can return ENODEV.
       Some virtual ethernet devices return ENOTTY. */
    test_assert(EOPNOTSUPP == err || EPERM == err || EINVAL == err || ENODEV == err || ENOTTY == err);
  } else {
    atomic_printf("wireless ESSID:%s\n", buf);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
