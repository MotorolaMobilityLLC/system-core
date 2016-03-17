/*
* Copyright (C) 2014 MediaTek Inc.
* Modification based on code covered by the mentioned copyright
* and/or permission notice(s).
*/
/*
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/route.h>
#include <linux/ipv6_route.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/un.h>

#include "netutils/ifc.h"

#ifdef ANDROID
#define LOG_TAG "NetUtils"
#include <cutils/log.h>
#include <cutils/properties.h>
#else
#include <stdio.h>
#include <string.h>
#define ALOGD printf
#define ALOGW printf
#endif

#ifdef HAVE_ANDROID_OS
/* SIOCKILLADDR is an Android extension. */
#define SIOCKILLADDR 0x8939
#define SIOCKILLSOCK 0x893a
#endif

static int ifc_ctl_sock = -1;
static int ifc_ctl_sock6 = -1;
void printerr(char *fmt, ...);

#define DBG 1
#define INET_ADDRLEN 4
#define INET6_ADDRLEN 16

in_addr_t prefixLengthToIpv4Netmask(int prefix_length)
{
    in_addr_t mask = 0;

    // C99 (6.5.7): shifts of 32 bits have undefined results
    if (prefix_length <= 0 || prefix_length > 32) {
        return 0;
    }

    mask = ~mask << (32 - prefix_length);
    mask = htonl(mask);

    return mask;
}

int ipv4NetmaskToPrefixLength(in_addr_t mask)
{
    int prefixLength = 0;
    uint32_t m = (uint32_t)ntohl(mask);
    while (m & 0x80000000) {
        prefixLength++;
        m = m << 1;
    }
    return prefixLength;
}

static const char *ipaddr_to_string(in_addr_t addr)
{
    struct in_addr in_addr;

    in_addr.s_addr = addr;
    return inet_ntoa(in_addr);
}

int string_to_ip(const char *string, struct sockaddr_storage *ss) {
    struct addrinfo hints, *ai;
    int ret;

    if (ss == NULL) {
        return -EFAULT;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_socktype = SOCK_DGRAM;

    ret = getaddrinfo(string, NULL, &hints, &ai);
    if (ret == 0) {
        memcpy(ss, ai->ai_addr, ai->ai_addrlen);
        freeaddrinfo(ai);
    }

    return ret;
}

int ifc_init(void)
{
    int ret;
    if (ifc_ctl_sock == -1) {
        ifc_ctl_sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (ifc_ctl_sock < 0) {
            printerr("socket() failed: %s\n", strerror(errno));
        }
    }

    ret = ifc_ctl_sock < 0 ? -1 : 0;
    if (0) printerr("ifc_init_returning %d", ret);
    return ret;
}

int ifc_init6(void)
{
    if (ifc_ctl_sock6 == -1) {
        ifc_ctl_sock6 = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (ifc_ctl_sock6 < 0) {
            printerr("socket() failed: %s\n", strerror(errno));
        }
    }
    return ifc_ctl_sock6 < 0 ? -1 : 0;
}

void ifc_close(void)
{
    if (0) printerr("ifc_close");
    if (ifc_ctl_sock != -1) {
        (void)close(ifc_ctl_sock);
        ifc_ctl_sock = -1;
    }
}

void ifc_close6(void)
{
    if (ifc_ctl_sock6 != -1) {
        (void)close(ifc_ctl_sock6);
        ifc_ctl_sock6 = -1;
    }
}

static void ifc_init_ifr(const char *name, struct ifreq *ifr)
{
    memset(ifr, 0, sizeof(struct ifreq));
    strncpy(ifr->ifr_name, name, IFNAMSIZ);
    ifr->ifr_name[IFNAMSIZ - 1] = 0;
}

int ifc_get_hwaddr(const char *name, void *ptr)
{
    int r;
    struct ifreq ifr;
    ifc_init_ifr(name, &ifr);

    r = ioctl(ifc_ctl_sock, SIOCGIFHWADDR, &ifr);
    if(r < 0) return -1;

    memcpy(ptr, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    return 0;
}

int ifc_get_ifindex(const char *name, int *if_indexp)
{
    int r;
    struct ifreq ifr;
    ifc_init_ifr(name, &ifr);

    r = ioctl(ifc_ctl_sock, SIOCGIFINDEX, &ifr);
    if(r < 0) return -1;

    *if_indexp = ifr.ifr_ifindex;
    return 0;
}

static int ifc_set_flags(const char *name, unsigned set, unsigned clr)
{
    struct ifreq ifr;
    ifc_init_ifr(name, &ifr);

    if(ioctl(ifc_ctl_sock, SIOCGIFFLAGS, &ifr) < 0) return -1;
    ifr.ifr_flags = (ifr.ifr_flags & (~clr)) | set;
    return ioctl(ifc_ctl_sock, SIOCSIFFLAGS, &ifr);
}

int ifc_up(const char *name)
{
    int ret = ifc_set_flags(name, IFF_UP, 0);
    if (DBG) printerr("ifc_up(%s) = %d", name, ret);
    return ret;
}

int ifc_down(const char *name)
{
    int ret = ifc_set_flags(name, 0, IFF_UP);
    if (DBG) printerr("ifc_down(%s) = %d", name, ret);
    return ret;
}

static void init_sockaddr_in(struct sockaddr *sa, in_addr_t addr)
{
    struct sockaddr_in *sin = (struct sockaddr_in *) sa;
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    sin->sin_addr.s_addr = addr;
}

int ifc_set_addr(const char *name, in_addr_t addr)
{
    struct ifreq ifr;
    int ret;

    ifc_init_ifr(name, &ifr);
    init_sockaddr_in(&ifr.ifr_addr, addr);

    ret = ioctl(ifc_ctl_sock, SIOCSIFADDR, &ifr);
    if (DBG) printerr("ifc_set_addr(%s, xx) = %d", name, ret);
    return ret;
}

/*
 * Adds or deletes an IP address on an interface.
 *
 * Action is one of:
 * - RTM_NEWADDR (to add a new address)
 * - RTM_DELADDR (to delete an existing address)
 *
 * Returns zero on success and negative errno on failure.
 */
int ifc_act_on_address(int action, const char *name, const char *address,
                       int prefixlen) {
    int ifindex, s, len, ret;
    struct sockaddr_storage ss;
    void *addr;
    size_t addrlen;
    struct {
        struct nlmsghdr n;
        struct ifaddrmsg r;
        // Allow for IPv6 address, headers, and padding.
        char attrbuf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
                     NLMSG_ALIGN(sizeof(struct rtattr)) +
                     NLMSG_ALIGN(INET6_ADDRLEN)];
    } req;
    struct rtattr *rta;
    struct nlmsghdr *nh;
    struct nlmsgerr *err;
    char buf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
             NLMSG_ALIGN(sizeof(struct nlmsgerr)) +
             NLMSG_ALIGN(sizeof(struct nlmsghdr))];

    // Get interface ID.
    ifindex = if_nametoindex(name);
    if (ifindex == 0) {
        return -errno;
    }

    // Convert string representation to sockaddr_storage.
    ret = string_to_ip(address, &ss);
    if (ret) {
        return ret;
    }

    // Determine address type and length.
    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
        addr = &sin->sin_addr;
        addrlen = INET_ADDRLEN;
    } else if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &ss;
        addr = &sin6->sin6_addr;
        addrlen = INET6_ADDRLEN;
    } else {
        return -EAFNOSUPPORT;
    }

    // Fill in netlink structures.
    memset(&req, 0, sizeof(req));

    // Netlink message header.
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.r));
    req.n.nlmsg_type = action;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_pid = getpid();

    // Interface address message header.
    req.r.ifa_family = ss.ss_family;
    req.r.ifa_prefixlen = prefixlen;
    req.r.ifa_index = ifindex;

    // Routing attribute. Contains the actual IP address.
    rta = (struct rtattr *) (((char *) &req) + NLMSG_ALIGN(req.n.nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = RTA_LENGTH(addrlen);
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_LENGTH(addrlen);
    memcpy(RTA_DATA(rta), addr, addrlen);

    s = socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (send(s, &req, req.n.nlmsg_len, 0) < 0) {
        close(s);
        return -errno;
    }

    len = recv(s, buf, sizeof(buf), 0);
    close(s);
    if (len < 0) {
        return -errno;
    }

    // Parse the acknowledgement to find the return code.
    nh = (struct nlmsghdr *) buf;
    if (!NLMSG_OK(nh, (unsigned) len) || nh->nlmsg_type != NLMSG_ERROR) {
        return -EINVAL;
    }
    err = NLMSG_DATA(nh);

    // Return code is negative errno.
    return err->error;
}

int ifc_add_address(const char *name, const char *address, int prefixlen) {
    return ifc_act_on_address(RTM_NEWADDR, name, address, prefixlen);
}

int ifc_del_address(const char *name, const char * address, int prefixlen) {
    return ifc_act_on_address(RTM_DELADDR, name, address, prefixlen);
}

/*
 * Clears IPv6 addresses on the specified interface.
 */
int ifc_clear_ipv6_addresses(const char *name) {
    char rawaddrstr[INET6_ADDRSTRLEN], addrstr[INET6_ADDRSTRLEN];
    unsigned int prefixlen;
    int lasterror = 0, i, j, ret;
    char ifname[64];  // Currently, IFNAMSIZ = 16.
    FILE *f = fopen("/proc/net/if_inet6", "r");
    if (!f) {
        return -errno;
    }

    // Format:
    // 20010db8000a0001fc446aa4b5b347ed 03 40 00 01    wlan0
    while (fscanf(f, "%32s %*02x %02x %*02x %*02x %63s\n",
                  rawaddrstr, &prefixlen, ifname) == 3) {
        // Is this the interface we're looking for?
        if (strcmp(name, ifname)) {
            continue;
        }

        // Put the colons back into the address.
        for (i = 0, j = 0; i < 32; i++, j++) {
            addrstr[j] = rawaddrstr[i];
            if (i % 4 == 3) {
                addrstr[++j] = ':';
            }
        }
        addrstr[j - 1] = '\0';

        // Don't delete the link-local address as well, or it will disable IPv6
        // on the interface.
        if (strncmp(addrstr, "fe80:", 5) == 0) {
            continue;
        }

        ret = ifc_del_address(ifname, addrstr, prefixlen);
        if (ret) {
            ALOGE("Deleting address %s/%d on %s: %s", addrstr, prefixlen, ifname,
                 strerror(-ret));
            lasterror = ret;
        }
    }

    fclose(f);
    ALOGD("ifc_clear_ipv6_addresses return %d", lasterror);
    return lasterror;
}

/*
 * Clears IPv4 addresses on the specified interface.
 */
void ifc_clear_ipv4_addresses(const char *name) {
    unsigned count, addr;
    ifc_init();
    for (count=0, addr=1;((addr != 0) && (count < 255)); count++) {
        if (ifc_get_addr(name, &addr) < 0)
            break;
        if (addr)
            ifc_set_addr(name, 0);
    }
    ifc_close();
    ALOGD("ifc_clear_ipv4_addresses return");
}

/*
 * Clears all IP addresses on the specified interface.
 */
int ifc_clear_addresses(const char *name) {
    ifc_clear_ipv4_addresses(name);
    return ifc_clear_ipv6_addresses(name);
}

int ifc_set_hwaddr(const char *name, const void *ptr)
{
    struct ifreq ifr;
    ifc_init_ifr(name, &ifr);

    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(&ifr.ifr_hwaddr.sa_data, ptr, ETH_ALEN);
    return ioctl(ifc_ctl_sock, SIOCSIFHWADDR, &ifr);
}

int ifc_set_mask(const char *name, in_addr_t mask)
{
    struct ifreq ifr;
    int ret;

    ifc_init_ifr(name, &ifr);
    init_sockaddr_in(&ifr.ifr_addr, mask);

    ret = ioctl(ifc_ctl_sock, SIOCSIFNETMASK, &ifr);
    if (DBG) printerr("ifc_set_mask(%s, xx) = %d", name, ret);
    return ret;
}

int ifc_set_prefixLength(const char *name, int prefixLength)
{
    struct ifreq ifr;
    // TODO - support ipv6
    if (prefixLength > 32 || prefixLength < 0) return -1;

    in_addr_t mask = prefixLengthToIpv4Netmask(prefixLength);
    ifc_init_ifr(name, &ifr);
    init_sockaddr_in(&ifr.ifr_addr, mask);

    return ioctl(ifc_ctl_sock, SIOCSIFNETMASK, &ifr);
}

int ifc_get_addr(const char *name, in_addr_t *addr)
{
    struct ifreq ifr;
    int ret = 0;

    ifc_init_ifr(name, &ifr);
    if (addr != NULL) {
        ret = ioctl(ifc_ctl_sock, SIOCGIFADDR, &ifr);
        if (ret < 0) {
            *addr = 0;
        } else {
            *addr = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
        }
    }
    return ret;
}

int ifc_get_info(const char *name, in_addr_t *addr, int *prefixLength, unsigned *flags)
{
    struct ifreq ifr;
    ifc_init_ifr(name, &ifr);

    if (addr != NULL) {
        if(ioctl(ifc_ctl_sock, SIOCGIFADDR, &ifr) < 0) {
            *addr = 0;
        } else {
            *addr = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
        }
    }

    if (prefixLength != NULL) {
        if(ioctl(ifc_ctl_sock, SIOCGIFNETMASK, &ifr) < 0) {
            *prefixLength = 0;
        } else {
            *prefixLength = ipv4NetmaskToPrefixLength(
                    ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr);
        }
    }

    if (flags != NULL) {
        if(ioctl(ifc_ctl_sock, SIOCGIFFLAGS, &ifr) < 0) {
            *flags = 0;
        } else {
            *flags = ifr.ifr_flags;
        }
    }

    return 0;
}

int ifc_act_on_ipv4_route(int action, const char *ifname, struct in_addr dst, int prefix_length,
      struct in_addr gw)
{
    struct rtentry rt;
    int result;
    in_addr_t netmask;

    memset(&rt, 0, sizeof(rt));

    rt.rt_dst.sa_family = AF_INET;
    rt.rt_dev = (void*) ifname;

    netmask = prefixLengthToIpv4Netmask(prefix_length);
    init_sockaddr_in(&rt.rt_genmask, netmask);
    init_sockaddr_in(&rt.rt_dst, dst.s_addr);
    rt.rt_flags = RTF_UP;

    if (prefix_length == 32) {
        rt.rt_flags |= RTF_HOST;
    }

    if (gw.s_addr != 0) {
        rt.rt_flags |= RTF_GATEWAY;
        init_sockaddr_in(&rt.rt_gateway, gw.s_addr);
    }

    ifc_init();

    if (ifc_ctl_sock < 0) {
        return -errno;
    }

    result = ioctl(ifc_ctl_sock, action, &rt);
    if (result < 0) {
        if (errno == EEXIST) {
            result = 0;
        } else {
            result = -errno;
        }
    }
    ifc_close();
    return result;
}

/* deprecated - v4 only */
int ifc_create_default_route(const char *name, in_addr_t gw)
{
    struct in_addr in_dst, in_gw;

    in_dst.s_addr = 0;
    in_gw.s_addr = gw;

    int ret = ifc_act_on_ipv4_route(SIOCADDRT, name, in_dst, 0, in_gw);
    if (DBG) printerr("ifc_create_default_route(%s, %d) = %d", name, gw, ret);
    return ret;
}

// Needed by code in hidden partner repositories / branches, so don't delete.
int ifc_enable(const char *ifname)
{
    int result;

    ifc_init();
    result = ifc_up(ifname);
    ifc_close();
    return result;
}

// Needed by code in hidden partner repositories / branches, so don't delete.
int ifc_disable(const char *ifname)
{
    unsigned addr, count;
    int result;

    ifc_init();
    result = ifc_down(ifname);

    ifc_set_addr(ifname, 0);
    for (count=0, addr=1;((addr != 0) && (count < 255)); count++) {
       if (ifc_get_addr(ifname, &addr) < 0)
            break;
       if (addr)
          ifc_set_addr(ifname, 0);
    }

    ifc_close();
    return result;
}

int ifc_reset_connections(const char *ifname, const int reset_mask)
{
#ifdef HAVE_ANDROID_OS
    int result, success;
    in_addr_t myaddr = 0;
    struct ifreq ifr;
    struct in6_ifreq ifr6;

    if (reset_mask & RESET_IPV4_ADDRESSES) {
        /* IPv4. Clear connections on the IP address. */
        ifc_init();
        if (!(reset_mask & RESET_IGNORE_INTERFACE_ADDRESS)) {
            ifc_get_info(ifname, &myaddr, NULL, NULL);
        }
        ifc_init_ifr(ifname, &ifr);
        init_sockaddr_in(&ifr.ifr_addr, myaddr);
        result = ioctl(ifc_ctl_sock, SIOCKILLADDR,  &ifr);
        ifc_close();
    } else {
        result = 0;
    }

    if (reset_mask & RESET_IPV6_ADDRESSES) {
        /*
         * IPv6. On Linux, when an interface goes down it loses all its IPv6
         * addresses, so we don't know which connections belonged to that interface
         * So we clear all unused IPv6 connections on the device by specifying an
         * empty IPv6 address.
         */
        ifc_init6();
        // This implicitly specifies an address of ::, i.e., kill all IPv6 sockets.
        memset(&ifr6, 0, sizeof(ifr6));
        success = ioctl(ifc_ctl_sock6, SIOCKILLADDR,  &ifr6);
        if (result == 0) {
            result = success;
        }
        ifc_close6();
    }

    return result;
#else
    return 0;
#endif
}

/*
 * Removes the default route for the named interface.
 */
int ifc_remove_default_route(const char *ifname)
{
    struct rtentry rt;
    int result;

    ifc_init();
    memset(&rt, 0, sizeof(rt));
    rt.rt_dev = (void *)ifname;
    rt.rt_flags = RTF_UP|RTF_GATEWAY;
    init_sockaddr_in(&rt.rt_dst, 0);
    if ((result = ioctl(ifc_ctl_sock, SIOCDELRT, &rt)) < 0) {
        ALOGD("failed to remove default route for %s: %s", ifname, strerror(errno));
    }
    ifc_close();
    return result;
}

int
ifc_configure(const char *ifname,
        in_addr_t address,
        uint32_t prefixLength,
        in_addr_t gateway,
        in_addr_t dns1,
        in_addr_t dns2) {

    char dns_prop_name[PROPERTY_KEY_MAX];

    ifc_init();

    if (ifc_up(ifname)) {
        printerr("failed to turn on interface %s: %s\n", ifname, strerror(errno));
        ifc_close();
        return -1;
    }
    if (ifc_set_addr(ifname, address)) {
        printerr("failed to set ipaddr %s: %s\n", ipaddr_to_string(address), strerror(errno));
        ifc_close();
        return -1;
    }
    if (ifc_set_prefixLength(ifname, prefixLength)) {
        printerr("failed to set prefixLength %d: %s\n", prefixLength, strerror(errno));
        ifc_close();
        return -1;
    }
    if (ifc_create_default_route(ifname, gateway)) {
        printerr("failed to set default route %s: %s\n", ipaddr_to_string(gateway), strerror(errno));
        ifc_close();
        return -1;
    }

    ifc_close();

    snprintf(dns_prop_name, sizeof(dns_prop_name), "net.%s.dns1", ifname);
    property_set(dns_prop_name, dns1 ? ipaddr_to_string(dns1) : "");
    snprintf(dns_prop_name, sizeof(dns_prop_name), "net.%s.dns2", ifname);
    property_set(dns_prop_name, dns2 ? ipaddr_to_string(dns2) : "");

    return 0;
}

int ifc_reset_connection_by_uid(int uid, int error)
{
#ifdef HAVE_ANDROID_OS

    int tcp_ctl_sock;
    int result = -1;
    struct uid_err uid_e;

	uid_e.appuid = uid;
	uid_e.errorNum = error;

    tcp_ctl_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_ctl_sock < 0) {
        printerr("socket() failed: %s\n", strerror(errno));
        return -1;
    }

    if(uid_e.appuid < 0){
        ALOGE("ifc_reset_connection_by_uid, invalide uid: %d", uid_e.appuid);
        close(tcp_ctl_sock);
        return -1;
    }

    ALOGD("ifc_reset_connection_by_uid, appuid = %d, error = %d ",
		      uid_e.appuid, uid_e.errorNum);
    result = ioctl(tcp_ctl_sock, SIOCKILLSOCK, &uid_e);
    if(result < 0)
        ALOGE("ifc_reset_connection_by_uid, result= %d, error =%s ", result, strerror(errno));

        close(tcp_ctl_sock);
    ALOGD("ifc_reset_connection_by_uid, result= %d ",result);
    return result;
#else
    return 0;
#endif
}

int ifc_enable_allmc(const char *ifname)
{
	int result;

	ifc_init();
	result = ifc_set_flags(ifname, IFF_ALLMULTI, 0);
	ifc_close();

	ALOGD("ifc_enable_allmc(%s) = %d", ifname, result);
	return result;
}

int ifc_disable_allmc(const char *ifname)
{
	int result;

	ifc_init();
	result = ifc_set_flags(ifname, 0, IFF_ALLMULTI);
	ifc_close();

	ALOGD("ifc_disable_allmc(%s) = %d", ifname, result);
	return result;
}
int ifc_is_up(const char *name, unsigned *isup)
{
    struct ifreq ifr;
    ifc_init_ifr(name, &ifr);

    if(ioctl(ifc_ctl_sock, SIOCGIFFLAGS, &ifr) < 0) {
        printerr("ifc_is_up get flags error:%d(%s)", errno, strerror(errno));
        return -1;
    }
    if(ifr.ifr_flags & IFF_UP)
        *isup = 1;
    else
        *isup = 0;

    return 0;
}

static int ifc_netd_sock_init(void)
{
    int ifc_netd_sock;
    const int one = 1;
    struct sockaddr_un netd_addr;
    int res = 0;

        ifc_netd_sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (ifc_netd_sock < 0) {
            printerr("ifc_netd_sock_init: create socket failed");
            return -1;
        }

        res = setsockopt(ifc_netd_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (res < 0) {
           printerr("setsockopt failed\n");
           close(ifc_netd_sock);
           return -1;
        }
        memset(&netd_addr, 0, sizeof(netd_addr));
        netd_addr.sun_family = AF_UNIX;
        strlcpy(netd_addr.sun_path, "/dev/socket/netd",
            sizeof(netd_addr.sun_path));
        if (TEMP_FAILURE_RETRY(connect(ifc_netd_sock,
                     (const struct sockaddr*) &netd_addr,
                     sizeof(netd_addr))) != 0) {
            printerr("ifc_netd_sock_init: connect to netd failed, fd=%d, err: %d(%s)",
                ifc_netd_sock, errno, strerror(errno));
            close(ifc_netd_sock);
            return -1;
        }

    if (DBG) printerr("ifc_netd_sock_init fd=%d", ifc_netd_sock);
    return ifc_netd_sock;
}

/*do not call this function in netd*/
int ifc_set_throttle(const char *ifname, int rxKbps, int txKbps)
{
    FILE* fnetd = NULL;
    int ret = -1;
    int seq = 1;
    char rcv_buf[24];
	int nread = 0;
	int netd_sock = 0;

    ALOGD("enter ifc_set_throttle: ifname = %s, rx = %d kbs, tx = %d kbs", ifname, rxKbps, txKbps);

    netd_sock = ifc_netd_sock_init();
    if(netd_sock <= 0)
        goto exit;

    // Send the request.
    fnetd = fdopen(netd_sock, "r+");
	if(fnetd == NULL){
		ALOGE("open netd socket failed, err:%d(%s)", errno, strerror(errno));
		goto exit;
	}
    if (fprintf(fnetd, "%d interface setthrottle %s %d %d", seq, ifname, rxKbps, txKbps) < 0) {
        goto exit;
    }
    // literal NULL byte at end, required by FrameworkListener
    if (fputc(0, fnetd) == EOF ||
        fflush(fnetd) != 0) {
        goto exit;
    }
    ret = 0;

	//Todo: read the whole response from netd
	nread = fread(rcv_buf, 1, 20, fnetd);
	rcv_buf[23] = 0;
	ALOGD("response: %s", rcv_buf);
exit:
    if (fnetd != NULL) {
        fclose(fnetd);
    }
    return ret;
}

/*do not call this function in netd*/
int ifc_set_fwmark_rule(const char *ifname, int mark, int add)
{
    FILE* fnetd = NULL;
    int ret = -1;
    int seq = 2;
    char rcv_buf[24];
	  int nread = 0;
	  const char* op;
    int netd_sock = 0;

    if (add) {
        op = "add";
    } else {
        op = "remove";
    }
    ALOGD("enter ifc_set_fwmark_rule: ifname = %s, mark = %d, op = %s", ifname, mark, op);

    netd_sock = ifc_netd_sock_init();
    if(netd_sock <= 0)
        goto exit;

    // Send the request.
    fnetd = fdopen(netd_sock, "r+");
	if(fnetd == NULL){
		ALOGE("open netd socket failed, err:%d(%s)", errno, strerror(errno));
		goto exit;
	}
    if (fprintf(fnetd, "%d network fwmark %s %s %d", seq, op, ifname, mark) < 0) {
        goto exit;
    }
    // literal NULL byte at end, required by FrameworkListener
    if (fputc(0, fnetd) == EOF ||
        fflush(fnetd) != 0) {
        goto exit;
    }
    ret = 0;

	//Todo: read the whole response from netd
	nread = fread(rcv_buf, 1, 20, fnetd);
	rcv_buf[23] = 0;
	ALOGD("ifc_set_fwmark_rule response: %s", rcv_buf);
exit:
    if (fnetd != NULL) {
        fclose(fnetd);
    }
    return ret;
}

#define SIOCSTXQSTATE (SIOCDEVPRIVATE + 0)  //start/stop ccmni tx queue
#define SIOCSCCMNICFG (SIOCDEVPRIVATE + 1)  //configure ccmni/md remapping

int ifc_set_txq_state(const char *ifname, int state)
{
    struct ifreq ifr;
    int ret, ctl_sock;

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;
    ifr.ifr_ifru.ifru_ivalue = state;

    ctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(ctl_sock < 0){
    	ALOGE("create ctl socket failed\n");
    	return -1;
    }
    ret = ioctl(ctl_sock, SIOCSTXQSTATE, &ifr);
    if(ret < 0)
    	ALOGE("ifc_set_txq_state failed, err:%d(%s)\n", errno, strerror(errno));
    else
    	ALOGI("ifc_set_txq_state as %d, ret: %d\n", state, ret);

    close(ctl_sock);

    return ret;
}

int ifc_ccmni_md_cfg(const char *ifname, int md_id)
{
    struct ifreq ifr;
    int ret = 0;
    int ctl_sock = 0;

    ifc_init_ifr(ifname, &ifr);
    ifr.ifr_ifru.ifru_ivalue = md_id;

    ctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(ctl_sock < 0){
    	printerr("ifc_ccmni_md_cfg: create ctl socket failed\n");
    	return -1;
    }

    if(ioctl(ctl_sock, SIOCSCCMNICFG, &ifr) < 0) {
    	printerr("ifc_ccmni_md_configure(ifname=%s, md_id=%d) error:%d(%s)", \
        	ifname, md_id, errno, strerror(errno));
    	ret = -1;
    } else {
    	printerr("ifc_ccmni_md_configure(ifname=%s, md_id=%d) OK", ifname, md_id);
    }

    close(ctl_sock);
    return ret;
}
