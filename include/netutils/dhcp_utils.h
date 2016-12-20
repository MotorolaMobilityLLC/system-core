#include <errno.h>
#include <fcntl.h>

#ifdef ANDROID
#define LOG_TAG "DhcpUtils"
#include <cutils/log.h>
#else
#include <stdio.h>
#include <string.h>
#define ALOGD printf
#define ALOGE printf
#endif
								  
/*mtk_net pcscf*/
static const char DAEMON_NAME_INFORM[]  = "dhcp_inform";	
static const char DAEMON_NAME_INFORMV6[]  = "dhcpv6_inform";
/*mtk_net pcscf end*/
static char errmsgv6[100];
static char errmsgPD[100];


static const char DHCPv6_DAEMON_NAME[]        = "dhcp6c";
static const char DHCPv6DNS_DAEMON_NAME[]        = "dhcp6cDNS";
static const char DHCPv6_DAEMON_PROP_NAME[]   = "init.svc.dhcp6c";
static const char DHCPv6DNS_DAEMON_PROP_NAME[]   = "init.svc.dhcp6cDNS";
static const char DHCPv6_PROP_NAME_PREFIX[]  = "dhcp.ipv6";
static const char PD_PROP_NAME_PREFIX[] = "dhcp.pd";
static const char PD_DAEMON_NAME[] = "dhcp6c_PD";
static const char PD_DAEMON_PROP_NAME[] = "init.svc.dhcp6c_PD";
#define DHCP6C_PIDFILE "/data/misc/wide-dhcpv6/dhcp6c.pid"
