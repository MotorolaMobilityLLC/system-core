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

/* Utilities for managing the dhcpcd DHCP client daemon */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <cutils/properties.h>

static const char DAEMON_NAME[]        = "dhcpcd";
static const char DAEMON_PROP_NAME[]   = "init.svc.dhcpcd";
static const char HOSTNAME_PROP_NAME[] = "net.hostname";
static const char DHCP_PROP_NAME_PREFIX[]  = "dhcp";
static const char DHCP_CONFIG_PATH[]   = "/system/etc/dhcpcd/dhcpcd.conf";
static const int NAP_TIME = 200;   /* wait for 200ms at a time */
                                  /* when polling for property values */
static const char DAEMON_NAME_RENEW[]  = "iprenew";
static char errmsg[100] = "\0";
//BEGIN MOT JB UPMERGE, w20079, Aug 10, 2012
static int autoip_enabled[2] = {0, 0};//WiFi, Bluetooth
//END MOT JB UPMERGE
/* interface length for dhcpcd daemon start (dhcpcd_<interface> as defined in init.rc file)
 * or for filling up system properties dhcpcd.<interface>.ipaddress, dhcpcd.<interface>.dns1
 * and other properties on a successful bind
 */
#define MAX_INTERFACE_LENGTH 25

/*
 * P2p interface names increase sequentially p2p-p2p0-1, p2p-p2p0-2.. after
 * group formation. This does not work well with system properties which can quickly
 * exhaust or for specifiying a dhcp start target in init which requires
 * interface to be pre-defined in init.rc file.
 *
 * This function returns a common string p2p for all p2p interfaces.
 */
void get_p2p_interface_replacement(const char *interface, char *p2p_interface) {
    /* Use p2p for any interface starting with p2p. */
    if (strncmp(interface, "p2p",3) == 0) {
        strncpy(p2p_interface, "p2p", MAX_INTERFACE_LENGTH);
    } else {
        strncpy(p2p_interface, interface, MAX_INTERFACE_LENGTH);
    }
}

/*
 * Wait for a system property to be assigned a specified value.
 * If desired_value is NULL, then just wait for the property to
 * be created with any value. maxwait is the maximum amount of
 * time in seconds to wait before giving up.
 */
static int wait_for_property(const char *name, const char *desired_value, int maxwait)
{
    char value[PROPERTY_VALUE_MAX] = {'\0'};
    int maxnaps = (maxwait * 1000) / NAP_TIME;

    if (maxnaps < 1) {
        maxnaps = 1;
    }

    while (maxnaps-- >= 0) {
        if (property_get(name, value, NULL)) {
            if (desired_value == NULL ||
                    strcmp(value, desired_value) == 0) {
                return 0;
            }
        }
        if (maxnaps >= 0) {
            usleep(NAP_TIME * 1000);
        }
    }
    return -1; /* failure */
}

static int fill_ip_info(const char *interface,
                     char *ipaddr,
                     char *gateway,
                     uint32_t *prefixLength,
                     char *dns[],
                     char *server,
                     uint32_t *lease,
                     char *vendorInfo,
                     char *domain,
                     char *mtu)
{
    char prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX];
    /* Interface name after converting p2p0-p2p0-X to p2p to reuse system properties */
    char p2p_interface[MAX_INTERFACE_LENGTH];
    int x;

    get_p2p_interface_replacement(interface, p2p_interface);

    snprintf(prop_name, sizeof(prop_name), "%s.%s.ipaddress", DHCP_PROP_NAME_PREFIX, p2p_interface);
    property_get(prop_name, ipaddr, NULL);

    snprintf(prop_name, sizeof(prop_name), "%s.%s.gateway", DHCP_PROP_NAME_PREFIX, p2p_interface);
    property_get(prop_name, gateway, NULL);

    snprintf(prop_name, sizeof(prop_name), "%s.%s.server", DHCP_PROP_NAME_PREFIX, p2p_interface);
    property_get(prop_name, server, NULL);

    //TODO: Handle IPv6 when we change system property usage
    if (gateway[0] == '\0' || strncmp(gateway, "0.0.0.0", 7) == 0) {
        //DHCP server is our best bet as gateway
        strncpy(gateway, server, PROPERTY_VALUE_MAX);
    }

    snprintf(prop_name, sizeof(prop_name), "%s.%s.mask", DHCP_PROP_NAME_PREFIX, p2p_interface);
    if (property_get(prop_name, prop_value, NULL)) {
        int p;
        // this conversion is v4 only, but this dhcp client is v4 only anyway
        in_addr_t mask = ntohl(inet_addr(prop_value));
        // Check netmask is a valid IP address.  ntohl gives NONE response (all 1's) for
        // non 255.255.255.255 inputs.  if we get that value check if it is legit..
        if (mask == INADDR_NONE && strcmp(prop_value, "255.255.255.255") != 0) {
            snprintf(errmsg, sizeof(errmsg), "DHCP gave invalid net mask %s", prop_value);
            return -1;
        }
        for (p = 0; p < 32; p++) {
            if (mask == 0) break;
            // check for non-contiguous netmask, e.g., 255.254.255.0
            if ((mask & 0x80000000) == 0) {
                snprintf(errmsg, sizeof(errmsg), "DHCP gave invalid net mask %s", prop_value);
                return -1;
            }
            mask = mask << 1;
        }
        *prefixLength = p;
    //BEGIN MOT JB UPMERGE, w20079, Aug 10, 2012
    //Begin Motorola w20079 IKTABLETMAIN-3679 Force close on wifi browser test
    } else {
        *prefixLength = 0;
    //END MOT JB UPMERGE
    }

    for (x=0; dns[x] != NULL; x++) {
        snprintf(prop_name, sizeof(prop_name), "%s.%s.dns%d", DHCP_PROP_NAME_PREFIX, p2p_interface, x+1);
        property_get(prop_name, dns[x], NULL);
    }

    snprintf(prop_name, sizeof(prop_name), "%s.%s.leasetime", DHCP_PROP_NAME_PREFIX, p2p_interface);
    if (property_get(prop_name, prop_value, NULL)) {
        *lease = atol(prop_value);
    }

    snprintf(prop_name, sizeof(prop_name), "%s.%s.vendorInfo", DHCP_PROP_NAME_PREFIX,
            p2p_interface);
    property_get(prop_name, vendorInfo, NULL);

    snprintf(prop_name, sizeof(prop_name), "%s.%s.domain", DHCP_PROP_NAME_PREFIX,
            p2p_interface);
    property_get(prop_name, domain, NULL);

    snprintf(prop_name, sizeof(prop_name), "%s.%s.mtu", DHCP_PROP_NAME_PREFIX,
            p2p_interface);
    property_get(prop_name, mtu, NULL);

    return 0;
}

// BEGIN MOT JB UPMERGE, w20079, Aug 10, 2012
// BEGIN MOT, w20079, Jan-15-2010, IKMAPFOUR-28 / Changed for auto ip feature
static int get_device_type(const char * interface)
{
    //tiwlan0, eth0 and wlan0 means WiFi
    //p2p means WiFi Direct
    // BEGIN MOTOROLA IKJBREL1-2078, dpn473, 08/16/2012, add p2p interface to support WiFi Direct
    if( strcmp(interface, "tiwlan0") == 0 || strcmp(interface, "eth0") == 0  ||
            strcmp(interface, "wlan0") == 0 || strncmp(interface, "p2p", 3) == 0) {
        return 0;
    } else if( strcmp(interface, "bnep0") == 0 ) {
        return 1;
    } else {
        //unknow type
        return -1;
    }
    // END IKJBREL1-2078
}
//END MOT JB UPMERGE

/*
 * Get any available DHCP results.
 */
int dhcp_get_results(const char *interface,
                     char *ipaddr,
                     char *gateway,
                     uint32_t *prefixLength,
                     char *dns[],
                     char *server,
                     uint32_t *lease,
                     char *vendorInfo,
                     char *domain,
                     char *mtu)
{
    char result_prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX];

    /* Interface name after converting p2p0-p2p0-X to p2p to reuse system properties */
    char p2p_interface[MAX_INTERFACE_LENGTH];
    get_p2p_interface_replacement(interface, p2p_interface);
    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_PREFIX,
            p2p_interface);

    memset(prop_value, '\0', PROPERTY_VALUE_MAX);
    if (!property_get(result_prop_name, prop_value, NULL)) {
        snprintf(errmsg, sizeof(errmsg), "%s", "DHCP result property was not set");
        return -1;
    }
    //BEGIN MOT w20079, Aug 10, 2012
    //Changed for auto ip feature
    if (strcmp(prop_value, "ok") == 0 || strcmp(prop_value, "limited") == 0) {
    //END MOT
        if (fill_ip_info(interface, ipaddr, gateway, prefixLength, dns,
                server, lease, vendorInfo, domain, mtu) == -1) {
            return -1;
        }
        return 0;
    } else {
        snprintf(errmsg, sizeof(errmsg), "DHCP result was %s", prop_value);
        return -1;
    }
}

/*
 * Start the dhcp client daemon, and wait for it to finish
 * configuring the interface.
 *
 * The device init.rc file needs a corresponding entry for this work.
 *
 * Example:
 * service dhcpcd_<interface> /system/bin/dhcpcd -ABKL -f dhcpcd.conf
 */
int dhcp_start(const char *interface)
{
    char result_prop_name[PROPERTY_KEY_MAX];
    char daemon_prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX] = {'\0'};
    char daemon_cmd[PROPERTY_VALUE_MAX * 2 + sizeof(DHCP_CONFIG_PATH)];
    const char *ctrl_prop = "ctl.start";
    const char *desired_status = "running";
    /* Interface name after converting p2p0-p2p0-X to p2p to reuse system properties */
    char p2p_interface[MAX_INTERFACE_LENGTH];

    get_p2p_interface_replacement(interface, p2p_interface);

    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_PREFIX,
            p2p_interface);

    snprintf(daemon_prop_name, sizeof(daemon_prop_name), "%s_%s",
            DAEMON_PROP_NAME,
            p2p_interface);

    /* Erase any previous setting of the dhcp result property */
    property_set(result_prop_name, "");

    // BEGIN MOT JB UPMERGE, w20079, Aug 10, 2012
    // Changed for auto ip feature
    int wait_time = 30;
    char * dhcp_param = "-ABKL";
    int wifiorbt = get_device_type(interface);
    if( wifiorbt >= 0 && autoip_enabled[wifiorbt] ) {
        wait_time = 90;
        dhcp_param = "-BK";
    }
    //END MOT JB UPMERGE

    /* Start the daemon and wait until it's ready */
    if (property_get(HOSTNAME_PROP_NAME, prop_value, NULL) && (prop_value[0] != '\0'))
        snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s:-f %s -h %s %s %s", DAEMON_NAME,
                 p2p_interface, DHCP_CONFIG_PATH, prop_value, dhcp_param, interface);
    else
        snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s:-f %s %s %s", DAEMON_NAME,
                 p2p_interface, DHCP_CONFIG_PATH, dhcp_param, interface);
    memset(prop_value, '\0', PROPERTY_VALUE_MAX);
    property_set(ctrl_prop, daemon_cmd);
    if (wait_for_property(daemon_prop_name, desired_status, 10) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for dhcpcd to start");
        return -1;
    }

    /* Wait for the daemon to return a result */
    if (wait_for_property(result_prop_name, NULL, wait_time) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for DHCP to finish");
        return -1;
    }

    return 0;
}

/**
 * Stop the DHCP client daemon.
 */
int dhcp_stop(const char *interface)
{
    char result_prop_name[PROPERTY_KEY_MAX];
    char daemon_prop_name[PROPERTY_KEY_MAX];
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    const char *ctrl_prop = "ctl.stop";
    const char *desired_status = "stopped";

    char p2p_interface[MAX_INTERFACE_LENGTH];

    get_p2p_interface_replacement(interface, p2p_interface);

    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_PREFIX,
            p2p_interface);

    snprintf(daemon_prop_name, sizeof(daemon_prop_name), "%s_%s",
            DAEMON_PROP_NAME,
            p2p_interface);

    snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s", DAEMON_NAME, p2p_interface);

    /* Stop the daemon and wait until it's reported to be stopped */
    property_set(ctrl_prop, daemon_cmd);
    if (wait_for_property(daemon_prop_name, desired_status, 5) < 0) {
        return -1;
    }
    property_set(result_prop_name, "failed");
    return 0;
}

/**
 * Release the current DHCP client lease.
 */
int dhcp_release_lease(const char *interface)
{
    char daemon_prop_name[PROPERTY_KEY_MAX];
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    const char *ctrl_prop = "ctl.stop";
    const char *desired_status = "stopped";

    char p2p_interface[MAX_INTERFACE_LENGTH];

    get_p2p_interface_replacement(interface, p2p_interface);

    snprintf(daemon_prop_name, sizeof(daemon_prop_name), "%s_%s",
            DAEMON_PROP_NAME,
            p2p_interface);

    snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s", DAEMON_NAME, p2p_interface);

    /* Stop the daemon and wait until it's reported to be stopped */
    property_set(ctrl_prop, daemon_cmd);
    if (wait_for_property(daemon_prop_name, desired_status, 5) < 0) {
        return -1;
    }
    return 0;
}

char *dhcp_get_errmsg() {
    return errmsg;
}

// BEGIN MOT JB UPMERGE, w20079, Aug 10, 2012
int dhcp_get_state(const char *interface,
                    in_addr_t *ipaddr,
                    in_addr_t *gateway,
                    in_addr_t *mask,
                    in_addr_t *dns1,
                    in_addr_t *dns2,
                    in_addr_t *server,
                    uint32_t  *lease) {
    int result=0;
    char result_prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX] = "null";

    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_PREFIX,
            interface);

    // Changed for auto ip feature
    int wifiorbt = get_device_type(interface);
    if( wifiorbt < 0 ) {
        *ipaddr=0;
        *gateway=0;
        *mask=0;
        *dns1=0;
        *dns2=0;
        *server=0;
        return 0;
    }

    if (!property_get(result_prop_name, prop_value, NULL)) {
        /* shouldn't ever happen, given the success of wait_for_property() */
        snprintf(errmsg, sizeof(errmsg), "%s", "dhcp_get_state:DHCP result property was not set");
    }

    if (strcmp(prop_value, "ok") == 0)
        result=1;
    else if (strcmp(prop_value, "limited") == 0)
        result=2;

    if (result) {
        char pv_ipaddr[PROPERTY_VALUE_MAX];
        char pv_gateway[PROPERTY_VALUE_MAX];
        char pv_dns1[PROPERTY_VALUE_MAX];
        char pv_dns2[PROPERTY_VALUE_MAX];
        char pv_server[PROPERTY_VALUE_MAX];
        char prop_name[PROPERTY_KEY_MAX];
        char prop_value[PROPERTY_VALUE_MAX];
        char prop_vendorInfo[PROPERTY_VALUE_MAX];
        uint32_t prefixLength;
        struct in_addr addr;

        int rv = fill_ip_info(interface, pv_ipaddr, pv_gateway,
                     &prefixLength, pv_dns1, pv_dns2, pv_server, lease, prop_vendorInfo);
        if (rv != -1) {
            *ipaddr = *gateway = *server = 0;
            *dns1 = *dns2 = 0;
            if (inet_aton(pv_ipaddr, &addr)) {
                *ipaddr = addr.s_addr;
            }
            if (inet_aton(pv_gateway, &addr)) {
                *gateway = addr.s_addr;
            }
            if (inet_aton(pv_dns1, &addr)) {
                *dns1= addr.s_addr;
            }
            if (inet_aton(pv_dns2, &addr)) {
                *dns2= addr.s_addr;
            }
            if (inet_aton(pv_server, &addr)) {
                *server= addr.s_addr;
            }
        }
        snprintf(prop_name, sizeof(prop_name), "%s.%s.mask", DHCP_PROP_NAME_PREFIX, interface);
        if (property_get(prop_name, prop_value, NULL) && inet_aton(prop_value, &addr)) {
            *mask = addr.s_addr;
        } else {
            *mask = 0;
        }
        return result;
    }

    *ipaddr=0;
    *gateway=0;
    *mask=0;
    *dns1=0;
    *dns2=0;
    *server=0;

    return 0;
}

void set_autoip(const char *interface, int value)
{
    value = value ? 1 : 0;
    int wifiorbt = get_device_type(interface);
    if( wifiorbt >= 0 ) {
        if( autoip_enabled[wifiorbt] != value ) {
            dhcp_stop(interface);
            autoip_enabled[wifiorbt] = value;
        }
    }
}
// END MOT JB UPMERGE
/**
 * The device init.rc file needs a corresponding entry.
 *
 * Example:
 * service iprenew_<interface> /system/bin/dhcpcd -n
 *
 */
int dhcp_start_renew(const char *interface)
{
    char result_prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX] = {'\0'};
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    const char *ctrl_prop = "ctl.start";

    char p2p_interface[MAX_INTERFACE_LENGTH];

    get_p2p_interface_replacement(interface, p2p_interface);

    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_PREFIX,
            p2p_interface);

    /* Erase any previous setting of the dhcp result property */
    property_set(result_prop_name, "");

    /* Start the renew daemon and wait until it's ready */
    snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s:%s", DAEMON_NAME_RENEW,
            p2p_interface, interface);
    memset(prop_value, '\0', PROPERTY_VALUE_MAX);
    property_set(ctrl_prop, daemon_cmd);

    /* Wait for the daemon to return a result */
    if (wait_for_property(result_prop_name, NULL, 30) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for DHCP Renew to finish");
        return -1;
    }

    return 0;
}
