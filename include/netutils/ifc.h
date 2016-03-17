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

#ifndef _NETUTILS_IFC_H_
#define _NETUTILS_IFC_H_

#include <sys/cdefs.h>
#include <arpa/inet.h>

__BEGIN_DECLS

extern int ifc_init(void);
extern void ifc_close(void);

extern int ifc_get_ifindex(const char *name, int *if_indexp);
extern int ifc_get_hwaddr(const char *name, void *ptr);

extern int ifc_up(const char *name);
extern int ifc_down(const char *name);

extern int ifc_enable(const char *ifname);
extern int ifc_disable(const char *ifname);

#define RESET_IPV4_ADDRESSES 0x01
#define RESET_IPV6_ADDRESSES 0x02
#define RESET_IGNORE_INTERFACE_ADDRESS 0x04
#define RESET_ALL_ADDRESSES  (RESET_IPV4_ADDRESSES | RESET_IPV6_ADDRESSES)
extern int ifc_reset_connections(const char *ifname, const int reset_mask);

extern int ifc_get_addr(const char *name, in_addr_t *addr);
extern int ifc_set_addr(const char *name, in_addr_t addr);
extern int ifc_add_address(const char *name, const char *address,
                           int prefixlen);
extern int ifc_del_address(const char *name, const char *address,
                           int prefixlen);
extern int ifc_set_prefixLength(const char *name, int prefixLength);
extern int ifc_set_hwaddr(const char *name, const void *ptr);
extern int ifc_clear_addresses(const char *name);

extern int ifc_create_default_route(const char *name, in_addr_t addr);
extern int ifc_remove_default_route(const char *ifname);
extern int ifc_get_info(const char *name, in_addr_t *addr, int *prefixLength,
                        unsigned *flags);

extern int ifc_configure(const char *ifname, in_addr_t address,
                         uint32_t prefixLength, in_addr_t gateway,
                         in_addr_t dns1, in_addr_t dns2);

extern in_addr_t prefixLengthToIpv4Netmask(int prefix_length);
extern int ifc_is_up(const char *name, unsigned *isup);
extern int ifc_enable_allmc(const char *name);
extern int ifc_disable_allmc(const char *name);
extern int ifc_reset_connection_by_uid(int uid, int error); 
extern int ifc_set_throttle(const char *ifname, int rxKbps, int txKbps);
extern int ifc_set_fwmark_rule(const char *ifname, int mark, int add);
extern int ifc_set_txq_state(const char *ifname, int state);
extern int ifc_ccmni_md_cfg(const char *ifname, int md_id);
struct uid_err {
    int appuid;
	int errorNum;
};
__END_DECLS

#endif /* _NETUTILS_IFC_H_ */
