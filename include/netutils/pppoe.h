#ifndef _NETUTILS_DHCP_H_
#define _NETUTILS_DHCP_H_

#include <sys/cdefs.h>
#include <arpa/inet.h>

__BEGIN_DECLS


extern int PPPOE_stop(const char *interface);
extern char *PPPOE_get_errmsg();
extern int PPPOE_do_request(const char *interface, int timeout_sec, const char *usr, const char *passwd, int interval, int failure, int mtu, int mru, int mss, char* iplocal, char* ipremote, char* gateway, char* dns1, char* dns2, char* ppplinkname);

__END_DECLS
#endif
