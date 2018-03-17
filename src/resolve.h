#ifndef _RESOLVE_H_
#define _RESOLVE_H_

#include <sys/socket.h>
#include <netinet/ether.h>


char* lookup_oui(const struct ether_addr *mac, const char path[]);
char* resolve_info(const struct sockaddr_storage *addr);
char* resolve_hostname(const struct sockaddr_storage *addr);
char* lookup_dhcp_hostname(const struct ether_addr *mac, const char dhcp_leases_path[]);

#endif // _RESOLVE_H_