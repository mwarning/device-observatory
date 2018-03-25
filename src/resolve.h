#ifndef _RESOLVE_H_
#define _RESOLVE_H_

#include <sys/socket.h>
#include <netinet/ether.h>

#include "parse_dns.h"


/* Callback for parsed DNS packets */
void handle_dns_rr(const struct ResourceRecord *rr, int rr_type);

char* lookup_dns_name(const struct sockaddr_storage *addr);
char* lookup_oui_name(const struct ether_addr *mac, const char oui_db_path[]);
char* lookup_dhcp_hostname(const struct ether_addr *mac, const char dhcp_leases_path[]);
char *lookup_port_name(int port, int is_tcp, const char services_db_path[]);
char* lookup_hostbyaddr(const struct sockaddr_storage *addr);

#endif // _RESOLVE_H_