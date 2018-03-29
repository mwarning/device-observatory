#ifndef _MAIN_H_
#define _MAIN_H_

#include <time.h>
#include <netinet/ether.h>

extern time_t g_now;

void add_connection(
  const struct ether_addr *smac,
  const struct ether_addr *dmac,
  const struct sockaddr_storage *saddr,
  const struct sockaddr_storage *daddr,
  const u_char *payload, size_t payload_len,
  size_t len);

#endif // _MAIN_H_