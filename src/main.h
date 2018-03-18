#ifndef _MAIN_H_
#define _MAIN_H_


void add_activity(
  const struct ether_addr *smac,
  const struct ether_addr *dmac,
  const struct sockaddr_storage *saddr,
  const struct sockaddr_storage *daddr,
  uint32_t len
);

#endif // _MAIN_H_