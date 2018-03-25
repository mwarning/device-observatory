#ifndef _PARSE_PACKET_H_
#define _PARSE_PACKET_H_

#include <pcap.h>


typedef void packet_callback(
  const struct ether_addr *smac,
  const struct ether_addr *dmac,
  const struct sockaddr_storage *saddr,
  const struct sockaddr_storage *daddr,
  const u_char *payload, size_t payload_len,
  size_t len);

void parse_packet(const struct pcap_pkthdr* pkthdr, const u_char* data, packet_callback *cb);


#endif // _PARSE_PACKET_H_