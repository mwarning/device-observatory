#ifndef _PARSE_PACKET_H_
#define _PARSE_PACKET_H_

#include <pcap.h>


const char *str_mac(const struct ether_addr *mac);
const char *str_addr(const struct sockaddr_storage *addr);

void parse_packet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* payload);


#endif // _PARSE_PACKET_H_