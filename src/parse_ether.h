#ifndef _PARSE_ETHER_H_
#define _PARSE_ETHER_H_

#include <pcap.h>


void parse_ether(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* payload);

#endif // _PARSE_ETHER_H_