#ifndef _PARSE_WIFI_H_
#define _PARSE_WIFI_H_

#include <pcap.h>


void parse_wifi(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* payload);

#endif // _PARSE_WIFI_H_