#ifndef _UTILS_H_
#define _UTILS_H_

#include <netinet/ether.h>

void printHexDump(const void *addr, int len);

const char *formatDuration(uint32_t time);
const char *str_mac(const struct ether_addr *mac);
const char *str_addr(const struct sockaddr_storage *addr);

int includesString(const uint8_t* payload, size_t payload_length, const uint8_t str[], size_t len);
void printStrings(const uint8_t* payload, size_t payload_length, int min);

#endif // _UTILS_H_