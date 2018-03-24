#ifndef _PARSE_DNS_H_
#define _PARSE_DNS_H_


char *lookup_dns(const struct sockaddr_storage *addr);

void parse_dns(const uint8_t *payload, int payload_len);

#endif // _PARSE_DNS_H_