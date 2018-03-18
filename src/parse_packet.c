
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>

#include "main.h"
#include "parse_packet.h"

/* tcpdump header (ether.h) defines ETHER_HDRLEN) */
#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

enum {
  PROTO_ICMP = 1,
  PROTO_TCP = 6,
  PROTO_UDP = 17
};

const char *str_mac(const struct ether_addr *mac)
{
  static char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
    mac->ether_addr_octet[0],
    mac->ether_addr_octet[1],
    mac->ether_addr_octet[2],
    mac->ether_addr_octet[3],
    mac->ether_addr_octet[4],
    mac->ether_addr_octet[5]);
  return buf;
}

#define FULL_ADDSTRLEN (INET6_ADDRSTRLEN + 8)
const char *str_addr(const struct sockaddr_storage *addr)
{
  static char addrbuf[FULL_ADDSTRLEN + 1];
  char buf[INET6_ADDRSTRLEN + 1];
  const char *fmt;
  int port;

  switch (addr->ss_family) {
  case AF_INET6:
    port = ((struct sockaddr_in6 *)addr)->sin6_port;
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr, buf, sizeof(buf));
    fmt = "[%s]:%d";
    break;
  case AF_INET:
    port = ((struct sockaddr_in *)addr)->sin_port;
    inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr, buf, sizeof(buf));
    fmt = "%s:%d";
    break;
  default:
    return "<invalid address>";
  }

  sprintf(addrbuf, fmt, buf, ntohs(port));

  return addrbuf;
}

void parse_ip4(
  const struct ether_header *eh,
  const struct ip* ip,
  const struct pcap_pkthdr* pkthdr,
  const u_char *payload, int payload_len)
{
  const struct tcphdr* tcp;
  const struct udphdr* udp;
  struct sockaddr_storage sip = {0};
  struct sockaddr_storage dip = {0};

  sip.ss_family = AF_INET;
  dip.ss_family = AF_INET;
  memcpy(&((struct sockaddr_in *)&sip)->sin_addr, &ip->ip_src, 4);
  memcpy(&((struct sockaddr_in *)&dip)->sin_addr, &ip->ip_dst, 4);

  switch (ip->ip_p) {
  case PROTO_TCP:
    tcp = (struct tcphdr*) payload;
    ((struct sockaddr_in *)&sip)->sin_port = tcp->th_sport;
    ((struct sockaddr_in *)&dip)->sin_port = tcp->th_dport;
    payload += sizeof(struct tcphdr);
    payload_len -= sizeof(struct tcphdr);
    break;
  case PROTO_UDP:
    udp = (struct udphdr*) payload;
    ((struct sockaddr_in *)&sip)->sin_port = udp->uh_sport;
    ((struct sockaddr_in *)&dip)->sin_port = udp->uh_dport;
    payload += sizeof(struct udphdr);
    payload_len -= sizeof(struct udphdr);
    break;
  default:
    return;
  }

  if (payload_len > 0) {
    add_activity(
      (struct ether_addr*)eh->ether_shost,
      (struct ether_addr*)eh->ether_dhost,
      &sip,
      &dip,
      pkthdr->len);
  }
}

void parse_ip6(
  const struct ether_header *eh,
  const struct ip6_hdr* ip,
  const struct pcap_pkthdr* pkthdr,
  const u_char *payload, size_t payload_len)
{
  const struct tcphdr* tcp;
  const struct udphdr* udp;
  struct sockaddr_storage sip = {0};
  struct sockaddr_storage dip = {0};

  sip.ss_family = AF_INET6;
  dip.ss_family = AF_INET6;
  memcpy(&((struct sockaddr_in6 *)&sip)->sin6_addr, &ip->ip6_src, 16);
  memcpy(&((struct sockaddr_in6 *)&dip)->sin6_addr, &ip->ip6_dst, 16);

  switch (ip->ip6_nxt) {
  case PROTO_TCP:
    tcp = (struct tcphdr*) payload;
    ((struct sockaddr_in6 *)&sip)->sin6_port = tcp->th_sport;
    ((struct sockaddr_in6 *)&dip)->sin6_port = tcp->th_dport;
    payload += sizeof(struct tcphdr);
    payload_len -= sizeof(struct tcphdr);
    break;
  case PROTO_UDP:
    udp = (struct udphdr*) payload;
    ((struct sockaddr_in6 *)&sip)->sin6_port = udp->uh_sport;
    ((struct sockaddr_in6 *)&dip)->sin6_port = udp->uh_dport;
    payload += sizeof(struct udphdr);
    payload_len -= sizeof(struct udphdr);
    break;
  default:
    return;
  }

  if (payload_len > 0) {
    add_activity(
      (struct ether_addr*)eh->ether_shost,
      (struct ether_addr*)eh->ether_dhost,
      &sip,
      &dip,
      pkthdr->len);
  }
}

void parse_ip(const struct ether_header* eh,
    const struct pcap_pkthdr* pkthdr,
    const u_char *payload, int payload_len)
{
  const struct ip* ip;
  u_int off;
  int len;

  /* jump pass the ethernet header */
  ip = (struct ip*) payload;

  if (payload_len < sizeof(struct ip)) {
    printf("truncated ip %d", payload_len);
    return;
  }

  len = ntohs(ip->ip_len);

  /* check header payload_len */
  if (ip->ip_hl < 5) {
    fprintf(stdout, "bad header length %d \n", ip->ip_hl);
  }

  /* see if we have as much packet as we should */
  if (payload_len < len) {
    printf("\ntruncated IP - %d bytes missing\n", len - payload_len);
  }

  /* Check to see if we have the first fragment */
  off = ntohs(ip->ip_off);
  if ((off & 0x1fff) != 0) {
    return;
  }

  /* Check IP version */
  switch (ip->ip_v) {
  case 4:
    payload += sizeof(struct ip);
    payload_len -= sizeof(struct ip);
    if (payload_len > 0)
      parse_ip4(eh, (const struct ip*) ip, pkthdr, payload, payload_len);
    return;
  case 6:
    payload += sizeof(struct ip6_hdr);
    payload_len -= sizeof(struct ip6_hdr);
    if (payload_len > 0)
      parse_ip6(eh, (const struct ip6_hdr*) ip, pkthdr, payload, payload_len);
    return;
  default:
    fprintf(stdout,"Unknown IP version %d\n", ip->ip_v);
    return;
  }
}

/* looking at ethernet headers */
void parse_packet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* payload)
{
  u_int caplen = pkthdr->caplen;
  u_int payload_length = pkthdr->len;
  struct ether_header *eptr;  /* net/ethernet.h */

  if (caplen < ETHER_HDRLEN) {
    fprintf(stdout,"Packet length less than ethernet header length\n");
    return;
  }

  /* lets start with the ether header... */
  eptr = (struct ether_header *) payload;

  if (ETHERTYPE_IP == ntohs(eptr->ether_type)) {
    payload += sizeof(struct ether_header);
    payload_length -= sizeof(struct ether_header);
    if (payload_length > 0)
      parse_ip(eptr, pkthdr, payload, payload_length);
  }
}
