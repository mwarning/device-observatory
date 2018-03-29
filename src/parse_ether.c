
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
#include "utils.h"
#include "parse_wifi.h"
#include "parse_ether.h"

/* tcpdump header (ether.h) defines ETHER_HDRLEN) */
#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif


const char *ip_protcol_str(int p)
{
  switch (p) {
  //case IPPROTO_IP: return "dummy (0)";   /* Dummy protocol for TCP   */
  case IPPROTO_ICMP: return "ICMP";   /* Internet Control Message Protocol  */
  case IPPROTO_IGMP: return "IGMP";   /* Internet Group Management Protocol */
  case IPPROTO_IPIP: return "IPIP";   /* IPIP tunnels (older KA9Q tunnels use 94) */
  case IPPROTO_TCP: return "TCP";    /* Transmission Control Protocol  */
  case IPPROTO_EGP: return "EGP";    /* Exterior Gateway Protocol    */
  case IPPROTO_PUP: return "PUP";   /* PUP protocol       */
  case IPPROTO_UDP: return "UDP";   /* User Datagram Protocol   */
  case IPPROTO_IDP: return "IDP";   /* XNS IDP protocol     */
  case IPPROTO_TP: return "TP";    /* SO Transport Protocol Class 4  */
  case IPPROTO_DCCP: return "DCCP";    /* Datagram Congestion Control Protocol */
  case IPPROTO_IPV6: return "IPV6";    /* IPv6-in-IPv4 tunnelling    */
  case IPPROTO_RSVP: return "RSVP";    /* RSVP Protocol      */
  case IPPROTO_GRE: return "GRE";   /* Cisco GRE tunnels (rfc 1701,1702)  */
  case IPPROTO_ESP: return "ESP";   /* Encapsulation Security Payload protocol */
  case IPPROTO_AH: return "AH";    /* Authentication Header protocol */
  case IPPROTO_MTP: return "MTP";   /* Multicast Transport Protocol   */
  case IPPROTO_BEETPH: return "BEET";    /* IP option pseudo header for BEET */
  case IPPROTO_ENCAP: return "ENCP";   /* Encapsulation Header     */
  case IPPROTO_PIM: return "PIM";    /* Protocol Independent Multicast */
  case IPPROTO_COMP: return "COMP";   /* Compression Header Protocol    */
  case IPPROTO_SCTP: return "SCTP";   /* Stream Control Transport Protocol  */
  case IPPROTO_UDPLITE: return "UDPLITE";  /* UDP-Lite (RFC 3828)      */
  case IPPROTO_MPLS: return "MPLS";   /* MPLS in IP (RFC 4023)    */
  case IPPROTO_RAW: return "Raw";    /* Raw IP packets     */

//hm?
    case IPPROTO_HOPOPTS: return "HOPOPTS";  /* IPv6 hop-by-hop options  */
case IPPROTO_ROUTING: return "ROUTING";   /* IPv6 routing header    */
case IPPROTO_FRAGMENT: return "ICMPV6";   /* IPv6 fragmentation header  */
case IPPROTO_ICMPV6: return "ICMPV6";   /* ICMPv6     */
case IPPROTO_NONE: return "NONE";  /* IPv6 no next header    */
case IPPROTO_DSTOPTS: return "DSTOPTS";  /* IPv6 destination options */
case IPPROTO_MH: return "MH"; /* IPv6 mobility header   */
  default: return "???";
  }
}

#if 0
const char *ip6_protcol_str(int p)
{
case IPPROTO_HOPOPTS: return "HOPOPTS";  /* IPv6 hop-by-hop options  */
case IPPROTO_ROUTING: return "ROUTING";   /* IPv6 routing header    */
case IPPROTO_FRAGMENT: return "ICMPV6";   /* IPv6 fragmentation header  */
case IPPROTO_ICMPV6: return "ICMPV6";   /* ICMPv6     */
case IPPROTO_NONE: return "NONE";  /* IPv6 no next header    */
case IPPROTO_DSTOPTS: return "DSTOPTS";  /* IPv6 destination options */
case IPPROTO_MH: return "MH"; /* IPv6 mobility header   */
}
#endif

const char *ether_protcol_str(int p)
{
  switch (p) {
  case ETHERTYPE_PUP: return "PUP";          /* Xerox PUP */
  case ETHERTYPE_SPRITE: return "SPRITE";    /* Sprite */
  case ETHERTYPE_IP: return "IP";    /* IP */
  case ETHERTYPE_ARP: return "ARP";    /* Address resolution */
  case ETHERTYPE_REVARP: return "REVARP";    /* Reverse ARP */
  case ETHERTYPE_AT: return "AT";    /* AppleTalk protocol */
  case ETHERTYPE_AARP: return "AARP";    /* AppleTalk ARP */
  case ETHERTYPE_VLAN: return "VLAN";    /* IEEE 802.1Q VLAN tagging */
  case ETHERTYPE_IPX: return "IPX";    /* IPX */
  case ETHERTYPE_IPV6: return "IPV6";    /* IP protocol version 6 */
  case ETHERTYPE_LOOPBACK: return "LOOPBACK";      /* used to test interfaces */
  default: return "???";
  }
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

  /* Check "Total Length" field */
  if ((payload_len + sizeof(struct ip)) < ntohs(ip->ip_len)) {
    debug("truncated IPv4 - %d bytes missing\n", (int) (ntohs(ip->ip_len) - payload_len - sizeof(struct ip)));
    return;
  }

  sip.ss_family = AF_INET;
  dip.ss_family = AF_INET;
  memcpy(&((struct sockaddr_in *)&sip)->sin_addr, &ip->ip_src, 4);
  memcpy(&((struct sockaddr_in *)&dip)->sin_addr, &ip->ip_dst, 4);

  switch (ip->ip_p) {
  case IPPROTO_TCP:
    tcp = (struct tcphdr*) payload;
    ((struct sockaddr_in *)&sip)->sin_port = tcp->th_sport;
    ((struct sockaddr_in *)&dip)->sin_port = tcp->th_dport;
    payload += sizeof(struct tcphdr);
    payload_len -= sizeof(struct tcphdr);
    break;
  case IPPROTO_UDP:
    udp = (struct udphdr*) payload;
    ((struct sockaddr_in *)&sip)->sin_port = udp->uh_sport;
    ((struct sockaddr_in *)&dip)->sin_port = udp->uh_dport;
    payload += sizeof(struct udphdr);
    payload_len -= sizeof(struct udphdr);
    break;
  default:
    debug("%s (%d) => ignore\n", ip_protcol_str(ip->ip_p), (int) ip->ip_p);
    return;
  }

  if (payload_len > 0) {
    add_connection(
      (struct ether_addr*)eh->ether_shost,
      (struct ether_addr*)eh->ether_dhost,
      &sip,
      &dip,
      payload,
      payload_len,
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

  /* Check "Payload Length" field */
  if (payload_len < ntohs(ip->ip6_plen)) {
    debug("truncated IPv6 - %d bytes missing\n", (int) (ntohs(ip->ip6_plen) - payload_len));
    return;
  }

  sip.ss_family = AF_INET6;
  dip.ss_family = AF_INET6;
  memcpy(&((struct sockaddr_in6 *)&sip)->sin6_addr, &ip->ip6_src, 16);
  memcpy(&((struct sockaddr_in6 *)&dip)->sin6_addr, &ip->ip6_dst, 16);

  switch (ip->ip6_nxt) {
  case IPPROTO_TCP:
    tcp = (struct tcphdr*) payload;
    ((struct sockaddr_in6 *)&sip)->sin6_port = tcp->th_sport;
    ((struct sockaddr_in6 *)&dip)->sin6_port = tcp->th_dport;
    payload += sizeof(struct tcphdr);
    payload_len -= sizeof(struct tcphdr);
    break;
  case IPPROTO_UDP:
    udp = (struct udphdr*) payload;
    ((struct sockaddr_in6 *)&sip)->sin6_port = udp->uh_sport;
    ((struct sockaddr_in6 *)&dip)->sin6_port = udp->uh_dport;
    payload += sizeof(struct udphdr);
    payload_len -= sizeof(struct udphdr);
    break;
  default:
    debug("%s (%d) => ignore\n", ip_protcol_str(ip->ip6_nxt), (int) ip->ip6_nxt);
    return;
  }

  if (payload_len > 0) {
    add_connection(
      (struct ether_addr*)eh->ether_shost,
      (struct ether_addr*)eh->ether_dhost,
      &sip,
      &dip,
      payload,
      payload_len,
      pkthdr->len);
  }
}

void parse_ether(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* payload)
{
  u_int caplen = pkthdr->caplen;
  u_int payload_length = pkthdr->len;
  struct ether_header *ether_hdr;
  struct ip6_hdr *ip6_hdr;
  struct ip *ip4_hdr;

  if (caplen < ETHER_HDRLEN) {
    debug("Packet length less than ethernet header length\n");
    return;
  }

  /* Let's start with the ether header... */
  ether_hdr = (struct ether_header *) payload;
  payload += sizeof(struct ether_header);
  payload_length -= sizeof(struct ether_header);

  int ether_type = ntohs(ether_hdr->ether_type);
  //debug("parse_ether: %s %d\n", ether_protcol_str(ether_type), (int) (*payload >> 4));

  switch (ether_type) {
  case ETHERTYPE_IP:
  printf("A\n");
    ip4_hdr = (struct ip*) payload;
    payload += sizeof(struct ip);
    payload_length -= sizeof(struct ip);
    if (payload_length > 0)
      parse_ip4(ether_hdr, ip4_hdr, pkthdr, payload, payload_length);
    break;
  case ETHERTYPE_IPV6:
  printf("B\n");
    ip6_hdr = (struct ip6_hdr*) payload;
    payload += sizeof(struct ip6_hdr);
    payload_length -= sizeof(struct ip6_hdr);
    if (payload_length > 0)
      parse_ip6(ether_hdr, ip6_hdr, pkthdr, payload, payload_length);
    break;
  default:
    debug("%s (%d) => ignore\n", ether_protcol_str(ether_type), ether_type);
  }
}
