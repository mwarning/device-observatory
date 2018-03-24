
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

const char *ip_protcol_str(int p)
{
  switch (p) {
  case IPPROTO_IP: return "dummy (0)";   /* Dummy protocol for TCP   */
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
  default: return "???";
  }
}

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

  sip.ss_family = AF_INET;
  dip.ss_family = AF_INET;
  memcpy(&((struct sockaddr_in *)&sip)->sin_addr, &ip->ip_src, 4);
  memcpy(&((struct sockaddr_in *)&dip)->sin_addr, &ip->ip_dst, 4);

  switch (ip->ip_p) {
  case IPPROTO_TCP:
    printf("tcp4\n");
    tcp = (struct tcphdr*) payload;
    ((struct sockaddr_in *)&sip)->sin_port = tcp->th_sport;
    ((struct sockaddr_in *)&dip)->sin_port = tcp->th_dport;
    payload += sizeof(struct tcphdr);
    payload_len -= sizeof(struct tcphdr);
    break;
  case IPPROTO_UDP:
    printf("udp4\n");
    udp = (struct udphdr*) payload;
    ((struct sockaddr_in *)&sip)->sin_port = udp->uh_sport;
    ((struct sockaddr_in *)&dip)->sin_port = udp->uh_dport;
    payload += sizeof(struct udphdr);
    payload_len -= sizeof(struct udphdr);
    break;
  default:
    printf("unknown type4: %s\n", ip_protcol_str(ip->ip_p));
    return;
  }

  if (payload_len > 0) {
    add_activity(
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

  sip.ss_family = AF_INET6;
  dip.ss_family = AF_INET6;
  memcpy(&((struct sockaddr_in6 *)&sip)->sin6_addr, &ip->ip6_src, 16);
  memcpy(&((struct sockaddr_in6 *)&dip)->sin6_addr, &ip->ip6_dst, 16);

  switch (ip->ip6_nxt) {
  case IPPROTO_TCP:
    printf("tcp6\n");
    tcp = (struct tcphdr*) payload;
    ((struct sockaddr_in6 *)&sip)->sin6_port = tcp->th_sport;
    ((struct sockaddr_in6 *)&dip)->sin6_port = tcp->th_dport;
    payload += sizeof(struct tcphdr);
    payload_len -= sizeof(struct tcphdr);
    break;
  case IPPROTO_UDP:
    printf("udp6\n");
    udp = (struct udphdr*) payload;
    ((struct sockaddr_in6 *)&sip)->sin6_port = udp->uh_sport;
    ((struct sockaddr_in6 *)&dip)->sin6_port = udp->uh_dport;
    payload += sizeof(struct udphdr);
    payload_len -= sizeof(struct udphdr);
    break;
  default:
    printf("unknown type6: %s\n", ip_protcol_str(ip->ip6_nxt));
    return;
  }

  if (payload_len > 0) {
    add_activity(
      (struct ether_addr*)eh->ether_shost,
      (struct ether_addr*)eh->ether_dhost,
      &sip,
      &dip,
      payload,
      payload_len,
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
    fprintf(stdout, "truncated ip %d", payload_len);
    return;
  }

  len = ntohs(ip->ip_len);

  /* check header payload_len */
  if (ip->ip_hl < 5) {
    fprintf(stdout, "bad header length %d \n", ip->ip_hl);
  }

  /* see if we have as much packet as we should */
  if (payload_len < len) {
    printf("truncated IP - %d bytes missing\n", len - payload_len);
  }

  /* Check to see if we have the first fragment */
  off = ntohs(ip->ip_off);
  if ((off & 0x1fff) != 0) {
    printf("not first fragment\n");
    return;
  }

  /* Check IP version */
  switch (ip->ip_v) {
  case 4:
    payload += sizeof(struct ip);
    payload_len -= sizeof(struct ip);
    if (payload_len > 0)
      parse_ip4(eh, (const struct ip*) ip, pkthdr, payload, payload_len);
    else
      printf("empty payload4\n");
    return;
  case 6:
    payload += sizeof(struct ip6_hdr);
    payload_len -= sizeof(struct ip6_hdr);
    if (payload_len > 0)
      parse_ip6(eh, (const struct ip6_hdr*) ip, pkthdr, payload, payload_len);
    else
      printf("empty payload6\n");
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

printf("parse_packet\n");
/*
  switch (ntohs(eptr->ether_type)) {
  case ETHERTYPE_IP:
    break;
  case ETHERTYPE_IPV6:
    break;
  default:
    printf("unhandled protocol (%s)\n", ether_protcol_str(ntohs(eptr->ether_type)));
  }
*/
  if (ETHERTYPE_IP == ntohs(eptr->ether_type)) {
    payload += sizeof(struct ether_header);
    payload_length -= sizeof(struct ether_header);
    if (payload_length > 0)
      parse_ip(eptr, pkthdr, payload, payload_length);
    else
      printf("empty payload\n");
  } else {
    // Might be ICMP/ICMP6
    printf("not ethernet (%s)\n", ether_protcol_str(ntohs(eptr->ether_type)));
  }
}
