
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "resolve.h"


char* lookup_oui(const struct ether_addr *mac, const char path[])
{
  char match[7];
  char line[256];
  char *nl;
  FILE *file;

  sprintf(match, "%02X%02X%02X",
    mac->ether_addr_octet[0],
    mac->ether_addr_octet[1],
    mac->ether_addr_octet[2]);

  file = fopen(path, "r");
  if (file == NULL) {
    fprintf(stderr, "fopen(): %s %s\n", path, strerror(errno));
    return NULL;
  }

  while (fgets(line, sizeof(line), file) != NULL) {
   if (0 == strncmp(line, match, sizeof(match) - 1)) {
    nl = strchr(line, '\n');
    if (nl) {
      *nl = '\0';
    }

    fclose(file);
    return strdup(&line[7]);
   }
  }

  fclose(file);
  return NULL;
}

static char *get_column(const char line[], int col)
{
  const char* s = line;
  const char* n;
  int i;

  if (col <= 0) {
    return NULL;
  }
  col -= 1;

  for (i = 0; i < col; i++) {
    n = strchr(s, ' ');
    if (!n) {
      return NULL;
    }
    s = n + 1;
  }

  n = strchr(s, ' ');
  if (n) {
    return strndup(s, n - s);
  }
  return strdup(s);
}

char* lookup_dhcp_hostname(const struct ether_addr *mac, const char dhcp_leases_path[])
{
  char line[512];
  char match[20];
  FILE *fp;

  fp = fopen(dhcp_leases_path, "r");
  if (fp == NULL) {
    fprintf(stderr, "fopen(): %s %s\n", dhcp_leases_path, strerror(errno));
    return NULL;
  }

  sprintf(match, " %02x:%02x:%02x:%02x:%02x:%02x ",
  		mac->ether_addr_octet[0],
        mac->ether_addr_octet[1],
        mac->ether_addr_octet[2],
        mac->ether_addr_octet[3],
        mac->ether_addr_octet[4],
        mac->ether_addr_octet[5]);

  while (fgets(line, sizeof(line), fp) != NULL) {
    if (strstr(line, match)) {
      fclose(fp);
      return get_column(line, 4);
    }
  }

  fclose(fp);
  return NULL;
}

static int get_port(const struct sockaddr_storage *addr)
{
  switch (addr->ss_family) {
  case AF_INET:
    return ntohs(((struct sockaddr_in *)addr)->sin_port);
  case AF_INET6:
    return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
  default:
    return -1;
  }
}

char* resolve_info(const struct sockaddr_storage *addr)
{
  int port;

  port = get_port(addr);

  switch (port) {
    case 80:
      return strdup("HTTP");
    case 443:
      return strdup("HTTPS");
    case 53:
      return strdup("DNS");
    case 67:
      return strdup("DHCP");
    default:
      return NULL;
  }
}

// TODO: use DNS data to get orignal domain
char* resolve_hostname(const struct sockaddr_storage *addr)
{
  struct hostent *hent;

  if (addr->ss_family == AF_INET) {
    hent = gethostbyaddr(&((struct sockaddr_in *)addr)->sin_addr, 4, AF_INET);
    if (hent) {
      return strdup(hent->h_name);
    }
  }

  if (addr->ss_family == AF_INET6) {
    hent = gethostbyaddr(&((struct sockaddr_in6 *)addr)->sin6_addr, 16, AF_INET6);
    if (hent) {
      return strdup(hent->h_name);
    }
  }

  return NULL;
}
