
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>

#include "main.h"
#include "utils.h"
#include "resolve.h"


struct dns4 {
  char *name;
  struct in_addr addr;
  struct dns4 *next;
};

struct dns6 {
  char *name;
  struct in6_addr addr;
  struct dns6 *next;
};

static struct dns4 *g_dns4_cache = NULL;
static struct dns6 *g_dns6_cache = NULL;


static const char *lookup_dns4(const struct in_addr *addr)
{
  struct dns4 *e;

  e = g_dns4_cache;
  while(e) {
    if (0 == memcmp(&e->addr, addr, 4)) {
      return e->name;
    }
    e = e->next;
  }

  return NULL;
}

static const char *lookup_dns6(const struct in6_addr *addr)
{
  struct dns6 *e;

  e = g_dns6_cache;
  while(e) {
    if (0 == memcmp(&e->addr, addr, 16)) {
      return e->name;
    }
    e = e->next;
  }

  return NULL;
}

static void add_dns4(const char name[], const struct in_addr *addr)
{
  struct dns4 *e;

  e = g_dns4_cache;
  while(e) {
    if (0 == memcmp(&e->addr, addr, 4)) {
      return;
    }
    e = e->next;
  }

  debug("add_dns4: %s\n", name);

  e = (struct dns4*) calloc(1, sizeof(struct dns4));
  e->name = strdup(name);
  memcpy(&e->addr, addr, 4);

  if (g_dns4_cache) {
    e->next = g_dns4_cache;
  }

  g_dns4_cache = e;
}

static void add_dns6(const char name[], const struct in6_addr *addr)
{
  struct dns6 *e;

  e = g_dns6_cache;
  while(e) {
    if (0 == memcmp(&e->addr, addr, 16)) {
      return;
    }
    e = e->next;
  }

  debug("add_dns6: %s\n", name);

  e = (struct dns6*) calloc(1, sizeof(struct dns6));
  e->name = strdup(name);
  memcpy(&e->addr, addr, 16);

  if (g_dns6_cache) {
    e->next = g_dns6_cache;
  }

  g_dns6_cache = e;
}

char *lookup_dns_name(const struct sockaddr_storage *addr)
{
  const char *name;

  switch(addr->ss_family) {
  case AF_INET:
    name = lookup_dns4(&((struct sockaddr_in*) addr)->sin_addr);
    break;
  case AF_INET6:
    name = lookup_dns6(&((struct sockaddr_in6*) addr)->sin6_addr);
    break;
  default:
    name = NULL;
  }

  if (name) {
    return strdup(name);
  } else {
    return NULL;
  }
}

/*
static void add_cname_alias(const char name[], const char cname[])
{
  {
    struct dns6 *e;

    e = g_dns6_cache;
    while(e) {
      if (0 == strcmp(e->name, name)) {
        add_dns6(cname, &e->addr);
        return;
      }
      e = e->next;
    }
  }

  {
    struct dns4 *e;

    e = g_dns4_cache;
    while(e) {
      if (0 == strcmp(e->name, name)) {
        add_dns4(cname, &e->addr);
        return;
      }
      e = e->next;
    }
  }
}
*/

void handle_dns_rr(const struct ResourceRecord *rr, int rr_type)
{
  UNUSED(rr_type);

  if (rr->type == A_Resource_RecordType)
    add_dns4(rr->name, &rr->rd_data.a_record.addr);

  if (rr->type == AAAA_Resource_RecordType)
    add_dns6(rr->name, &rr->rd_data.aaaa_record.addr);

  //if (rr->type == CNAME_Resource_RecordType) {
  //  add_cname_alias(rr->name, rr->cname);
  //}
}

/* Get column content from a line string */
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

char* lookup_oui_name(const struct ether_addr *mac, const char path[])
{
  char match[7];
  char line[256];
  char *nl;
  FILE *file;

  if (path == NULL) {
    return NULL;
  }

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

char *lookup_port_name(int port, int is_tcp, const char path[])
{
  char line[256];
  char match[20];
  FILE *fp;

  /* Some frequently used ports */
  switch (port) {
    case 80:
      return strdup("HTTP");
    case 443:
      return strdup("HTTPS");
    case 53:
      return strdup("DNS");
    case 67:
      return strdup("DHCP");
  }

  if (path == NULL) {
    return NULL;
  }

  fp = fopen(path, "r");
  if (fp == NULL) {
    fprintf(stderr, "fopen(): %s %s\n", path, strerror(errno));
    return NULL;
  }

 sprintf(match, " %d/%s ", port, is_tcp ? "tcp" : "udp");

  while (fgets(line, sizeof(line), fp) != NULL) {
    if (strstr(line, match)) {
      fclose(fp);
      return get_column(line, 1);
    }
  }

  fclose(fp);
  return NULL;
}

char* lookup_dhcp_hostname(const struct ether_addr *mac, const char dhcp_leases_path[])
{
  char line[512];
  char match[20];
  FILE *fp;

  if (dhcp_leases_path == NULL) {
    return NULL;
  }

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

char* lookup_hostbyaddr(const struct sockaddr_storage *addr)
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
