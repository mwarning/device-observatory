#include <stdio.h>
#include <time.h>
#include <time.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>

#include <inttypes.h>
#include <netinet/ether.h>
#include <getopt.h>

#include <microhttpd.h>


#define MAC_FMT "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx"

const char *g_mac_db = "/usr/share/macdb/db.txt";

char *lookup_oui(const struct ether_addr *mac)
{
  FILE *file;
  char match[7];
  char line[256];

  sprintf(match, "%hhx%hhx%hhx",
    mac->ether_addr_octet[0],
    mac->ether_addr_octet[1],
    mac->ether_addr_octet[2]);

  file = fopen(g_mac_db, "r");
  if (file == NULL) {
    fprintf(stderr, "fopen() %s", strerror(errno));
    goto end;
  }

  while (fgets(line, sizeof(line), file) != NULL) {
   if (0 == strncmp(line, match, sizeof(match) - 1)) {
    fclose(file);
    return strdup(&line[7]);
   }
  }

  fclose(file);

end:
  return strdup("");
}

struct resource
{
  char *domain;
  uint16_t port;
  time_t last_accessed;
  struct resource *next;
};

struct device
{
  struct ether_addr mac;
  char *oui_name;
  char *host_name;
  char *ip_addr;
  time_t last_seen;
  // Resource the client accesses
  struct resource *resources;
  struct device *next;
};

struct device *g_devices = NULL;

void free_resource(struct resource *resource)
{
  free(resource->domain);
  free(resource);
}

void free_resource_list(struct resource *resource)
{
  struct resource *next;

  while (resource) {
     next = resource->next;
     free_resource(resource);
     resource = next;
  }
}

void free_device(struct device *device)
{
  free_resource_list(device->resources);

  free(device->host_name);
  free(device->oui_name);
  free(device);
}

void add_resource(struct device *device, const char domain[], uint16_t port)
{
  struct resource *resource;

  resource = device->resources;
  while (resource) {
    if (0 == strcmp(resource->domain, domain) && resource->port == port) {
      resource->last_accessed = time(NULL);
      // entry exists
      return;
    }
    resource = resource->next;
  }

  resource = (struct resource*) calloc(1, sizeof(struct resource));
  resource->domain = strdup(domain);
  resource->port = port;
  resource->last_accessed = time(NULL);

  if (device->resources) {
    resource->next = device->resources;
  }
  device->resources = resource;
}

void add_device(const struct ether_addr *mac, const char ip_addr[], const char host_name[])
{
  struct device *device;

  device = g_devices;
  while (device) {
    if (0 == memcmp(&device->mac, mac, sizeof(struct ether_addr))) {
      device->last_seen = time(NULL);
      if (strcmp(&device->host_name[0], host_name)) {
        strncpy(&device->host_name[0], host_name, 64);
      }
      return;
    }
    device = device->next;
  }

  device = (struct device*) calloc(1, sizeof(struct device));
  memcpy(&device->mac, mac, sizeof(struct ether_addr));
  device->last_seen = time(NULL);
  device->host_name = strdup(host_name);
  device->oui_name = lookup_oui(mac);
  device->ip_addr = strdup(ip_addr);

  if (g_devices) {
    device->next = g_devices;
  }
  g_devices = device;
}

void read_dhcp_leases(const char dhcp_leases_path[])
{
  char line[512];
  char name[128];
  char ip[128];
  struct ether_addr mac;
  FILE *fp;

  fp = fopen(dhcp_leases_path, "r");
  if (fp == NULL) {
    fprintf(stderr, "fopen() %s", strerror(errno));
    return;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
      //printf("%s", line);
      if (7 == sscanf(line, "%*s "MAC_FMT" %s %127s %*s",
        &mac.ether_addr_octet[0],
        &mac.ether_addr_octet[1],
        &mac.ether_addr_octet[2],
        &mac.ether_addr_octet[3],
        &mac.ether_addr_octet[4],
        &mac.ether_addr_octet[5],
        ip, name)) {
        add_device(&mac, ip, name);
      }
  }

  fclose(fp);
}

void writeJSON(const char path[])
{
  struct device *device;
  struct resource *resource;
  FILE *fp;

  fp = fopen(path, "w");
  if (fp == NULL) {
    fprintf(stderr, "fopen() %s", strerror(errno));
    return;
  }

  fprintf(fp, "{\n");
  device = g_devices;
  while (device) {
    fprintf(fp, "\""MAC_FMT"\": {",
        device->mac.ether_addr_octet[0],
        device->mac.ether_addr_octet[1],
        device->mac.ether_addr_octet[2],
        device->mac.ether_addr_octet[3],
        device->mac.ether_addr_octet[4],
        device->mac.ether_addr_octet[5]);

    fprintf(fp, "\"host_name\": \"%s\",\n", device->host_name);
    fprintf(fp, "\"oui_name\": \"%s\",\n", device->oui_name);
    fprintf(fp, "\"last_seen\": %u\n", (uint32_t) device->last_seen);

    fprintf(fp, "\"domains\": {\n");
    resource = device->resources;
    while (resource) {
      fprintf(fp, "\"domain\": \"%s\",\n", resource->domain);
      fprintf(fp, "\"port\": \"%u\",\n", (uint32_t) resource->port);
      fprintf(fp, "\"last_accessed\": \"%u\",\n", (uint32_t) resource->last_accessed);
      resource = resource->next;
    }
    fprintf(fp, "}\n");

    fprintf(fp, "}\n");
    device = device->next;
  }
  fprintf(fp, "}\n");

  fclose(fp);
}

#if 0
int call_tcpdump(const char ifname[])
{
  FILE *fp;
  char cmd[64];
  char line[1024]

  snprintf(cmd, sizeof(cmd), "tcpdump -i %s", ifname);

  /* Open the command for reading. */
  fp = popen(cmd, "r");
  if (fp == NULL) {
    fprintf(stderr, "Failed to run command.\n");
    return 1;
  }

  /* Read the output a line at a time - output it. */
  while (fgets(line, sizeof(line) - 1, fp) != NULL) {
    
  }

  /* close */
  pclose(fp);
}
#endif

enum {
  oMacDb,
  oJsonOutput,
  oDhcpLeases
};

static struct option options[] = {
  {"mac_db", required_argument, 0, oMacDb},
  {"json_output", required_argument, 0, oJsonOutput},
  {"dhcp_leases", required_argument, 0, oDhcpLeases},
  {0, 0, 0, 0}
};


static int answer_to_connection(void *cls, struct MHD_Connection *connection,
  const char *url, const char *method, const char *version,
  const char *upload_data, size_t *upload_data_size, void **con_cls)
{
  return MHD_NO;
}

static struct MHD_Daemon *g_webserver;

void start_webserver()
{
  g_webserver = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, 8080, NULL, NULL, &answer_to_connection, NULL, MHD_OPTION_END);
}

int main(int argc, char **argv)
{
  const char *json_output = "/www/device-observatory.json";
  const char *dhcp_leases = "/tmp/dhcp.leases";
  const char *optname;
  int index;
  int i;
  int c;

  while (1) {
    index = 0;
    c = getopt_long(argc, argv, "", options, &index);
    optname = options[index].name;

    switch (c)
    {
    case oMacDb:
      g_mac_db = optname;
      break;
    case oJsonOutput:
      json_output = optname;
      break;
    case oDhcpLeases:
      dhcp_leases = optname;
      break;
    case -1:
      // End of options reached
      for (i = optind; i < argc; i++) {
        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return 1;
      }
      break;
    //case '?':
    //  return 1;
    default:
      return 1;
    }
  }

  while (1) {
    read_dhcp_leases(dhcp_leases);
    writeJSON(json_output);
    sleep(5);
  }

  return 0;
}
