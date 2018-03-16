#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <inttypes.h>
#include <netinet/ether.h>
#include <getopt.h>

#include <microhttpd.h>


#define MAC_FMT "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx"


const char *g_mac_db;

char *lookup_oui(const struct ether_addr *mac, const char path[])
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
    goto end;
  }

  while (fgets(line, sizeof(line), file) != NULL) {
   if (0 == strncmp(line, match, sizeof(match) - 1)) {
    nl = strchr(line, '\n');
    if (nl) {
      *nl = '\0';
    }
//printf("'%s'\n", &line[7]);
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
  device->oui_name = lookup_oui(mac, g_mac_db);
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
    fprintf(stderr, "fopen(): %s %s\n", dhcp_leases_path, strerror(errno));
    return;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
      int rc = sscanf(line, "%*s "MAC_FMT" %s %127s",
      	&mac.ether_addr_octet[0],
        &mac.ether_addr_octet[1],
        &mac.ether_addr_octet[2],
        &mac.ether_addr_octet[3],
        &mac.ether_addr_octet[4],
        &mac.ether_addr_octet[5],
        ip, name);

      if (rc == 8) {
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
    fprintf(stderr, "fopen(): %s %s\n", path, strerror(errno));
    return;
  }

  fprintf(fp, "{\n");
  device = g_devices;
  while (device) {
    fprintf(fp, " \"%02X:%02X:%02X:%02X:%02X:%02X\": {\n",
        device->mac.ether_addr_octet[0],
        device->mac.ether_addr_octet[1],
        device->mac.ether_addr_octet[2],
        device->mac.ether_addr_octet[3],
        device->mac.ether_addr_octet[4],
        device->mac.ether_addr_octet[5]);

    fprintf(fp, "  \"host_name\": \"%s\",\n", device->host_name);
    fprintf(fp, "  \"oui_name\": \"%s\",\n", device->oui_name);
    fprintf(fp, "  \"last_seen\": %u,\n", (uint32_t) device->last_seen);

    fprintf(fp, "  \"domains\": {\n");
    resource = device->resources;
    while (resource) {
      fprintf(fp, "   \"domain\": \"%s\",\n", resource->domain);
      fprintf(fp, "   \"port\": \"%u\",\n", (uint32_t) resource->port);
      fprintf(fp, "   \"last_accessed\": \"%u\"\n", (uint32_t) resource->last_accessed);
      resource = resource->next;
    }
    fprintf(fp, "  }\n");

    if (device->next) {
      fprintf(fp, " },\n");
    } else {
      fprintf(fp, " }\n");
    }

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
  oLeasesOutput,
  oHelp
};

static struct option options[] = {
  {"mac-db", required_argument, 0, oMacDb},
  {"json-output", required_argument, 0, oJsonOutput},
  {"leases-input", required_argument, 0, oLeasesOutput},
  {"help", no_argument, 0, oHelp},
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


int file_exists(const char path[])
{
	return access(path, F_OK) != -1;
}

static const char *help_text = "\n"
  " --mac-db <file>		MAC manufacturer database\n"
  " --json-output <file>	JSON data output\n"
  " --leases-input <file>	DHCP lease file\n"
  " --help\n";

int main(int argc, char **argv)
{
  const char *json_output = "/tmp/device-observatory.json";
  const char *leases_input = "/tmp/dhcp.leases";
  const char *mac_db = "/usr/share/macdb/db.txt";
  int index;
  int i;
  int c;
  int s;

  s = 1;
  while (s) {
    index = 0;
    c = getopt_long(argc, argv, "", options, &index);

    switch (c)
    {
    case oMacDb:
      mac_db = optarg;
      break;
    case oJsonOutput:
      json_output = optarg;
      break;
    case oLeasesOutput:
      leases_input = optarg;
      break;
    case oHelp:
      printf("%s", help_text);
      return 0;
    case -1:
      // End of options reached
      for (i = optind; i < argc; i++) {
        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return 1;
      }
      s = 0;
      break;
    //case '?':
    //  return 1;
    default:
      return 1;
    }
  }

  if (!file_exists(leases_input)) {
    fprintf(stderr, "File not found: %s\n", leases_input);
    return 1;
  }

  if (!file_exists(mac_db)) {
    fprintf(stderr, "File not found: %s\n", mac_db);
    return 1;
  }

  printf("leases_input: %s\n", leases_input);
  printf("json_output: %s\n", json_output);
  printf("mac_db: %s\n", mac_db);

  g_mac_db = mac_db;

  while (1) {
    read_dhcp_leases(leases_input);
    writeJSON(json_output);
    sleep(5);
  }

  return 0;
}
