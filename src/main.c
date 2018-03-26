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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <inttypes.h>
#include <netinet/ether.h>
#include <inttypes.h>
#include <getopt.h>

//#include <microhttpd.h>

#include "parse_packet.h"
#include "parse_dns.h"
#include "resolve.h"
#include "main.h"


static const char *g_mac_db = NULL;
static const char *g_port_db = NULL;
static const char *g_leases_input = NULL;
static const char *g_json_ouput = NULL;

static struct ether_addr g_dev_mac = {0};
static time_t g_output_timer = 0;
static time_t g_now = 0;


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

struct info
{
  char *data;
  struct info *next;
};

struct connection
{
  char *hostname;
  char *portname;
  struct info *infos;
  struct sockaddr_storage saddr;
  struct sockaddr_storage daddr;
  int times_accessed;
  time_t first_accessed;
  time_t last_accessed;
  uint64_t upload;
  uint64_t download;
  struct connection *next;
};

struct device
{
  struct ether_addr mac;
  char *ouiname;
  char *hostname;
  time_t first_seen;
  time_t last_seen;
  uint64_t upload;
  uint64_t download;
  struct connection *connections;
  struct device *next;
};

static struct device *g_devices = NULL;

void free_info(struct info *info)
{
  free(info->data);
  free(info);
}

void free_connection(struct connection *connection)
{
  struct info *info;
  struct info *next;

  info = connection->infos;
  while (info) {
     next = info->next;
     free_info(info);
     info = next;
  }

  free(connection->hostname);
  free(connection->portname);
  free(connection);
}

void free_device(struct device *device)
{
  struct connection *connection;
  struct connection *next;

  connection = device->connections;
  while (connection) {
     next = connection->next;
     free_connection(connection);
     connection = next;
  }

  free(device->hostname);
  free(device->ouiname);
  free(device);
}

static struct device *find_device(const struct ether_addr *mac)
{
  struct device *device;

  device = g_devices;
  while (device) {
     if (0 == memcmp(&device->mac, mac, sizeof(struct ether_addr))) {
       return device;
     }
     device = device->next;
  }

  return NULL;
}

static void add_info(struct connection *connection, const char data[])
{
  struct info *info;

  if (data == NULL || data[0] == '\0')
    return;

  info = connection->infos;
  while (info) {
    if (!strcmp(info->data, data)) {
      return;
    }
  }

  info = (struct info*) calloc(1, sizeof(struct info));
  info->data = strdup(data);

  if (connection->infos) {
    info->next = connection->infos;
  }
  connection->infos = info;
}

/*
static struct device *find_device(const struct sockaddr_storage *addr)
{
  struct device *device;

  device = g_devices;
  while (device) {
     if (0 == memcmp(&device->addr, addr, sizeof(struct sockaddr_storage))) {
       return device;
     }
     device = device->next;
  }

  return NULL;
}
*/

int addr_port(const struct sockaddr_storage *addr)
{
  switch (addr->ss_family) {
  case AF_INET6:
    return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
  case AF_INET:
    return ntohs(((struct sockaddr_in *)addr)->sin_port);
  default:
    return -1;
  }
}

static char* get_port_name(int port)
{
  /* Some common ports */
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

  if (g_port_db) {
      // TODO: TCP/UDP flag needed?
      return lookup_port_name(port, 1, g_port_db);
  }

  return NULL;
}

static char* get_hostname(const struct sockaddr_storage *addr)
{
  char *name;

  name = lookup_dns_name(addr);
  if (name)
    return name;

  name = lookup_hostbyaddr(addr);
  if (name)
    return name;

  return NULL;
}

static void parse_http(struct connection *connection, const u_char *payload, size_t payload_len)
{
  char path[256];
  const int offset = 4;

  path[0] = '\0';

  if (payload_len <= offset)
      return;

  if (memcmp("GET ", payload, offset))
    return;

  int i;
  for (i = offset; i < payload_len; i++) {
    const int c = payload[i];
    if (c < '!' || c > '~') {
      break;
    }
  }

  int len = i - offset;
  if (i > offset && len < sizeof(path)) {
    memcpy(path, &payload[offset], len);
    path[len] = '\0';
    add_info(connection, path);
  }
}

static struct connection *find_connection(struct device *device, const struct sockaddr_storage *daddr)
{
  struct connection *connection;

  connection = device->connections;
  while (connection) {
    if (0 == memcmp(&connection->daddr, daddr, sizeof(struct sockaddr_storage))) {
      return connection;
    }
    connection = connection->next;
  }

  return NULL;
}

static struct device *get_device(
  const struct ether_addr *mac,
  const struct sockaddr_storage *addr)
{
  struct device *device;
  char *hostname;
  char *ouiname;

  device = find_device(mac);
  if (device) {
    return device;
  }

  hostname = lookup_dhcp_hostname(mac, g_leases_input);
  ouiname = lookup_oui_name(mac, g_mac_db);
  device = (struct device*) calloc(1, sizeof(struct device));
  memcpy(&device->mac, mac, sizeof(struct ether_addr));
  device->last_seen = g_now;
  device->first_seen = g_now;
  device->hostname = hostname;
  device->ouiname = ouiname;

  if (g_devices) {
    device->next = g_devices;
  }
  g_devices = device;

  return device;
}

static void add_connection(
  const struct ether_addr *smac,
  const struct ether_addr *dmac,
  const struct sockaddr_storage *saddr,
  const struct sockaddr_storage *daddr,
  const u_char *payload, size_t payload_len,
  size_t len)
{
  struct connection *connection;
  struct device *device;

  // source port
  int dport = addr_port(daddr);

  debug("add_connection() for port %d\n", dport);

  if (dport == 53 && dport == 5353) {
    debug("parse DNS: %d\n", dport);
    parse_dns(payload, payload_len, &handle_dns_rr);
  }

  device = find_device(dmac);
  if (device) {
    device->download += len;
    connection = find_connection(device, saddr);
    if (connection) {
      connection->download += len;
    }
  }

  // Ignore own MAC address
  if (0 == memcmp(smac, &g_dev_mac, sizeof(struct ether_addr))) {
    debug("ignore own mac\n");
    return;
  }

  device = get_device(smac, saddr);
  device->last_seen = g_now;
  connection = find_connection(device, daddr);

  if (connection) {
    connection->times_accessed += 1;
    connection->last_accessed = g_now;
    connection->upload += len;
    device->upload += len;
    return;
  }
  connection = (struct connection*) calloc(1, sizeof(struct connection));
  connection->portname = get_port_name(dport);
  connection->hostname = get_hostname(daddr);
  memcpy(&connection->saddr, saddr, sizeof(struct sockaddr_storage));
  memcpy(&connection->daddr, daddr, sizeof(struct sockaddr_storage));
  connection->times_accessed = 1;
  connection->last_accessed = g_now;
  connection->first_accessed = g_now;
  connection->upload = len;
  device->upload = len;

  if (device->connections) {
    connection->next = device->connections;
  }
  device->connections = connection;

  if (dport == 80) {
      debug("parse HTTP: %d\n", dport);
      parse_http(connection, payload, payload_len);
  }
}

const char *json_sanitize(const char str[])
{
  static char buf[500];
  int len;
  int i;
  int j;

  if (!str) {
    buf[0] = '\0';
    return buf;
  }

  len = strlen(str);
  for (i = 0, j = 0; i < len && (j + 1) < sizeof(buf); i++) {
    const int c = str[i];
    if (c == '"') {
      buf[j++] = '\\';
      buf[j++] = '"';
    } else if (c == '\\') {
      buf[j++] = '\\';
      buf[j++] = '\\';
    } else if (c >= ' ' && c <= '~') {
      buf[j++] = c;
    } else {
      buf[j++] = '?';
    }
  }

  buf[j] = '\0';

  return buf;
}

static void write_json(const char path[])
{
  struct device *device;
  struct connection *connection;
  struct info *info;
  FILE *fp;

  fp = fopen(path, "w");
  if (fp == NULL) {
    fprintf(stderr, "fopen(): %s %s\n", path, strerror(errno));
    return;
  }

  fprintf(fp, "{\n");
  device = g_devices;
  while (device) {
    fprintf(fp, " \"%s\": {\n", str_mac(&device->mac));
    fprintf(fp, "  \"hostname\": \"%s\",\n", json_sanitize(device->hostname));
    fprintf(fp, "  \"ouiname\": \"%s\",\n", json_sanitize(device->ouiname));
    fprintf(fp, "  \"upload\": %"PRIu64",\n", device->upload);
    fprintf(fp, "  \"download\": %"PRIu64",\n", device->download);
    fprintf(fp, "  \"first_seen\": %"PRIu32",\n", (uint32_t) (g_now - device->first_seen));
    fprintf(fp, "  \"last_seen\": %"PRIu32",\n", (uint32_t) (g_now - device->last_seen));
    fprintf(fp, "  \"connections\": [\n");

    connection = device->connections;
    while (connection) {
      fprintf(fp, "   {\n");
      fprintf(fp, "    \"saddr\": \"%s\",\n", str_addr(&connection->saddr));
      fprintf(fp, "    \"daddr\": \"%s\",\n", str_addr(&connection->daddr));
      fprintf(fp, "    \"hostname\": \"%s\",\n", json_sanitize(connection->hostname));
      fprintf(fp, "    \"portname\": \"%s\",\n", json_sanitize(connection->portname));
      fprintf(fp, "    \"first_accessed\": %"PRIu32",\n", (uint32_t) (g_now - connection->first_accessed));
      fprintf(fp, "    \"last_accessed\": %"PRIu32",\n", (uint32_t) (g_now - connection->last_accessed));
      fprintf(fp, "    \"upload\": %"PRIu64",\n", connection->upload);
      fprintf(fp, "    \"download\": %"PRIu64",\n", connection->download);

      fprintf(fp, "    \"infos\": [\n");
      info = connection->infos;
      while (info) {
        fprintf(fp, "    \"%s\"", json_sanitize(info->data));

        info = info->next;

        if (info) {
          fprintf(fp, ",\n");
        } else {
          fprintf(fp, "\n");
        }
      }
      fprintf(fp, "    ]\n");

      connection = connection->next;

      if (connection) {
        fprintf(fp, "   },\n");
      } else {
        fprintf(fp, "   }\n");
      }
    }
    fprintf(fp, "  ]\n");

    device = device->next;

    if (device) {
      fprintf(fp, " },\n");
    } else {
      fprintf(fp, " }\n");
    }
  }
  fprintf(fp, "}\n");

  fclose(fp);
}

int get_device_mac(struct ether_addr *mac, const char dev[])
{
  struct ifreq s;
  int fd;

  fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  strcpy(s.ifr_name, dev);
  if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
    memcpy(mac, &s.ifr_addr.sa_data[0], 6);
    return 0;
  }
  return 1;
}

void handle_pcap_event(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* payload)
{
  g_now = time(NULL);

  parse_packet(pkthdr, payload, &add_connection);

  /* Write JSON every second */
  if (g_now > g_output_timer) {
    g_output_timer = g_now;
    write_json(g_json_ouput);
  }
}

enum {
  oDev,
  oMacDb,
  oPortDb,
  oJsonOutput,
  oLeasesOutput,
  oHelp
};

static struct option options[] = {
  {"dev", required_argument, 0, oDev},
  {"mac-db", required_argument, 0, oMacDb},
  {"port-db", required_argument, 0, oPortDb},
  {"json-output", required_argument, 0, oJsonOutput},
  {"leases-input", required_argument, 0, oLeasesOutput},
  {"help", no_argument, 0, oHelp},
  {0, 0, 0, 0}
};

/*
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
*/

int file_exists(const char path[])
{
  return access(path, F_OK) != -1;
}

static const char *help_text = "\n"
  " --dev <device>		Network device to listen on\n"
  " --mac-db <file>	MAC manufacturer database\n"
  " --port-db <file>	Port name database\n"
  " --json-output <file>	JSON output file\n"
  " --leases-input <file>	DHCP lease file\n"
  " --help			Display this help\n";

int main(int argc, char **argv)
{
  const char *json_output = "/tmp/device-observatory.json";
  const char *leases_input = NULL;
  const char *mac_db = NULL;
  const char *port_db = NULL;
  const char *dev = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* descr;
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
    case oDev:
      dev = optarg;
      break;
    case oMacDb:
      mac_db = optarg;
      break;
    case oPortDb:
      port_db = optarg;
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

  if (mac_db && !file_exists(mac_db)) {
    fprintf(stderr, "File not found: %s\n", mac_db);
    return 1;
  }

  if (port_db && !file_exists(port_db)) {
    fprintf(stderr, "File not found: %s\n", port_db);
    return 1;
  }

  if (!dev) {
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
      fprintf(stderr, "%s\n", errbuf);
      return 1;
    }
  }

  get_device_mac(&g_dev_mac, dev);

  printf("Listening on device: %s\n", dev);
  printf("Device MAC: %s\n", str_mac(&g_dev_mac));
  printf("DHCP leases file: %s\n", leases_input);
  printf("MAC OUI database: %s\n", mac_db);
  printf("JSON output file: %s\n", json_output);

  g_leases_input = leases_input;
  g_json_ouput = json_output;
  g_mac_db = mac_db;
  g_port_db = port_db;

  /*
   * Try 10 times to listen on a device,
   * in case this program ist started at boot
   */
  int wait = 1;
  while (wait < 10) {
    descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    if (descr == NULL) {
      fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
    } else {
      pcap_loop(descr, -1, handle_pcap_event, NULL);
      wait = 1;
    }

    sleep(wait++);
  }

  if (wait >= 10) {
    fprintf(stderr, "Giving up...");
  }

  return (wait != 1);
}
