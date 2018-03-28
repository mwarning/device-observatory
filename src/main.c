#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/ether.h>
#include <inttypes.h>
#include <getopt.h>

//#include <microhttpd.h>

#include "parse_packet.h"
#include "parse_dns.h"
#include "resolve.h"
#include "utils.h"
#include "data.h"
#include "main.h"


static const char *help_text = "\n"
  " --dev <device>		Ethernet device to listen for network traffic\n"
  " --mdev <device>   Monitoring device to listen for Wifi beacons\n"
  " --mac-db <file>	MAC manufacturer database\n"
  " --port-db <file>	Port name database\n"
  " --json-output <file>	JSON output file\n"
  " --leases-input <file>	DHCP lease file\n"
  " --device-timeout <seconds>	Timeout device information after last activity\n"
  " --help			Display this help\n";

static const char *g_mac_db = NULL;
static const char *g_port_db = NULL;
static const char *g_leases_input = NULL;
static const char *g_json_output = NULL;
static uint32_t g_device_timeout = UINT32_MAX;

// Own MAC address
static struct ether_addr g_dev_mac = {0};

// Time time between json writes
static time_t g_output_timer = 0;

// Current time
time_t g_now = 0;


static int addr_port(const struct sockaddr_storage *addr)
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
    add_connection_info(connection, path);
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
  int sport = addr_port(saddr);
  int dport = addr_port(daddr);

  debug("add_connection() for port %d\n", dport);

  if (sport == 53 || dport == 53 || sport == 5353 || dport == 5353) {
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

  /* Remove devices after a specific time */
  if (g_device_timeout < UINT32_MAX) {
	  timeout_devices(g_device_timeout);
  }

  /* Write JSON every second */
  if (g_now > g_output_timer) {
    g_output_timer = g_now;
    write_json(g_json_output);
  }
}

enum {
  oDev,
  oMDev,
  oMacDb,
  oPortDb,
  oJsonOutput,
  oLeasesOutput,
  oDeviceTimeout,
  oHelp
};

static struct option options[] = {
  {"dev", required_argument, 0, oDev},
  {"mdev", required_argument, 0, oMDev},
  {"mac-db", required_argument, 0, oMacDb},
  {"port-db", required_argument, 0, oPortDb},
  {"json-output", required_argument, 0, oJsonOutput},
  {"leases-input", required_argument, 0, oLeasesOutput},
  {"device-timeout", required_argument, 0, oDeviceTimeout},
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

int main(int argc, char **argv)
{
  const char *json_output = "/tmp/device-observatory.json";
  const char *leases_input = NULL;
  const char *mac_db = NULL;
  const char *port_db = NULL;
  const char *mdev = NULL;
  const char *dev = NULL;
  uint32_t device_timeout = UINT32_MAX;
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
    case oMDev:
      mdev = optarg;
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
    case oDeviceTimeout:
      device_timeout = atoi(optarg);
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

  if (device_timeout < 0) {
  	fprintf(stderr, "Invalid device timeout\n");
  	return 1;
  }

  get_device_mac(&g_dev_mac, dev);
  g_leases_input = leases_input;
  g_json_output = json_output;
  g_mac_db = mac_db;
  g_port_db = port_db;
  g_device_timeout = device_timeout;

  printf("Listen on ethernet device: %s\n", dev);
  printf("Listen on monitoring device: %s\n", mdev);
  printf("Device MAC: %s\n", str_mac(&g_dev_mac));
  printf("DHCP leases file: %s\n", g_leases_input);
  printf("MAC OUI database: %s\n", g_mac_db);
  printf("JSON output file: %s\n", g_json_output);
  printf("Device timeout: %s\n", formatDuration(g_device_timeout));

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
