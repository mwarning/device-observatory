#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <inttypes.h>
#include <sys/select.h>
#include <signal.h>
#include <getopt.h>
#include <sys/time.h>

#include "parse_ether.h"
#include "parse_dns.h"
#include "parse_wifi.h"
#include "webserver.h"
#include "resolve.h"
#include "utils.h"
#include "data.h"
#include "main.h"


static const char *help_text = "\n"
  " --dev <device>			Ethernet device to listen for network traffic.\n"
  "				Argument may occur multiple times.\n"
  " --mdev <device>		Monitoring device to listen for Wifi beacons\n"
  "				Argument may occur multiple times.\n"
  " --mac-db <file>		MAC manufacturer database. Default: disabled\n"
  " --port-db <file>		Port name database. Default: disabled\n"
  " --json-output <file>		JSON output file. Default: disabled\n"
  " --device-timeout <seconds>	Timeout device information after last activity. Default: never\n"
  " --track-localhost <0|1>	Do not track localhost. Default: true\n"
#ifdef WEBSERVER
  " --webserver-port <port>	Port for the build-in webserver. Set to 0 to disable webserver. Default: 8080\n"
  " --webserver-path <path>	Root folder for the build-in webserver. Default: internal\n"
#endif
  " --help				Display this help\n";

// Global settings
static const char *g_mac_db = NULL;
static const char *g_port_db = NULL;
static const char *g_json_output = NULL;
static uint32_t g_track_localhost = 1;
static uint32_t g_device_timeout = UINT32_MAX;

// Interface information
typedef void pcap_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *data);
static pcap_t *g_pcap[8];
static pcap_callback *g_pcbs[8];
static char *g_pcap_dev[8];
static struct ether_addr g_pcap_macs[8];
static int g_pcap_num = 0;

// Time time between json writes
static time_t g_once_per_second = 0;

// Run state
static int g_is_running;

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
  const int offset = 4;
  char path[256];
  int i;

  path[0] = '\0';

  if (payload_len <= offset)
      return;

  if (memcmp("GET ", payload, offset))
    return;

  for (i = offset; i < payload_len; i++) {
    if (payload[i] < '!' || payload[i] > '~') {
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

static struct device *get_device(
  const struct ether_addr *mac,
  const struct sockaddr_storage *addr)
{
  struct device *device;
  char *ouiname;

  device = find_device_by_mac(mac);
  if (device) {
    return device;
  }

  ouiname = lookup_oui_name(mac, g_mac_db);
  device = (struct device*) calloc(1, sizeof(struct device));
  memcpy(&device->mac, mac, sizeof(struct ether_addr));
  device->last_seen = g_now;
  device->first_seen = g_now;
  device->ouiname = ouiname;

  if (g_devices) {
    device->next = g_devices;
  }
  g_devices = device;

  return device;
}

static void parse_dhcp(struct device *device, const uint8_t *payload, size_t payload_len)
{
  char buf[64];
  int i;
  int j;

  if (payload_len < 240) {
    return;
  }

  if (payload[0] != 0x01 || payload[1] != 0x01 || payload[2] != 0x06 || payload[3] != 0x00) {
    return;
  }

  // Check magic value
  if (payload[236] != 0x63 || payload[237] != 0x82 || payload[238] != 0x53 || payload[239] != 0x63) {
    return;
  }

  for (i = 240; i < payload_len - 1; i++) {
    int option = payload[i];
    int option_len = payload[i + 1];

    if ((i + 1 + option_len) >= payload_len) {
      break;
    }

    // Hostname option
    if (option == 0x0c) {
      // Read hostname
      for (j = 0; j < option_len; j++) {
        int c = payload[i + 2 + j];
        if (c < ' ' || c > '~')
          break;
      }

      snprintf(buf, sizeof(buf), "%.*s", option_len, &payload[i+2]);

      if (device->hostname) {
        free(device->hostname);
      }
      device->hostname = strdup(buf);
      break;
    } else {
      // Jump over entry
      i += 1 + option_len;
    }
  }
}

void add_connection(
  const struct ether_addr *smac,
  const struct ether_addr *dmac,
  const struct sockaddr_storage *saddr,
  const struct sockaddr_storage *daddr,
  const u_char *payload, size_t payload_len,
  size_t len)
{
  struct connection *connection;
  struct device *device;
  int sport;
  int dport;
  int i;

  sport = addr_port(saddr);
  dport = addr_port(daddr);

  debug("add_connection() for port %d\n", dport);

  // Remember DNS server reponse (or multicast DNS)
  if (sport == 53 || dport == 53 || sport == 5353 || dport == 5353) {
    debug("parse DNS: %d\n", dport);
    parse_dns(payload, payload_len, &handle_dns_rr);
  }

  device = find_device_by_mac(dmac);
  if (device) {
    device->download += len;
    connection = find_connection(device, saddr);
    if (connection) {
      connection->download += len;
    }
  }

  if (!g_track_localhost) {
    // Prevent logging of localhost MAC addresses
    for (i = 0; i < g_pcap_num; i++) {
      if (0 == memcmp(&g_pcap_macs[i], smac, sizeof(struct ether_addr))) {
        return;
      }
    }
  }

  device = get_device(smac, saddr);
  device->last_seen = g_now;
  connection = find_connection(device, daddr);

  if (connection) {
    connection->times_accessed += 1;
    connection->last_accessed = g_now;
    connection->upload += len;
    device->upload += len;
  } else {
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
  }

  if (dport == 80) {
    debug("parse HTTP: %d\n", dport);
    parse_http(connection, payload, payload_len);
  }

  if (sport == 68 || dport == 67) {
    debug("parse DHCP: %d\n", dport);
    parse_dhcp(device, payload, payload_len);
  }
}

static void write_json_to_file(const char path[])
{
  FILE *fp;

  fp = fopen(path, "w");
  if (fp == NULL) {
    fprintf(stderr, "fopen(): %s %s\n", path, strerror(errno));
    return;
  }

  write_devices_json(fp);

  fclose(fp);
}

static void unix_signal_handler(int signo)
{
  // exit on second stop request
  if (g_is_running == 0) {
    exit(1);
  }

  g_is_running = 0;

  printf("Shutting down...\n");
}

static void setup_signal_handlers()
{
  struct sigaction sig_stop;
  struct sigaction sig_term;

  // STRG+C aka SIGINT => Stop the program
  sig_stop.sa_handler = unix_signal_handler;
  sig_stop.sa_flags = 0;
  if ((sigemptyset(&sig_stop.sa_mask) == -1) || (sigaction(SIGINT, &sig_stop, NULL) != 0)) {
    fprintf(stderr, "Failed to set SIGINT handler: %s", strerror(errno));
    exit(1);
  }

  // SIGTERM => Stop the program gracefully
  sig_term.sa_handler = unix_signal_handler;
  sig_term.sa_flags = 0;
  if ((sigemptyset(&sig_term.sa_mask) == -1) || (sigaction(SIGTERM, &sig_term, NULL) != 0)) {
    fprintf(stderr, "Failed to set SIGTERM handler: %s", strerror(errno));
    exit(1);
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
    return EXIT_SUCCESS;
  }

  return EXIT_FAILURE;
}

static int add_interface(const char dev[], pcap_callback *cb)
{
  char errstr[PCAP_ERRBUF_SIZE];
  pcap_t *pd;
  int rc;

  if (g_pcap_num >= ARRAY_SIZE(g_pcap)) {
    fprintf(stderr, "Too many interfaces\n");
    return EXIT_FAILURE;
  }

  pd = pcap_open_live(dev, BUFSIZ, 1 /* promisc */, 500 /* timeout */, errstr);
  if (pd == NULL) {
    fprintf(stderr, "%s\n", errstr);
    return EXIT_FAILURE;
  }

  rc = pcap_setnonblock(pd, 1, errstr);
  if (rc == -1) {
    fprintf(stderr, "%s\n", errstr);
    return EXIT_FAILURE;
  }

  g_pcap[g_pcap_num] = pd;
  g_pcbs[g_pcap_num] = cb;
  g_pcap_dev[g_pcap_num] = strdup(dev);
  get_device_mac(&g_pcap_macs[g_pcap_num], dev);
  g_pcap_num += 1;

  return EXIT_SUCCESS;
}

enum {
  oDev,
  oMDev,
  oMacDb,
  oPortDb,
  oJsonOutput,
  oDeviceTimeout,
  oTrackLocalhost,
  oWebserverPort,
  oWebserverPath,
  oHelp
};

static struct option options[] = {
  {"dev", required_argument, 0, oDev},
  {"mdev", required_argument, 0, oMDev},
  {"mac-db", required_argument, 0, oMacDb},
  {"port-db", required_argument, 0, oPortDb},
  {"json-output", required_argument, 0, oJsonOutput},
  {"device-timeout", required_argument, 0, oDeviceTimeout},
  {"track-localhost", required_argument, 0, oTrackLocalhost},
#ifdef WEBSERVER
  {"webserver-port", required_argument, 0, oWebserverPort},
  {"webserver-path", required_argument, 0, oWebserverPath},
#endif
  {"help", no_argument, 0, oHelp},
  {0, 0, 0, 0}
};

int file_exists(const char path[])
{
  return access(path, F_OK) != -1;
}

int main(int argc, char **argv)
{
#ifdef WEBSERVER
  int webserver_port = 8080;
  const char *webserver_path = NULL;
#endif
  struct timeval tv;
  fd_set rset;
  fd_set wset;
  fd_set xset;
  int maxfd;
  int index;
  int rc;
  int i;

  i = 1;
  while (i) {
    index = 0;
    int c = getopt_long(argc, argv, "", options, &index);

    switch (c)
    {
    case oDev:
      // Parse raw ethernet packets
      rc = add_interface(optarg, &parse_ether);
      if (rc == EXIT_FAILURE)
        return EXIT_FAILURE;
      break;
    case oMDev:
      // Parse raw wifi packets
      rc = add_interface(optarg, &parse_wifi);
      if (rc == EXIT_FAILURE)
        return EXIT_FAILURE;
      break;
    case oTrackLocalhost:
      g_track_localhost = atoi(optarg);
      break;
#ifdef WEBSERVER
    case oWebserverPort:
      webserver_port = atoi(optarg);
      break;
    case oWebserverPath:
      webserver_path = optarg;
      break;
#endif
    case oMacDb:
      g_mac_db = optarg;
      break;
    case oPortDb:
      g_port_db = optarg;
      break;
    case oJsonOutput:
      g_json_output = optarg;
      break;
    case oDeviceTimeout:
      g_device_timeout = atoi(optarg);
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
      i = 0;
      break;
    //case '?':
    //  return 1;
    default:
      return EXIT_FAILURE;
    }
  }

  if (g_mac_db && !file_exists(g_mac_db)) {
    fprintf(stderr, "File not found: %s\n", g_mac_db);
    return EXIT_FAILURE;
  }

  if (g_port_db && !file_exists(g_port_db)) {
    fprintf(stderr, "File not found: %s\n", g_port_db);
    return EXIT_FAILURE;
  }

#ifdef WEBSERVER
  if (webserver_port < 0) {
    fprintf(stderr, "Invalid webserver port\n");
    return EXIT_FAILURE;
  }

  if (webserver_path && !file_exists(webserver_path)) {
    fprintf(stderr, "Invalid webserver path: %s\n", webserver_path);
    return EXIT_FAILURE;
  }
#endif

  if (g_device_timeout < 0) {
    fprintf(stderr, "Invalid device timeout: %u\n", g_device_timeout);
    return EXIT_FAILURE;
  }

  if (g_pcap_num == 0) {
    fprintf(stderr, "No interfaces configured\n");
    return EXIT_FAILURE;
  }

  printf("Listen on devices:\n");
  for (i = 0; i < g_pcap_num; i++) {
    printf(" * %s (%s)\n", g_pcap_dev[i],
      (g_pcbs[i] == &parse_ether) ? "ethernet" : "monitoring");
  }
  printf("MAC OUI database: %s\n", g_mac_db ? g_mac_db : "none");
  printf("JSON output file: %s\n", g_json_output ? g_json_output : "none");
  printf("Device timeout: %s\n", formatDuration(g_device_timeout));
  printf("Track Localhost: %s\n", g_track_localhost ? "on" : "off");
#ifdef WEBSERVER
  printf("Webserver port: %d\n", webserver_port);
  printf("Webserver path: %s\n", webserver_path ? webserver_path : "internal");
#endif

  setup_signal_handlers();

#ifdef WEBSERVER
  if (webserver_port) {
    rc = webserver_start(webserver_path, webserver_port);
    if (rc == EXIT_FAILURE)
      return EXIT_FAILURE;
  }
#endif

  g_is_running = 1;
  while (g_is_running) {
    g_now = time(NULL);

    // Make select block for at most 1 second
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    FD_ZERO(&rset);
    FD_ZERO(&wset);
    FD_ZERO(&xset);

    maxfd = 0;

    for (i = 0; i < g_pcap_num; i++) {
      int fd = pcap_get_selectable_fd(g_pcap[i]);
      FD_SET(fd, &rset);
      if (fd > maxfd) {
        maxfd = fd;
      }
    }
#ifdef WEBSERVER
    if (webserver_port) {
      webserver_before_select(&rset, &wset, &xset, &maxfd);
    }
#endif
    if (select(maxfd + 1, &rset, &wset, &xset, &tv) < 0) {
      if( errno == EINTR ) {
        continue;
      }

      //fprintf(stderr, "select() %s\n", strerror(errno));
      return EXIT_FAILURE;
    }

    for (i = 0; i < g_pcap_num; i++) {
      if (FD_ISSET(pcap_get_selectable_fd(g_pcap[i]), &rset)) {
        if (pcap_dispatch(g_pcap[i], 1, g_pcbs[i], NULL) < 0) {
          fprintf(stderr, "pcap_dispatch() %s\n", strerror(errno));
          return EXIT_FAILURE;
        }
      }
    }

    if (g_now != g_once_per_second) {
      g_once_per_second = g_now;

      /* Remove devices after a specific time */
      if (g_device_timeout < UINT32_MAX) {
        timeout_devices(g_device_timeout);
      }

      /* Write JSON every second */
      if (g_json_output) {
        write_json_to_file(g_json_output);
      }
    }
#ifdef WEBSERVER
    if (webserver_port) {
      webserver_after_select();
    }
#endif
  }

  return EXIT_SUCCESS;
}
