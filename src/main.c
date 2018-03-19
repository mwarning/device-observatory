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
#include <getopt.h>

//#include <microhttpd.h>

#include "parse_packet.h"
#include "resolve.h"


static const char *g_mac_db = NULL;
static const char *g_leases_input = NULL;
static const char *g_json_ouput = NULL;
static struct ether_addr g_dev_mac = {0};
static time_t g_output_timer = 0;
static time_t g_now = 0;


struct activity
{
  char *hostname;
  char *info;
  struct sockaddr_storage addr;
  int times_accessed;
  time_t first_accessed;
  time_t last_accessed;
  uint64_t upload;
  uint64_t download;
  struct activity *next;
};

struct device
{
  struct ether_addr mac;
  struct sockaddr_storage addr;
  char *ouiname;
  char *hostname;
  time_t first_seen;
  time_t last_seen;
  uint64_t upload;
  uint64_t download;
  struct activity *activities;
  struct device *next;
};

static struct device *g_devices = NULL;


void free_activity(struct activity *activity)
{
  free(activity->hostname);
  free(activity->info);
  free(activity);
}

void free_device(struct device *device)
{
  struct activity *activity;
  struct activity *next;

  activity = device->activities;
  while (activity) {
     next = activity->next;
     free_activity(activity);
     activity = next;
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

static struct activity *find_activity(struct device *device, const struct sockaddr_storage *addr)
{
  struct activity *activity;

  activity = device->activities;
  while (activity) {
    if (0 == memcmp(&activity->addr, addr, sizeof(struct sockaddr_storage))) {
      return activity;
    }
    activity = activity->next;
  }

  return NULL;
}

static struct device *get_device(
  const struct ether_addr *mac, const struct sockaddr_storage *addr)
{
  struct device *device;
  char *hostname;
  char *ouiname;

  device = find_device(mac);
  if (device) {
    return device;
  }

  hostname = lookup_dhcp_hostname(mac, g_leases_input);
  ouiname = lookup_oui(mac, g_mac_db);

  device = (struct device*) calloc(1, sizeof(struct device));
  memcpy(&device->mac, mac, sizeof(struct ether_addr));
  memcpy(&device->addr, addr, sizeof(struct sockaddr_storage));
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

void add_activity(
  const struct ether_addr *smac,
  const struct ether_addr *dmac,
  const struct sockaddr_storage *saddr,
  const struct sockaddr_storage *daddr,
  uint32_t len)
{
  struct activity *activity;
  struct device *device;
  char* hostname;
  char* info;

  device = find_device(dmac);
  if (device) {
    device->download += len;
    activity = find_activity(device, saddr);
    if (activity) {
      activity->download += len;
    }
  }

  // Ignore own MAC address
  if (0 == memcmp(smac, &g_dev_mac, sizeof(struct ether_addr))) {
    return;
  }

  device = get_device(smac, saddr);
  device->last_seen = g_now;

  activity = find_activity(device, daddr);
  if (activity) {
    activity->times_accessed += 1;
    activity->last_accessed = g_now;
    activity->upload += len;
    device->upload += len;
    return;
  }

  hostname = resolve_hostname(daddr);
  info = resolve_info(daddr);

  activity = (struct activity*) calloc(1, sizeof(struct activity));
  activity->hostname = hostname;
  activity->info = info;
  memcpy(&activity->addr, daddr, sizeof(struct sockaddr_storage));
  activity->times_accessed = 1;
  activity->last_accessed = g_now;
  activity->first_accessed = g_now;
  activity->upload = len;
  device->upload = len;

  if (device->activities) {
    activity->next = device->activities;
  }
  device->activities = activity;
}

const char *json_sanitize(const char str[])
{
  if (!str) {
    return "";
  }

  if (strchr(str, '"')) {
    return ""; //TODO
  } else {
    return str;
  }
}

void write_json(const char path[])
{
  struct device *device;
  struct activity *activity;
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
    fprintf(fp, "  \"addr\": \"%s\",\n", str_addr(&device->addr));
    fprintf(fp, "  \"hostname\": \"%s\",\n", json_sanitize(device->hostname));
    fprintf(fp, "  \"ouiname\": \"%s\",\n", json_sanitize(device->ouiname));
    fprintf(fp, "  \"upload\": %lu,\n", device->upload);
    fprintf(fp, "  \"download\": %lu,\n", device->download);
    fprintf(fp, "  \"first_seen\": %u,\n", (uint32_t) (g_now - device->first_seen));
    fprintf(fp, "  \"last_seen\": %u,\n", (uint32_t) (g_now - device->last_seen));

    fprintf(fp, "  \"activity\": {\n");
    activity = device->activities;
    while (activity) {
      fprintf(fp, "   \"%s\": {\n", str_addr(&activity->addr));
      fprintf(fp, "    \"hostname\": \"%s\",\n", json_sanitize(activity->hostname));
      fprintf(fp, "    \"info\": \"%s\",\n", json_sanitize(activity->info));
      //fprintf(fp, "    \"times_accessed\": %u,\n", (uint32_t) activity->times_accessed);
      fprintf(fp, "    \"first_accessed\": %u,\n", (uint32_t) (g_now - activity->first_accessed));
      fprintf(fp, "    \"last_accessed\": %u,\n", (uint32_t) (g_now - activity->last_accessed));
      fprintf(fp, "    \"upload\": %lu,\n", activity->upload);
      fprintf(fp, "    \"download\": %lu\n", activity->download);

      if (activity->next) {
        fprintf(fp, "   },\n");
      } else {
        fprintf(fp, "   }\n");
      }
      activity = activity->next;
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

  parse_packet(args, pkthdr, payload);

  if (g_now > g_output_timer) {
    g_output_timer = g_now;
    write_json(g_json_ouput);
  }
}

enum {
  oDev,
  oMacDb,
  oJsonOutput,
  oLeasesOutput,
  oHelp
};

static struct option options[] = {
  {"dev", required_argument, 0, oDev},
  {"mac-db", required_argument, 0, oMacDb},
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
  " --dev <device>\n"
  " --mac-db <file>		MAC manufacturer database\n"
  " --json-output <file>	JSON data output\n"
  " --leases-input <file>	DHCP lease file\n"
  " --help\n";

int main(int argc, char **argv)
{
  const char *json_output = "/tmp/device-observatory.json";
  const char *leases_input = "/tmp/dhcp.leases";
  const char *mac_db = "/usr/share/macdb/db.txt";
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

  if (!file_exists(mac_db)) {
    fprintf(stderr, "File not found: %s\n", mac_db);
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
  printf("JSON output file: %s\n", json_output);
  printf("MAC OUI database: %s\n", mac_db);

  g_leases_input = leases_input;
  g_json_ouput = json_output;
  g_mac_db = mac_db;

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
