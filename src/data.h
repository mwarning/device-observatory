#ifndef _DATA_H_
#define _DATA_H_

#include <netinet/ether.h>
#include <time.h>


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
  struct info *infos;
  time_t first_seen;
  time_t last_seen;
  uint64_t upload;
  uint64_t download;
  struct connection *connections;
  struct device *next;
};

extern struct device *g_devices;

void timeout_devices(uint32_t age_seconds);
void write_devices_json(FILE *fp);
void write_device_json(FILE *fp, const struct device *device);
struct device *find_device_by_ip(const  struct sockaddr *ip);
struct device *find_device_by_mac(const struct ether_addr *mac);
struct connection *find_connection(struct device *device, const struct sockaddr_storage *daddr);
void add_connection_info(struct connection *connection, const char data[]);
void add_device_info(struct device *device, const char data[]);

#endif // _DATA_H_