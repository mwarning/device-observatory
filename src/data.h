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
void write_json(const char path[]);
struct device *find_device(const struct ether_addr *mac);
void add_connection_info(struct connection *connection, const char data[]);
void add_device_info(struct device *device, const char data[]);

#endif // _DATA_H_