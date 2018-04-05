#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "main.h"
#include "utils.h"
#include "data.h"


struct device *g_devices = NULL;


void free_info(struct info *info)
{
  free(info->data);
  free(info);
}

void free_infos(struct info *info)
{
  struct info *next;

  while (info) {
    next = info->next;
    free_info(info);
    info = next;
  }
}

void free_connection(struct connection *connection)
{
  free_infos(connection->infos);
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

  free_infos(device->infos);
  free(device->hostname);
  free(device->ouiname);
  free(device);
}

void timeout_devices(uint32_t age_seconds)
{
  struct device *device;
  struct device *prev;
  struct device *next;

  prev = NULL;
  next = NULL;

  device = g_devices;
  while (device) {
    if ((g_now - device->last_seen) > age_seconds) {
      next = device->next;
      if (prev) {
        prev->next = next;
      } else {
        g_devices = next;
      }
      free_device(device);
      device = next;
    } else {
      prev = device;
      device = device->next;
    }
  }
}

static int is_addr_equal(const struct sockaddr *addr1, const struct sockaddr *addr2)
{
	if (addr1->sa_family != addr2->sa_family) {
		return 0;
	} else if (addr1->sa_family == AF_INET) {
		return 0 == memcmp(&((struct sockaddr_in *)addr1)->sin_addr, &((struct sockaddr_in *)addr2)->sin_addr, 4);
	} else if (addr1->sa_family == AF_INET6) {
		return 0 == memcmp(&((struct sockaddr_in6 *)addr1)->sin6_addr, &((struct sockaddr_in6 *)addr2)->sin6_addr, 16);
	} else {
		return 0;
   }
}

struct device *find_device_by_ip(const struct sockaddr *ip)
{
  struct connection *connection;
  struct device *device;

  if (!ip) {
    return NULL;
  }

  device = g_devices;
  while (device) {
    connection = device->connections;
    while(connection) {
      if (is_addr_equal((const struct sockaddr *) &connection->saddr, ip)) {
        return device;
      }
      connection = connection->next;
    }
    device = device->next;
  }

  return NULL;
}

struct device *find_device_by_mac(const struct ether_addr *mac)
{
  struct device *device;

  if (!mac) {
    return NULL;
  }

  device = g_devices;
  while (device) {
     if (0 == memcmp(&device->mac, mac, sizeof(struct ether_addr))) {
       return device;
     }
     device = device->next;
  }

  return NULL;
}

struct connection *find_connection(struct device *device, const struct sockaddr_storage *daddr)
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

static void add_info(struct info **infos, const char data[])
{
  struct info *info;

  if (data == NULL || data[0] == '\0')
    return;

  info = *infos;
  while (info) {
    if (0 == strcmp(info->data, data)) {
      return;
    }
    info = info->next;
  }

  info = (struct info*) calloc(1, sizeof(struct info));
  info->data = strdup(data);

  // prepend new item to list
  if (*infos) {
    info->next = *infos;
  }
  *infos = info;
}

void add_connection_info(struct connection *connection, const char data[])
{
  add_info(&connection->infos, data);
}

void add_device_info(struct device *device, const char data[])
{
  add_info(&device->infos, data);
}

static const char *json_sanitize(const char str[])
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

static void write_json(FILE *fp, const struct device *device)
{
  struct connection *connection;
  struct info *info;

  fprintf(fp, " \"%s\": {\n", str_mac(&device->mac));
  fprintf(fp, "  \"hostname\": \"%s\",\n", json_sanitize(device->hostname));
  fprintf(fp, "  \"ouiname\": \"%s\",\n", json_sanitize(device->ouiname));
  fprintf(fp, "  \"upload\": %"PRIu64",\n", device->upload);
  fprintf(fp, "  \"download\": %"PRIu64",\n", device->download);
  fprintf(fp, "  \"first_seen\": %"PRIu32",\n", (uint32_t) (g_now - device->first_seen));
  fprintf(fp, "  \"last_seen\": %"PRIu32",\n", (uint32_t) (g_now - device->last_seen));

  fprintf(fp, "  \"infos\": [\n");
  info = device->infos;
  while (info) {
    fprintf(fp, "  \"%s\"", json_sanitize(info->data));

    info = info->next;

    if (info) {
      fprintf(fp, ",\n");
    } else {
      fprintf(fp, "\n");
    }
  }
  fprintf(fp, "  ],\n");

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

  fprintf(fp, " }\n");
}

void write_devices_json(FILE *fp)
{
  struct device *device;

  fprintf(fp, "{\n");
  device = g_devices;
  while (device) {
    write_json(fp, device);
    device = device->next;

    if (device) {
      fprintf(fp, ",");
    }
  }
  fprintf(fp, "}\n");
}

void write_device_json(FILE *fp, const struct device *device)
{
  fprintf(fp, "{\n");

  if (device) {
    write_json(fp, device);
  }

  fprintf(fp, "}\n");
}
