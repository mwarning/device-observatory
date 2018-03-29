#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#include "utils.h"


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

const char *formatDuration(uint32_t time)
{
  static char buf[16];
  unsigned years;
  unsigned days;
  unsigned hours;
  unsigned minutes;
  unsigned seconds;

  if (time < UINT32_MAX) {
    years = time / 31536000;
    time -= years * 31536000;
    days = time / 86400;
    time -= days * 86400;
    hours = time / 3600;
    time -= hours * 3600;
    minutes = time / 60;
    time -= hours * 60;
    seconds = time;

    UNUSED(years);

    sprintf(buf, "%02u:%02u:%02u", hours, minutes, seconds);
  } else {
    sprintf(buf, "%s", "-");
  }

  return buf;
}

void printHexDump(const void *addr, int len)
{
  int i;
  unsigned char buff[17];
  unsigned char *pc = (unsigned char*)addr;

  if (len == 0) {
    printf("  ZERO LENGTH\n");
    return;
  }
  if (len < 0) {
    printf("  NEGATIVE LENGTH: %i\n",len);
    return;
  }

  // Process every byte in the data.
  for (i = 0; i < len; i++) {
    // Multiple of 16 means new line (with line offset).

    if ((i % 16) == 0) {
      // Just don't print ASCII for the zeroth line.
      if (i != 0)
        printf ("  %s\n", buff);

      // Output the offset.
      printf ("  %04x ", i);
    }

    // Now the hex code for the specific character.
    printf (" %02x", pc[i]);

    // And store a printable ASCII character for later.
    if ((pc[i] < 0x20) || (pc[i] > 0x7e))
      buff[i % 16] = '.';
    else
      buff[i % 16] = pc[i];

    buff[(i % 16) + 1] = '\0';
  }

  // Pad out last line if not exactly 16 characters.
  while ((i % 16) != 0) {
    printf ("   ");
    i++;
  }

  // And print the final ASCII bit.
  printf ("  %s\n", buff);
}

int includesString(const uint8_t* payload, size_t payload_length, const uint8_t str[], size_t len)
{
  int i;

  if (len == 0)
    return 0;

  if (len > payload_length)
    return 0;

  for (i = 0; i < (payload_length - len); i++) {
    if (payload[i] == str[0]) {
      if (!memcmp(&payload[i], str, len)) {
        return 1;
      }
    }
  }

  return 0;
}

void printStrings(const uint8_t* payload, size_t payload_length, int min)
{
  int start;
  int i;

  start = -1;
  for (i = 0; i < payload_length; i++) {
    if (isalnum(payload[i])) {
      if (start < 0) {
        start = i;
      }
    } else {
      if (start >= 0) {
        if ((i - start) >= min) {
          printf("%.*s\n", (int) (i - start), &payload[start]);
        }
        start = -1;
      }
    }
  }
}
