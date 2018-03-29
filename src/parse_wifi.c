#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "data.h"
#include "utils.h"
#include "main.h"
#include "parse_wifi.h"


/*
static int frequency_to_channel(int freq)
{
  if (freq < 2412 && freq > 2472) {
    return -1;
  }

  return 1 + (freq - 2412) / 5;
}*/

// Extract SSID - since we don't know how to parse the packet yet
static void extract_ssids(const uint8_t* payload, size_t payload_length, struct device *device)
{
  char ssid[32];
  const int min_len = 2;
  int expected_len;
  int match_len;
  int start;
  int i;

  start = -1;
  for (i = 2; i < payload_length; i++) {
    if (isalnum(payload[i])) {
      if (start < 0) {
        start = i;
      }
    } else if (start >= 0) {
      match_len = i - start;
      expected_len = ntohs(*((uint16_t*) &payload[start - 2]));
      if (match_len >= min_len && expected_len >= min_len
          && match_len >= expected_len && expected_len < sizeof(ssid)) {
        printf("expected_len: %d\n", expected_len);
        printf("%.*s\n", expected_len, &payload[start]);
        if (device) {
          snprintf(ssid, sizeof(ssid), "%.*s", expected_len, &payload[start]);
          add_device_info(device, ssid);
        }
      }
      start = -1;
    }
  }
}

/*
 * Parse wifi packets. The parsing method is very crude! (TODO) 
 */
void parse_wifi(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* payload)
{
  static struct ether_addr broadcast = {{0xff}};
  u_int payload_length = pkthdr->len;
  struct ether_addr mac;
  struct device *device;
  int i;

  if (payload_length <= 12)
    return;

  // Search for sender mac after broadcast address
  for (i = 0; i < payload_length - 12; i++) {
    if (0 != memcmp(&payload[i], &broadcast, 6))
      continue;
    if (0 == memcmp(&payload[i + 6], &broadcast, 6))
      continue;

    memcpy(&mac, &payload[i + 6], 6);
    device = find_device(&mac);
    if (device) {
      printf("device: found!\n");
    }
    printf("mac: %s\n", str_mac(&mac));
    extract_ssids(payload, payload_length, NULL);
    break;
  }
}
