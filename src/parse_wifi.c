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
      if (expected_len >= min_len && match_len >= expected_len && expected_len < sizeof(ssid)) {
        snprintf(ssid, sizeof(ssid), "SSID: %.*s", expected_len, &payload[start]);
        add_device_info(device, ssid);
      }
      start = -1;
    }
  }
}

struct ieee80211_radiotap_header {
  u_int8_t    it_version;     /* set to 0 */
  u_int8_t    it_pad;
  u_int16_t   it_len;         /* entire length */
  u_int32_t   it_present;     /* fields present */
} __attribute__((__packed__));

/*
 * Parse wifi packets. The parsing method is very crude! (TODO) 
 */
void parse_wifi(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* payload)
{
  static struct ether_addr broadcast = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
  struct ieee80211_radiotap_header *rthdr;
  u_int payload_length = pkthdr->len;
  struct ether_addr mac;
  struct device *device;
  int it_len;

  if (payload_length < sizeof(struct ieee80211_radiotap_header))
    return;

  rthdr = (typeof(rthdr)) payload;
  it_len = le16toh(rthdr->it_len);

  if (payload_length <= (it_len + 16))
    return;

  // Check for broadcast
  if (0 != memcmp(&payload[it_len + 4], &broadcast, 6))
    return;

  // Extract sender MAC
  memcpy(&mac, &payload[it_len + 10], 6);

  device = find_device_by_mac(&mac);

  if (device) {
    extract_ssids(payload, payload_length, device);
  }
}
