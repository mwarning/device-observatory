#ifndef _PARSE_DNS_H_
#define _PARSE_DNS_H_


/* Data part of a Resource Record */
union ResourceData {
  struct {
    char *txt_data;
  } txt_record;
  struct {
      struct in_addr addr;
  } a_record;
  struct {
    char* MName;
    char* RName;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
  } soa_record;
  struct {
    char *name;
  } name_server_record;
  struct {
    char name;
  } cname_record;
  struct {
    char *name;
  } ptr_record;
  struct {
    uint16_t preference;
    char *exchange;
  } mx_record;
  struct {
    struct in6_addr addr;
  } aaaa_record;
  struct {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    char *target;
  } srv_record;
};

/* Resource Record Section */
struct ResourceRecord {
  char name[256]; // variable size
  int type;
  int class;
  int ttl;
  int rd_length;
  union ResourceData rd_data;
};

/* Resource Record Types */
enum {
  A_Resource_RecordType = 1,
  NS_Resource_RecordType = 2,
  CNAME_Resource_RecordType = 5,
  SOA_Resource_RecordType = 6,
  PTR_Resource_RecordType = 12,
  MX_Resource_RecordType = 15,
  TXT_Resource_RecordType = 16,
  AAAA_Resource_RecordType = 28,
  SRV_Resource_RecordType = 33
};

enum {
  RR_TYPE_QUESTION,
  RR_TYPE_ANSWER,
  RR_TYPE_AUTHORITY,
  RR_TYPE_ADDITIONAL
};

typedef void dns_callback(const struct ResourceRecord *rr, int rr_type);

void parse_dns(const uint8_t *payload, size_t payload_len, dns_callback *cb);

#endif // _PARSE_DNS_H_