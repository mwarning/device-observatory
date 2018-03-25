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


/*
* Masks and constants.
*/

static const uint32_t QR_MASK = 0x8000;
static const uint32_t OPCODE_MASK = 0x7800;
static const uint32_t AA_MASK = 0x0400;
static const uint32_t TC_MASK = 0x0200;
static const uint32_t RD_MASK = 0x0100;
static const uint32_t RA_MASK = 0x8000;
static const uint32_t RCODE_MASK = 0x000F;

/* Response Type */
enum {
  Ok_ResponseType = 0,
  FormatError_ResponseType = 1,
  ServerFailure_ResponseType = 2,
  NameError_ResponseType = 3,
  NotImplemented_ResponseType = 4,
  Refused_ResponseType = 5
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

/* Operation Code */
enum {
  QUERY_OperationCode = 0, /* standard query */
  IQUERY_OperationCode = 1, /* inverse query */
  STATUS_OperationCode = 2, /* server status request */
  NOTIFY_OperationCode = 4, /* request zone transfer */
  UPDATE_OperationCode = 5 /* change resource records */
};

/* Response Code */
enum {
  NoError_ResponseCode = 0,
  FormatError_ResponseCode = 1,
  ServerFailure_ResponseCode = 2,
  NameError_ResponseCode = 3
};

/* Query Type */
enum {
  IXFR_QueryType = 251,
  AXFR_QueryType = 252,
  MAILB_QueryType = 253,
  MAILA_QueryType = 254,
  STAR_QueryType = 255
};

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

size_t get16bits(const uint8_t** buffer)
{
  uint16_t value;

  memcpy(&value, *buffer, 2);
  *buffer += 2;

  return ntohs(value);
}

size_t get16bits_masked(const uint8_t** buffer, uint16_t mask)
{
  uint16_t value;

  memcpy(&value, *buffer, 2);
  *buffer += 2;

  return ntohs(value & mask);
}

size_t get32bits(const uint8_t** buffer)
{
  uint32_t value;

  memcpy(&value, *buffer, 4);
  *buffer += 4;

  return ntohl(value);
}

// 3foo3bar3com0 => foo.bar.com
int decode_domain_name(char name[256], const uint8_t** beg, const uint8_t *end)
{
  int j = 0;
  const uint8_t *p = *beg;
  int dot;

  if ((end - p) >= 255) {
    end = p + 255;
  }

  dot = 0;
  while (1) {
    if (p >= end) {
      return EXIT_FAILURE;
    }

    if (*p == 0) {
      p++;
      break;
    }

    if (dot) {
      name[j] = '.';
      j++;
    }
    dot = 1;

    int len = *p;
    p++;

    if ((p + len) >= end) {
      return -1;
    }

    memcpy(&name[j], p, len);

    p += len;
    j += len;
  }

  name[j] = '\0';
  *beg = p;

  return EXIT_SUCCESS;
}

struct dns4 {
  char *name;
  struct in_addr addr;
  struct dns4 *next;
};

struct dns6 {
  char *name;
  struct in6_addr addr;
  struct dns6 *next;
};

static struct dns4 *g_dns4_cache = NULL;
static struct dns6 *g_dns6_cache = NULL;

static const char *lookup_dns4(struct in_addr *addr)
{
  struct dns4 *e;

  e = g_dns4_cache;
  while(e) {
    if (0 == memcmp(&e->addr, addr, 4)) {
      return e->name;
    }
    e = e->next;
  }

  return NULL;
}

static const char *lookup_dns6(struct in6_addr *addr)
{
  struct dns6 *e;

  e = g_dns6_cache;
  while(e) {
    if (0 == memcmp(&e->addr, addr, 16)) {
      return e->name;
    }
    e = e->next;
  }

  return NULL;
}

static void add_dns4(const char name[], struct in_addr *addr)
{
  struct dns4 *e;

  e = g_dns4_cache;
  while(e) {
    if (0 == memcmp(&e->addr, addr, 4)) {
      return;
    }
    e = e->next;
  }

  e = (struct dns4*) calloc(1, sizeof(struct dns4));
  e->name = strdup(name);
  memcpy(&e->addr, addr, 4);

  if (g_dns4_cache) {
    e->next = g_dns4_cache;
  }

  g_dns4_cache = e;
}

static void add_dns6(const char name[], struct in6_addr *addr)
{
  struct dns6 *e;

  e = g_dns6_cache;
  while(e) {
    if (0 == memcmp(&e->addr, addr, 16)) {
      return;
    }
    e = e->next;
  }

  e = (struct dns6*) calloc(1, sizeof(struct dns6));
  e->name = strdup(name);
  memcpy(&e->addr, addr, 16);

  if (g_dns6_cache) {
    e->next = g_dns6_cache;
  }

  g_dns6_cache = e;
}

char *lookup_dns(const struct sockaddr_storage *addr)
{
  const char *name;

  switch(addr->ss_family) {
  case AF_INET:
    name = lookup_dns4(&((struct sockaddr_in*) addr)->sin_addr);
    break;
  case AF_INET6:
    name = lookup_dns6(&((struct sockaddr_in6*) addr)->sin6_addr);
    break;
  default:
    name = NULL;
  }

  if (name)
    return strdup(name);
  else
    return NULL;
}

const char *type_str(int type)
{
  switch (type) {
  case A_Resource_RecordType:
  return "A";
  case NS_Resource_RecordType:
  return "NS";
  case CNAME_Resource_RecordType:
  return "CNAME";
  case SOA_Resource_RecordType:
  return "SOA";
  case PTR_Resource_RecordType:
  return "PTR";
  case MX_Resource_RecordType:
  return "MX";
  case TXT_Resource_RecordType:
  return "TXT";
  case AAAA_Resource_RecordType:
  return "AAAA";
  case SRV_Resource_RecordType:
  return "SRV";
  default:
      return "unknown";
  }
}

void printHexDump(const void *addr, int len) {
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

enum {
  RR_TYPE_QUESTION,
  RR_TYPE_ANSWER,
  RR_TYPE_AUTHORITY,
  RR_TYPE_ADDITIONAL
};

int parse_rr(struct ResourceRecord *rr, const uint8_t *beg, const uint8_t **data, const uint8_t *end, int rr_type)
{
  memset(rr, 0, sizeof(struct ResourceRecord));

  printf("resource dump:\n");
  printHexDump(*data, end - *data);

  /*
	 * Select start position for decode_domain_name()
	 * Question alway have an in-place name.
	 * Other resources can also have an offset,
	 * marked by a bx11 (3) prefix.
   */

  const uint8_t *name_pos;
  int set = 0;
  if (rr_type != RR_TYPE_QUESTION && (**data >> 6) == 3) {
    size_t offset = get16bits(data) & 0x3FFF;
    printf("label detected, offset: %d\n", (int) offset);
    if (offset > (end - beg)) {
      printf("Name index out of range: %d (%d)\n", (int) offset, (int) (end - beg));
      return EXIT_FAILURE;
    }
    name_pos = beg + offset;
  } else {
    name_pos = *data;
    set = 1;
  }

  // Parse QNAME
  int rc = decode_domain_name(&rr->name[0], &name_pos, end);
  if (rc == EXIT_FAILURE) {
    printf("decode_domain_name failure\n");
    return EXIT_FAILURE;
  }

  if (set) {
    *data = name_pos;
  }

  if ((end - *data) < 10) {
    printf("no enough < 10\n");
    return EXIT_FAILURE;
  }

  rr->type = get16bits(data);
  rr->class = get16bits(data);

  // Question RR ends here
  if (rr_type == RR_TYPE_QUESTION) {
    return EXIT_SUCCESS;
  }

  rr->ttl = get32bits(data);
  rr->rd_length = get16bits(data);

  printf("type: %s\n", type_str(rr->type));
  printf("rd_length: %d\n", rr->rd_length);

  if (rr->rd_length > (end - *data)) {
    //no enough for rd_length: 3072 42
    printf("no enough for rd_length: %d %d\n", rr->rd_length, (int) (end - *data));
    return EXIT_FAILURE;
  }

  if (rr->rd_length > sizeof(union ResourceData)) {
    printf("too big rd_length: %d %d\n", (int) rr->rd_length, (int) sizeof(union ResourceData));
    return EXIT_FAILURE;
  }

  memcpy(&rr->rd_data, *data, rr->rd_length);

  *data += rr->rd_length;

  return EXIT_SUCCESS;
}

void handle_rr(const struct ResourceRecord *rr, int rr_type)
{
  printf("name: %s (%d)\n", rr->name, rr_type);
}

void parse_dns(const uint8_t *data, size_t size)
{
  struct ResourceRecord rr;
  const uint8_t *beg;
  const uint8_t *end;
  int rc;
  int i;

  beg = data;
  end = data + size;

  if (size < 12) {
    return;
  }

  int id = get16bits(&data);
  uint32_t fields = get16bits(&data);
  int qr = (fields & QR_MASK) >> 15;
  int opcode = (fields & OPCODE_MASK) >> 11;
  int aa = (fields & AA_MASK) >> 10;
  int tc = (fields & TC_MASK) >> 9;
  int rd = (fields & RD_MASK) >> 8;
  int ra = (fields & RA_MASK) >> 7;
  int rcode = (fields & RCODE_MASK) >> 0;
  int qdCount = get16bits(&data);
  int anCount = get16bits(&data);
  int nsCount = get16bits(&data);
  int arCount = get16bits(&data);

  rc = EXIT_SUCCESS;

  printf("id: %d, qr: %d, opcode: %d, aa: %d, tc: %d, rd: %d, ra: %d, rcode: %d\n",
    id, qr, opcode, aa, tc, rd, ra, rcode
  );

  printf("qdCount: %u, anCount: %u, nsCount: %u, arCount: %u\n", qdCount, anCount, nsCount, arCount);

  for (i = 0; i < qdCount; ++i) {
    rc = parse_rr(&rr, beg, &data, end, RR_TYPE_QUESTION);
    if (rc == EXIT_FAILURE) {
      printf("dns parse failure\n");
      return;
    }
    handle_rr(&rr, RR_TYPE_QUESTION);
  }

  for (i = 0; i < anCount; ++i) {
    rc = parse_rr(&rr, beg, &data, end, RR_TYPE_ANSWER);
    if (rc == EXIT_FAILURE) {
      printf("dns parse failure\n");
      return;
    }
    handle_rr(&rr, RR_TYPE_ANSWER);
  }

  for (i = 0; i < nsCount; ++i) {
    rc = parse_rr(&rr, beg, &data, end, RR_TYPE_AUTHORITY);
    if (rc == EXIT_FAILURE) {
      printf("dns parse failure\n");
      return;
    }
    handle_rr(&rr, RR_TYPE_AUTHORITY);
  }

  for (i = 0; i < arCount; ++i) {
    rc = parse_rr(&rr, beg, &data, end, RR_TYPE_ADDITIONAL);
    if (rc == EXIT_FAILURE) {
      printf("dns parse failure\n");
      return;
    }
    handle_rr(&rr, RR_TYPE_ADDITIONAL);
  }
}
