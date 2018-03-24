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
  char name[256];
  uint16_t type;
  uint16_t class;
  uint16_t ttl;
  uint16_t rd_length;
  union ResourceData rd_data;
};

struct Message {
  uint16_t id; /* Identifier */

  /* Flags */
  uint16_t qr; /* Query/Response Flag */
  uint16_t opcode; /* Operation Code */
  uint16_t aa; /* Authoritative Answer Flag */
  uint16_t tc; /* Truncation Flag */
  uint16_t rd; /* Recursion Desired */
  uint16_t ra; /* Recursion Available */
  uint16_t rcode; /* Response Code */

  uint16_t qdCount; /* Question Count */
  uint16_t anCount; /* Answer Record Count */
  uint16_t nsCount; /* Authority Record Count */
  uint16_t arCount; /* Additional Record Count */

  /* At least one question; questions are copied to the response 1:1 */
  struct Question* questions;

  /*
  * Resource records to be send back.
  * Every resource record can be in any of the following places.
  * But every place has a different semantic.
  */
  struct ResourceRecord* answers;
  struct ResourceRecord* authorities;
  struct ResourceRecord* additionals;
};

size_t get16bits(const uint8_t** buffer)
{
  uint16_t value;

  memcpy(&value, *buffer, 2);
  *buffer += 2;

  return ntohs(value);
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
  int first;

  if ((end - p) >= 255) {
  	end = p + 255;
  }

  first = 1;
  while (1) {
    if (p >= end) {
      return EXIT_FAILURE;
    }

    if (*p == 0) {
      break;
    }

    if (first) {
      name[j] = '.';
      j += 1;
      first = 0;
    }

    int len = *p;
    p++;

    if ((p + len) >= end) {
      return -1;
    }

    memcpy(&name[j], p, len);

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

int parse_rr(struct ResourceRecord *r, const uint8_t **data, const uint8_t *end)
{
	//char name[256];

    int rc = decode_domain_name(&r->name[0], data, end);
    if (rc == EXIT_FAILURE) {
    	printf("decode_domain_name failure\n");
    	return EXIT_FAILURE;
    }

    if ((end - *data) < 10) {
    	printf("no enough < 10\n");
    	return EXIT_FAILURE;
    }

    r->type = get16bits(data);
    r->class = get16bits(data);
    r->ttl = get32bits(data);
    r->rd_length = get16bits(data);

	if (r->rd_length > (end - *data)) {
		printf("no enough for rd_length\n");
    	return EXIT_FAILURE;
    }

	if (r->rd_length > sizeof(union ResourceData)) {
		printf("too big rd_length\n");
    	return EXIT_FAILURE;
    }

    memcpy(&r->rd_data, *data, r->rd_length);
   	/*
    switch (type)
    {
      case A_Resource_RecordType:
      	if (r->rc_data != 4) {
			return EXIT_FAILURE;
		}
      case AAAA_Resource_RecordType:
     	if (r->rc_data != 16) {
			return EXIT_FAILURE;
		}
      default:
        fprintf(stderr, "Unknown type %u. => Ignore resource record.\n", type);
      	break;
    }
    */

    *data += r->rd_length;

    return EXIT_SUCCESS;
}

void parse_dns(const uint8_t *data, size_t size)
{
	struct ResourceRecord r;
	const uint8_t *end;
	int rc;
	int i;

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

	const int count = qdCount + anCount + nsCount + arCount;
	for (i = 0; i < count; ++i) {
		memset(&r, 0, sizeof(r));

		rc = parse_rr(&r, &data, end);
		if (rc == EXIT_FAILURE) {
			printf("dns parse failure\n");
			return;
		}

		printf("qName: %s %s %d %d\n", r.name, type_str(r.type), r.class, r.ttl);
		/* Add entry to cache */
		if (r.name[0]) {
			if (r.type == A_Resource_RecordType) {
				add_dns4(&r.name[0], &r.rd_data.a_record.addr);
			}
			if (r.type == AAAA_Resource_RecordType) {
				add_dns6(&r.name[0], &r.rd_data.aaaa_record.addr);
			}
		}
	}

/*
	printf("answers: %u\n", anCount);
	for (i = 0; i < anCount && rc == EXIT_SUCCESS; ++i) {
		rc = parse_rr(&r, &data, end);
	}

	printf("authorities: %u\n", nsCount);
	for (i = 0; i < nsCount && rc == EXIT_SUCCESS; ++i) {
		rc = parse_rr(&r, &data, end);
	}

	printf("additionals: %u\n", arCount);
	for (i = 0; i < arCount && rc == EXIT_SUCCESS; ++i) {
		rc = parse_rr(&r, &data, end);
	}
*/
}
