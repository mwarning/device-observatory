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

#include "parse_dns.h"

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

static size_t get16bits(const uint8_t** buffer)
{
  uint16_t value;

  memcpy(&value, *buffer, 2);
  *buffer += 2;

  return ntohs(value);
}

static size_t get32bits(const uint8_t** buffer)
{
  uint32_t value;

  memcpy(&value, *buffer, 4);
  *buffer += 4;

  return ntohl(value);
}

// 3foo3bar3com0 => foo.bar.com
static int decode_domain_name(char name[256], const uint8_t** beg, const uint8_t *end)
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

static const char *type_str(int type)
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

static int parse_rr(struct ResourceRecord *rr, const uint8_t *beg, const uint8_t **cur, const uint8_t *end, int rr_type)
{
  int rc;

  memset(rr, 0, sizeof(struct ResourceRecord));

  /*
	 * Set start position for decode_domain_name().
	 * Question alway have an in-place name.
	 * Other resources can also have an offset at
   * which the name is to be found.
	 * The offset is marked by a bx11 (3) prefix.
   */

  if (rr_type != RR_TYPE_QUESTION && (**cur >> 6) == 3) {
    size_t offset = get16bits(cur) & 0x3FFF;
    printf("label detected, offset: %d\n", (int) offset);
    if (offset > (end - beg)) {
      printf("Name index out of range: %d (%d)\n", (int) offset, (int) (end - beg));
      return EXIT_FAILURE;
    }
    const uint8_t *pos = beg + offset;

    // Parse NAME
    rc = decode_domain_name(&rr->name[0], &pos, end);
    if (rc == EXIT_FAILURE) {
      printf("decode_domain_name failure\n");
      return EXIT_FAILURE;
    }
  } else {
    // Parse (Q)NAME
    rc = decode_domain_name(&rr->name[0], cur, end);
    if (rc == EXIT_FAILURE) {
      printf("decode_domain_name failure\n");
      return EXIT_FAILURE;
    }
  }

  if ((end - *cur) < 10) {
    printf("no enough < 10\n");
    return EXIT_FAILURE;
  }

  rr->type = get16bits(cur);
  rr->class = get16bits(cur);

  // Question RR ends here
  if (rr_type == RR_TYPE_QUESTION) {
    return EXIT_SUCCESS;
  }

  rr->ttl = get32bits(cur);
  rr->rd_length = get16bits(cur);

  printf("type: %s\n", type_str(rr->type));
  printf("rd_length: %d\n", rr->rd_length);

  if (rr->rd_length > (end - *cur)) {
    printf("no enough for rd_length: %d %d\n", rr->rd_length, (int) (end - *cur));
    return EXIT_FAILURE;
  }

  if (rr->rd_length > sizeof(union ResourceData)) {
    printf("too big rd_length: %d %d\n", (int) rr->rd_length, (int) sizeof(union ResourceData));
    return EXIT_FAILURE;
  }

  // Make sure data for these have the expected length
  switch (rr->type) {
    case AAAA_Resource_RecordType:
      if (rr->rd_length != 16)
        return EXIT_FAILURE;
    case A_Resource_RecordType:
      if (rr->rd_length != 4)
        return EXIT_FAILURE;
  }

  memcpy(&rr->rd_data, *cur, rr->rd_length);

  *cur += rr->rd_length;

  return EXIT_SUCCESS;
}

void parse_dns(const uint8_t *data, size_t size, dns_callback *cb)
{
  struct ResourceRecord rr;
  const uint8_t *beg;
  const uint8_t **cur;
  const uint8_t *end;
  int rc;
  int i;

  beg = data;
  cur = &data;
  end = data + size;

  if (size < 12) {
    return;
  }

  int id = get16bits(cur);
  uint32_t fields = get16bits(cur);
  int qr = (fields & QR_MASK) >> 15;
  int opcode = (fields & OPCODE_MASK) >> 11;
  int aa = (fields & AA_MASK) >> 10;
  int tc = (fields & TC_MASK) >> 9;
  int rd = (fields & RD_MASK) >> 8;
  int ra = (fields & RA_MASK) >> 7;
  int rcode = (fields & RCODE_MASK) >> 0;
  int qdCount = get16bits(cur);
  int anCount = get16bits(cur);
  int nsCount = get16bits(cur);
  int arCount = get16bits(cur);

  rc = EXIT_SUCCESS;

  printf("id: %d, qr: %d, opcode: %d, aa: %d, tc: %d, rd: %d, ra: %d, rcode: %d\n",
    id, qr, opcode, aa, tc, rd, ra, rcode
  );

  printf("qdCount: %u, anCount: %u, nsCount: %u, arCount: %u\n", qdCount, anCount, nsCount, arCount);

  for (i = 0; i < qdCount; ++i) {
    rc = parse_rr(&rr, beg, cur, end, RR_TYPE_QUESTION);
    if (rc == EXIT_FAILURE) {
      printf("dns parse failure\n");
      return;
    }
    cb(&rr, RR_TYPE_QUESTION);
  }

  for (i = 0; i < anCount; ++i) {
    rc = parse_rr(&rr, beg, cur, end, RR_TYPE_ANSWER);
    if (rc == EXIT_FAILURE) {
      printf("dns parse failure\n");
      return;
    }
    cb(&rr, RR_TYPE_ANSWER);
  }

  for (i = 0; i < nsCount; ++i) {
    rc = parse_rr(&rr, beg, cur, end, RR_TYPE_AUTHORITY);
    if (rc == EXIT_FAILURE) {
      printf("dns parse failure\n");
      return;
    }
    cb(&rr, RR_TYPE_AUTHORITY);
  }

  for (i = 0; i < arCount; ++i) {
    rc = parse_rr(&rr, beg, cur, end, RR_TYPE_ADDITIONAL);
    if (rc == EXIT_FAILURE) {
      printf("dns parse failure\n");
      return;
    }
    cb(&rr, RR_TYPE_ADDITIONAL);
  }
}
