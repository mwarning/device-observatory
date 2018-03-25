CC ?= gcc
CFLAGS ?= -O2
CFLAGS += -std=gnu99 -Wall -pedantic
LFLAGS += -lpcap
#LFLAGS += -lmicrohttpd

.PHONY: all clean debug

all: main.c resolve.c parse_packet.c parse_dns.c
	$(CC) $(CFLAGS) $(LFLAGS) $^ -o device-observatory

debug: CFLAGS += -DDEBUG
debug: all

clean:
	rm -f device-observatory
