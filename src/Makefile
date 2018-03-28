CC ?= gcc
CFLAGS ?= -O2
CFLAGS += -std=gnu99 -Wall -pedantic -Werror -fno-strict-aliasing -Wwrite-strings
LFLAGS += -lpcap
#LFLAGS += -lmicrohttpd

.PHONY: all clean debug

#all: CFLAGS += -DDEBUG
all: main.c resolve.c parse_packet.c parse_dns.c data.c utils.c
	$(CC) $(CFLAGS) $(LFLAGS) $^ -o device-observatory

debug: CFLAGS += -DDEBUG
debug: all

clean:
	rm -f device-observatory
