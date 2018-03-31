CC ?= gcc
CFLAGS ?= -O2
CFLAGS += -std=gnu99 -Wall -pedantic -Werror -fno-strict-aliasing -Wwrite-strings
LFLAGS += -lpcap -lmicrohttpd

.PHONY: all clean debug

#all: CFLAGS += -DDEBUG
all: main.c resolve.c parse_dns.c parse_ether.c parse_wifi.c data.c webserver.c utils.c
	$(CC) $(CFLAGS) $(LFLAGS) $^ -o device-observatory

debug: CFLAGS += -DDEBUG
debug: all

clean:
	rm -f device-observatory
