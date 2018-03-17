CC ?= gcc
CFLAGS ?= -O2
CFLAGS += -std=gnu99 -Wall -pedantic
LFLAGS += -lpcap
#LFLAGS += -lmicrohttpd

.PHONY: clean

all: main.c resolve.c parse_packet.c
	$(CC) $(CFLAGS) $(LFLAGS) $^ -o device-observatory

clean:
	rm -f device-observatory
