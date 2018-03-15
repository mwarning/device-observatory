CC ?= gcc
CFLAGS ?= -O2 -Wall -pedantic
CFLAGS += -std=gnu99
LFLAGS += -lmicrohttpd

.PHONY: clean

all: main.c
	$(CC) $(CFLAGS) $(LFLAGS) main.c -o device-observatory

clean:
	rm -f device-observatory
