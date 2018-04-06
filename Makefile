CC ?= gcc
CFLAGS ?= -O2
CFLAGS += -std=gnu99 -Wall -pedantic -Werror -fno-strict-aliasing -Wwrite-strings
LFLAGS += -lpcap
SRC = src/data.c src/main.c src/parse_dns.c src/parse_ether.c \
	src/parse_wifi.c src/resolve.c src/utils.c

ifneq ($(NO_WEBSERVER),1)
CFLAGS += -DWEBSERVER
LFLAGS += -lmicrohttpd
SRC += src/webserver.c src/files.h
endif

.PHONY: all clean debug

#all: CFLAGS += -DDEBUG
all: $(SRC)
	$(CC) $(CFLAGS) $(LFLAGS) $(SRC) -o device-observatory

src/files.h: www/index.html www/logo.png
	@rm -f src/files.h
	xxd -i www/index.html >> src/files.h
	xxd -i www/logo.png >> src/files.h

debug: CFLAGS += -DDEBUG
debug: all

clean:
	rm -f device-observatory
