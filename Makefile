CC ?= gcc
CFLAGS ?= -O2
CFLAGS += -std=gnu99 -Wall -pedantic -Werror -fno-strict-aliasing -Wwrite-strings
LFLAGS += -lpcap -lmicrohttpd

.PHONY: all clean debug files

#all: CFLAGS += -DDEBUG
all: $(wildcard src/*.c) files
	$(CC) $(CFLAGS) $(LFLAGS) $(filter %.c,$^) -o device-observatory

files: www/index.html www/logo.png
	@rm -f src/files.h
	xxd -i www/index.html >> src/files.h
	xxd -i www/logo.png >> src/files.h

debug: CFLAGS += -DDEBUG
debug: all

clean:
	rm -f device-observatory
