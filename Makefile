CC ?= gcc
CFLAGS ?= -O2
CFLAGS += -std=gnu99 -Wall -pedantic -Werror -fno-strict-aliasing -Wwrite-strings
LFLAGS += -lpcap
SRC = src/data.c src/main.c src/parse_dns.c src/parse_ether.c \
	src/parse_wifi.c src/resolve.c src/utils.c

# Add webserver and include web ui files
ifneq ($(NO_WEBSERVER),1)
CFLAGS += -DWEBSERVER
LFLAGS += -lmicrohttpd
SRC += src/webserver.c src/files.h
endif

.PHONY: all clean debug


#all: CFLAGS += -DDEBUG
all: $(SRC)
	$(CC) $(CFLAGS) $(LFLAGS) $(SRC) -o device-observatory

# Include files in www into files.h
src/files.h: $(wildcard www/*)
	@rm -f src/files.h
	@for file in www/*; do \
		xxd -i $$file >> src/files.h; \
	done
	@echo "struct file_entry { const char *content_path; unsigned char* content_data; unsigned int content_size;};" >> src/files.h
	@echo "struct file_entry g_file_entries[] = {" >> src/files.h
	@for file in www/*; do \
		echo "{\"/$$(basename $$file)\", &$$(echo $$file | tr '/.' '_')[0], sizeof($$(echo $$file | tr '/.' '_'))}," >> src/files.h; \
	done
	@echo "{0, 0, 0}" >> src/files.h
	@echo "};" >> src/files.h

debug: CFLAGS += -DDEBUG
debug: all

clean:
	rm -f device-observatory
