.POSIX:
.PHONY: all clean

-include config.mk

CFLAGS+=-Wall -Wpedantic -D _GNU_SOURCE
LDLIBS+=-l pthread
HEXDUMP={ tr -d '\n\t' | od -v -A n -t x1 | sed 's/[[:xdigit:]]\+/0x&,/g'; }

OBJ=\
	upnp-mediaserver.o\
	http.o\
	ssdp.o\
	util.o\
	xml.o

all: upnp-mediaserver

MediaServer.inc: MediaServer.xml
	$(HEXDUMP) <MediaServer.xml >$@
ContentDirectory.inc: ContentDirectory.xml
	$(HEXDUMP) <ContentDirectory.xml >$@
upnp-mediaserver.o: MediaServer.inc ContentDirectory.inc
$(OBJ): http.h ssdp.h util.h version.h xml.h

upnp-mediaserver: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

clean:
	rm -f upnp-mediaserver $(OBJ) MediaServer.inc ContentDirectory.inc
