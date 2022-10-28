SOURCE = netflow.c
CFLAGS = -Wall -std=c99 -D_GNU_SOURCE
.PHONY: clean run install all
all: run
bin: $(SOURCE)
        $(CC) $(CFLAGS) $< -lpcap -o bin
install: bin
        @cp bin /var/tmp/pcap/bin
run: install
        @sleep 0.1
clean:
/var/tmp/pcap/bin eth0
rm -f bin
