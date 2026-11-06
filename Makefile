CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11 -D_GNU_SOURCE
INC     := -Isrc/common
COMMON  := src/common/crypto.c src/common/packet.c src/common/channel.c

all: build/device build/sender build/receiver build/test_channel

build:
	mkdir -p build

build/device: src/device/device.c $(COMMON) | build
	$(CC) $(CFLAGS) $(INC) -o $@ $^ -lnetfilter_queue -lcrypto

build/sender: src/sender/sender.c | build
	$(CC) $(CFLAGS) -o $@ $^

build/receiver: src/receiver/receiver.c | build
	$(CC) $(CFLAGS) -o $@ $^

build/test_channel: tests/test_channel.c $(COMMON) | build
	$(CC) $(CFLAGS) $(INC) -o $@ $^ -lcrypto

test: build/test_channel
	./build/test_channel

integration: all
	sudo tests/run_integration.sh

clean:
	rm -rf build

.PHONY: all test integration clean
