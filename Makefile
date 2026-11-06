CC := gcc
CPPFLAGS := -Isrc/common
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2
OPENSSL_LIBS := -lcrypto
NFQUEUE_LIBS := -lnetfilter_queue -lmnl

BUILD := build
COMMON_CRYPTO := src/common/crypto.c

.PHONY: all clean test

all: $(BUILD)/sender $(BUILD)/receiver $(BUILD)/test_crypto

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/sender: src/sender/client.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@

$(BUILD)/receiver: src/receiver/server.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@

$(BUILD)/test_crypto: tests/test_crypto.c $(COMMON_CRYPTO) src/common/crypto.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_crypto.c $(COMMON_CRYPTO) $(OPENSSL_LIBS) -o $@

# NFQUEUE dependencies are installed now for the later packet-processing milestone.
# Device programs are intentionally not built until packet logic is implemented.

test: all
	./$(BUILD)/test_crypto

clean:
	rm -rf $(BUILD)
