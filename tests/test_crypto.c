#include "crypto.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s\n", message); \
        goto fail; \
    } \
} while (0)

int main(void) {
    void *alice_private = NULL, *bob_private = NULL;
    uint8_t alice_public[32], bob_public[32];
    uint8_t alice_secret[32], bob_secret[32];
    uint8_t alice_key[32], bob_key[32];
    uint8_t nonce[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    const uint8_t info[] = "secure-inline-channel test key";
    const uint8_t message[] = "AES-256-GCM test message";
    uint8_t ciphertext[sizeof(message)];
    uint8_t recovered[sizeof(message)];
    uint8_t tag[16];

    CHECK(sic_x25519_generate(&alice_private, alice_public), "Alice key generation");
    CHECK(sic_x25519_generate(&bob_private, bob_public), "Bob key generation");
    CHECK(sic_x25519_derive(alice_private, bob_public, alice_secret), "Alice DH");
    CHECK(sic_x25519_derive(bob_private, alice_public, bob_secret), "Bob DH");
    CHECK(CRYPTO_memcmp(alice_secret, bob_secret, 32) == 0, "shared secrets differ");

    CHECK(sic_hkdf_sha256(alice_secret, 32, NULL, 0,
                          info, sizeof(info) - 1, alice_key), "Alice HKDF");
    CHECK(sic_hkdf_sha256(bob_secret, 32, NULL, 0,
                          info, sizeof(info) - 1, bob_key), "Bob HKDF");
    CHECK(CRYPTO_memcmp(alice_key, bob_key, 32) == 0, "derived keys differ");

    CHECK(sic_aes256gcm_encrypt(alice_key, nonce, message, sizeof(message),
                               ciphertext, tag), "AES-GCM encryption");
    CHECK(sic_aes256gcm_decrypt(bob_key, nonce, ciphertext, sizeof(ciphertext),
                               tag, recovered), "AES-GCM decryption");
    CHECK(CRYPTO_memcmp(message, recovered, sizeof(message)) == 0,
          "recovered plaintext differs");

    tag[0] ^= 0x01;
    CHECK(!sic_aes256gcm_decrypt(bob_key, nonce, ciphertext, sizeof(ciphertext),
                                 tag, recovered), "tampered tag was accepted");

    puts("PASS: X25519, HKDF-SHA256, AES-256-GCM and tag rejection");
    EVP_PKEY_free((EVP_PKEY *)alice_private);
    EVP_PKEY_free((EVP_PKEY *)bob_private);
    return 0;

fail:
    EVP_PKEY_free((EVP_PKEY *)alice_private);
    EVP_PKEY_free((EVP_PKEY *)bob_private);
    return 1;
}
