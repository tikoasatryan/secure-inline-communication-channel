#ifndef SIC_CRYPTO_H
#define SIC_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* Generate an X25519 keypair. Caller owns both returned EVP_PKEY objects. */
int sic_x25519_generate(void **private_key, uint8_t public_key[32]);

/* Derive a 32-byte X25519 shared secret from our private key and peer public key. */
int sic_x25519_derive(void *private_key, const uint8_t peer_public_key[32],
                     uint8_t shared_secret[32]);

/* Derive a 32-byte key using HKDF-SHA256. */
int sic_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t output_key[32]);

/* AES-256-GCM. Nonce must be unique for each encryption under a given key.
   Returns 1 on success, 0 on failure. Tag length is 16 bytes. */
int sic_aes256gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t *plaintext, size_t plaintext_len,
                          uint8_t *ciphertext, uint8_t tag[16]);

int sic_aes256gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          const uint8_t tag[16], uint8_t *plaintext);

#endif
