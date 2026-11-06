#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>
#include "common.h"

typedef struct {
    uint8_t key[KEY_LEN];
    uint8_t salt[SALT_LEN];
} dir_key_t;

typedef struct {
    dir_key_t tx;   /* used to encrypt packets we send to the peer   */
    dir_key_t rx;   /* used to decrypt packets received from the peer */
} session_t;

/* Diffie-Hellman (X25519) */
int dh_generate(EVP_PKEY **kp, uint8_t pub[32]);

/* shared secret -> HKDF-SHA256 -> per-direction keys/salts + confirmation key */
int session_derive(EVP_PKEY *mine, const uint8_t peer_pub[32],
                   const uint8_t client_pub[32], const uint8_t server_pub[32],
                   int is_client, const char *psk,
                   session_t *s, uint8_t confirm_key[32]);

int make_confirm(const uint8_t confirm_key[32], const char *label,
                 const uint8_t client_pub[32], const uint8_t server_pub[32],
                 uint8_t out[32]);

void make_nonce(uint8_t nonce[NONCE_LEN], const uint8_t salt[SALT_LEN], uint64_t ctr);

/* AES-256-GCM. Return 0 on success, -1 on failure (decrypt: bad tag). */
int gcm_encrypt(const uint8_t key[KEY_LEN], const uint8_t nonce[NONCE_LEN],
                const uint8_t *aad, int aad_len,
                const uint8_t *pt, int len, uint8_t *ct, uint8_t tag[TAG_LEN]);
int gcm_decrypt(const uint8_t key[KEY_LEN], const uint8_t nonce[NONCE_LEN],
                const uint8_t *aad, int aad_len,
                const uint8_t *ct, int len, const uint8_t tag[TAG_LEN], uint8_t *pt);

#endif
