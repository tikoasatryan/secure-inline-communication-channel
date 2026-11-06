#include "crypto.h"

#include <limits.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

int sic_x25519_generate(void **private_key, uint8_t public_key[32]) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    size_t public_len = 32;
    int ok = 0;

    if (!private_key || !public_key) return 0;
    *private_key = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0 ||
        EVP_PKEY_get_raw_public_key(key, public_key, &public_len) <= 0 ||
        public_len != 32) {
        goto cleanup;
    }

    *private_key = key;
    key = NULL;
    ok = 1;

cleanup:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

int sic_x25519_derive(void *private_key, const uint8_t peer_public_key[32],
                      uint8_t shared_secret[32]) {
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t secret_len = 32;
    int ok = 0;

    if (!private_key || !peer_public_key || !shared_secret) return 0;

    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                       peer_public_key, 32);
    if (!peer) goto cleanup;

    ctx = EVP_PKEY_CTX_new((EVP_PKEY *)private_key, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer) <= 0 ||
        EVP_PKEY_derive(ctx, shared_secret, &secret_len) <= 0 ||
        secret_len != 32) {
        goto cleanup;
    }

    ok = 1;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    return ok;
}

int sic_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t output_key[32]) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[5];
    char digest[] = "SHA256";
    uint8_t empty = 0;
    int ok = 0;

    if (!ikm || ikm_len == 0 || !output_key) return 0;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) goto cleanup;
    ctx = EVP_KDF_CTX_new(kdf);
    if (!ctx) goto cleanup;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                  digest, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                   (void *)ikm, ikm_len);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                   (void *)(salt ? salt : &empty), salt_len);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                   (void *)(info ? info : &empty), info_len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, output_key, 32, params) <= 0) goto cleanup;
    ok = 1;

cleanup:
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return ok;
}

int sic_aes256gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t *plaintext, size_t plaintext_len,
                          uint8_t *ciphertext, uint8_t tag[16]) {
    EVP_CIPHER_CTX *ctx = NULL;
    int out_len = 0, final_len = 0;
    int ok = 0;

    if (!key || !nonce || (!plaintext && plaintext_len) ||
        (!ciphertext && plaintext_len) || !tag || plaintext_len > INT_MAX)
        return 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    if (plaintext_len &&
        EVP_EncryptUpdate(ctx, ciphertext, &out_len,
                          plaintext, (int)plaintext_len) != 1)
        goto cleanup;

    if (EVP_EncryptFinal_ex(ctx,
            ciphertext ? ciphertext + out_len : NULL, &final_len) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        goto cleanup;

    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int sic_aes256gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          const uint8_t tag[16], uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = NULL;
    int out_len = 0, final_len = 0;
    int ok = 0;

    if (!key || !nonce || (!ciphertext && ciphertext_len) ||
        (!plaintext && ciphertext_len) || !tag || ciphertext_len > INT_MAX)
        return 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    if (ciphertext_len &&
        EVP_DecryptUpdate(ctx, plaintext, &out_len,
                          ciphertext, (int)ciphertext_len) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1)
        goto cleanup;

    if (EVP_DecryptFinal_ex(ctx,
            plaintext ? plaintext + out_len : NULL, &final_len) != 1)
        goto cleanup;

    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
