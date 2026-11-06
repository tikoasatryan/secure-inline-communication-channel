#include "crypto.h"

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

#define HKDF_LABEL "secure-channel v1"

int dh_generate(EVP_PKEY **kp, uint8_t pub[32])
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!c) return -1;
    *kp = NULL;
    int ok = EVP_PKEY_keygen_init(c) > 0 && EVP_PKEY_keygen(c, kp) > 0;
    EVP_PKEY_CTX_free(c);
    if (!ok) return -1;
    size_t n = 32;
    if (EVP_PKEY_get_raw_public_key(*kp, pub, &n) <= 0 || n != 32) return -1;
    return 0;
}

static int hkdf(const uint8_t *ikm, size_t ikm_len,
                const uint8_t *salt, size_t salt_len,
                const uint8_t *info, size_t info_len,
                uint8_t *out, size_t out_len)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!c) return -1;
    int ok = EVP_PKEY_derive_init(c) > 0
          && EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha256()) > 0
          && EVP_PKEY_CTX_set1_hkdf_salt(c, salt, (int)salt_len) > 0
          && EVP_PKEY_CTX_set1_hkdf_key(c, ikm, (int)ikm_len) > 0
          && EVP_PKEY_CTX_add1_hkdf_info(c, info, (int)info_len) > 0
          && EVP_PKEY_derive(c, out, &out_len) > 0;
    EVP_PKEY_CTX_free(c);
    return ok ? 0 : -1;
}

int session_derive(EVP_PKEY *mine, const uint8_t peer_pub[32],
                   const uint8_t client_pub[32], const uint8_t server_pub[32],
                   int is_client, const char *psk,
                   session_t *s, uint8_t confirm_key[32])
{
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    if (!peer) return -1;

    uint8_t secret[32];
    size_t sl = sizeof secret;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(mine, NULL);
    int ok = c && EVP_PKEY_derive_init(c) > 0
               && EVP_PKEY_derive_set_peer(c, peer) > 0
               && EVP_PKEY_derive(c, secret, &sl) > 0 && sl == 32;
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(peer);
    if (!ok) return -1;

    static const uint8_t zero[32] = {0};           /* reject low-order points */
    if (CRYPTO_memcmp(secret, zero, 32) == 0) return -1;

    /* The transcript (both public keys) is bound into the key derivation. */
    uint8_t info[sizeof(HKDF_LABEL) - 1 + 64];
    memcpy(info, HKDF_LABEL, sizeof(HKDF_LABEL) - 1);
    memcpy(info + sizeof(HKDF_LABEL) - 1, client_pub, 32);
    memcpy(info + sizeof(HKDF_LABEL) - 1 + 32, server_pub, 32);

    const char *salt = (psk && *psk) ? psk : "secure-channel-no-psk";

    /* c2s key(32)+salt(4) | s2c key(32)+salt(4) | confirmation key(32) */
    uint8_t okm[2 * (KEY_LEN + SALT_LEN) + 32];
    if (hkdf(secret, 32, (const uint8_t *)salt, strlen(salt),
             info, sizeof info, okm, sizeof okm) < 0) {
        OPENSSL_cleanse(secret, sizeof secret);
        return -1;
    }
    const uint8_t *c2s = okm, *s2c = okm + (KEY_LEN + SALT_LEN);
    const uint8_t *tx = is_client ? c2s : s2c;
    const uint8_t *rx = is_client ? s2c : c2s;
    memcpy(s->tx.key, tx, KEY_LEN);  memcpy(s->tx.salt, tx + KEY_LEN, SALT_LEN);
    memcpy(s->rx.key, rx, KEY_LEN);  memcpy(s->rx.salt, rx + KEY_LEN, SALT_LEN);
    memcpy(confirm_key, okm + 2 * (KEY_LEN + SALT_LEN), 32);

    OPENSSL_cleanse(secret, sizeof secret);
    OPENSSL_cleanse(okm, sizeof okm);
    return 0;
}

int make_confirm(const uint8_t confirm_key[32], const char *label,
                 const uint8_t client_pub[32], const uint8_t server_pub[32],
                 uint8_t out[32])
{
    uint8_t msg[16 + 64];
    size_t ll = strlen(label);
    if (ll > 16) return -1;
    memcpy(msg, label, ll);
    memcpy(msg + ll, client_pub, 32);
    memcpy(msg + ll + 32, server_pub, 32);
    unsigned int olen = 32;
    return HMAC(EVP_sha256(), confirm_key, 32, msg, ll + 64, out, &olen) ? 0 : -1;
}

void make_nonce(uint8_t nonce[NONCE_LEN], const uint8_t salt[SALT_LEN], uint64_t ctr)
{
    memcpy(nonce, salt, SALT_LEN);
    for (int i = 0; i < 8; i++)
        nonce[SALT_LEN + i] = (uint8_t)(ctr >> (56 - 8 * i));
}

int gcm_encrypt(const uint8_t key[KEY_LEN], const uint8_t nonce[NONCE_LEN],
                const uint8_t *aad, int aad_len,
                const uint8_t *pt, int len, uint8_t *ct, uint8_t tag[TAG_LEN])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    int n = 0, ok = 0;
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1
        && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) == 1
        && EVP_EncryptInit_ex(c, NULL, NULL, key, nonce) == 1
        && EVP_EncryptUpdate(c, NULL, &n, aad, aad_len) == 1
        && EVP_EncryptUpdate(c, ct, &n, pt, len) == 1
        && EVP_EncryptFinal_ex(c, ct + n, &n) == 1
        && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) == 1)
        ok = 1;
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

int gcm_decrypt(const uint8_t key[KEY_LEN], const uint8_t nonce[NONCE_LEN],
                const uint8_t *aad, int aad_len,
                const uint8_t *ct, int len, const uint8_t tag[TAG_LEN], uint8_t *pt)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    int n = 0, fl = 0, ok = 0;
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1
        && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) == 1
        && EVP_DecryptInit_ex(c, NULL, NULL, key, nonce) == 1
        && EVP_DecryptUpdate(c, NULL, &n, aad, aad_len) == 1
        && EVP_DecryptUpdate(c, pt, &n, ct, len) == 1
        && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag) == 1
        && EVP_DecryptFinal_ex(c, pt + n, &fl) > 0)   /* verifies the tag */
        ok = 1;
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}
