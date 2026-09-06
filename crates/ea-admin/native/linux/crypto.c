#include "ea_native.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string.h>

gboolean ea_random(unsigned char out[32]) { return RAND_priv_bytes(out, 32) == 1; }
gboolean ea_hash(const unsigned char *data, size_t len, unsigned char out[32]) {
    unsigned n = 0;
    return EVP_Digest(data, len, out, &n, EVP_sha256(), NULL) == 1 && n == 32;
}
gboolean ea_public(const unsigned char seed[32], unsigned char public_key[32]) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    size_t n = 32;
    gboolean ok = key && EVP_PKEY_get_raw_public_key(key, public_key, &n) == 1 && n == 32;
    EVP_PKEY_free(key);
    return ok;
}
gboolean ea_sign(const unsigned char seed[32], const unsigned char *data, size_t len, unsigned char signature[64]) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t n = 64;
    /* PureEdDSA: NULL digest and a single-shot EVP_DigestSign, never Update. */
    gboolean ok = key && ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestSign(ctx, signature, &n, data, len) == 1 && n == 64;
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key);
    if (!ok) OPENSSL_cleanse(signature, 64);
    return ok;
}

static gboolean derive(const EaMarker *m, const unsigned char instance[32], unsigned char key[32]) {
    static const unsigned char info[] = "EINSATZARCHIV-LINUX-TWO-STORE-KEY-v1";
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t n = 32;
    gboolean ok = ctx && EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, instance, 32) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_key(ctx, m->wrapping, 32) == 1 &&
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof info - 1) == 1 &&
        EVP_PKEY_CTX_add1_hkdf_info(ctx, m->id, 32) == 1 && EVP_PKEY_derive(ctx, key, &n) == 1 && n == 32;
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static char *aad(const EaMarker *m, const char *slot, const char *kind, const char *pub) {
    char *id = ea_hex(m->id, 32), *binding = ea_hex(m->binding, 32);
    char *value = g_strdup_printf("EINSATZARCHIV-LINUX-KEY-v1\n%s\n%s\n%s\n%s\n%s", id, binding, slot, kind, pub);
    g_free(id); g_free(binding);
    return value;
}

char *ea_metadata_mac(const EaMarker *m, const char *slot, const char *kind, const char *pub) {
    char *context = aad(m, slot, kind, pub);
    char *value = g_strconcat("EINSATZARCHIV-LINUX-METADATA-v1\n", context, NULL);
    unsigned char mac[32]; unsigned n = 0;
    char *result = NULL;
    if (HMAC(EVP_sha256(), m->wrapping, 32, (unsigned char *)value, strlen(value), mac, &n) && n == 32) result = ea_hex(mac, 32);
    OPENSSL_cleanse(mac, sizeof mac); g_free(context); g_free(value);
    return result;
}

gboolean ea_seal(const EaMarker *m, const unsigned char instance[32], const char *slot, const char *kind, const char *pub, const unsigned char plain[32], unsigned char box[EA_ENVELOPE_SIZE]) {
    unsigned char key[32] = {0};
    char *context = aad(m, slot, kind, pub);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, tail = 0;
    box[0] = 1; /* version || nonce[12] || ciphertext[32] || tag[16] */
    gboolean ok = ctx && derive(m, instance, key) && RAND_bytes(box + 1, 12) == 1 &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, box + 1) == 1 &&
        EVP_EncryptUpdate(ctx, NULL, &n, (unsigned char *)context, (int)strlen(context)) == 1 &&
        EVP_EncryptUpdate(ctx, box + 13, &n, plain, 32) == 1 && n == 32 &&
        EVP_EncryptFinal_ex(ctx, box + 45, &tail) == 1 && tail == 0 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, box + 45) == 1;
    EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, sizeof key); g_free(context);
    if (!ok) OPENSSL_cleanse(box, EA_ENVELOPE_SIZE);
    return ok;
}

gboolean ea_open(const EaMarker *m, const unsigned char instance[32], const char *slot, const char *kind, const char *pub, const unsigned char box[EA_ENVELOPE_SIZE], unsigned char plain[32]) {
    unsigned char key[32] = {0}, scratch[48] = {0};
    char *context = aad(m, slot, kind, pub);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, tail = 0;
    gboolean ok = box[0] == 1 && ctx && derive(m, instance, key) &&
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, box + 1) == 1 &&
        EVP_DecryptUpdate(ctx, NULL, &n, (unsigned char *)context, (int)strlen(context)) == 1 &&
        EVP_DecryptUpdate(ctx, scratch, &n, box + 13, 32) == 1 && n == 32 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)(box + 45)) == 1 &&
        EVP_DecryptFinal_ex(ctx, scratch + 32, &tail) == 1 && tail == 0;
    if (ok) memcpy(plain, scratch, 32); else OPENSSL_cleanse(plain, 32);
    EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, sizeof key); OPENSSL_cleanse(scratch, sizeof scratch); g_free(context);
    return ok;
}
