#include "ea_native.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <string.h>

static void accepts_protocol(void) {
    const char *valid[] = {
        "{\"op\":\"account\"}",
        "{\"op\":\"initialize\",\"presence\":true}",
        "{\"op\":\"generate\",\"slot\":\"operator-instance\",\"kind\":\"ed25519\",\"replace\":true,\"presence\":true}",
        "{\"op\":\"sign\",\"slot\":\"writer-signing\",\"data\":\"\"}",
        "{\"op\":\"wrap-secret\",\"slot\":\"draft-key\",\"data\":\"0000000000000000000000000000000000000000000000000000000000000000\"}",
        "{\"op\":\"contains\",\"slot\":\"admin-signing\",\"presence\":false}",
        "{\"op\":\"account\",\"installation_id\":\"0000000000000000000000000000000000000000000000000000000000000000\"}",
        "{\"op\":\"reset\",\"presence\":true}",
        "{\"op\":\"watch-session\",\"installation_id\":\"0000000000000000000000000000000000000000000000000000000000000000\"}"
    };
    for (size_t i = 0; i < G_N_ELEMENTS(valid); i++) {
        EaRequest r;
        g_assert_null(ea_parse((const unsigned char *)valid[i], strlen(valid[i]), &r));
        OPENSSL_cleanse(&r, sizeof r);
    }
}

static void rejects_ambiguous_protocol(void) {
    const char *invalid[] = {
        "{}", "[]", "null", "{\"op\":\"account\"}{}",
        "{\"op\":\"account\",}", "{\"op\":\"account\",\"op\":\"initialize\"}",
        "{\"op\":\"account\",\"o\\u0070\":\"account\"}",
        "{\"op\":\"account\\u0000x\"}", "{\"op\":\"account\",\"presence\":1}",
        "{\"op\":\"account\",\"presence\":true}", "{\"op\":\"initialize\",\"slot\":\"a\"}",
        "{\"op\":\"contains\",\"slot\":\"../key\"}", "{\"op\":\"contains\",\"slot\":\"A\"}",
        "{\"op\":\"contains\",\"slot\":\"\"}", "{\"op\":\"contains\",\"slot\":\"a\",\"data\":\"00\"}",
        "{\"op\":\"generate\",\"slot\":\"writer-signing\",\"kind\":\"secret32\"}",
        "{\"op\":\"generate\",\"slot\":\"draft-key\",\"kind\":\"ed25519\"}",
        "{\"op\":\"sign\",\"slot\":\"operator-instance\",\"data\":\"00\"}",
        "{\"op\":\"sign\",\"slot\":\"root-signing\",\"data\":\"00\",\"presence\":false}",
        "{\"op\":\"sign\",\"slot\":\"draft-key\",\"data\":\"00\",\"presence\":true}",
        "{\"op\":\"sign\",\"slot\":\"writer-signing\",\"data\":\"AA\"}",
        "{\"op\":\"sign\",\"slot\":\"writer-signing\",\"data\":\"0\"}",
        "{\"op\":\"unwrap-secret\",\"slot\":\"writer-signing\"}",
        "{\"op\":\"generate\",\"slot\":\"admin-signing\",\"kind\":\"ed25519\",\"replace\":true,\"presence\":true}",
        "{\"op\":\"generate\",\"slot\":\"operator-instance\",\"kind\":\"ed25519\",\"replace\":true}",
        "{\"op\":\"account\",\"installation_id\":\"00\"}",
        "{\"op\":\"account\",\"unknown\":false}", "{\"op\":\"account\",\"presence\":{}}",
        "{\"op\":\"reset\"}",
        "{\"op\":\"watch-session\"}",
        "{\"op\":\"watch-session\",\"installation_id\":\"00\"}",
        "{\"op\":\"watch-session\",\"installation_id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"presence\":false}",
        "{\"op\":\"watch-session\",\"installation_id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"slot\":\"operator-instance\"}"
    };
    for (size_t i = 0; i < G_N_ELEMENTS(invalid); i++) {
        EaRequest r;
        g_assert_nonnull(ea_parse((const unsigned char *)invalid[i], strlen(invalid[i]), &r));
    }
    unsigned char *large = g_malloc0(EA_MAX_MESSAGE + 1);
    EaRequest r;
    g_assert_cmpstr(ea_parse(large, EA_MAX_MESSAGE + 1, &r), ==, "request-too-large");
    g_free(large);
}

/* RFC 8032 test 1 catches hashing before signing or a non-Ed25519 primitive. */
static void signing_backup_parser(void) {
    const char *slots[] = {"admin-signing", "root-signing"};
    for (size_t i = 0; i < G_N_ELEMENTS(slots); i++) {
        char *wire = g_strdup_printf("{\"op\":\"backup-signing-seed\",\"slot\":\"%s\",\"installation_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"expected_public_key\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"presence\":true}", slots[i]);
        EaRequest r;
        g_assert_null(ea_parse((const unsigned char *)wire, strlen(wire), &r));
        unsigned char exact[512]; memset(exact, ' ', sizeof exact); memcpy(exact, wire, strlen(wire));
        g_assert_null(ea_parse(exact, sizeof exact, &r));
        g_free(wire);
    }
}

static void ed25519_rfc8032(void) {
    unsigned char seed[32], pub[32], sig[64], expected_pub[32], expected_sig[64];
    size_t n;
    g_assert_true(ea_unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed, 32, &n));
    g_assert_true(ea_unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", expected_pub, 32, &n));
    g_assert_true(ea_unhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", expected_sig, 64, &n));
    g_assert_true(ea_public(seed, pub));
    g_assert_cmpmem(pub, 32, expected_pub, 32);
    g_assert_true(ea_sign(seed, (const unsigned char *)"", 0, sig));
    g_assert_cmpmem(sig, 64, expected_sig, 64);
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    g_assert_cmpint(EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key), ==, 1);
    g_assert_cmpint(EVP_DigestVerify(ctx, sig, 64, (const unsigned char *)"", 0), ==, 1);
    sig[0] ^= 1;
    g_assert_cmpint(EVP_DigestVerify(ctx, sig, 64, (const unsigned char *)"", 0), ==, 0);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(seed, sizeof seed);
}

/* Marker loss, public-ID substitution, keyring loss, metadata/slot swaps,
 * and tag tampering must each independently prevent recovering the secret. */
static void two_store_encryption(void) {
    EaMarker m = {0};
    unsigned char instance[32], plain[32], recovered[32], box[EA_ENVELOPE_SIZE], other[EA_ENVELOPE_SIZE];
    g_assert_true(ea_random(m.id));
    g_assert_true(ea_random(m.wrapping));
    g_assert_true(ea_random(instance));
    g_assert_true(ea_random(plain));
    g_assert_true(ea_seal(&m, instance, "draft-key", "secret32", "", plain, box));
    g_assert_true(ea_seal(&m, instance, "draft-key", "secret32", "", plain, other));
    g_assert_cmpint(CRYPTO_memcmp(box, other, sizeof box), !=, 0);
    g_assert_true(ea_open(&m, instance, "draft-key", "secret32", "", box, recovered));
    g_assert_cmpmem(plain, 32, recovered, 32);
    EaMarker wrong = m;
    memcpy(wrong.wrapping, m.id, 32);
    g_assert_false(ea_open(&wrong, instance, "draft-key", "secret32", "", box, recovered));
    wrong = m; wrong.id[0] ^= 1;
    g_assert_false(ea_open(&wrong, instance, "draft-key", "secret32", "", box, recovered));
    instance[0] ^= 1;
    g_assert_false(ea_open(&m, instance, "draft-key", "secret32", "", box, recovered));
    instance[0] ^= 1;
    g_assert_false(ea_open(&m, instance, "database-key", "secret32", "", box, recovered));
    g_assert_false(ea_open(&m, instance, "draft-key", "ed25519", "", box, recovered));
    for (size_t i = 0; i < sizeof box; i++) {
        box[i] ^= 1;
        g_assert_false(ea_open(&m, instance, "draft-key", "secret32", "", box, recovered));
        unsigned char zero[32] = {0};
        g_assert_cmpmem(recovered, 32, zero, 32);
        box[i] ^= 1;
    }
    OPENSSL_cleanse(&m, sizeof m);
    OPENSSL_cleanse(instance, sizeof instance);
    OPENSSL_cleanse(plain, sizeof plain);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/protocol/valid", accepts_protocol);
    g_test_add_func("/protocol/reject", rejects_ambiguous_protocol);
    g_test_add_func("/crypto/rfc8032", ed25519_rfc8032);
    g_test_add_func("/crypto/two-store", two_store_encryption);
    g_test_add_func("/backup/parser", signing_backup_parser);
    return g_test_run();
}
