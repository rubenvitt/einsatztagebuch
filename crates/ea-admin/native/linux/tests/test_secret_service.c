/* Exercise the storage layer against a REAL isolated gnome-keyring-daemon.
 * Calling the internal post-authorization layer is deliberately not a native
 * authentication or desktop session test. No production bypass is compiled. */
#include "../provider.c"
#include "../watch.h"
#include <openssl/evp.h>

static void real_storage_roundtrip(void) {
    Context c = {.account = {.uid = getuid()}, .store = {.dir_fd = -1, .base_fd = -1}};
    g_assert_true(ea_random(c.marker.id));
    g_assert_true(ea_random(c.marker.wrapping));
    g_assert_true(ea_random(c.instance));
    g_assert_true(ea_hash(c.instance, 32, c.marker.instance_hash));
    unsigned char ns[32];
    g_assert_true(ea_hash(c.marker.id, 32, ns));
    c.namespace = ea_hex(ns, 32);
    g_assert_null(open_secret_service(&c));
    g_assert_cmpstr(g_dbus_proxy_get_object_path(G_DBUS_PROXY(c.login)), ==, "/org/freedesktop/secrets/collection/login");
    char *hash = ea_hex(c.marker.instance_hash, 32);
    g_assert_null(put(&c, "_account-instance", "instance", hash, c.instance, 32, FALSE));
    g_free(hash);
    SecretItem *probe = NULL;
    char *probe_pub = NULL;
    g_assert_cmpstr(lookup(&c, "_account-instance", &probe), ==, NULL);
    g_assert_nonnull(probe);
    g_assert_cmpstr(metadata(&c, probe, "_account-instance", "instance", &probe_pub), ==, NULL);
    char *instance_path = g_strdup(g_dbus_proxy_get_object_path(G_DBUS_PROXY(probe)));
    g_free(probe_pub);
    g_assert_true(secret_item_load_secret_sync(probe, NULL, NULL));
    SecretValue *probe_value = secret_item_get_secret(probe);
    gsize probe_len;
    (void)secret_value_get(probe_value, &probe_len);
    g_test_message("Native value length=%zu, content-type=%s", probe_len, secret_value_get_content_type(probe_value));
    secret_value_unref(probe_value); g_object_unref(probe);
    g_assert_cmpstr(instance(&c, TRUE), ==, NULL);
    EaWatchState state = {0}; EaWatchBus watch;
    g_assert_true(ea_watch_bus_start(&watch, &state, c.session, "org.freedesktop.secrets", getuid()));
    watch.instance_path = instance_path;
    EaRequest r = {.op = "generate", .slot = "writer-signing", .kind = "ed25519"};
    JsonObject *out = json_object_new();
    g_assert_null(operate(&c, &r, out));
    g_assert_true(ea_watch_bus_barrier(&watch));
    while (g_main_context_iteration(NULL, FALSE)) {}
    g_assert_false(state.invalidated);
    unsigned char pub[32], sig[64]; size_t n;
    g_assert_true(ea_unhex(json_object_get_string_member(out, "public_key"), pub, 32, &n));
    json_object_unref(out); out = json_object_new();
    g_assert_cmpstr(operate(&c, &r, out), ==, "key-exists");
    strcpy(r.op, "sign"); memcpy(r.data, "real-libsecret-roundtrip", 23); r.data_len = 23;
    g_assert_null(operate(&c, &r, out));
    g_assert_true(ea_unhex(json_object_get_string_member(out, "signature"), sig, 64, &n));
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    g_assert_cmpint(EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key), ==, 1);
    g_assert_cmpint(EVP_DigestVerify(ctx, sig, 64, r.data, r.data_len), ==, 1);
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key);
    json_object_unref(out); out = json_object_new();
    strcpy(r.op, "wrap-secret"); strcpy(r.slot, "draft-key");
    g_assert_true(ea_random(r.data)); r.data_len = 32;
    g_assert_null(operate(&c, &r, out));
    g_assert_false(json_object_has_member(out, "secret"));
    strcpy(r.op, "unwrap-secret");
    g_assert_null(operate(&c, &r, out));
    unsigned char actual[32];
    g_assert_true(ea_unhex(json_object_get_string_member(out, "secret"), actual, 32, &n));
    g_assert_cmpmem(actual, 32, r.data, 32);
    json_object_unref(out); out = json_object_new();
    c.marker.wrapping[0] ^= 1;
    g_assert_cmpstr(operate(&c, &r, out), ==, "key-invalid");
    c.marker.wrapping[0] ^= 1;
    c.instance[0] ^= 1;
    g_assert_cmpstr(operate(&c, &r, out), ==, "key-invalid");
    c.instance[0] ^= 1;
    strcpy(r.op, "delete");
    g_assert_null(operate(&c, &r, out));
    g_assert_null(operate(&c, &r, out));
    strcpy(r.op, "contains");
    g_assert_null(operate(&c, &r, out));
    g_assert_false(json_object_get_boolean_member(out, "contains"));
    g_assert_true(ea_watch_bus_barrier(&watch));
    while (g_main_context_iteration(NULL, FALSE)) {}
    g_assert_false(state.invalidated);
    /* Real collection locking must prevent storage access, without a prompt. */
    GList *objects = g_list_append(NULL, c.login), *locked = NULL;
    g_assert_cmpint(secret_service_lock_sync(c.service, objects, NULL, &locked, NULL), ==, 1);
    g_list_free(objects); g_list_free_full(locked, g_object_unref);
    g_assert_cmpstr(operate(&c, &r, out), ==, "locked");
    g_assert_true(ea_watch_bus_barrier(&watch));
    while (g_main_context_iteration(NULL, FALSE)) {}
    g_assert_true(state.invalidated);
    ea_watch_bus_stop(&watch);
    json_object_unref(out);
    g_clear_object(&c.login); g_clear_object(&c.service); g_clear_object(&c.session);
    g_free(c.namespace); g_free(c.owner);
    OPENSSL_cleanse(&c.marker, sizeof c.marker); OPENSSL_cleanse(c.instance, 32);
    OPENSSL_cleanse(&r, sizeof r); OPENSSL_cleanse(actual, sizeof actual);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/native-secret-service/real-storage", real_storage_roundtrip);
    return g_test_run();
}
