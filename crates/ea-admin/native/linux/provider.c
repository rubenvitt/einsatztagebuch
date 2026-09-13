#include "ea_native.h"
#include <libsecret/secret.h>
#include <openssl/crypto.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Secret Service must already have been unlocked by the desktop/PAM stack.
 * Even a lock race must not cause libsecret to launch a keyring password UI. */
typedef struct { SecretService parent; } EaSecretService;
typedef struct { SecretServiceClass parent; } EaSecretServiceClass;
G_DEFINE_TYPE(EaSecretService, ea_secret_service, SECRET_TYPE_SERVICE)
static GVariant *no_prompt(SecretService *self, SecretPrompt *prompt, GCancellable *cancellable,
                           const GVariantType *type, GError **error) {
    (void)self; (void)prompt; (void)cancellable; (void)type;
    g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "locked");
    return NULL;
}
static void ea_secret_service_class_init(EaSecretServiceClass *klass) { klass->parent.prompt_sync = no_prompt; }
static void ea_secret_service_init(EaSecretService *self) { (void)self; }

static const SecretSchema schema = {
    .name = "org.einsatzarchiv.NativeOperator.v1", .flags = SECRET_SCHEMA_NONE,
    .attributes = {{"namespace", SECRET_SCHEMA_ATTRIBUTE_STRING}, {"slot", SECRET_SCHEMA_ATTRIBUTE_STRING},
        {"kind", SECRET_SCHEMA_ATTRIBUTE_STRING}, {"public", SECRET_SCHEMA_ATTRIBUTE_STRING},
        {"mac", SECRET_SCHEMA_ATTRIBUTE_STRING}, {NULL, 0}}
};

typedef struct {
    GDBusConnection *system, *session;
    SecretService *service;
    SecretCollection *login;
    char *session_path, *owner, *namespace;
    EaAccount account;
    EaMarker marker;
    EaMarkerStore store;
    unsigned char instance[32];
} Context;

static gboolean bus_uid(GDBusConnection *bus, const char *name, uid_t uid) {
    GVariant *v = g_dbus_connection_call_sync(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
        "GetConnectionUnixUser", g_variant_new("(s)", name), G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE, 5000, NULL, NULL);
    if (!v) return FALSE;
    guint32 actual; g_variant_get(v, "(u)", &actual); g_variant_unref(v);
    return actual == uid;
}

static char *secret_owner(GDBusConnection *bus) {
    GVariant *v = g_dbus_connection_call_sync(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
        "GetNameOwner", g_variant_new("(s)", "org.freedesktop.secrets"), G_VARIANT_TYPE("(s)"),
        G_DBUS_CALL_FLAGS_NONE, 5000, NULL, NULL);
    if (!v) return NULL;
    char *owner; g_variant_get(v, "(s)", &owner); g_variant_unref(v);
    return owner;
}

static gboolean login_unlocked(Context *c) {
    if (!c->login || !c->session || g_dbus_connection_is_closed(c->session)) return FALSE;
    char *owner = secret_owner(c->session);
    gboolean same = owner && !strcmp(owner, c->owner);
    g_free(owner);
    if (!same) return FALSE;
    GVariant *v = g_dbus_connection_call_sync(c->session, c->owner, g_dbus_proxy_get_object_path(G_DBUS_PROXY(c->login)),
        "org.freedesktop.DBus.Properties", "Get", g_variant_new("(ss)", "org.freedesktop.Secret.Collection", "Locked"),
        G_VARIANT_TYPE("(v)"), G_DBUS_CALL_FLAGS_NO_AUTO_START, 5000, NULL, NULL);
    if (!v) return FALSE;
    GVariant *locked; g_variant_get(v, "(v)", &locked);
    gboolean unlocked = g_variant_is_of_type(locked, G_VARIANT_TYPE_BOOLEAN) && !g_variant_get_boolean(locked);
    g_variant_unref(locked); g_variant_unref(v);
    return unlocked;
}

static const char *open_secret_service(Context *c) {
    struct stat st;
    char *directory = g_strdup_printf("/run/user/%u", (unsigned)c->account.uid);
    char *socket = g_strconcat(directory, "/bus", NULL);
    gboolean safe = !lstat(directory, &st) && S_ISDIR(st.st_mode) && st.st_uid == c->account.uid && !(st.st_mode & 077) &&
        !lstat(socket, &st) && S_ISSOCK(st.st_mode) && st.st_uid == c->account.uid;
    char *address = g_strconcat("unix:path=", socket, NULL);
    g_free(directory); g_free(socket);
    if (!safe) { g_free(address); return "secret-service-unavailable"; }
    /* No request or inherited environment may choose a bus or account. */
    g_setenv("DBUS_SESSION_BUS_ADDRESS", address, TRUE); g_free(address);
    c->session = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, NULL);
    if (!c->session || !(c->owner = secret_owner(c->session)) || !bus_uid(c->session, c->owner, c->account.uid)) return "secret-service-unavailable";
    c->service = secret_service_open_sync(ea_secret_service_get_type(), c->owner, SECRET_SERVICE_NONE, NULL, NULL);
    if (!c->service) return "secret-service-unavailable";
    /* The default alias can be a different keyring. Never create a collection. */
    c->login = secret_collection_for_alias_sync(c->service, "login", SECRET_COLLECTION_NONE, NULL, NULL);
    if (!c->login || strcmp(g_dbus_proxy_get_object_path(G_DBUS_PROXY(c->login)),
                            "/org/freedesktop/secrets/collection/login") || !login_unlocked(c)) return "locked";
    return NULL;
}

static GHashTable *attrs(Context *c, const char *slot) {
    return secret_attributes_build(&schema, "namespace", c->namespace, "slot", slot, NULL);
}

/* Narrow lookup in the current login collection and current random namespace;
 * no unlock/load flags, no global enumeration, reject duplicate slots. */
static const char *lookup(Context *c, const char *slot, SecretItem **item) {
    *item = NULL;
    if (!login_unlocked(c)) return "locked";
    GHashTable *a = attrs(c, slot);
    GError *error = NULL;
    GList *items = secret_collection_search_sync(c->login, &schema, a, SECRET_SEARCH_ALL, NULL, &error);
    g_hash_table_unref(a);
    const char *result = NULL;
    if (error) result = "key-store-unavailable";
    else if (items && items->next) result = "key-ambiguous";
    else if (items) {
        if (secret_item_get_locked(items->data)) result = "locked";
        else *item = g_object_ref(items->data);
    }
    g_list_free_full(items, g_object_unref); g_clear_error(&error);
    return result;
}

static const char *metadata(Context *c, SecretItem *item, const char *slot, const char *kind, char **pub) {
    GHashTable *a = secret_item_get_attributes(item);
    const char *ns = g_hash_table_lookup(a, "namespace"), *s = g_hash_table_lookup(a, "slot");
    const char *k = g_hash_table_lookup(a, "kind"), *p = g_hash_table_lookup(a, "public"), *mac = g_hash_table_lookup(a, "mac");
    const char *error = "key-invalid";
    if (!ns || !s || !k || !p || !mac || strcmp(ns, c->namespace) || strcmp(s, slot) || strcmp(k, kind)) goto done;
    unsigned char decoded[32]; size_t n;
    if ((!strcmp(kind, "ed25519") || !strcmp(kind, "instance")) && (!ea_unhex(p, decoded, 32, &n) || n != 32)) goto done;
    if (!strcmp(kind, "secret32") && p[0]) goto done;
    char *expected = ea_metadata_mac(&c->marker, slot, kind, p);
    gboolean valid = expected && strlen(mac) == 64 && !CRYPTO_memcmp(mac, expected, 64);
    g_free(expected);
    if (!valid) goto done;
    *pub = g_strdup(p);
    error = NULL;
done:
    g_hash_table_unref(a);
    return error;
}

static gboolean encrypted_session(Context *c) {
    return secret_service_ensure_session_sync(c->service, NULL, NULL) &&
        !g_strcmp0(secret_service_get_session_algorithms(c->service), "dh-ietf1024-sha256-aes128-cbc-pkcs7");
}

static const char *read_value(Context *c, SecretItem *item, unsigned char *out, size_t required) {
    if (!login_unlocked(c)) return "locked";
    if (!encrypted_session(c) || !secret_item_load_secret_sync(item, NULL, NULL)) return "key-store-unavailable";
    SecretValue *value = secret_item_get_secret(item);
    if (!value) return "key-missing";
    gsize len = 0;
    const char *bytes = secret_value_get(value, &len);
    /* GNOME Keyring returns text/plain even for binary secrets submitted as
     * application/octet-stream. MIME metadata is not an integrity boundary:
     * exact byte length plus instance hash / AEAD authenticate every value. */
    const char *type = secret_value_get_content_type(value);
    gboolean ok = len == required && bytes && type &&
        (!strcmp(type, "application/octet-stream") || !strcmp(type, "text/plain"));
    if (ok) memcpy(out, bytes, required);
    secret_value_unref(value);
    return ok ? NULL : "key-invalid";
}

static const char *put(Context *c, const char *slot, const char *kind, const char *pub,
                       const unsigned char *bytes, size_t size, gboolean replace) {
    SecretItem *old = NULL;
    const char *error = lookup(c, slot, &old);
    if (error) return error;
    if (old && !replace) { g_object_unref(old); return "key-exists"; }
    if (!encrypted_session(c)) { g_clear_object(&old); return "key-store-unavailable"; }
    GHashTable *a = attrs(c, slot);
    char *mac = ea_metadata_mac(&c->marker, slot, kind, pub);
    if (!mac) { g_clear_object(&old); g_hash_table_unref(a); return "crypto-failed"; }
    g_hash_table_insert(a, g_strdup("kind"), g_strdup(kind));
    g_hash_table_insert(a, g_strdup("public"), g_strdup(pub));
    g_hash_table_insert(a, g_strdup("mac"), mac);
    SecretValue *value = secret_value_new((const char *)bytes, (gssize)size, "application/octet-stream");
    if (old) {
        /* Explicit replacement invalidates the previous instance first. A crash
         * can lose availability, never silently return the former instance. */
        if (!secret_item_delete_sync(old, NULL, NULL)) error = "key-delete-failed";
        g_clear_object(&old);
    }
    if (!error) {
        SecretItem *created = secret_item_create_sync(c->login, &schema, a, "Einsatzarchiv native key", value,
                                                      SECRET_ITEM_CREATE_NONE, NULL, NULL);
        if (!created) error = "key-write-failed";
        g_clear_object(&created);
    }
    secret_value_unref(value); g_hash_table_unref(a);
    return error;
}

static const char *instance(Context *c, gboolean read_secret) {
    SecretItem *item = NULL;
    char *pub = NULL, *hash = ea_hex(c->marker.instance_hash, 32);
    const char *error = lookup(c, "_account-instance", &item);
    if (!error && !item) error = "installation-instance-missing";
    if (!error) error = metadata(c, item, "_account-instance", "instance", &pub);
    if (!error && strcmp(hash, pub)) error = "installation-invalid";
    if (!error && read_secret) {
        error = read_value(c, item, c->instance, 32);
        unsigned char digest[32];
        if (!error && (!ea_hash(c->instance, 32, digest) || CRYPTO_memcmp(digest, c->marker.instance_hash, 32))) error = "installation-invalid";
        OPENSSL_cleanse(digest, sizeof digest);
    }
    g_free(hash); g_free(pub); g_clear_object(&item);
    return error;
}

static const char *check(Context *c, gboolean require_unlock) {
    EaAccount after;
    const char *error = ea_read_account(&after);
    if (!error && (after.uid != c->account.uid || after.machine_len != c->account.machine_len ||
                   CRYPTO_memcmp(after.binding, c->account.binding, 32))) error = "account-changed";
    if (!error) error = ea_marker_recheck(&c->store, &c->account, &c->marker);
    if (!error && require_unlock && (!ea_session_unlocked(c->system, c->account.uid, &c->session_path) || !login_unlocked(c))) error = "locked";
    return error;
}

static void hex_member(JsonObject *o, const char *name, const unsigned char *bytes, size_t len) {
    char *hex = ea_hex(bytes, len);
    json_object_set_string_member(o, name, hex);
    OPENSSL_cleanse(hex, len * 2); g_free(hex);
}
static void account_fields(Context *c, JsonObject *o, gboolean locked) {
    json_object_set_string_member(o, "platform", "linux");
    json_object_set_int_member(o, "uid", c->account.uid);
    hex_member(o, "machine_id_bytes", c->account.machine, c->account.machine_len);
    json_object_set_boolean_member(o, "locked", locked);
}

static const char *operate_inner(Context *c, const EaRequest *r, JsonObject *o, EaSigningBackupFrame *backup) {
    if (backup) {
        OPENSSL_cleanse(backup, sizeof *backup);
        const char *invalid = ea_validate_signing_backup(r);
        if (invalid) return invalid;
        if (CRYPTO_memcmp(r->installation, c->marker.id, 32)) return "installation-changed";
    } else if (!strcmp(r->op, "backup-signing-seed")) return "invalid-request";
    const char *kind = ea_secret_slot(r->slot) ? "secret32" : "ed25519";
    unsigned char plain[32] = {0}, box[EA_ENVELOPE_SIZE] = {0}, public_key[32] = {0}, signature[64] = {0};
    SecretItem *item = NULL;
    char *pub = NULL;
    const char *error = NULL;
    if (!strcmp(r->op, "generate") || !strcmp(r->op, "wrap-secret")) {
        if (!strcmp(r->op, "wrap-secret")) memcpy(plain, r->data, 32);
        else if (!ea_random(plain)) { error = "crypto-failed"; goto done; }
        if (!strcmp(kind, "ed25519")) {
            if (!ea_public(plain, public_key)) { error = "crypto-failed"; goto done; }
            pub = ea_hex(public_key, 32);
        } else pub = g_strdup("");
        if (!ea_seal(&c->marker, c->instance, r->slot, kind, pub, plain, box)) { error = "crypto-failed"; goto done; }
        error = put(c, r->slot, kind, pub, box, sizeof box, r->replace);
        if (!error && !strcmp(r->op, "generate")) {
            if (*pub) json_object_set_string_member(o, "public_key", pub);
            else json_object_set_null_member(o, "public_key");
        }
        goto done;
    }
    error = lookup(c, r->slot, &item);
    if (error) goto done;
    if (item) error = metadata(c, item, r->slot, kind, &pub);
    if (error) goto done;
    if (!strcmp(r->op, "contains")) { json_object_set_boolean_member(o, "contains", item != NULL); goto done; }
    if (!strcmp(r->op, "public-key")) {
        if (pub && *pub) json_object_set_string_member(o, "public_key", pub);
        else json_object_set_null_member(o, "public_key");
        goto done;
    }
    if (!strcmp(r->op, "delete")) {
        if (item && !secret_item_delete_sync(item, NULL, NULL)) error = "key-delete-failed";
        goto done;
    }
    if (!item) { error = "key-missing"; goto done; }
    if (backup) {
        unsigned char expected[32]; size_t n;
        if (!pub || !ea_unhex(pub, expected, 32, &n) || n != 32 || CRYPTO_memcmp(expected, r->expected_public, 32)) {
            error = "key-invalid"; goto done;
        }
    }
    error = read_value(c, item, box, sizeof box);
    if (error) goto done;
    if (!ea_open(&c->marker, c->instance, r->slot, kind, pub, box, plain)) { error = "key-invalid"; goto done; }
    if (backup) {
        if (!ea_public(plain, public_key) || CRYPTO_memcmp(public_key, r->expected_public, 32)) { error = "key-invalid"; goto done; }
        /* Re-read authenticated public metadata after the blocking seed read. */
        SecretItem *latest = NULL; char *latest_pub = NULL;
        error = lookup(c, r->slot, &latest);
        if (!error && !latest) error = "key-missing";
        if (!error) error = metadata(c, latest, r->slot, "ed25519", &latest_pub);
        if (!error && strcmp(latest_pub, pub)) error = "key-invalid";
        g_free(latest_pub); g_clear_object(&latest);
        if (error) goto done;
        memcpy(backup->bytes, "EABKSEED", 8); backup->bytes[8] = 1;
        backup->bytes[9] = !strcmp(r->slot, "admin-signing") ? 1 : 2;
        memcpy(backup->bytes + 10, c->marker.id, 32);
        memcpy(backup->bytes + 42, public_key, 32);
        memcpy(backup->bytes + 74, plain, 32);
    } else if (!strcmp(r->op, "unwrap-secret")) hex_member(o, "secret", plain, 32);
    else if (!strcmp(r->op, "sign")) {
        if (!ea_public(plain, public_key)) { error = "crypto-failed"; goto done; }
        char *actual = ea_hex(public_key, 32);
        gboolean valid = !strcmp(actual, pub); g_free(actual);
        if (!valid) { error = "key-invalid"; goto done; }
        if (!ea_sign(plain, r->data, r->data_len, signature)) { error = "crypto-failed"; goto done; }
        hex_member(o, "signature", signature, 64);
    } else error = "invalid-request";
done:
    if (error && backup) OPENSSL_cleanse(backup, sizeof *backup);
    OPENSSL_cleanse(plain, sizeof plain); OPENSSL_cleanse(box, sizeof box); OPENSSL_cleanse(signature, sizeof signature);
    g_free(pub); g_clear_object(&item);
    return error;
}

static const char *operate(Context *c, const EaRequest *r, JsonObject *o) {
    return operate_inner(c, r, o, NULL);
}

static const char *execute(const EaRequest *r, JsonObject **fields, char **watched_instance, EaSigningBackupFrame *backup) {
    if (backup) {
        const char *invalid = ea_validate_signing_backup(r);
        if (invalid) return invalid;
    } else if (!strcmp(r->op, "backup-signing-seed")) return "invalid-request";
    Context c = {.store = {.base_fd = -1, .dir_fd = -1, .lock_fd = -1}};
    JsonObject *o = json_object_new();
    gboolean account_op = !strcmp(r->op, "account") || !strcmp(r->op, "initialize");
    gboolean fresh = FALSE;
    const char *error = ea_read_account(&c.account);
    if (error) goto done;
    error = ea_marker_store_open(&c.store, c.account.uid);
    if (error) goto done;
    error = ea_marker_load(&c.store, &c.account, &c.marker);
    if (error && !strcmp(error, "installation-missing") && !strcmp(r->op, "initialize") && !r->has_installation) {
        fresh = TRUE; error = NULL;
        memcpy(c.marker.binding, c.account.binding, 32);
        if (!ea_random(c.marker.id) || !ea_random(c.marker.wrapping) || !ea_random(c.instance) ||
            !ea_hash(c.instance, 32, c.marker.instance_hash)) { error = "crypto-failed"; goto done; }
    }
    if (error) goto done;
    if (r->has_installation && CRYPTO_memcmp(r->installation, c.marker.id, 32)) { error = "installation-changed"; goto done; }
    unsigned char namespace_digest[32];
    if (!ea_hash(c.marker.id, 32, namespace_digest)) { error = "crypto-failed"; goto done; }
    c.namespace = ea_hex(namespace_digest, 32);
    g_setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/run/dbus/system_bus_socket", TRUE);
    c.system = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
    if (!ea_session_unlocked(c.system, c.account.uid, &c.session_path)) {
        if (account_op && !fresh && !r->presence) { account_fields(&c, o, TRUE); goto success; }
        error = "locked"; goto done;
    }
    error = open_secret_service(&c);
    if (error) {
        if (account_op && !fresh && !r->presence) { error = NULL; account_fields(&c, o, TRUE); goto success; }
        goto done;
    }
    if (r->presence) {
        if (!ea_fresh_presence(c.system)) { error = "presence-denied"; goto done; }
        if (!ea_session_unlocked(c.system, c.account.uid, &c.session_path) || !login_unlocked(&c)) { error = "locked"; goto done; }
    }
    if (fresh) {
        char *hash = ea_hex(c.marker.instance_hash, 32);
        error = put(&c, "_account-instance", "instance", hash, c.instance, 32, FALSE);
        g_free(hash);
        if (error) goto done;
        EaAccount now;
        error = ea_read_account(&now);
        if (!error && CRYPTO_memcmp(now.binding, c.account.binding, 32)) error = "account-changed";
        if (!error && (!ea_session_unlocked(c.system, c.account.uid, &c.session_path) || !login_unlocked(&c))) error = "locked";
        if (!error) error = ea_marker_publish(&c.store, &c.marker);
        if (error) goto done;
    }
    error = check(&c, TRUE);
    if (error) goto done;
    /* Metadata operations never fetch either the instance secret or key data. */
    gboolean metadata_only = !strcmp(r->op, "public-key") || !strcmp(r->op, "contains");
    error = instance(&c, !metadata_only);
    if (error) goto done;
    if (watched_instance) {
        SecretItem *item = NULL;
        error = lookup(&c, "_account-instance", &item);
        if (!error && !item) error = "installation-instance-missing";
        if (!error) *watched_instance = g_strdup(g_dbus_proxy_get_object_path(G_DBUS_PROXY(item)));
        g_clear_object(&item);
        if (error) goto done;
    }
    if (!strcmp(r->op, "reset")) {
        error = check(&c, TRUE);
        if (!error) error = ea_marker_reset(&c.store);
        if (!error) {
            json_object_set_boolean_member(o, "reset", TRUE);
            /* Success identifies the invalidated public ID. No new namespace. */
            hex_member(o, "installation_id", c.marker.id, 32);
            json_object_set_boolean_member(o, "ok", TRUE);
        }
        goto done;
    }
    if (account_op) account_fields(&c, o, FALSE);
    else error = backup ? operate_inner(&c, r, o, backup) : operate(&c, r, o);
    if (!error) error = check(&c, TRUE);
    if (!error) error = instance(&c, !metadata_only);
    if (error) goto done;
success:
    error = check(&c, backup != NULL);
    if (!error) {
        hex_member(o, "installation_id", c.marker.id, 32);
        json_object_set_boolean_member(o, "ok", TRUE);
    }
done:
    if (error && backup) OPENSSL_cleanse(backup, sizeof *backup);
    if (error && watched_instance) g_clear_pointer(watched_instance, g_free);
    if (!error) *fields = o;
    else {
        if (json_object_has_member(o, "secret")) {
            const char *secret = json_object_get_string_member(o, "secret");
            OPENSSL_cleanse((char *)secret, strlen(secret));
        }
        json_object_unref(o);
    }
    g_clear_object(&c.login); g_clear_object(&c.service); g_clear_object(&c.session); g_clear_object(&c.system);
    g_free(c.session_path); g_free(c.owner); g_free(c.namespace);
    ea_marker_store_close(&c.store);
    OPENSSL_cleanse(c.instance, sizeof c.instance); OPENSSL_cleanse(&c.marker, sizeof c.marker);
    return error;
}

const char *ea_execute(const EaRequest *r, JsonObject **fields) { return execute(r, fields, NULL, NULL); }

/* Internal watch setup only; the object path never enters JSON or logs. */
const char *ea_watch_account(const EaRequest *r, JsonObject **fields, char **instance_path) {
    *instance_path = NULL;
    if (strcmp(r->op, "account") || !r->has_installation || r->presence) return "invalid-request";
    return execute(r, fields, instance_path, NULL);
}

const char *ea_execute_signing_backup(const EaRequest *r, EaSigningBackupFrame *frame) {
    memset(frame, 0, sizeof *frame);
    JsonObject *fields = NULL;
    const char *error = execute(r, &fields, NULL, frame);
    if (fields) json_object_unref(fields);
    if (error) OPENSSL_cleanse(frame, sizeof *frame);
    return error;
}
