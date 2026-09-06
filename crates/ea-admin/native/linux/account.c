#include "ea_native.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <polkit/polkit.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

const char *ea_read_account(EaAccount *a) {
    memset(a, 0, sizeof *a);
    a->uid = getuid();
    if (a->uid != geteuid() || getgid() != getegid()) return "account-invalid";
    int fd = open("/etc/machine-id", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return "account-unavailable";
    struct stat st;
    unsigned char raw[34]; size_t n = 0;
    const char *error = "account-invalid";
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) goto done;
    while (n < sizeof raw) {
        ssize_t count = read(fd, raw + n, sizeof raw - n);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) goto done;
        if (!count) break;
        n += (size_t)count;
    }
    if ((n != 32 && n != 33) || (n == 33 && raw[32] != '\n')) goto done;
    gboolean nonzero = FALSE;
    for (size_t i = 0; i < 32; i++) {
        if (!((raw[i] >= '0' && raw[i] <= '9') || (raw[i] >= 'a' && raw[i] <= 'f'))) goto done;
        if (raw[i] != '0') nonzero = TRUE;
    }
    if (!nonzero) goto done;
    memcpy(a->machine, raw, n); a->machine_len = n;
    /* Local marker fingerprint only. Rust owns the normative CBOR account hash.
     * The IPC returns the original file bytes, including an optional newline. */
    unsigned char context[37];
    memcpy(context, raw, n);
    uint32_t uid = GUINT32_TO_BE((uint32_t)a->uid);
    memcpy(context + n, &uid, 4);
    if (!ea_hash(context, n + 4, a->binding)) goto done;
    error = NULL;
done:
    close(fd);
    return error;
}

static GVariant *call(GDBusConnection *bus, const char *name, const char *path,
                      const char *interface, const char *method, GVariant *args, const GVariantType *type) {
    return g_dbus_connection_call_sync(bus, name, path, interface, method, args, type,
                                      G_DBUS_CALL_FLAGS_NO_AUTO_START, 5000, NULL, NULL);
}

gboolean ea_session_properties_unlocked(GVariant *props, uid_t uid) {
    if (!g_variant_is_of_type(props, G_VARIANT_TYPE("a{sv}"))) return FALSE;
    gboolean active = FALSE, locked = TRUE, remote = TRUE;
    const char *state = NULL, *type = NULL, *class = NULL, *seat = NULL, *unused = NULL;
    guint32 session_uid = G_MAXUINT32;
    return g_variant_lookup(props, "Active", "b", &active) && active &&
        g_variant_lookup(props, "LockedHint", "b", &locked) && !locked &&
        g_variant_lookup(props, "Remote", "b", &remote) && !remote &&
        g_variant_lookup(props, "State", "&s", &state) && !strcmp(state, "active") &&
        g_variant_lookup(props, "Type", "&s", &type) && (!strcmp(type, "wayland") || !strcmp(type, "x11")) &&
        g_variant_lookup(props, "Class", "&s", &class) && !strcmp(class, "user") &&
        g_variant_lookup(props, "Seat", "(&s&o)", &seat, &unused) && seat[0] &&
        g_variant_lookup(props, "User", "(u&o)", &session_uid, &unused) && session_uid == uid;
}

gboolean ea_session_unlocked(GDBusConnection *bus, uid_t uid, char **session_path) {
    if (!bus || g_dbus_connection_is_closed(bus) || getuid() != uid || geteuid() != uid) return FALSE;
    const char *unique = g_dbus_connection_get_unique_name(bus);
    if (!unique) return FALSE;
    GVariant *v = call(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                       "GetConnectionUnixProcessID", g_variant_new("(s)", unique), G_VARIANT_TYPE("(u)"));
    guint32 pid = 0, peer_uid = 0;
    if (!v) return FALSE;
    g_variant_get(v, "(u)", &pid); g_variant_unref(v);
    if (pid != (guint32)getpid()) return FALSE;
    v = call(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
             "GetConnectionUnixUser", g_variant_new("(s)", unique), G_VARIANT_TYPE("(u)"));
    if (!v) return FALSE;
    g_variant_get(v, "(u)", &peer_uid); g_variant_unref(v);
    if (peer_uid != uid) return FALSE;
    v = call(bus, "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
             "GetSessionByPID", g_variant_new("(u)", pid), G_VARIANT_TYPE("(o)"));
    if (!v) return FALSE;
    const char *path;
    g_variant_get(v, "(&o)", &path);
    if (*session_path && strcmp(*session_path, path)) { g_variant_unref(v); return FALSE; }
    if (!*session_path) *session_path = g_strdup(path);
    GVariant *reply = call(bus, "org.freedesktop.login1", path, "org.freedesktop.DBus.Properties",
                          "GetAll", g_variant_new("(s)", "org.freedesktop.login1.Session"), G_VARIANT_TYPE("(a{sv})"));
    g_variant_unref(v);
    if (!reply) return FALSE;
    GVariant *props = g_variant_get_child_value(reply, 0);
    gboolean ok = ea_session_properties_unlocked(props, uid);
    g_variant_unref(props); g_variant_unref(reply);
    return ok;
}

static gboolean transient(PolkitAuthorizationResult *r) {
    return polkit_authorization_result_get_retains_authorization(r) ||
           polkit_authorization_result_get_temporary_authorization_id(r) != NULL;
}

gboolean ea_fresh_presence(GDBusConnection *bus) {
    gboolean ok = FALSE, policy_ok = FALSE;
    PolkitAuthority *authority = polkit_authority_get_sync(NULL, NULL);
    PolkitSubject *subject = NULL;
    PolkitAuthorizationResult *before = NULL, *after = NULL;
    if (!authority || !bus || g_dbus_connection_is_closed(bus)) goto done;
    GList *actions = polkit_authority_enumerate_actions_sync(authority, NULL, NULL);
    for (GList *it = actions; it; it = it->next) {
        PolkitActionDescription *a = it->data;
        if (!strcmp(polkit_action_description_get_action_id(a), EA_ACTION)) {
            policy_ok = polkit_action_description_get_implicit_active(a) == POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED &&
                polkit_action_description_get_implicit_inactive(a) == POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED &&
                polkit_action_description_get_implicit_any(a) == POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED;
        }
    }
    g_list_free_full(actions, g_object_unref);
    if (!policy_ok) goto done;
    subject = polkit_system_bus_name_new(g_dbus_connection_get_unique_name(bus));
    /* A pre-authorized, retained or non-challenge result is not fresh presence. */
    before = polkit_authority_check_authorization_sync(authority, subject, EA_ACTION, NULL,
                                                      POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE, NULL, NULL);
    if (!before || polkit_authorization_result_get_is_authorized(before) ||
        !polkit_authorization_result_get_is_challenge(before) || transient(before)) goto done;
    after = polkit_authority_check_authorization_sync(authority, subject, EA_ACTION, NULL,
            POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION, NULL, NULL);
    ok = after && polkit_authorization_result_get_is_authorized(after) && !transient(after) &&
         !polkit_authorization_result_get_dismissed(after) && !g_dbus_connection_is_closed(bus);
done:
    g_clear_object(&before); g_clear_object(&after); g_clear_object(&subject); g_clear_object(&authority);
    return ok;
}
