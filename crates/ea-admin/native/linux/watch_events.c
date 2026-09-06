#include "watch.h"
#include <errno.h>
#include <string.h>
#include <sys/inotify.h>
#include <time.h>
#include <unistd.h>

void ea_watch_invalidate(EaWatchState *s) { s->invalidated = TRUE; }
gboolean ea_watch_expire(EaWatchState *s, gint64 now, gint64 deadline) {
    if (now < 0 || now >= deadline) ea_watch_invalidate(s);
    return !s->invalidated;
}

/* Includes suspension and SIGSTOP time; no wall-clock adjustment can renew
 * the total lifetime or erase a stopped native subscriber. */
gint64 ea_watch_now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_BOOTTIME, &t)) return -1;
    return (gint64)t.tv_sec * G_USEC_PER_SEC + t.tv_nsec / 1000;
}

gboolean ea_watch_fresh(EaWatchState *s, gint64 now, gint64 deadline) {
    (void)ea_watch_expire(s, now, deadline);
    if (s->ready_sent && (s->last_dispatch <= 0 || now < s->last_dispatch ||
        now - s->last_dispatch > EA_WATCH_FRESH_USEC)) ea_watch_invalidate(s);
    if ((s->input_len || s->challenge_pending) && (s->challenge_started <= 0 ||
        now < s->challenge_started || now - s->challenge_started >= EA_WATCH_FRESH_USEC)) ea_watch_invalidate(s);
    return !s->invalidated && !s->parent_gone;
}

gboolean ea_watch_dispatch(EaWatchState *s, gint64 now, gint64 deadline) {
    if (!ea_watch_fresh(s, now, deadline)) return FALSE;
    if (s->ready_sent) s->last_dispatch = now;
    return TRUE;
}

static gboolean message(EaWatchState *s, int output, const unsigned char id[32], const char *member) {
    JsonObject *o = json_object_new();
    char *hex = ea_hex(id, 32);
    json_object_set_boolean_member(o, "ok", TRUE);
    json_object_set_string_member(o, "installation_id", hex);
    json_object_set_boolean_member(o, member, TRUE);
    gboolean ok = ea_write_json(output, o);
    json_object_unref(o); g_free(hex);
    if (!ok) ea_watch_invalidate(s);
    return ok;
}

gboolean ea_watch_ready(EaWatchState *s, int output, const unsigned char id[32]) {
    if (s->invalidated || s->parent_gone || s->ready_sent) return FALSE;
    /* Mark before writing: a failed/partial write must never be retried. */
    s->last_dispatch = ea_watch_now();
    if (s->last_dispatch <= 0) { ea_watch_invalidate(s); return FALSE; }
    s->ready_sent = TRUE;
    return message(s, output, id, "ready");
}

gboolean ea_watch_invalidated(EaWatchState *s, int output, const unsigned char id[32]) {
    if (!s->invalidated || s->parent_gone || !s->ready_sent || s->invalidation_sent) return FALSE;
    s->invalidation_sent = TRUE;
    return message(s, output, id, "invalidated");
}

gboolean ea_watch_parent(EaWatchState *s, int input) {
    unsigned char bytes[EA_WATCH_FRAME_LIMIT + 1];
    /* Bound both work and storage, including partial input and an input flood.
     * Never reply here: this fd callback has not yet drained native events. */
    for (unsigned batch = 0; batch <= EA_WATCH_FRAME_LIMIT; batch++) {
        ssize_t n = read(input, bytes, sizeof bytes);
        if (!n) { s->parent_gone = TRUE; return FALSE; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return !s->invalidated && !s->parent_gone;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 || !s->ready_sent || s->challenge_pending || s->invalidated || s->parent_gone) break;
        if (!s->input_len) s->challenge_started = ea_watch_now();
        for (ssize_t i = 0; i < n; i++) {
            if (s->input_len == sizeof s->input_frame || s->challenge_pending) goto fail;
            s->input_frame[s->input_len++] = bytes[i];
            if (bytes[i] != '\n') continue;
            if (!ea_parse_challenge(s->input_frame, s->input_len, s->challenge)) goto fail;
            if (!s->seen) s->seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
            if (g_hash_table_size(s->seen) >= EA_WATCH_NONCE_LIMIT || g_hash_table_contains(s->seen, s->challenge)) goto fail;
            g_hash_table_add(s->seen, g_strdup(s->challenge));
            s->challenge_pending = TRUE;
        }
        /* A full buffer without LF cannot become a <=1024-byte frame. */
        if (s->input_len == sizeof s->input_frame && !s->challenge_pending) break;
    }
fail:
    ea_watch_invalidate(s); return FALSE;
}

void ea_watch_release(EaWatchState *s) { g_clear_pointer(&s->seen, g_hash_table_unref); }

static GVariant *bus_call(GDBusConnection *bus, const char *method, GVariant *args, const GVariantType *type) {
    return g_dbus_connection_call_sync(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", method, args, type, G_DBUS_CALL_FLAGS_NO_AUTO_START, 5000, NULL, NULL);
}

static gboolean match(GDBusConnection *bus, const char *method, const char *rule) {
    GVariant *v = bus_call(bus, method, g_variant_new("(s)", rule), G_VARIANT_TYPE_UNIT);
    if (!v) return FALSE;
    g_variant_unref(v); return TRUE;
}

static gboolean ordinary_key_event(EaWatchBus *w, const char *path, const char *interface,
                                    const char *signal, GVariant *parameters) {
    const char *login = "/org/freedesktop/secrets/collection/login";
    const char *prefix = "/org/freedesktop/secrets/collection/login/";
    if (!w->instance_path || !strcmp(path, w->instance_path)) return FALSE;
    if (!strcmp(path, login) && !strcmp(interface, "org.freedesktop.Secret.Collection") &&
        (!strcmp(signal, "ItemCreated") || !strcmp(signal, "ItemChanged") || !strcmp(signal, "ItemDeleted")) &&
        g_variant_is_of_type(parameters, G_VARIANT_TYPE("(o)"))) {
        const char *item; g_variant_get(parameters, "(&o)", &item);
        return g_str_has_prefix(item, prefix) && strcmp(item, w->instance_path);
    }
    if (strcmp(interface, "org.freedesktop.DBus.Properties") || strcmp(signal, "PropertiesChanged") ||
        !g_variant_is_of_type(parameters, G_VARIANT_TYPE("(sa{sv}as)"))) return FALSE;
    const char *changed_interface; GVariant *changed, *invalidated;
    g_variant_get(parameters, "(&s@a{sv}@as)", &changed_interface, &changed, &invalidated);
    gboolean collection = !strcmp(path, login) && !strcmp(changed_interface, "org.freedesktop.Secret.Collection");
    gboolean item = g_str_has_prefix(path, prefix) && !strcmp(changed_interface, "org.freedesktop.Secret.Item");
    gboolean benign = (collection || item) && !g_variant_n_children(invalidated);
    GVariantIter iter; const char *key; GVariant *value;
    g_variant_iter_init(&iter, changed);
    while (g_variant_iter_next(&iter, "{&sv}", &key, &value)) {
        gboolean allowed = (!strcmp(key, "Label") && g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) ||
            ((!strcmp(key, "Created") || !strcmp(key, "Modified")) && g_variant_is_of_type(value, G_VARIANT_TYPE_UINT64)) ||
            (item && !strcmp(key, "Attributes") && g_variant_is_of_type(value, G_VARIANT_TYPE("a{ss}")));
        if (collection && !strcmp(key, "Items") && g_variant_is_of_type(value, G_VARIANT_TYPE("ao"))) {
            GVariantIter paths; const char *entry;
            g_variant_iter_init(&paths, value);
            while (g_variant_iter_next(&paths, "&o", &entry)) if (!strcmp(entry, w->instance_path)) allowed = TRUE;
        }
        /* Locked (even false), invalidated properties and unknown fields all
         * latch. A restored unlocked snapshot cannot erase the lock event. */
        benign = benign && allowed; g_variant_unref(value);
    }
    g_variant_unref(changed); g_variant_unref(invalidated);
    return benign;
}

static void service_signal(GDBusConnection *bus, const char *sender, const char *path,
                           const char *interface, const char *signal, GVariant *parameters, gpointer data) {
    (void)bus; (void)sender;
    EaWatchBus *w = data;
    if (!strcmp(w->name, "org.freedesktop.secrets") && ordinary_key_event(w, path, interface, signal, parameters)) return;
    /* Deliberately conservative: Lock, PropertiesChanged, seat/user/session
     * changes, sleep/shutdown, account-instance changes AND unknown signals.
     * In particular, a later Unlock/resume can never clear a prior event. */
    ea_watch_invalidate(w->state);
}

static void owner_signal(GDBusConnection *bus, const char *sender, const char *path,
                         const char *interface, const char *signal, GVariant *parameters, gpointer data) {
    (void)bus; (void)sender; (void)path; (void)interface; (void)signal; (void)parameters;
    EaWatchBus *w = data;
    ea_watch_invalidate(w->state);
}

static void closed(GDBusConnection *bus, gboolean vanished, GError *error, gpointer data) {
    (void)bus; (void)vanished; (void)error;
    EaWatchBus *w = data;
    ea_watch_invalidate(w->state);
}

gboolean ea_watch_bus_start(EaWatchBus *w, EaWatchState *s, GDBusConnection *bus, const char *name, uid_t uid) {
    *w = (EaWatchBus){.state = s};
    if (!bus || g_dbus_connection_is_closed(bus) || !g_dbus_is_name(name)) goto fail;
    w->bus = g_object_ref(bus); w->name = g_strdup(name);
    g_dbus_connection_set_exit_on_close(bus, FALSE);
    w->closed_handler = g_signal_connect(bus, "closed", G_CALLBACK(closed), w);
    w->owner_subscription = g_dbus_connection_signal_subscribe(bus, "org.freedesktop.DBus",
        "org.freedesktop.DBus", "NameOwnerChanged", "/org/freedesktop/DBus", name,
        G_DBUS_SIGNAL_FLAGS_NO_MATCH_RULE, owner_signal, w, NULL);
    char *rule = g_strdup_printf("type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',path='/org/freedesktop/DBus',arg0='%s'", name);
    w->owner_match = match(bus, "AddMatch", rule); g_free(rule);
    if (!w->owner_subscription || !w->owner_match) goto fail;
    GVariant *v = bus_call(bus, "GetNameOwner", g_variant_new("(s)", name), G_VARIANT_TYPE("(s)"));
    if (!v) goto fail;
    g_variant_get(v, "(s)", &w->owner); g_variant_unref(v);
    if (!g_dbus_is_unique_name(w->owner)) goto fail;
    v = bus_call(bus, "GetConnectionUnixUser", g_variant_new("(s)", w->owner), G_VARIANT_TYPE("(u)"));
    if (!v) goto fail;
    guint32 actual; g_variant_get(v, "(u)", &actual); g_variant_unref(v);
    if (actual != uid) goto fail;
    w->service_subscription = g_dbus_connection_signal_subscribe(bus, w->owner, NULL, NULL, NULL, NULL,
        G_DBUS_SIGNAL_FLAGS_NO_MATCH_RULE, service_signal, w, NULL);
    w->match = g_strdup_printf("type='signal',sender='%s'", w->owner);
    w->service_match = match(bus, "AddMatch", w->match);
    /* signal_subscribe alone does not report AddMatch failure. A synchronous
     * bus acknowledgement is mandatory before any initial-state checks. */
    if (!w->service_subscription || !w->service_match || !ea_watch_bus_barrier(w)) goto fail;
    return TRUE;
fail:
    ea_watch_invalidate(s); return FALSE;
}

gboolean ea_watch_bus_barrier(EaWatchBus *w) {
    if (!w->bus || g_dbus_connection_is_closed(w->bus)) goto fail;
    GVariant *v = bus_call(w->bus, "GetNameOwner", g_variant_new("(s)", w->name), G_VARIANT_TYPE("(s)"));
    if (!v) goto fail;
    const char *owner; g_variant_get(v, "(&s)", &owner);
    gboolean same = w->owner && !strcmp(owner, w->owner);
    g_variant_unref(v);
    if (same) return TRUE;
fail:
    ea_watch_invalidate(w->state); return FALSE;
}

void ea_watch_bus_stop(EaWatchBus *w) {
    if (w->bus) {
        if (w->service_subscription) g_dbus_connection_signal_unsubscribe(w->bus, w->service_subscription);
        if (w->owner_subscription) g_dbus_connection_signal_unsubscribe(w->bus, w->owner_subscription);
        if (w->closed_handler) g_signal_handler_disconnect(w->bus, w->closed_handler);
        /* This runs on the subscribing thread, after all sources have stopped.
         * Do not reconnect or wait on a vanished daemon during teardown. */
        if (!g_dbus_connection_is_closed(w->bus)) {
            if (w->service_match) (void)match(w->bus, "RemoveMatch", w->match);
            if (w->owner_match) {
                char *rule = g_strdup_printf("type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',path='/org/freedesktop/DBus',arg0='%s'", w->name);
                (void)match(w->bus, "RemoveMatch", rule); g_free(rule);
            }
        }
    }
    g_clear_object(&w->bus); g_free(w->owner); g_free(w->name); g_free(w->match); g_free(w->instance_path);
    *w = (EaWatchBus){0};
}

gboolean ea_watch_files_start(EaWatchFiles *f, EaWatchState *s, uid_t uid) {
    *f = (EaWatchFiles){.fd = -1, .state = s};
    g_snprintf(f->uid_name, sizeof f->uid_name, "%u", (unsigned)uid);
    g_snprintf(f->restore_name, sizeof f->restore_name, EA_RESTORE_PREFIX "%u", (unsigned)uid);
    f->fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (f->fd < 0) goto fail;
    char *directory = g_strdup_printf(EA_MARKER_ROOT "/%u", (unsigned)uid);
    char *marker = g_strconcat(directory, "/marker", NULL);
    char *runtime = g_strdup_printf("/run/user/%u", (unsigned)uid);
    const char *paths[] = {"/etc", "/etc/machine-id", "/etc/passwd", "/etc/ea-native-operator",
                          "/var/lib", EA_MARKER_ROOT, directory, marker, "/run/dbus", runtime};
    const uint32_t mutations = IN_MODIFY | IN_CLOSE_WRITE | IN_ATTRIB | IN_CREATE | IN_DELETE |
        IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT | IN_DONT_FOLLOW;
    for (unsigned i = 0; i < G_N_ELEMENTS(paths); i++) {
        f->descriptors[i] = inotify_add_watch(f->fd, paths[i], mutations | ((i == 1 || i == 2 || i == 7) ? 0 : IN_ONLYDIR));
        if (f->descriptors[i] < 0) break;
        f->count++;
    }
    g_free(directory); g_free(marker); g_free(runtime);
    if (f->count == G_N_ELEMENTS(paths)) return TRUE;
fail:
    ea_watch_invalidate(s); return FALSE;
}

static gboolean relevant(EaWatchFiles *f, const struct inotify_event *e) {
    if (e->mask & (IN_Q_OVERFLOW | IN_IGNORED | IN_UNMOUNT | IN_DELETE_SELF | IN_MOVE_SELF)) return TRUE;
    unsigned i;
    for (i = 0; i < f->count; i++) if (f->descriptors[i] == e->wd) break;
    if (i == f->count || !e->len || !e->name[0]) return TRUE;
    if (i == 0) return !strcmp(e->name, "machine-id") || !strcmp(e->name, "passwd") ||
        !strcmp(e->name, "group") || !strcmp(e->name, "shadow") || !strcmp(e->name, "gshadow") ||
        !strcmp(e->name, "ea-native-operator");
    if (i == 4) return !strcmp(e->name, "ea-native-operator");
    if (i == 5) return !strcmp(e->name, f->uid_name) || !strcmp(e->name, f->restore_name);
    if (i == 8) return !strcmp(e->name, "system_bus_socket");
    if (i == 9) return !strcmp(e->name, "bus");
    return TRUE;
}

gboolean ea_watch_files_drain(EaWatchFiles *f) {
    union { struct inotify_event align; unsigned char bytes[4096]; } buffer;
    /* A never-ending event flood is unknown coverage, not a reason to postpone
     * invalidation/readiness indefinitely. */
    for (unsigned batch = 0; batch < 256; batch++) {
        ssize_t n = read(f->fd, buffer.bytes, sizeof buffer.bytes);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return !f->state->invalidated;
        if (n <= 0) break;
        size_t offset = 0;
        while (offset < (size_t)n) {
            if ((size_t)n - offset < sizeof(struct inotify_event)) goto fail;
            const struct inotify_event *e = (const void *)(buffer.bytes + offset);
            if (e->len > (size_t)n - offset - sizeof *e || (e->len && !memchr(e->name, 0, e->len))) goto fail;
            if (relevant(f, e)) goto fail;
            offset += sizeof *e + e->len;
        }
    }
fail:
    ea_watch_invalidate(f->state); return FALSE;
}

void ea_watch_files_stop(EaWatchFiles *f) {
    if (f->fd >= 0) close(f->fd);
    f->fd = -1;
}
