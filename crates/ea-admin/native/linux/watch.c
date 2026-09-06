#include "watch.h"
#include <fcntl.h>
#include <glib-unix.h>
#include <openssl/crypto.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    EaWatchState state;
    EaWatchFiles files;
    EaWatchBus system, secrets;
    EaAccount account;
    EaMarker marker;
    EaMarkerStore store;
    char *session_path, *user_directory, *user_socket;
    struct stat directory_stat, socket_stat, system_stat;
    gint64 deadline, next_check;
    GCancellable *cancel;
    unsigned pending;
    gboolean challenge_check_started;
    int input;
} Watch;

static gboolean nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && !fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static gboolean socket_paths(Watch *w, gboolean initial) {
    struct stat directory, socket, system;
    if (lstat(w->user_directory, &directory) || !S_ISDIR(directory.st_mode) ||
        directory.st_uid != w->account.uid || (directory.st_mode & 077) ||
        lstat(w->user_socket, &socket) || !S_ISSOCK(socket.st_mode) || socket.st_uid != w->account.uid ||
        lstat("/run/dbus/system_bus_socket", &system) || !S_ISSOCK(system.st_mode) || system.st_uid != 0) return FALSE;
    if (initial) {
        w->directory_stat = directory; w->socket_stat = socket; w->system_stat = system;
        return TRUE;
    }
    return directory.st_dev == w->directory_stat.st_dev && directory.st_ino == w->directory_stat.st_ino &&
        socket.st_dev == w->socket_stat.st_dev && socket.st_ino == w->socket_stat.st_ino &&
        system.st_dev == w->system_stat.st_dev && system.st_ino == w->system_stat.st_ino;
}

static gboolean keyring_unlocked(Watch *w) {
    GVariant *v = g_dbus_connection_call_sync(w->secrets.bus, w->secrets.owner,
        "/org/freedesktop/secrets/collection/login", "org.freedesktop.DBus.Properties", "Get",
        g_variant_new("(ss)", "org.freedesktop.Secret.Collection", "Locked"), G_VARIANT_TYPE("(v)"),
        G_DBUS_CALL_FLAGS_NO_AUTO_START, 5000, NULL, NULL);
    if (!v) return FALSE;
    GVariant *locked; g_variant_get(v, "(v)", &locked);
    gboolean ok = g_variant_is_of_type(locked, G_VARIANT_TYPE_BOOLEAN) && !g_variant_get_boolean(locked);
    g_variant_unref(locked); g_variant_unref(v);
    return ok;
}

static gboolean awake(GVariant *properties) {
    gboolean sleeping = TRUE, stopping = TRUE;
    return g_variant_lookup(properties, "PreparingForSleep", "b", &sleeping) && !sleeping &&
        g_variant_lookup(properties, "PreparingForShutdown", "b", &stopping) && !stopping;
}

static gboolean initial_snapshot(Watch *w) {
    EaAccount now;
    if (ea_read_account(&now) || CRYPTO_memcmp(now.binding, w->account.binding, 32) ||
        ea_marker_recheck(&w->store, &now, &w->marker) || !socket_paths(w, FALSE) ||
        !ea_watch_bus_barrier(&w->system) || !ea_watch_bus_barrier(&w->secrets) ||
        !ea_session_unlocked(w->system.bus, now.uid, &w->session_path) || !keyring_unlocked(w)) {
        ea_watch_invalidate(&w->state); return FALSE;
    }
    GVariant *reply = g_dbus_connection_call_sync(w->system.bus, w->system.owner,
        "/org/freedesktop/login1", "org.freedesktop.DBus.Properties", "GetAll",
        g_variant_new("(s)", "org.freedesktop.login1.Manager"), G_VARIANT_TYPE("(a{sv})"),
        G_DBUS_CALL_FLAGS_NO_AUTO_START, 5000, NULL, NULL);
    if (!reply) { ea_watch_invalidate(&w->state); return FALSE; }
    GVariant *properties = g_variant_get_child_value(reply, 0);
    if (!awake(properties)) ea_watch_invalidate(&w->state);
    g_variant_unref(properties); g_variant_unref(reply);
    return !w->state.invalidated;
}

enum Probe { SYSTEM_OWNER, SECRET_OWNER, SESSION, SESSION_PATH, MANAGER, KEYRING };
typedef struct { Watch *watch; enum Probe probe; } Pending;

static void checked(GObject *object, GAsyncResult *result, gpointer data) {
    Pending *p = data; Watch *w = p->watch;
    GVariant *v = g_dbus_connection_call_finish(G_DBUS_CONNECTION(object), result, NULL);
    gboolean valid = FALSE;
    if (v) {
        GVariant *value = g_variant_get_child_value(v, 0);
        if (p->probe == SYSTEM_OWNER || p->probe == SECRET_OWNER) {
            const char *expected = p->probe == SYSTEM_OWNER ? w->system.owner : w->secrets.owner;
            valid = !strcmp(g_variant_get_string(value, NULL), expected);
        } else if (p->probe == SESSION_PATH) valid = !strcmp(g_variant_get_string(value, NULL), w->session_path);
        else if (p->probe == SESSION) valid = ea_session_properties_unlocked(value, w->account.uid);
        else if (p->probe == MANAGER) valid = awake(value);
        else if (p->probe == KEYRING) {
            GVariant *locked = g_variant_get_variant(value);
            valid = g_variant_is_of_type(locked, G_VARIANT_TYPE_BOOLEAN) && !g_variant_get_boolean(locked);
            g_variant_unref(locked);
        }
        g_variant_unref(value); g_variant_unref(v);
    }
    if (!valid) ea_watch_invalidate(&w->state);
    w->pending--; g_free(p);
}

static void probe(Watch *w, enum Probe which, GDBusConnection *bus, const char *name, const char *path,
                  const char *interface, const char *method, GVariant *args, const GVariantType *type) {
    Pending *p = g_new(Pending, 1); *p = (Pending){w, which}; w->pending++;
    g_dbus_connection_call(bus, name, path, interface, method, args, type,
        G_DBUS_CALL_FLAGS_NO_AUTO_START, 750, w->cancel, checked, p);
}

static void heartbeat(Watch *w) {
    /* No synchronous D-Bus calls after ready. Lock/EOF callbacks must remain
     * dispatchable even if a native service stalls a supplemental query. */
    probe(w, SYSTEM_OWNER, w->system.bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
          "GetNameOwner", g_variant_new("(s)", w->system.name), G_VARIANT_TYPE("(s)"));
    probe(w, SECRET_OWNER, w->secrets.bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
          "GetNameOwner", g_variant_new("(s)", w->secrets.name), G_VARIANT_TYPE("(s)"));
    probe(w, SESSION, w->system.bus, w->system.owner, w->session_path, "org.freedesktop.DBus.Properties",
          "GetAll", g_variant_new("(s)", "org.freedesktop.login1.Session"), G_VARIANT_TYPE("(a{sv})"));
    probe(w, SESSION_PATH, w->system.bus, w->system.owner, "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
          "GetSessionByPID", g_variant_new("(u)", (guint32)getpid()), G_VARIANT_TYPE("(o)"));
    probe(w, MANAGER, w->system.bus, w->system.owner, "/org/freedesktop/login1", "org.freedesktop.DBus.Properties",
          "GetAll", g_variant_new("(s)", "org.freedesktop.login1.Manager"), G_VARIANT_TYPE("(a{sv})"));
    probe(w, KEYRING, w->secrets.bus, w->secrets.owner, "/org/freedesktop/secrets/collection/login", "org.freedesktop.DBus.Properties",
          "Get", g_variant_new("(ss)", "org.freedesktop.Secret.Collection", "Locked"), G_VARIANT_TYPE("(v)"));
}

static gboolean parent_event(gint fd, GIOCondition condition, gpointer data) {
    Watch *w = data;
    if (condition & (G_IO_ERR | G_IO_NVAL)) ea_watch_invalidate(&w->state);
    (void)ea_watch_parent(&w->state, fd);
    return w->state.parent_gone || w->state.invalidated ? G_SOURCE_REMOVE : G_SOURCE_CONTINUE;
}

static gboolean file_event(gint fd, GIOCondition condition, gpointer data) {
    (void)fd;
    Watch *w = data;
    if (condition & (G_IO_ERR | G_IO_NVAL | G_IO_HUP)) ea_watch_invalidate(&w->state);
    (void)ea_watch_files_drain(&w->files);
    return w->state.invalidated ? G_SOURCE_REMOVE : G_SOURCE_CONTINUE;
}

static gboolean local_snapshot(Watch *w) {
    EaAccount account;
    if (ea_read_account(&account) || CRYPTO_memcmp(account.binding, w->account.binding, 32) ||
        ea_marker_recheck(&w->store, &account, &w->marker) || !socket_paths(w, FALSE) ||
        !w->system.bus || !w->secrets.bus ||
        g_dbus_connection_is_closed(w->system.bus) || g_dbus_connection_is_closed(w->secrets.bus) ||
        !w->system.service_match || !w->system.owner_match || !w->system.service_subscription ||
        !w->system.owner_subscription || !w->system.closed_handler ||
        !w->secrets.service_match || !w->secrets.owner_match || !w->secrets.service_subscription ||
        !w->secrets.owner_subscription || !w->secrets.closed_handler || !w->secrets.instance_path ||
        w->files.fd < 0 || w->files.count != G_N_ELEMENTS(w->files.descriptors)) ea_watch_invalidate(&w->state);
    return !w->state.invalidated;
}

static gboolean tick(gpointer data) {
    Watch *w = data;
    gint64 now = ea_watch_now();
    if (!ea_watch_fresh(&w->state, now, w->deadline)) return G_SOURCE_REMOVE;
    if (now >= w->next_check) {
        w->next_check = now + 5 * G_USEC_PER_SEC;
        if (!local_snapshot(w)) return G_SOURCE_REMOVE;
        if (!w->pending && !w->state.input_len) heartbeat(w);
    }
    return G_SOURCE_CONTINUE;
}

static gboolean dispatch(GMainContext *context, Watch *w, gboolean block) {
    if (!ea_watch_fresh(&w->state, ea_watch_now(), w->deadline)) return FALSE;
    g_main_context_iteration(context, block);
    /* Only this subscribing thread advances the dispatch timestamp, AFTER
     * checking the previous timestamp. A queued timer must not erase a stall. */
    return ea_watch_dispatch(&w->state, ea_watch_now(), w->deadline);
}

static void drain(GMainContext *context, Watch *w) {
    unsigned i = 0;
    while (g_main_context_pending(context)) {
        if (i++ >= 1024 || w->state.invalidated || w->state.parent_gone) break;
        if (!dispatch(context, w, FALSE)) break;
    }
    if (i >= 1024) ea_watch_invalidate(&w->state);
    (void)ea_watch_files_drain(&w->files);
    (void)ea_watch_parent(&w->state, w->input);
    (void)ea_watch_fresh(&w->state, ea_watch_now(), w->deadline);
}

static gboolean answer_challenge(Watch *w, int output, const unsigned char id[32]) {
    EaWatchState *s = &w->state;
    if (!s->ready_sent || !s->challenge_pending || !w->challenge_check_started || w->pending ||
        !ea_watch_fresh(s, ea_watch_now(), w->deadline)) return FALSE;
    char frame[256]; char *hex = ea_hex(id, 32);
    int length = g_snprintf(frame, sizeof frame,
        "{\"ok\":true,\"installation_id\":\"%s\",\"challenge\":\"%s\"}\n", hex, s->challenge);
    g_free(hex);
    if (length <= 0 || length >= (int)sizeof frame) { ea_watch_invalidate(s); return FALSE; }
    if (!ea_watch_fresh(s, ea_watch_now(), w->deadline)) return FALSE;
    /* Consume before writing. No queued retry, background writer, secret key
     * or lifetime renewal is involved; nonce history lasts until exit. */
    s->challenge_pending = FALSE; s->challenge_started = 0; s->input_len = 0;
    w->challenge_check_started = FALSE;
    /* Below PIPE_BUF, on the verified nonblocking anonymous pipe: one atomic
     * write or fail closed. No serialization or blocking retry after freshness. */
    gboolean ok = write(output, frame, (size_t)length) == length;
    if (!ok) ea_watch_invalidate(s);
    return ok;
}

static void service_challenge(GMainContext *context, Watch *w, int output, const unsigned char id[32]) {
    if (!w->state.challenge_pending || !ea_watch_fresh(&w->state, ea_watch_now(), w->deadline)) return;
    if (!w->challenge_check_started) {
        /* Do not reuse replies from a periodic query predating this nonce. */
        if (w->pending || !local_snapshot(w)) return;
        w->challenge_check_started = TRUE;
        heartbeat(w);
        return;
    }
    if (w->pending || !local_snapshot(w)) return;
    /* All six NEW native replies have arrived on this context. Drain queued
     * signals/inotify/input after the final snapshot and before answering. A
     * lock/unlock burst, extra frame or stalled loop always wins over an ack. */
    drain(context, w);
    (void)answer_challenge(w, output, id);
}

int ea_watch_session(const EaRequest *r, int input, int output) {
    Watch w = {.store = {.base_fd = -1, .dir_fd = -1, .lock_fd = -1}, .files = {.fd = -1}, .input = input};
    gint64 start = ea_watch_now();
    w.deadline = start + (gint64)EA_WATCH_SECONDS * G_USEC_PER_SEC;
    const char *error = "watch-unavailable";
    GMainContext *context = g_main_context_new();
    GSource *parent_source = NULL, *file_source = NULL, *timer = NULL;
    GDBusConnection *system = NULL, *session = NULL;
    JsonObject *account_fields = NULL;
    EaRequest *account_request = NULL;
    int result = 1;
    g_main_context_push_thread_default(context);
    if (start < 0 || !nonblock(input) || !nonblock(output) || !ea_watch_parent(&w.state, input)) goto done;
    error = "watch-unavailable";
    /* Register filesystem events before any marker/namespace acceptance. */
    if (!ea_watch_files_start(&w.files, &w.state, getuid())) goto done;
    error = ea_read_account(&w.account);
    if (error) goto done;
    error = ea_marker_store_open(&w.store, w.account.uid);
    if (!error) error = ea_marker_load(&w.store, &w.account, &w.marker);
    if (error) goto done;
    if (CRYPTO_memcmp(w.marker.id, r->installation, 32)) { error = "installation-changed"; goto done; }
    /* Never monopolize the exclusive directory lock across requests. Retain
     * descriptors and the event queue, then recheck after bus subscriptions. */
    if (flock(w.store.dir_fd, LOCK_UN)) { error = "watch-unavailable"; goto done; }
    error = "watch-unavailable";
    w.user_directory = g_strdup_printf("/run/user/%u", (unsigned)w.account.uid);
    w.user_socket = g_strconcat(w.user_directory, "/bus", NULL);
    if (!socket_paths(&w, TRUE)) goto done;
    /* Set both fixed addresses before GIO starts its worker threads. */
    char *address = g_strconcat("unix:path=", w.user_socket, NULL);
    g_setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/run/dbus/system_bus_socket", TRUE);
    g_setenv("DBUS_SESSION_BUS_ADDRESS", address, TRUE); g_free(address);
    system = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
    session = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, NULL);
    if (!ea_watch_bus_start(&w.system, &w.state, system, "org.freedesktop.login1", 0) ||
        !ea_watch_bus_start(&w.secrets, &w.state, session, "org.freedesktop.secrets", w.account.uid)) goto done;

    /* Full existing account path verifies installation, actual process-bound
     * session, unlocked login collection and native account-instance secret.
     * This is read-only: it cannot initialize, unlock or prompt. */
    account_request = g_malloc0(sizeof *account_request);
    *account_request = *r; g_strlcpy(account_request->op, "account", sizeof account_request->op);
    error = ea_watch_account(account_request, &account_fields, &w.secrets.instance_path);
    if (error) goto done;
    error = "locked";
    if (!json_object_get_boolean_member(account_fields, "ok") ||
        json_object_get_boolean_member(account_fields, "locked") || !w.secrets.instance_path) goto done;
    error = "watch-unavailable";
    if (!initial_snapshot(&w)) goto done;

    parent_source = g_unix_fd_source_new(input, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL);
    g_source_set_callback(parent_source, G_SOURCE_FUNC(parent_event), &w, NULL);
    g_source_attach(parent_source, context);
    file_source = g_unix_fd_source_new(w.files.fd, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL);
    g_source_set_callback(file_source, G_SOURCE_FUNC(file_event), &w, NULL);
    g_source_attach(file_source, context);
    timer = g_timeout_source_new(100);
    w.cancel = g_cancellable_new();
    g_source_set_callback(timer, tick, &w, NULL); g_source_attach(timer, context);
    w.next_check = ea_watch_now() + 5 * G_USEC_PER_SEC;
    /* Synchronous owner barriers precede draining queued callbacks. A lock /
     * unlock burst during initial checks remains latched before readiness. */
    if (!ea_watch_bus_barrier(&w.system) || !ea_watch_bus_barrier(&w.secrets)) goto done;
    drain(context, &w);
    if (!ea_watch_ready(&w.state, output, r->installation)) goto done;
    error = NULL; result = 0;
    while (!w.state.invalidated && !w.state.parent_gone) {
        if (!dispatch(context, &w, TRUE)) break;
        drain(context, &w);
        service_challenge(context, &w, output, r->installation);
    }
    (void)ea_watch_invalidated(&w.state, output, r->installation);
done:
    /* Before readiness, unknown coverage is an ordinary failure, never a
     * simulated ready frame. EOF always stops silently. */
    if (error && !w.state.parent_gone && !w.state.ready_sent) {
        JsonObject *o = json_object_new();
        json_object_set_boolean_member(o, "ok", FALSE);
        json_object_set_string_member(o, "code", error);
        (void)ea_write_json(output, o); json_object_unref(o);
    }
    if (parent_source) { g_source_destroy(parent_source); g_source_unref(parent_source); }
    if (file_source) { g_source_destroy(file_source); g_source_unref(file_source); }
    if (timer) { g_source_destroy(timer); g_source_unref(timer); }
    if (w.cancel) g_cancellable_cancel(w.cancel);
    while (w.pending) g_main_context_iteration(context, TRUE);
    g_clear_object(&w.cancel);
    ea_watch_release(&w.state);
    ea_watch_files_stop(&w.files);
    ea_watch_bus_stop(&w.secrets); ea_watch_bus_stop(&w.system);
    g_clear_object(&session); g_clear_object(&system);
    if (account_fields) json_object_unref(account_fields);
    if (account_request) { OPENSSL_cleanse(account_request, sizeof *account_request); g_free(account_request); }
    ea_marker_store_close(&w.store);
    g_free(w.session_path); g_free(w.user_directory); g_free(w.user_socket);
    OPENSSL_cleanse(&w.marker, sizeof w.marker);
    g_main_context_pop_thread_default(context); g_main_context_unref(context);
    return result;
}
