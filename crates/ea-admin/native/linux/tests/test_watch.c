/* Deterministic wire/event tests with real GDBus and inotify. The private bus
 * is an event source, NOT a logind/desktop/presence acceptance simulator. */
#include "../watch.c"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

static GTestDBus *test_bus;
static const char *nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static char *challenge_frame(const char *value) { return g_strdup_printf("{\"challenge\":\"%s\"}\n", value); }

static void no_output(int fd) {
    char byte;
    g_assert_cmpint(read(fd, &byte, 1), ==, -1);
    g_assert_cmpint(errno, ==, EAGAIN);
}

static void messages(void) {
    int fds[2]; g_assert_cmpint(pipe2(fds, O_NONBLOCK | O_CLOEXEC), ==, 0);
    EaWatchState s = {0}; unsigned char id[32]; memset(id, 0xab, sizeof id);
    g_assert_true(ea_watch_ready(&s, fds[1], id));
    g_assert_false(ea_watch_ready(&s, fds[1], id));
    g_assert_false(ea_watch_invalidated(&s, fds[1], id));
    ea_watch_invalidate(&s); ea_watch_invalidate(&s);
    g_assert_false(ea_watch_ready(&s, fds[1], id));
    g_assert_true(ea_watch_invalidated(&s, fds[1], id));
    g_assert_false(ea_watch_invalidated(&s, fds[1], id));
    close(fds[1]);
    char bytes[1024]; ssize_t n = read(fds[0], bytes, sizeof bytes - 1);
    g_assert_cmpint(n, >, 0); bytes[n] = 0; close(fds[0]);
    char *hex = ea_hex(id, 32);
    char *expected = g_strdup_printf("{\"ok\":true,\"installation_id\":\"%s\",\"ready\":true}\n{\"ok\":true,\"installation_id\":\"%s\",\"invalidated\":true}\n", hex, hex);
    g_assert_cmpstr(bytes, ==, expected); g_free(expected); g_free(hex);
    s = (EaWatchState){0}; ea_watch_invalidate(&s);
    g_assert_false(ea_watch_ready(&s, -1, id));
    g_assert_false(ea_watch_invalidated(&s, -1, id));
}

static void parent(void) {
    int fds[2]; unsigned char id[32] = {0};
    g_assert_cmpint(pipe2(fds, O_NONBLOCK | O_CLOEXEC), ==, 0);
    EaWatchState s = {0};
    g_assert_true(ea_watch_parent(&s, fds[0]));
    close(fds[1]); g_assert_false(ea_watch_parent(&s, fds[0]));
    g_assert_true(s.parent_gone); g_assert_false(s.invalidated);
    g_assert_false(ea_watch_ready(&s, -1, id)); close(fds[0]);
    g_assert_cmpint(pipe2(fds, O_NONBLOCK | O_CLOEXEC), ==, 0);
    s = (EaWatchState){.ready_sent = TRUE};
    g_assert_cmpint(write(fds[1], "\n", 1), ==, 1);
    g_assert_false(ea_watch_parent(&s, fds[0])); g_assert_true(s.invalidated);
    close(fds[1]); g_assert_false(ea_watch_parent(&s, fds[0]));
    g_assert_false(ea_watch_invalidated(&s, -1, id)); close(fds[0]);
}

static void expiry(void) {
    EaWatchState s = {0}; gint64 start = 1234567;
    gint64 deadline = start + (gint64)EA_WATCH_SECONDS * G_USEC_PER_SEC;
    g_assert_cmpint(EA_WATCH_SECONDS, <=, 300);
    g_assert_true(ea_watch_expire(&s, deadline - 1, deadline));
    g_assert_false(ea_watch_expire(&s, deadline, deadline));
    g_assert_false(ea_watch_expire(&s, start, deadline));
    s = (EaWatchState){0}; g_assert_false(ea_watch_expire(&s, -1, deadline));
    s = (EaWatchState){0}; g_assert_false(ea_watch_expire(&s, deadline + 100000000, deadline));
}

static void challenge_input(void) {
    int fds[2];
    g_assert_cmpint(pipe2(fds, O_NONBLOCK | O_CLOEXEC), ==, 0);
    EaWatchState s = {.ready_sent = TRUE};
    const char *request = "{\"challenge\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}\n";
    g_assert_cmpint(write(fds[1], request, strlen(request)), ==, (ssize_t)strlen(request));
    /* A retained writer now supplies a coverage challenge after readiness. */
    g_assert_true(ea_watch_parent(&s, fds[0]));
    g_assert_false(s.invalidated);
    g_assert_true(s.challenge_pending); g_assert_cmpstr(s.challenge, ==, nonce);
    ea_watch_release(&s);
    close(fds[1]); close(fds[0]);
}

static void challenge_messages(void) {
    int input[2], output[2]; unsigned char id[32]; memset(id, 0x42, sizeof id);
    g_assert_cmpint(pipe2(input, O_NONBLOCK | O_CLOEXEC), ==, 0);
    g_assert_cmpint(pipe2(output, O_NONBLOCK | O_CLOEXEC), ==, 0);
    Watch w = {.deadline = ea_watch_now() + 300 * G_USEC_PER_SEC};
    w.state.ready_sent = TRUE; w.state.last_dispatch = ea_watch_now();
    gint64 original_deadline = w.deadline;
    char *request = challenge_frame(nonce);
    /* A partial frame never starts a proof or produces an acknowledgement. */
    g_assert_cmpint(write(input[1], request, 11), ==, 11);
    g_assert_true(parent_event(input[0], G_IO_IN, &w));
    g_assert_false(w.state.challenge_pending);
    g_assert_false(answer_challenge(&w, output[1], id)); no_output(output[0]);
    g_assert_cmpint(write(input[1], request + 11, strlen(request) - 11), ==, (ssize_t)strlen(request) - 11);
    g_assert_true(parent_event(input[0], G_IO_IN, &w));
    g_assert_true(w.state.challenge_pending); no_output(output[0]);
    /* Old periodic replies are not a fresh per-challenge check. */
    g_assert_false(answer_challenge(&w, output[1], id));
    w.challenge_check_started = TRUE; w.pending = 1;
    g_assert_false(answer_challenge(&w, output[1], id)); no_output(output[0]);
    w.pending = 0;
    g_assert_true(answer_challenge(&w, output[1], id));
    g_assert_false(answer_challenge(&w, output[1], id));
    char bytes[1024]; ssize_t n = read(output[0], bytes, sizeof bytes - 1);
    g_assert_cmpint(n, >, 0); bytes[n] = 0;
    char *hex = ea_hex(id, 32);
    char *expected = g_strdup_printf("{\"ok\":true,\"installation_id\":\"%s\",\"challenge\":\"%s\"}\n", hex, nonce);
    g_assert_cmpstr(bytes, ==, expected); no_output(output[0]);
    g_assert_cmpint(w.deadline, ==, original_deadline);
    g_assert_cmpuint(g_hash_table_size(w.state.seen), ==, 1);
    /* A different nonce works; replaying the first (not only the last) fails. */
    char *second = challenge_frame("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    g_assert_cmpint(write(input[1], second, strlen(second)), ==, (ssize_t)strlen(second));
    g_assert_true(ea_watch_parent(&w.state, input[0])); w.challenge_check_started = TRUE;
    g_assert_true(answer_challenge(&w, output[1], id));
    g_assert_cmpint(read(output[0], bytes, sizeof bytes), >, 0);
    g_assert_cmpint(write(input[1], request, strlen(request)), ==, (ssize_t)strlen(request));
    g_assert_false(ea_watch_parent(&w.state, input[0])); g_assert_true(w.state.invalidated);
    g_assert_false(answer_challenge(&w, output[1], id)); no_output(output[0]);
    ea_watch_release(&w.state); g_free(expected); g_free(hex); g_free(request); g_free(second);
    close(input[0]); close(input[1]); close(output[0]); close(output[1]);
}

static void challenge_reject(void) {
    const char *invalid[] = {
        "{}\n", "[]\n", "null\n", "\n", "{\"challenge\":null}\n", "{\"challenge\":false}\n",
        "{\"challenge\":32}\n", "{\"challenge\":[]}\n", "{\"challenge\":{}}\n",
        "{\"challenge\":\"%s\",\"extra\":true}\n", "{\"unknown\":\"%s\"}\n",
        "{\"challenge\":\"%s\",\"challenge\":\"%s\"}\n",
        "{\"challenge\":\"%s\",\"challe\\u006ege\":\"%s\"}\n",
        "{\"challenge\":\"%s\"}{}\n", "{\"challenge\":\"%s\",}\n",
        "{\"challenge\":\"%s\"}\n\n", "{\"challenge\":\"%s\"}\n{",
        "{\"challenge\":\"%s\"}\n{\"challenge\":\"%s\"}\n",
        "{\"challenge\":\"%sa\"}\n", "{\"challenge\":\"short\"}\n",
        "{\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}\n",
        "{\"challenge\":\"%s\\u0000\"}\n", "{\"challenge\":\"%s\",\"op\":\"account\"}\n"
    };
    for (unsigned i = 0; i < G_N_ELEMENTS(invalid); i++) {
        int fds[2]; g_assert_cmpint(pipe2(fds, O_NONBLOCK | O_CLOEXEC), ==, 0);
        EaWatchState s = {.ready_sent = TRUE};
        char *request = g_strdup_printf(invalid[i], nonce, nonce);
        g_assert_cmpint(write(fds[1], request, strlen(request)), ==, (ssize_t)strlen(request));
        g_assert_false(ea_watch_parent(&s, fds[0])); g_assert_true(s.invalidated);
        ea_watch_release(&s); close(fds[0]); close(fds[1]); g_free(request);
    }
    /* NUL bytes and missing LF are not C-string truncation opportunities. */
    unsigned char bytes[1025]; memset(bytes, ' ', sizeof bytes);
    const size_t sizes[] = {1, 1024, 1025};
    for (unsigned i = 0; i < G_N_ELEMENTS(sizes); i++) {
        int fds[2]; g_assert_cmpint(pipe2(fds, O_NONBLOCK | O_CLOEXEC), ==, 0);
        EaWatchState s = {.ready_sent = TRUE};
        if (!i) bytes[0] = '\n';
        g_assert_cmpint(write(fds[1], bytes, sizes[i]), ==, (ssize_t)sizes[i]);
        g_assert_false(ea_watch_parent(&s, fds[0])); g_assert_true(s.invalidated);
        ea_watch_release(&s); close(fds[0]); close(fds[1]); bytes[0] = ' ';
    }
    char *request = challenge_frame(nonce); char value[65];
    request[20] = 0;
    g_assert_false(ea_parse_challenge((unsigned char *)request, 81, value));
    g_free(request);
}

static void challenge_bounds(void) {
    char *request = challenge_frame(nonce);
    unsigned char bytes[EA_WATCH_FRAME_LIMIT + 1]; memset(bytes, ' ', sizeof bytes);
    memcpy(bytes + EA_WATCH_FRAME_LIMIT - strlen(request), request, strlen(request));
    int fds[2]; g_assert_cmpint(pipe2(fds, O_NONBLOCK | O_CLOEXEC), ==, 0);
    EaWatchState s = {.ready_sent = TRUE};
    g_assert_cmpint(write(fds[1], bytes, EA_WATCH_FRAME_LIMIT), ==, EA_WATCH_FRAME_LIMIT);
    g_assert_true(ea_watch_parent(&s, fds[0])); g_assert_true(s.challenge_pending);
    ea_watch_release(&s); close(fds[0]); close(fds[1]);
    memmove(bytes + 1, bytes, EA_WATCH_FRAME_LIMIT); bytes[0] = ' ';
    g_assert_cmpint(pipe2(fds, O_NONBLOCK | O_CLOEXEC), ==, 0);
    s = (EaWatchState){.ready_sent = TRUE};
    g_assert_cmpint(write(fds[1], bytes, sizeof bytes), ==, sizeof bytes);
    g_assert_false(ea_watch_parent(&s, fds[0])); g_assert_true(s.invalidated);
    ea_watch_release(&s); close(fds[0]); close(fds[1]);
    /* Exhausting replay tracking fails closed instead of discarding history. */
    g_assert_cmpint(pipe2(fds, O_NONBLOCK | O_CLOEXEC), ==, 0);
    s = (EaWatchState){.ready_sent = TRUE, .seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL)};
    for (unsigned i = 0; i < EA_WATCH_NONCE_LIMIT; i++) g_hash_table_add(s.seen, g_strdup_printf("%064x", i));
    g_assert_cmpint(write(fds[1], request, strlen(request)), ==, (ssize_t)strlen(request));
    g_assert_false(ea_watch_parent(&s, fds[0])); g_assert_true(s.invalidated);
    ea_watch_release(&s); close(fds[0]); close(fds[1]); g_free(request);
}

static void challenge_eof(void) {
    for (unsigned mode = 0; mode < 3; mode++) {
        int fds[2]; g_assert_cmpint(pipe2(fds, O_NONBLOCK | O_CLOEXEC), ==, 0);
        EaWatchState s = {.ready_sent = mode != 0};
        char *request = challenge_frame(nonce);
        size_t n = mode == 2 ? 20 : strlen(request);
        g_assert_cmpint(write(fds[1], request, n), ==, (ssize_t)n);
        if (!mode) {
            g_assert_false(ea_watch_parent(&s, fds[0])); g_assert_true(s.invalidated);
            close(fds[1]);
        } else {
            close(fds[1]); g_assert_false(ea_watch_parent(&s, fds[0]));
            g_assert_true(s.parent_gone);
            g_assert_false(ea_watch_invalidated(&s, -1, (unsigned char[32]){0}));
        }
        ea_watch_release(&s); close(fds[0]); g_free(request);
    }
}

static void loop_freshness(void) {
    gint64 now = 10000000, deadline = now + 300 * G_USEC_PER_SEC;
    EaWatchState s = {.ready_sent = TRUE, .last_dispatch = now};
    g_assert_true(ea_watch_dispatch(&s, now + G_USEC_PER_SEC, deadline));
    g_assert_false(ea_watch_dispatch(&s, now + 2 * G_USEC_PER_SEC + 1, deadline));
    g_assert_cmpint(s.last_dispatch, ==, now + G_USEC_PER_SEC);
    g_assert_false(ea_watch_dispatch(&s, now + G_USEC_PER_SEC, deadline));
    s = (EaWatchState){.ready_sent = TRUE, .last_dispatch = now};
    g_assert_false(ea_watch_dispatch(&s, now - 1, deadline));
    for (unsigned partial = 0; partial < 2; partial++) {
        s = (EaWatchState){.ready_sent = TRUE, .last_dispatch = now, .challenge_started = now,
            .input_len = partial, .challenge_pending = !partial};
        g_assert_true(ea_watch_dispatch(&s, now + G_USEC_PER_SEC - 1, deadline));
        g_assert_false(ea_watch_dispatch(&s, now + G_USEC_PER_SEC, deadline));
    }
    s = (EaWatchState){.ready_sent = TRUE, .last_dispatch = now};
    for (gint64 t = now; t < deadline; t += 500000) g_assert_true(ea_watch_dispatch(&s, t, deadline));
    g_assert_false(ea_watch_dispatch(&s, deadline, deadline));
    Watch w = {.state = {.ready_sent = TRUE, .challenge_pending = TRUE, .input_len = 81,
        .last_dispatch = ea_watch_now() - G_USEC_PER_SEC - 1, .challenge_started = ea_watch_now()},
        .deadline = ea_watch_now() + 300 * G_USEC_PER_SEC, .challenge_check_started = TRUE};
    g_strlcpy(w.state.challenge, nonce, sizeof w.state.challenge);
    g_assert_false(answer_challenge(&w, -1, (unsigned char[32]){0})); g_assert_true(w.state.invalidated);
}

static GDBusConnection *connection(void) {
    GError *error = NULL;
    GDBusConnection *bus = g_dbus_connection_new_for_address_sync(g_test_dbus_get_bus_address(test_bus),
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
        NULL, NULL, &error);
    g_assert_no_error(error); g_assert_nonnull(bus);
    g_dbus_connection_set_exit_on_close(bus, FALSE);
    return bus;
}

static void method(GDBusConnection *bus, const char *member, GVariant *args) {
    GError *error = NULL;
    GVariant *v = g_dbus_connection_call_sync(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", member, args, NULL, G_DBUS_CALL_FLAGS_NONE, 2000, NULL, &error);
    g_assert_no_error(error); g_assert_nonnull(v); g_variant_unref(v);
}

static void emit(GDBusConnection *peer, const char *path, const char *interface, const char *member, GVariant *args) {
    GError *error = NULL;
    g_assert_true(g_dbus_connection_emit_signal(peer, NULL, path, interface, member, args, &error));
    g_assert_no_error(error);
    /* Bus acknowledgement after the signal, so no arbitrary sleep is needed. */
    method(peer, "GetId", NULL);
}

static void wait_event(GMainContext *context, EaWatchState *s) {
    gint64 deadline = g_get_monotonic_time() + 3 * G_USEC_PER_SEC;
    while (!s->invalidated && g_get_monotonic_time() < deadline) {
        while (g_main_context_iteration(context, FALSE)) {}
        if (!s->invalidated) g_usleep(1000);
    }
    g_assert_true(s->invalidated);
}

static void signals(gconstpointer data) {
    const char *name = data;
    GMainContext *context = g_main_context_new(); g_main_context_push_thread_default(context);
    GDBusConnection *peer = connection(), *bus = connection(), *spoof = connection();
    method(peer, "RequestName", g_variant_new("(su)", name, 0u));
    const char *interfaces[] = {"org.freedesktop.login1.Session", "org.freedesktop.DBus.Properties",
        "org.freedesktop.login1.Seat", "org.freedesktop.login1.Manager", "org.freedesktop.login1.Manager",
        "org.freedesktop.login1.Manager", "org.freedesktop.login1.Manager", "org.freedesktop.Secret.Collection",
        "org.freedesktop.login1.FutureInterface"};
    const char *members[] = {"Lock", "PropertiesChanged", "PropertiesChanged", "SessionRemoved", "UserRemoved",
        "PrepareForSleep", "PrepareForShutdown", "ItemDeleted", "UnknownCoverage"};
    for (unsigned i = 0; i < G_N_ELEMENTS(members); i++) {
        EaWatchState s = {0}; EaWatchBus w;
        g_assert_true(ea_watch_bus_start(&w, &s, bus, name, getuid()));
        while (g_main_context_iteration(context, FALSE)) {}
        g_assert_false(s.invalidated);
        /* Another connection cannot impersonate the pinned sender. */
        emit(spoof, "/org/freedesktop/login1/session/test", interfaces[i], members[i], g_variant_new("()"));
        g_assert_true(ea_watch_bus_barrier(&w));
        while (g_main_context_iteration(context, FALSE)) {}
        g_assert_false(s.invalidated);
        emit(peer, "/org/freedesktop/login1/session/test", interfaces[i], members[i],
             !strcmp(members[i], "PrepareForSleep") ? g_variant_new("(b)", TRUE) : g_variant_new("()"));
        /* Queue an opposite event before processing either event. */
        emit(peer, "/org/freedesktop/login1/session/test", "org.freedesktop.login1.Session", "Unlock", g_variant_new("()"));
        g_assert_true(ea_watch_bus_barrier(&w));
        wait_event(context, &s);
        g_assert_false(ea_watch_ready(&s, -1, (unsigned char[32]){0}));
        ea_watch_bus_stop(&w);
        while (g_main_context_iteration(context, FALSE)) {}
    }
    g_object_unref(spoof); g_object_unref(bus); g_object_unref(peer);
    g_main_context_pop_thread_default(context); g_main_context_unref(context);
}

static void lifecycle(void) {
    GMainContext *context = g_main_context_new(); g_main_context_push_thread_default(context);
    GDBusConnection *peer = connection(), *bus = connection();
    const char *name = "org.einsatzarchiv.TestLifecycle";
    EaWatchState s = {0}; EaWatchBus w;
    g_assert_false(ea_watch_bus_start(&w, &s, bus, name, getuid()));
    g_assert_true(s.invalidated); ea_watch_bus_stop(&w);
    method(peer, "RequestName", g_variant_new("(su)", name, 0u));
    s = (EaWatchState){0};
    g_assert_false(ea_watch_bus_start(&w, &s, bus, name, getuid() + 1));
    g_assert_true(s.invalidated); ea_watch_bus_stop(&w);
    s = (EaWatchState){0};
    g_assert_true(ea_watch_bus_start(&w, &s, bus, name, getuid()));
    method(peer, "ReleaseName", g_variant_new("(s)", name));
    method(peer, "RequestName", g_variant_new("(su)", name, 0u));
    wait_event(context, &s); ea_watch_bus_stop(&w);
    s = (EaWatchState){0};
    g_assert_true(ea_watch_bus_start(&w, &s, bus, name, getuid()));
    g_assert_true(g_dbus_connection_close_sync(bus, NULL, NULL));
    wait_event(context, &s); ea_watch_bus_stop(&w);
    g_object_unref(peer); g_object_unref(bus);
    g_main_context_pop_thread_default(context); g_main_context_unref(context);
}

static void challenge_events(gconstpointer data) {
    const char *name = data;
    GMainContext *context = g_main_context_new(); g_main_context_push_thread_default(context);
    GDBusConnection *peer = connection(), *bus = connection();
    method(peer, "RequestName", g_variant_new("(su)", name, 0u));
    const char *members[] = {"Lock", "PropertiesChanged", "SessionRemoved", "UserRemoved", "SeatRemoved",
        "PrepareForSleep", "PrepareForShutdown", "ItemDeleted", "UnknownCoverage"};
    for (unsigned i = 0; i < G_N_ELEMENTS(members); i++) {
        int input[2], output[2];
        g_assert_cmpint(pipe2(input, O_NONBLOCK | O_CLOEXEC), ==, 0);
        g_assert_cmpint(pipe2(output, O_NONBLOCK | O_CLOEXEC), ==, 0);
        Watch w = {.input = input[0], .deadline = ea_watch_now() + 300 * G_USEC_PER_SEC};
        w.files = (EaWatchFiles){.state = &w.state, .fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC)};
        g_assert_cmpint(w.files.fd, >=, 0);
        g_assert_true(ea_watch_bus_start(&w.system, &w.state, bus, name, getuid()));
        w.state.ready_sent = TRUE; w.state.last_dispatch = ea_watch_now();
        char *request = challenge_frame(nonce);
        g_assert_cmpint(write(input[1], request, strlen(request)), ==, (ssize_t)strlen(request));
        g_assert_true(parent_event(input[0], G_IO_IN, &w)); no_output(output[0]);
        /* A completed query may not jump ahead of queued native events. */
        w.challenge_check_started = TRUE;
        emit(peer, "/test", "org.freedesktop.login1.Session", members[i], g_variant_new("()"));
        emit(peer, "/test", "org.freedesktop.login1.Session", "Unlock", g_variant_new("()"));
        g_assert_true(ea_watch_bus_barrier(&w.system));
        drain(context, &w);
        g_assert_true(w.state.invalidated);
        g_assert_false(answer_challenge(&w, output[1], (unsigned char[32]){0})); no_output(output[0]);
        g_assert_true(ea_watch_invalidated(&w.state, output[1], (unsigned char[32]){0}));
        g_assert_false(ea_watch_invalidated(&w.state, output[1], (unsigned char[32]){0}));
        char bytes[256]; ssize_t n = read(output[0], bytes, sizeof bytes - 1);
        g_assert_cmpint(n, >, 0); bytes[n] = 0;
        g_assert_nonnull(strstr(bytes, "\"invalidated\":true")); g_assert_null(strstr(bytes, "challenge"));
        ea_watch_bus_stop(&w.system); ea_watch_files_stop(&w.files); ea_watch_release(&w.state);
        g_free(request); close(input[0]); close(input[1]); close(output[0]); close(output[1]);
        while (g_main_context_iteration(context, FALSE)) {}
    }
    g_object_unref(bus); g_object_unref(peer);
    g_main_context_pop_thread_default(context); g_main_context_unref(context);
}

static void keyring_typed_events(void) {
    GMainContext *context = g_main_context_new(); g_main_context_push_thread_default(context);
    GDBusConnection *peer = connection(), *bus = connection();
    const char *name = "org.freedesktop.secrets", *login = "/org/freedesktop/secrets/collection/login";
    const char *instance = "/org/freedesktop/secrets/collection/login/instance";
    const char *ordinary = "/org/freedesktop/secrets/collection/login/ordinary";
    method(peer, "RequestName", g_variant_new("(su)", name, 0u));
    for (unsigned i = 0; i < 8; i++) {
        EaWatchState s = {0}; EaWatchBus w;
        g_assert_true(ea_watch_bus_start(&w, &s, bus, name, getuid())); w.instance_path = g_strdup(instance);
        emit(peer, login, "org.freedesktop.Secret.Collection", "ItemCreated", g_variant_new("(o)", ordinary));
        g_assert_true(ea_watch_bus_barrier(&w));
        while (g_main_context_iteration(context, FALSE)) {}
        g_assert_false(s.invalidated);
        if (i < 2) {
            emit(peer, login, "org.freedesktop.Secret.Collection", i ? "ItemChanged" : "ItemDeleted", g_variant_new("(o)", instance));
        } else {
            GVariantBuilder changed, invalidated;
            g_variant_builder_init(&changed, G_VARIANT_TYPE("a{sv}"));
            g_variant_builder_init(&invalidated, G_VARIANT_TYPE("as"));
            if (i == 2 || i == 3) g_variant_builder_add(&changed, "{sv}", "Locked", g_variant_new_boolean(i == 2));
            if (i == 4) g_variant_builder_add(&invalidated, "s", "Locked");
            if (i == 5) {
                const char *paths[] = {ordinary, NULL};
                g_variant_builder_add(&changed, "{sv}", "Items", g_variant_new_objv(paths, -1));
            }
            if (i == 6) g_variant_builder_add(&changed, "{sv}", "Modified", g_variant_new_string("wrong-type"));
            if (i == 7) g_variant_builder_add(&changed, "{sv}", "FutureProperty", g_variant_new_boolean(FALSE));
            emit(peer, login, "org.freedesktop.DBus.Properties", "PropertiesChanged",
                g_variant_new("(s@a{sv}@as)", "org.freedesktop.Secret.Collection",
                    g_variant_builder_end(&changed), g_variant_builder_end(&invalidated)));
        }
        g_assert_true(ea_watch_bus_barrier(&w)); wait_event(context, &s);
        ea_watch_bus_stop(&w);
    }
    g_object_unref(peer); g_object_unref(bus);
    g_main_context_pop_thread_default(context); g_main_context_unref(context);
}

static void filesystem(void) {
    GError *error = NULL; char *directory = g_dir_make_tmp("ea-watch-XXXXXX", &error);
    g_assert_no_error(error);
    char *path = g_strconcat(directory, "/marker", NULL);
    char *moved = g_strconcat(directory, "/moved", NULL);
    for (unsigned i = 0; i < 3; i++) {
        g_assert_true(g_file_set_contents(path, "original", -1, &error)); g_assert_no_error(error);
        EaWatchState s = {0}; EaWatchFiles f = {.state = &s, .count = 8};
        for (unsigned j = 0; j < f.count; j++) f.descriptors[j] = -100 - (int)j;
        f.fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC); g_assert_cmpint(f.fd, >=, 0);
        f.descriptors[7] = inotify_add_watch(f.fd, path, IN_MODIFY | IN_ATTRIB | IN_MOVE_SELF | IN_DELETE_SELF);
        g_assert_cmpint(f.descriptors[7], >=, 0);
        g_assert_true(ea_watch_files_drain(&f));
        if (i == 0) {
            int fd = open(path, O_WRONLY); g_assert_cmpint(fd, >=, 0);
            g_assert_cmpint(write(fd, "changed!", 8), ==, 8);
            g_assert_cmpint(lseek(fd, 0, SEEK_SET), ==, 0);
            g_assert_cmpint(write(fd, "original", 8), ==, 8); close(fd);
        } else if (i == 1) {
            g_assert_cmpint(rename(path, moved), ==, 0); g_assert_cmpint(rename(moved, path), ==, 0);
        } else {
            g_assert_cmpint(inotify_rm_watch(f.fd, f.descriptors[7]), ==, 0);
        }
        g_assert_false(ea_watch_files_drain(&f)); g_assert_true(s.invalidated);
        ea_watch_files_stop(&f); g_assert_cmpint(unlink(path), ==, 0);
    }
    g_assert_cmpint(rmdir(directory), ==, 0); g_free(path); g_free(moved); g_free(directory);
}

static void coverage(void) {
    /* Feed kernel record formats through a pipe to deterministically exercise
     * overflow, malformed and unknown-descriptor handling without overflowing
     * the host's inotify resources. */
    const uint32_t masks[] = {IN_Q_OVERFLOW, IN_UNMOUNT, IN_IGNORED, IN_MODIFY};
    for (unsigned i = 0; i < G_N_ELEMENTS(masks) + 1; i++) {
        int fds[2]; g_assert_cmpint(pipe2(fds, O_NONBLOCK | O_CLOEXEC), ==, 0);
        EaWatchState s = {0}; EaWatchFiles f = {.fd = fds[0], .state = &s};
        struct inotify_event e = {.wd = -1, .mask = i < G_N_ELEMENTS(masks) ? masks[i] : IN_MODIFY};
        size_t n = i == G_N_ELEMENTS(masks) ? sizeof e - 1 : sizeof e;
        g_assert_cmpint(write(fds[1], &e, n), ==, (ssize_t)n);
        g_assert_false(ea_watch_files_drain(&f)); g_assert_true(s.invalidated);
        close(fds[1]); ea_watch_files_stop(&f);
    }
}

static void maintenance_event(void) {
    char *directory = g_dir_make_tmp("ea-watch-maintenance-XXXXXX", NULL);
    g_assert_nonnull(directory);
    int dir = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    g_assert_cmpint(dir, >=, 0);
    EaWatchState state = {0};
    EaWatchFiles files = {.state = &state, .count = 6, .uid_name = "1234", .restore_name = ".restore-1234"};
    for (unsigned i = 0; i < files.count; i++) files.descriptors[i] = -100 - (int)i;
    files.fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC); g_assert_cmpint(files.fd, >=, 0);
    files.descriptors[5] = inotify_add_watch(files.fd, directory, IN_CREATE | IN_DELETE | IN_MODIFY);
    g_assert_cmpint(files.descriptors[5], >=, 0);
    int guard = openat(dir, ".restore-1235", O_WRONLY | O_CREAT | O_EXCL, 0600);
    g_assert_cmpint(guard, >=, 0); close(guard);
    g_assert_true(ea_watch_files_drain(&files));
    guard = openat(dir, ".restore-1234", O_WRONLY | O_CREAT | O_EXCL, 0600);
    g_assert_cmpint(guard, >=, 0); close(guard);
    g_assert_cmpint(unlinkat(dir, ".restore-1234", 0), ==, 0);
    /* Even a completed maintenance interval between requests is terminal. */
    g_assert_false(ea_watch_files_drain(&files)); g_assert_true(state.invalidated);
    ea_watch_files_stop(&files);
    g_assert_cmpint(unlinkat(dir, ".restore-1235", 0), ==, 0);
    close(dir); g_assert_cmpint(rmdir(directory), ==, 0); g_free(directory);
}

static void session_properties(void) {
    const char *names[] = {"Active", "LockedHint", "Remote", "State", "Type", "Class", "Seat", "User"};
    /* Real typed property decoder: missing fields, wrong type, lock, inactive,
     * remote, non-GUI, greeter and other UID all fail closed. */
    for (unsigned failure = 0; failure < 19; failure++) {
        GVariantBuilder b; g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
        GVariant *values[] = {g_variant_new_boolean(failure != 9), g_variant_new_boolean(failure == 10),
            g_variant_new_boolean(failure == 11), g_variant_new_string(failure == 12 ? "closing" : "active"),
            g_variant_new_string(failure == 13 ? "tty" : "wayland"), g_variant_new_string(failure == 14 ? "greeter" : "user"),
            g_variant_new("(so)", failure == 15 ? "" : "seat0", "/org/freedesktop/login1/seat/seat0"),
            g_variant_new("(uo)", failure == 16 ? 9999u : (guint32)getuid(), "/org/freedesktop/login1/user/test")};
        for (unsigned i = 0; i < G_N_ELEMENTS(names); i++) {
            g_variant_ref_sink(values[i]);
            if (failure != i + 1) {
                g_variant_builder_add(&b, "{sv}", names[i], failure == 17 && i == 1 ? g_variant_new_string("false") : values[i]);
            }
            g_variant_unref(values[i]);
        }
        GVariant *props = g_variant_ref_sink(g_variant_builder_end(&b));
        g_assert_cmpint(ea_session_properties_unlocked(props, failure == 18 ? getuid() + 1 : getuid()), ==, failure == 0);
        g_variant_unref(props);
    }
    GVariantBuilder b; g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&b, "{sv}", "PreparingForSleep", g_variant_new_boolean(FALSE));
    g_variant_builder_add(&b, "{sv}", "PreparingForShutdown", g_variant_new_boolean(FALSE));
    GVariant *props = g_variant_ref_sink(g_variant_builder_end(&b));
    g_assert_true(awake(props)); g_variant_unref(props);
    for (unsigned i = 0; i < 3; i++) {
        g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
        if (i != 2) {
            g_variant_builder_add(&b, "{sv}", "PreparingForSleep", g_variant_new_boolean(i == 0));
            g_variant_builder_add(&b, "{sv}", "PreparingForShutdown", g_variant_new_boolean(i == 1));
        }
        props = g_variant_ref_sink(g_variant_builder_end(&b));
        g_assert_false(awake(props)); g_variant_unref(props);
    }
}

static void hold_call(GDBusConnection *bus, const char *sender, const char *path, const char *interface,
                      const char *member, GVariant *args, GDBusMethodInvocation *invocation, gpointer data) {
    (void)bus; (void)sender; (void)path; (void)interface; (void)member; (void)args;
    GDBusMethodInvocation **held = data;
    *held = g_object_ref(invocation);
}

static void stalled_query(void) {
    GMainContext *context = g_main_context_new(); g_main_context_push_thread_default(context);
    GDBusConnection *peer = connection(), *bus = connection();
    const char *name = "org.einsatzarchiv.TestStalled";
    method(peer, "RequestName", g_variant_new("(su)", name, 0u));
    Watch w = {.cancel = g_cancellable_new(), .deadline = ea_watch_now() + 300 * G_USEC_PER_SEC};
    g_assert_true(ea_watch_bus_start(&w.system, &w.state, bus, name, getuid()));
    GDBusNodeInfo *info = g_dbus_node_info_new_for_xml("<node><interface name='org.einsatzarchiv.Test'><method name='Wait'><arg type='a{sv}' direction='out'/></method></interface></node>", NULL);
    g_assert_nonnull(info);
    GDBusMethodInvocation *held = NULL;
    const GDBusInterfaceVTable table = {.method_call = hold_call};
    guint registration = g_dbus_connection_register_object(peer, "/test", info->interfaces[0], &table, &held, NULL, NULL);
    g_assert_cmpuint(registration, >, 0);
    probe(&w, SESSION, bus, w.system.owner, "/test", "org.einsatzarchiv.Test", "Wait", NULL, G_VARIANT_TYPE("(a{sv})"));
    gint64 deadline = g_get_monotonic_time() + 2 * G_USEC_PER_SEC;
    while (!held && g_get_monotonic_time() < deadline) {
        while (g_main_context_iteration(context, FALSE)) {}
        if (!held) g_usleep(1000);
    }
    g_assert_nonnull(held); g_assert_cmpuint(w.pending, ==, 1); g_assert_false(w.state.invalidated);
    w.state.ready_sent = TRUE; w.state.last_dispatch = ea_watch_now();
    w.state.challenge_started = ea_watch_now(); w.state.challenge_pending = TRUE;
    g_strlcpy(w.state.challenge, nonce, sizeof w.state.challenge);
    /* An outstanding older probe must not be labelled as this nonce's probe. */
    service_challenge(context, &w, -1, (unsigned char[32]){0});
    g_assert_false(w.challenge_check_started);
    g_assert_false(answer_challenge(&w, -1, (unsigned char[32]){0}));
    emit(peer, "/test", "org.freedesktop.login1.Session", "Lock", g_variant_new("()"));
    emit(peer, "/test", "org.freedesktop.login1.Session", "Unlock", g_variant_new("()"));
    wait_event(context, &w.state);
    /* The lock is delivered while the query is STILL waiting for its reply. */
    g_assert_cmpuint(w.pending, ==, 1);
    g_assert_false(answer_challenge(&w, -1, (unsigned char[32]){0}));
    g_cancellable_cancel(w.cancel);
    while (w.pending) g_main_context_iteration(context, TRUE);
    g_dbus_method_invocation_return_dbus_error(held, "org.einsatzarchiv.Test.Cancelled", "test complete");
    g_object_unref(held);
    g_assert_true(g_dbus_connection_unregister_object(peer, registration));
    g_dbus_node_info_unref(info); ea_watch_bus_stop(&w.system); g_object_unref(w.cancel);
    g_object_unref(bus); g_object_unref(peer);
    g_main_context_pop_thread_default(context); g_main_context_unref(context);
}

static gboolean fixture_tick(gpointer data) {
    Watch *w = data;
    return ea_watch_fresh(&w->state, ea_watch_now(), w->deadline);
}

static gboolean block_fixture_loop(gpointer data) {
    (void)data;
    g_assert_cmpint(write(STDERR_FILENO, "blocked\n", 8), ==, 8);
    g_usleep(1200000);
    return G_SOURCE_REMOVE;
}

/* Test executable ONLY: real dispatch/drain/pipe/clock functions, with native
 * acceptance deliberately omitted. No such mode exists in the shipped helper.
 * Python uses it to stop/resume this process and to block its actual GLib loop. */
static int challenge_loop_fixture(gboolean block_loop) {
    GMainContext *context = g_main_context_new(); g_main_context_push_thread_default(context);
    Watch w = {.input = STDIN_FILENO, .deadline = ea_watch_now() + 300 * G_USEC_PER_SEC};
    w.files = (EaWatchFiles){.state = &w.state, .fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC)};
    g_assert_cmpint(w.files.fd, >=, 0); g_assert_true(nonblock(STDIN_FILENO)); g_assert_true(nonblock(STDOUT_FILENO));
    GSource *parent_source = g_unix_fd_source_new(STDIN_FILENO, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL);
    g_source_set_callback(parent_source, G_SOURCE_FUNC(parent_event), &w, NULL); g_source_attach(parent_source, context);
    GSource *timer = g_timeout_source_new(100);
    g_source_set_callback(timer, fixture_tick, &w, NULL); g_source_attach(timer, context);
    GSource *blocker = NULL;
    if (block_loop) {
        blocker = g_timeout_source_new(1);
        g_source_set_callback(blocker, block_fixture_loop, NULL, NULL); g_source_attach(blocker, context);
    }
    unsigned char id[32] = {0};
    g_assert_true(ea_watch_ready(&w.state, STDOUT_FILENO, id));
    while (!w.state.invalidated && !w.state.parent_gone) {
        if (!dispatch(context, &w, TRUE)) break;
        drain(context, &w);
        if (w.state.challenge_pending) {
            w.challenge_check_started = TRUE;
            (void)answer_challenge(&w, STDOUT_FILENO, id);
        }
    }
    (void)ea_watch_invalidated(&w.state, STDOUT_FILENO, id);
    if (blocker) { g_source_destroy(blocker); g_source_unref(blocker); }
    g_source_destroy(timer); g_source_unref(timer);
    g_source_destroy(parent_source); g_source_unref(parent_source);
    ea_watch_files_stop(&w.files); ea_watch_release(&w.state);
    g_main_context_pop_thread_default(context); g_main_context_unref(context);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--test-challenge-loop")) return challenge_loop_fixture(FALSE);
    if (argc == 2 && !strcmp(argv[1], "--test-blocked-loop")) return challenge_loop_fixture(TRUE);
    g_test_init(&argc, &argv, NULL);
    test_bus = g_test_dbus_new(G_TEST_DBUS_NONE); g_test_dbus_up(test_bus);
    g_test_add_func("/watch/messages", messages);
    g_test_add_func("/watch/parent", parent);
    g_test_add_func("/watch/deadline", expiry);
    g_test_add_func("/watch/challenge-input", challenge_input);
    g_test_add_func("/watch/challenge-exact-ack-replay", challenge_messages);
    g_test_add_func("/watch/challenge-malformed-queued", challenge_reject);
    g_test_add_func("/watch/challenge-frame-history-bounds", challenge_bounds);
    g_test_add_func("/watch/challenge-parent-eof-before-ready", challenge_eof);
    g_test_add_func("/watch/loop-stall-partial-deadline", loop_freshness);
    g_test_add_data_func("/watch/challenge-logind-drained-before-ack", "org.freedesktop.login1", challenge_events);
    g_test_add_data_func("/watch/challenge-keyring-drained-before-ack", "org.freedesktop.secrets", challenge_events);
    g_test_add_data_func("/watch/logind-events", "org.freedesktop.login1", signals);
    g_test_add_data_func("/watch/keyring-events", "org.freedesktop.secrets", signals);
    g_test_add_func("/watch/owner-disconnect-coverage", lifecycle);
    g_test_add_func("/watch/typed-keyring-events", keyring_typed_events);
    g_test_add_func("/watch/marker-change-restore", filesystem);
    g_test_add_func("/watch/unknown-file-coverage", coverage);
    g_test_add_func("/watch/maintenance-interval", maintenance_event);
    g_test_add_func("/watch/typed-session-and-suspend-state", session_properties);
    g_test_add_func("/watch/signals-during-stalled-query", stalled_query);
    int result = g_test_run();
    g_test_dbus_down(test_bus); g_object_unref(test_bus);
    return result;
}
