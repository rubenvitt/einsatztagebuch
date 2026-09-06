#ifndef EA_WATCH_H
#define EA_WATCH_H
#include "ea_native.h"

#define EA_WATCH_SECONDS 300
#define EA_WATCH_FRAME_LIMIT 1024
#define EA_WATCH_NONCE_LIMIT 65536
#define EA_WATCH_FRESH_USEC G_USEC_PER_SEC

typedef struct {
    gboolean invalidated, parent_gone, ready_sent, invalidation_sent;
    gboolean challenge_pending;
    gint64 last_dispatch, challenge_started;
    size_t input_len;
    unsigned char input_frame[EA_WATCH_FRAME_LIMIT];
    char challenge[65];
    GHashTable *seen;
} EaWatchState;

/* Monotone state: there is intentionally no reset/rearm operation. */
void ea_watch_invalidate(EaWatchState *state);
gboolean ea_watch_expire(EaWatchState *state, gint64 now, gint64 deadline);
gint64 ea_watch_now(void);
gboolean ea_watch_fresh(EaWatchState *state, gint64 now, gint64 deadline);
gboolean ea_watch_dispatch(EaWatchState *state, gint64 now, gint64 deadline);
gboolean ea_parse_challenge(const unsigned char *data, size_t len, char challenge[65]);
gboolean ea_watch_ready(EaWatchState *state, int output, const unsigned char id[32]);
gboolean ea_watch_invalidated(EaWatchState *state, int output, const unsigned char id[32]);
gboolean ea_watch_parent(EaWatchState *state, int input);
void ea_watch_release(EaWatchState *state);

typedef struct {
    EaWatchState *state;
    GDBusConnection *bus;
    char *owner, *name, *match, *instance_path;
    guint service_subscription, owner_subscription;
    gulong closed_handler;
    gboolean service_match, owner_match;
} EaWatchBus;

gboolean ea_watch_bus_start(EaWatchBus *watch, EaWatchState *state,
                           GDBusConnection *bus, const char *name, uid_t uid);
gboolean ea_watch_bus_barrier(EaWatchBus *watch);
void ea_watch_bus_stop(EaWatchBus *watch);

typedef struct {
    int fd;
    int descriptors[10];
    unsigned count;
    char uid_name[16];
    char restore_name[32];
    EaWatchState *state;
} EaWatchFiles;

gboolean ea_watch_files_start(EaWatchFiles *files, EaWatchState *state, uid_t uid);
gboolean ea_watch_files_drain(EaWatchFiles *files);
void ea_watch_files_stop(EaWatchFiles *files);

int ea_watch_session(const EaRequest *request, int input, int output);
#endif
