#ifndef EA_NATIVE_H
#define EA_NATIVE_H
#include <gio/gio.h>
#include <json-glib/json-glib.h>
#include <stdint.h>
#include <sys/types.h>

#define EA_MAX_MESSAGE 65536
#define EA_MARKER_ROOT "/var/lib/ea-native-operator"
#define EA_RESTORE_PREFIX ".restore-"
#define EA_POLICY "/etc/ea-native-operator/backup-policy"
#define EA_POLICY_TEXT "ea-native-operator-backup-v1\ngnu-tar-exclude-marker-tree\n"
#define EA_EXCLUDES "/etc/ea-native-operator/backup-excludes"
#define EA_EXCLUDES_TEXT "ea-native-operator\n*/ea-native-operator\n*/ea-native-operator/*\n"
#define EA_ACTION "org.einsatzarchiv.operator.authenticate"
#define EA_ENVELOPE_SIZE 61

typedef struct {
    char op[20], slot[65], kind[10];
    gboolean presence, replace, has_installation, has_expected_public;
    unsigned char installation[32], expected_public[32], data[EA_MAX_MESSAGE / 2];
    size_t data_len;
} EaRequest;

typedef struct {
    uid_t uid;
    unsigned char machine[33];
    size_t machine_len;
    unsigned char binding[32];
} EaAccount;

typedef struct {
    unsigned char id[32], wrapping[32], instance_hash[32];
    unsigned char binding[32];
} EaMarker;

typedef struct {
    int base_fd, dir_fd, lock_fd;
    uid_t uid;
} EaMarkerStore;

const char *ea_parse(const unsigned char *data, size_t len, EaRequest *request);
const char *ea_receive(int input, EaRequest *request, gboolean *watch);
gboolean ea_write_json(int output, JsonObject *fields);
gboolean ea_unhex(const char *hex, unsigned char *out, size_t capacity, size_t *len);
char *ea_hex(const unsigned char *bytes, size_t len);
gboolean ea_random(unsigned char out[32]);
gboolean ea_hash(const unsigned char *data, size_t len, unsigned char out[32]);
gboolean ea_public(const unsigned char seed[32], unsigned char public_key[32]);
gboolean ea_sign(const unsigned char seed[32], const unsigned char *data, size_t len, unsigned char signature[64]);
gboolean ea_seal(const EaMarker *marker, const unsigned char instance[32], const char *slot, const char *kind, const char *public_hex, const unsigned char plain[32], unsigned char envelope[EA_ENVELOPE_SIZE]);
gboolean ea_open(const EaMarker *marker, const unsigned char instance[32], const char *slot, const char *kind, const char *public_hex, const unsigned char envelope[EA_ENVELOPE_SIZE], unsigned char plain[32]);
char *ea_metadata_mac(const EaMarker *marker, const char *slot, const char *kind, const char *public_hex);
gboolean ea_secret_slot(const char *slot);
const char *ea_read_account(EaAccount *account);
gboolean ea_session_unlocked(GDBusConnection *bus, uid_t uid, char **session_path);
gboolean ea_session_properties_unlocked(GVariant *props, uid_t uid);
gboolean ea_fresh_presence(GDBusConnection *bus);
const char *ea_marker_store_open(EaMarkerStore *store, uid_t uid);
const char *ea_marker_maintenance(int base_fd, uid_t uid);
const char *ea_marker_load(EaMarkerStore *store, const EaAccount *account, EaMarker *marker);
const char *ea_marker_publish(EaMarkerStore *store, const EaMarker *marker);
const char *ea_marker_recheck(EaMarkerStore *store, const EaAccount *account, const EaMarker *marker);
const char *ea_marker_reset(EaMarkerStore *store);
void ea_marker_store_close(EaMarkerStore *store);
typedef struct { unsigned char bytes[106]; } EaSigningBackupFrame;
const char *ea_validate_signing_backup(const EaRequest *request);
const char *ea_execute_signing_backup(const EaRequest *request, EaSigningBackupFrame *frame);
gboolean ea_write_signing_backup(int output, EaSigningBackupFrame *frame);
const char *ea_execute(const EaRequest *request, JsonObject **fields);
const char *ea_watch_account(const EaRequest *request, JsonObject **fields, char **instance_path);
#endif
