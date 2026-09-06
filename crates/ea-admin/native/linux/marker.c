#include "ea_native.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <openssl/crypto.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

static const unsigned char magic[8] = {'E','A','N','A','T','0','1',0};
static gboolean nodump(int fd, gboolean set) {
    int flags = 0;
    if (ioctl(fd, FS_IOC_GETFLAGS, &flags)) return FALSE;
    if (!(flags & FS_NODUMP_FL) && set) {
        flags |= FS_NODUMP_FL;
        if (ioctl(fd, FS_IOC_SETFLAGS, &flags) || ioctl(fd, FS_IOC_GETFLAGS, &flags)) return FALSE;
    }
    return (flags & FS_NODUMP_FL) != 0;
}

static gboolean safe_dir(int fd, uid_t uid, gboolean private) {
    struct stat st;
    return fd >= 0 && !fstat(fd, &st) && S_ISDIR(st.st_mode) && st.st_uid == uid &&
           !(st.st_mode & (private ? 077 : 022));
}

static gboolean policy_file(int directory, const char *name, const char *expected) {
    int fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return FALSE;
    struct stat st; char data[256];
    ssize_t n = -1;
    if (!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == 0 && !(st.st_mode & 022) && st.st_nlink == 1) {
        do { n = read(fd, data, sizeof data); } while (n < 0 && errno == EINTR);
    }
    close(fd);
    return n == (ssize_t)strlen(expected) && !memcmp(data, expected, (size_t)n);
}

static gboolean policy(void) {
    int etc = open("/etc", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (!safe_dir(etc, 0, FALSE)) { if (etc >= 0) close(etc); return FALSE; }
    int fd = openat(etc, "ea-native-operator", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    close(etc);
    gboolean ok = safe_dir(fd, 0, FALSE) &&
        policy_file(fd, "backup-policy", EA_POLICY_TEXT) &&
        policy_file(fd, "backup-excludes", EA_EXCLUDES_TEXT);
    if (fd >= 0) close(fd);
    return ok;
}

const char *ea_marker_maintenance(int base_fd, uid_t uid) {
    char name[32]; g_snprintf(name, sizeof name, EA_RESTORE_PREFIX "%u", (unsigned)uid);
    struct stat st;
    /* A protected root-directory entry is a persistent deny gate, including
     * an interrupted empty record, symlink or malformed object. Never read it
     * as identity/presence data. Only a confirmed absent entry permits use. */
    if (!fstatat(base_fd, name, &st, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) return "installation-maintenance";
    return NULL;
}

const char *ea_marker_store_open(EaMarkerStore *s, uid_t uid) {
    *s = (EaMarkerStore){.base_fd = -1, .dir_fd = -1, .lock_fd = -1, .uid = uid};
    if (!policy()) return "backup-policy-required";
    int var = open("/var", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (!safe_dir(var, 0, FALSE)) { if (var >= 0) close(var); return "installation-invalid"; }
    int lib = openat(var, "lib", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    close(var);
    if (!safe_dir(lib, 0, FALSE)) { if (lib >= 0) close(lib); return "installation-invalid"; }
    s->base_fd = openat(lib, "ea-native-operator", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    close(lib);
    if (!safe_dir(s->base_fd, 0, FALSE) || !nodump(s->base_fd, FALSE)) return "backup-policy-required";
    const char *maintenance = ea_marker_maintenance(s->base_fd, uid);
    if (maintenance) return maintenance;
    char name[16]; g_snprintf(name, sizeof name, "%u", (unsigned)uid);
    s->dir_fd = openat(s->base_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (!safe_dir(s->dir_fd, uid, TRUE) || !nodump(s->dir_fd, FALSE)) return "installation-not-enrolled";
    /* Lock the directory inode, so deleting a lock file cannot fork the lock. */
    if (flock(s->dir_fd, LOCK_EX | LOCK_NB)) return "busy";
    return ea_marker_maintenance(s->base_fd, uid);
}

const char *ea_marker_load(EaMarkerStore *s, const EaAccount *a, EaMarker *m) {
    const char *maintenance = ea_marker_maintenance(s->base_fd, s->uid);
    if (maintenance) { OPENSSL_cleanse(m, sizeof *m); return maintenance; }
    unsigned char raw[8 + sizeof *m + 1];
    size_t n = 0;
    const char *error = "installation-invalid";
    int fd = openat(s->dir_fd, "marker", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? "installation-missing" : error;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != s->uid || (st.st_mode & 0777) != 0600 || st.st_nlink != 1) goto done;
    if (!nodump(fd, FALSE)) { error = "backup-policy-required"; goto done; }
    while (n < sizeof raw) {
        ssize_t count = read(fd, raw + n, sizeof raw - n);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) goto done;
        if (!count) break;
        n += (size_t)count;
    }
    if (n != 8 + sizeof *m || memcmp(raw, magic, 8)) goto done;
    memcpy(m, raw + 8, sizeof *m);
    unsigned char zero[32] = {0};
    if (CRYPTO_memcmp(m->binding, a->binding, 32) || !CRYPTO_memcmp(m->id, zero, 32) ||
        !CRYPTO_memcmp(m->wrapping, zero, 32) || !CRYPTO_memcmp(m->id, m->wrapping, 32)) goto done;
    error = NULL;
done:
    close(fd); OPENSSL_cleanse(raw, sizeof raw);
    if (error) OPENSSL_cleanse(m, sizeof *m);
    return error;
}

const char *ea_marker_publish(EaMarkerStore *s, const EaMarker *m) {
    const char *maintenance = ea_marker_maintenance(s->base_fd, s->uid);
    if (maintenance) return maintenance;
    unsigned char raw[8 + sizeof *m];
    memcpy(raw, magic, 8); memcpy(raw + 8, m, sizeof *m);
    const char *error = "installation-write-failed";
    int fd = openat(s->dir_fd, ".pending", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) { OPENSSL_cleanse(raw, sizeof raw); return error; }
    size_t n = 0;
    if (fchmod(fd, 0600) || !nodump(fd, TRUE)) { error = "backup-policy-required"; goto done; }
    while (n < sizeof raw) {
        ssize_t count = write(fd, raw + n, sizeof raw - n);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) goto done;
        n += (size_t)count;
    }
    if (fsync(fd) || linkat(s->dir_fd, ".pending", s->dir_fd, "marker", 0)) goto done;
    if (unlinkat(s->dir_fd, ".pending", 0) || fsync(s->dir_fd)) goto done;
    error = NULL;
done:
    close(fd);
    if (error) { (void)unlinkat(s->dir_fd, ".pending", 0); (void)fsync(s->dir_fd); }
    OPENSSL_cleanse(raw, sizeof raw);
    return error;
}

const char *ea_marker_recheck(EaMarkerStore *s, const EaAccount *a, const EaMarker *m) {
    const char *maintenance = ea_marker_maintenance(s->base_fd, s->uid);
    if (maintenance) return maintenance;
    if (!policy() || !nodump(s->base_fd, FALSE) || !nodump(s->dir_fd, FALSE)) return "backup-policy-required";
    char name[16]; g_snprintf(name, sizeof name, "%u", (unsigned)s->uid);
    struct stat before, now;
    if (fstat(s->dir_fd, &before) || fstatat(s->base_fd, name, &now, AT_SYMLINK_NOFOLLOW) ||
        !S_ISDIR(now.st_mode) || before.st_dev != now.st_dev || before.st_ino != now.st_ino ||
        !safe_dir(s->dir_fd, s->uid, TRUE)) return "installation-changed";
    EaMarker check = {0};
    const char *error = ea_marker_load(s, a, &check);
    if (!error && CRYPTO_memcmp(&check, m, sizeof check)) error = "installation-changed";
    OPENSSL_cleanse(&check, sizeof check);
    return error;
}

const char *ea_marker_reset(EaMarkerStore *s) {
    const char *maintenance = ea_marker_maintenance(s->base_fd, s->uid);
    if (maintenance) return maintenance;
    if (unlinkat(s->dir_fd, "marker", 0) || fsync(s->dir_fd)) return "installation-write-failed";
    return NULL;
}

void ea_marker_store_close(EaMarkerStore *s) {
    if (s->dir_fd >= 0) close(s->dir_fd);
    if (s->base_fd >= 0) close(s->base_fd);
    s->dir_fd = s->base_fd = -1;
}
