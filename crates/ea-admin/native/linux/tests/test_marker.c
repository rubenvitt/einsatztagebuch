/* Run only in our disposable root-owned Ubuntu test container. Uses the actual
 * Linux filesystem, nodump ioctls, permissions and atomic publication paths. */
#include "ea_native.h"
#include <fcntl.h>
#include <linux/fs.h>
#include <openssl/crypto.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

static void marker_lifecycle(void) {
    EaAccount a = {.uid = getuid(), .binding = {0x42}};
    EaMarkerStore store;
    EaMarker m = {.binding = {0x42}}, loaded = {0};
    g_assert_null(ea_marker_store_open(&store, getuid()));
    g_assert_cmpstr(ea_marker_load(&store, &a, &loaded), ==, "installation-missing");
    g_assert_true(ea_random(m.id));
    g_assert_true(ea_random(m.wrapping));
    g_assert_true(ea_random(m.instance_hash));
    g_assert_null(ea_marker_publish(&store, &m));
    g_assert_null(ea_marker_load(&store, &a, &loaded));
    g_assert_cmpmem(&m, sizeof m, &loaded, sizeof loaded);
    g_assert_null(ea_marker_recheck(&store, &a, &m));
    /* Exclusive publication must not overwrite an existing wrapping key. */
    EaMarker newer = m;
    g_assert_true(ea_random(newer.wrapping));
    g_assert_nonnull(ea_marker_publish(&store, &newer));
    g_assert_null(ea_marker_recheck(&store, &a, &m));
    /* A second process/descriptor must not create a separate lock. */
    EaMarkerStore busy;
    g_assert_cmpstr(ea_marker_store_open(&busy, getuid()), ==, "busy");
    ea_marker_store_close(&busy);
    EaAccount wrong = a; wrong.binding[0] ^= 1;
    g_assert_cmpstr(ea_marker_load(&store, &wrong, &loaded), ==, "installation-invalid");
    int fd = openat(store.dir_fd, "marker", O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(fchmod(fd, 0644), ==, 0);
    g_assert_cmpstr(ea_marker_load(&store, &a, &loaded), ==, "installation-invalid");
    g_assert_cmpint(fchmod(fd, 0600), ==, 0);
    int flags;
    g_assert_cmpint(ioctl(fd, FS_IOC_GETFLAGS, &flags), ==, 0);
    flags &= ~FS_NODUMP_FL;
    g_assert_cmpint(ioctl(fd, FS_IOC_SETFLAGS, &flags), ==, 0);
    g_assert_cmpstr(ea_marker_load(&store, &a, &loaded), ==, "backup-policy-required");
    flags |= FS_NODUMP_FL;
    g_assert_cmpint(ioctl(fd, FS_IOC_SETFLAGS, &flags), ==, 0);
    close(fd);
    g_assert_cmpint(linkat(store.dir_fd, "marker", store.dir_fd, "copied-marker", 0), ==, 0);
    g_assert_cmpstr(ea_marker_load(&store, &a, &loaded), ==, "installation-invalid");
    g_assert_cmpint(unlinkat(store.dir_fd, "copied-marker", 0), ==, 0);
    g_assert_null(ea_marker_reset(&store));
    g_assert_cmpstr(ea_marker_recheck(&store, &a, &m), ==, "installation-missing");
    g_assert_cmpint(symlinkat("/etc/passwd", store.dir_fd, "marker"), ==, 0);
    g_assert_cmpstr(ea_marker_load(&store, &a, &loaded), ==, "installation-invalid");
    g_assert_cmpint(unlinkat(store.dir_fd, "marker", 0), ==, 0);
    ea_marker_store_close(&store);
    OPENSSL_cleanse(&m, sizeof m); OPENSSL_cleanse(&newer, sizeof newer); OPENSSL_cleanse(&loaded, sizeof loaded);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/marker/lifecycle-and-failures", marker_lifecycle);
    return g_test_run();
}
