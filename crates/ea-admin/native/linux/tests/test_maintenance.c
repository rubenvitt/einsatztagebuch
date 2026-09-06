/* Native maintenance gate under an owned temporary subtree only. */
#include "ea_native.h"
#include <fcntl.h>
#include <glib/gstdio.h>
#include <unistd.h>

static void gate(void) {
    char *directory = g_dir_make_tmp("ea-native-maintenance-XXXXXX", NULL);
    g_assert_nonnull(directory);
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    g_assert_cmpint(fd, >=, 0);
    g_assert_null(ea_marker_maintenance(fd, 1234));
    int marker = openat(fd, ".restore-1234", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    g_assert_cmpint(marker, >=, 0); close(marker);
    /* Empty/interrupted records also block. No parsing or following a link. */
    g_assert_cmpstr(ea_marker_maintenance(fd, 1234), ==, "installation-maintenance");
    g_assert_null(ea_marker_maintenance(fd, 1235));
    EaMarkerStore store = {.base_fd = fd, .dir_fd = fd, .uid = 1234};
    EaAccount account = {0}; EaMarker value = {0};
    marker = openat(fd, "marker", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    g_assert_cmpint(marker, >=, 0); close(marker);
    g_assert_cmpstr(ea_marker_load(&store, &account, &value), ==, "installation-maintenance");
    g_assert_cmpstr(ea_marker_publish(&store, &value), ==, "installation-maintenance");
    g_assert_cmpstr(ea_marker_recheck(&store, &account, &value), ==, "installation-maintenance");
    g_assert_cmpstr(ea_marker_reset(&store), ==, "installation-maintenance");
    g_assert_cmpint(faccessat(fd, "marker", F_OK, 0), ==, 0);
    g_assert_cmpint(unlinkat(fd, "marker", 0), ==, 0);
    g_assert_cmpint(unlinkat(fd, ".restore-1234", 0), ==, 0);
    g_assert_cmpint(symlinkat("missing", fd, ".restore-1234"), ==, 0);
    g_assert_cmpstr(ea_marker_maintenance(fd, 1234), ==, "installation-maintenance");
    g_assert_cmpint(unlinkat(fd, ".restore-1234", 0), ==, 0);
    g_assert_null(ea_marker_maintenance(fd, 1234));
    close(fd);
    g_assert_cmpstr(ea_marker_maintenance(-1, 1234), ==, "installation-maintenance");
    g_assert_cmpint(g_rmdir(directory), ==, 0); g_free(directory);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/maintenance/blocks-until-explicitly-cleared", gate);
    return g_test_run();
}
