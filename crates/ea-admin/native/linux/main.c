#include "ea_native.h"
#include "watch.h"
#include <errno.h>
#include <linux/magic.h>
#include <openssl/crypto.h>
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

static void discard_log(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer data) {
    (void)domain; (void)level; (void)message; (void)data;
}
static GLogWriterOutput discard_structured(GLogLevelFlags level, const GLogField *fields, gsize n, gpointer data) {
    (void)level; (void)fields; (void)n; (void)data;
    return G_LOG_WRITER_HANDLED;
}

static gboolean pipes(void) {
    struct stat st;
    struct statfs fs;
    for (int fd = STDIN_FILENO; fd <= STDOUT_FILENO; fd++) {
        /* Linux anonymous pipes have st_nlink == 1. Only kernel pipefs, not
         * the link count shared with named FIFOs, identifies this transport. */
        if (fstat(fd, &st) || !S_ISFIFO(st.st_mode) || fstatfs(fd, &fs) || fs.f_type != PIPEFS_MAGIC) return FALSE;
    }
    return TRUE;
}

int main(int argc, char **argv) {
    (void)argv;
    g_log_set_default_handler(discard_log, NULL);
    g_log_set_writer_func(discard_structured, NULL, NULL);
    struct rlimit core = {0, 0};
    const char *error = NULL;
    JsonObject *fields = NULL;
    EaRequest *request = g_malloc0(sizeof *request);
    gboolean watch = FALSE;
    /* Fixed process deadline includes EOF waiting, D-Bus and the native prompt.
     * No alarm handler can emit secret material or continue after timeout. */
    signal(SIGPIPE, SIG_IGN);
    alarm(90);
    umask(077);
    if (argc != 1) error = "invalid-request";
    else if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) error = "process-protection-failed";
    else if (!pipes()) error = "protected-pipe-required";
    if (!error) error = ea_receive(STDIN_FILENO, request, &watch);
    if (!error && watch) {
        alarm(EA_WATCH_SECONDS);
        int result = ea_watch_session(request, STDIN_FILENO, STDOUT_FILENO);
        OPENSSL_cleanse(request, sizeof *request); g_free(request);
        return result;
    }
    if (!error) error = ea_execute(request, &fields);
    OPENSSL_cleanse(request, sizeof *request); g_free(request);
    if (error) {
        fields = json_object_new();
        json_object_set_boolean_member(fields, "ok", FALSE);
        json_object_set_string_member(fields, "code", error);
    }
    gboolean written = ea_write_json(STDOUT_FILENO, fields);
    if (json_object_has_member(fields, "secret")) {
        const char *secret = json_object_get_string_member(fields, "secret");
        OPENSSL_cleanse((char *)secret, strlen(secret));
    }
    json_object_unref(fields);
    return error || !written ? 1 : 0;
}
