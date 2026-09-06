#include "ea_native.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <string.h>
#include <unistd.h>

const char *ea_receive(int input, EaRequest *request, gboolean *watch) {
    unsigned char *bytes = g_malloc0(EA_MAX_MESSAGE + 1);
    EaRequest *candidate = g_malloc0(sizeof *candidate);
    size_t length = 0, scanned = 0;
    const char *error = NULL;
    *watch = FALSE;
    for (;;) {
        ssize_t n = read(input, bytes + length, EA_MAX_MESSAGE + 1 - length);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { error = "io-failed"; break; }
        if (!n) {
            error = ea_parse(bytes, length, request);
            if (!error && !strcmp(request->op, "watch-session")) error = "invalid-request";
            break;
        }
        length += (size_t)n;
        if (length > EA_MAX_MESSAGE) { error = "request-too-large"; break; }
        for (; scanned < length; scanned++) {
            if (bytes[scanned] != '\n') continue;
            /* A normal request, including pretty-printed JSON or trailing LF,
             * still waits for EOF. Only a valid watch request changes framing. */
            if (!ea_parse(bytes, scanned, candidate) && !strcmp(candidate->op, "watch-session")) {
                if (scanned + 1 != length) { error = "invalid-request"; goto done; }
                *request = *candidate; *watch = TRUE;
                goto done;
            }
        }
    }
done:
    OPENSSL_cleanse(bytes, EA_MAX_MESSAGE + 1); g_free(bytes);
    OPENSSL_cleanse(candidate, sizeof *candidate); g_free(candidate);
    return error;
}

gboolean ea_write_json(int output, JsonObject *fields) {
    JsonNode *node = json_node_new(JSON_NODE_OBJECT);
    json_node_set_object(node, fields);
    JsonGenerator *generator = json_generator_new();
    json_generator_set_root(generator, node);
    gsize length = 0;
    char *bytes = json_generator_to_data(generator, &length);
    gboolean ok = FALSE;
    if (bytes && length < EA_MAX_MESSAGE) {
        size_t offset = 0;
        while (offset < length) {
            ssize_t n = write(output, bytes + offset, length - offset);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            offset += (size_t)n;
        }
        if (offset == length) {
            ssize_t n;
            do { n = write(output, "\n", 1); } while (n < 0 && errno == EINTR);
            ok = n == 1;
        }
    }
    if (bytes) OPENSSL_cleanse(bytes, length);
    g_free(bytes); g_object_unref(generator); json_node_free(node);
    return ok;
}
