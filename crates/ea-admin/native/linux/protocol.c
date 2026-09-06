#include "watch.h"
#include <openssl/crypto.h>
#include <string.h>

static int nibble(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

gboolean ea_unhex(const char *hex, unsigned char *out, size_t capacity, size_t *len) {
    size_t n = strlen(hex);
    if (n % 2 || n / 2 > capacity) return FALSE;
    for (size_t i = 0; i < n; i += 2) {
        int a = nibble((unsigned char)hex[i]), b = nibble((unsigned char)hex[i + 1]);
        if (a < 0 || b < 0) { OPENSSL_cleanse(out, i / 2); return FALSE; }
        out[i / 2] = (unsigned char)((a << 4) | b);
    }
    *len = n / 2;
    return TRUE;
}

char *ea_hex(const unsigned char *bytes, size_t len) {
    static const char digits[] = "0123456789abcdef";
    char *text = g_malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++) {
        text[i * 2] = digits[bytes[i] >> 4];
        text[i * 2 + 1] = digits[bytes[i] & 15];
    }
    text[len * 2] = 0;
    return text;
}

gboolean ea_secret_slot(const char *slot) {
    return !strcmp(slot, "database-key") || !strcmp(slot, "draft-key");
}

typedef struct { const unsigned char *bytes; size_t len, pos; } Parser;
static void whitespace(Parser *p) {
    while (p->pos < p->len && strchr(" \t\r\n", p->bytes[p->pos]) && p->bytes[p->pos]) p->pos++;
}
static gboolean take(Parser *p, unsigned char c) {
    whitespace(p);
    if (p->pos == p->len || p->bytes[p->pos] != c) return FALSE;
    p->pos++;
    return TRUE;
}

/* The interface contains only ASCII identifiers and hex. Decode JSON escapes
 * before duplicate detection; reject NUL, Unicode, nesting and coercions. */
static char *string(Parser *p) {
    if (!take(p, '"')) return NULL;
    char *s = g_malloc(p->len - p->pos + 1);
    size_t n = 0;
    while (p->pos < p->len) {
        unsigned char c = p->bytes[p->pos++];
        if (c == '"') { s[n] = 0; return s; }
        if (c < 32 || c > 126) break;
        if (c == '\\') {
            if (p->pos == p->len) break;
            c = p->bytes[p->pos++];
            if (c == 'u') {
                if (p->len - p->pos < 4) break;
                unsigned value = 0;
                gboolean valid = TRUE;
                for (size_t j = 0; j < 4; j++) {
                    unsigned char h = p->bytes[p->pos++];
                    if (h >= 'A' && h <= 'F') h = (unsigned char)(h + ('a' - 'A'));
                    int digit = nibble(h);
                    if (digit < 0) { valid = FALSE; break; }
                    value = value * 16 + (unsigned)digit;
                }
                if (!valid || !value || value > 127) break;
                c = (unsigned char)value;
            } else {
                switch (c) {
                    case '"': case '\\': case '/': break;
                    case 'b': c = '\b'; break;
                    case 'f': c = '\f'; break;
                    case 'n': c = '\n'; break;
                    case 'r': c = '\r'; break;
                    case 't': c = '\t'; break;
                    default: goto invalid;
                }
            }
        }
        s[n++] = (char)c;
    }
invalid:
    OPENSSL_cleanse(s, n);
    g_free(s);
    return NULL;
}

const char *ea_parse(const unsigned char *data, size_t len, EaRequest *r) {
    enum { OP, SLOT, KIND, DATA, PRESENCE, REPLACE, INSTALLATION, FIELD_COUNT };
    const char *names[] = {"op", "slot", "kind", "data", "presence", "replace", "installation_id"};
    char *values[FIELD_COUNT] = {0};
    gboolean seen[FIELD_COUNT] = {0}, boolean[FIELD_COUNT] = {0};
    const char *error = "invalid-request";
    memset(r, 0, sizeof *r);
    if (len > EA_MAX_MESSAGE) return "request-too-large";
    Parser p = {data, len, 0};
    if (!take(&p, '{')) goto done;
    whitespace(&p);
    if (p.pos < p.len && p.bytes[p.pos] != '}') {
        for (;;) {
            char *key = string(&p);
            if (!key) goto done;
            size_t field;
            for (field = 0; field < FIELD_COUNT; field++) if (!strcmp(names[field], key)) break;
            g_free(key);
            if (field == FIELD_COUNT || seen[field] || !take(&p, ':')) goto done;
            seen[field] = TRUE;
            whitespace(&p);
            if (field == PRESENCE || field == REPLACE) {
                if (p.len - p.pos >= 4 && !memcmp(p.bytes + p.pos, "true", 4)) {
                    boolean[field] = TRUE; p.pos += 4;
                } else if (p.len - p.pos >= 5 && !memcmp(p.bytes + p.pos, "false", 5)) p.pos += 5;
                else goto done;
            } else if (!(values[field] = string(&p))) goto done;
            whitespace(&p);
            if (p.pos < p.len && p.bytes[p.pos] == '}') break;
            if (!take(&p, ',')) goto done;
        }
    }
    if (!take(&p, '}')) goto done;
    whitespace(&p);
    if (p.pos != p.len || !seen[OP] || strlen(values[OP]) >= sizeof r->op) goto done;
    strcpy(r->op, values[OP]);
    r->presence = boolean[PRESENCE]; r->replace = boolean[REPLACE];
    gboolean watch = !strcmp(r->op, "watch-session");
    if (watch && (!seen[INSTALLATION] || seen[PRESENCE])) goto done;
    gboolean bare = watch || !strcmp(r->op, "account") || !strcmp(r->op, "initialize") || !strcmp(r->op, "reset");
    gboolean generate = !strcmp(r->op, "generate"), sign = !strcmp(r->op, "sign");
    gboolean wrap = !strcmp(r->op, "wrap-secret"), unwrap = !strcmp(r->op, "unwrap-secret");
    gboolean pub = !strcmp(r->op, "public-key"), contains = !strcmp(r->op, "contains");
    if (!bare && !generate && !sign && !wrap && !unwrap && !pub && !contains && strcmp(r->op, "delete")) goto done;
    if (bare && (seen[SLOT] || seen[KIND])) goto done;
    if (seen[REPLACE] && !generate) goto done;
    if (seen[DATA] != (sign || wrap)) goto done;
    if (r->presence && (pub || contains || !strcmp(r->op, "account"))) goto done;
    if (!bare) {
        if (!seen[SLOT]) goto done;
        size_t n = strlen(values[SLOT]);
        if (!n || n > 64) goto done;
        for (size_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)values[SLOT][i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) goto done;
        }
        strcpy(r->slot, values[SLOT]);
    }
    if (seen[KIND]) {
        if (strcmp(values[KIND], "ed25519") && strcmp(values[KIND], "secret32")) goto done;
        if ((!strcmp(values[KIND], "secret32")) != ea_secret_slot(r->slot)) goto done;
        strcpy(r->kind, values[KIND]);
    } else if (generate) goto done;
    if ((wrap || unwrap) && !ea_secret_slot(r->slot)) goto done;
    if (sign && ea_secret_slot(r->slot)) goto done;
    if (r->replace && (!generate || strcmp(r->slot, "operator-instance") || strcmp(r->kind, "ed25519"))) goto done;
    if (!r->presence && ((sign && strcmp(r->slot, "writer-signing")) || r->replace || !strcmp(r->op, "reset"))) {
        error = "presence-required"; goto done;
    }
    if (seen[DATA] && !ea_unhex(values[DATA], r->data, sizeof r->data, &r->data_len)) goto done;
    if (wrap && r->data_len != 32) goto done;
    if (seen[INSTALLATION]) {
        size_t n;
        if (!ea_unhex(values[INSTALLATION], r->installation, 32, &n) || n != 32) goto done;
        r->has_installation = TRUE;
    }
    error = NULL;
done:
    for (size_t i = 0; i < FIELD_COUNT; i++) if (values[i]) {
        OPENSSL_cleanse(values[i], strlen(values[i])); g_free(values[i]);
    }
    if (error) OPENSSL_cleanse(r, sizeof *r);
    return error;
}

/* A watch continuation has exactly one string member. Reuse the strict JSON
 * decoder: duplicate/escaped duplicate members and trailing data cannot hide
 * behind JSON-GLib's last-member-wins object representation. */
gboolean ea_parse_challenge(const unsigned char *data, size_t len, char challenge[65]) {
    Parser p = {data, len, 0};
    char *key = NULL, *value = NULL;
    gboolean ok = FALSE;
    if (!len || len > EA_WATCH_FRAME_LIMIT || data[len - 1] != '\n' || !take(&p, '{')) goto done;
    key = string(&p);
    if (!key || strcmp(key, "challenge") || !take(&p, ':')) goto done;
    value = string(&p);
    if (!value || strlen(value) != 64 || !take(&p, '}')) goto done;
    for (unsigned i = 0; i < 64; i++) if (nibble((unsigned char)value[i]) < 0) goto done;
    whitespace(&p);
    if (p.pos != p.len) goto done;
    memcpy(challenge, value, 65); ok = TRUE;
done:
    g_free(key); g_free(value);
    return ok;
}
