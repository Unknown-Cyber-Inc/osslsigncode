#include "outjson.h"
#include "cJSON.h"

/* ----------------- JSON Object globals ----------------- */
static outjson_verify *g_vj = NULL;
static int g_enabled = 0;

void outjson_global_enable(void) { g_enabled = 1; }
int outjson_global_is_enabled(void) { return g_enabled ? 1 : 0; }
outjson_verify *outjson_global_get(void) { return g_vj; }

int outjson_global_begin(void) {
    if (!g_enabled) return 0;
    if (g_vj) return 1;
    g_vj = outjson_verify_new();
    return g_vj ? 1 : 0;
}

void outjson_global_finish_and_print(FILE *fp) {
    if (!g_enabled || !g_vj) return;
    outjson_verify_collect_signature_errors(g_vj);
    outjson_verify_print(g_vj, fp);
    outjson_verify_free(g_vj);
    g_vj = NULL;
    g_enabled = 0;
}

void outjson_global_disable(void) {
    if (g_vj) {
        outjson_verify_free(g_vj);
        g_vj = NULL;
    }
    g_enabled = 0;
}

/* ----------------- Signature globals ----------------- */
static outjson_signature *g_sig_cur = NULL;
static int sig_has_curr = 0;

int outjson_sig_has_curr(void) { return sig_has_curr ? 1: 0; }
outjson_signature *outjson_sig_curr_get(void) { return g_sig_cur; }

void outjson_sig_curr_set(outjson_signature *sig) {
    if (!sig) return;

    if (outjson_sig_has_curr){
        outjson_sig_finish();
    }

    g_sig_cur = sig;
    sig_has_curr = 1;
}

void outjson_sig_finish(void) {
    if (!sig_has_curr || !g_sig_cur) return;
    // free sig?
    g_sig_cur = NULL;
    sig_has_curr = 0;
}


/* ----------------- tiny helpers ----------------- */

static char *xstrdup0(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *p = (char *)malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

static void xfree0(void *p) {
    if (p) free(p);
}

static int arr_push_ptr(void ***arr, size_t *cnt, void *item) {
    size_t n = *cnt + 1;
    void **tmp = (void **)realloc(*arr, n * sizeof(void *));
    if (!tmp) return 0;
    tmp[*cnt] = item;
    *arr = tmp;
    *cnt = n;
    return 1;
}

static int arr_push_str(char ***arr, size_t *cnt, const char *s) {
    char *copy = xstrdup0(s ? s : "");
    if (!copy) return 0;
    if (!arr_push_ptr((void ***)arr, cnt, copy)) {
        free(copy);
        return 0;
    }
    return 1;
}

static void free_str_list(char **arr, size_t cnt) {
    if (!arr) return;
    for (size_t i = 0; i < cnt; i++) free(arr[i]);
    free(arr);
}

static void outjson_error_group_free(outjson_error_group *g)
{
    if (!g) return;
    free_str_list(g->errors, g->errors_count);
    free(g);
}

static char *trim(char *s) {
    if (!s) return s;
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;
    size_t len = strlen(s);
    while (len > 0) {
        char c = s[len - 1];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            s[len - 1] = '\0';
            len--;
        } else {
            break;
        }
    }
    return s;
}

static void set_str(char **dst, const char *src) {
    xfree0(*dst);
    *dst = xstrdup0(src ? src : "");
}

static void set_str_once(char **dst, const char *src) {
    if (*dst && (*dst)[0] != '\0') return;
    set_str(dst, src);
}

static char *make_dedup_key(const outjson_certificate *c) {
    /* Prefer sha256 fingerprint if present */
    if (c && c->fp_sha256 && c->fp_sha256[0] != '\0') {
        size_t n = strlen(c->fp_sha256) + 8;
        char *k = (char *)malloc(n);
        if (!k) return NULL;
        snprintf(k, n, "sha256=%s", c->fp_sha256);
        return k;
    }

    /* Fallback: serial|issuer|subject */
    const char *serial = (c && c->serial) ? c->serial : "";
    const char *issuer = (c && c->issuer) ? c->issuer : "";
    const char *subject = (c && c->subject) ? c->subject : "";

    size_t n = strlen(serial) + strlen(issuer) + strlen(subject) + 3;
    char *k = (char *)malloc(n + 1);
    if (!k) return NULL;
    snprintf(k, n + 1, "%s|%s|%s", serial, issuer, subject);
    return k;
}

static int seen_key(const outjson_verify *vj, const char *key) {
    if (!vj || !key) return 0;
    for (size_t i = 0; i < vj->x509_certs_count; i++) {
        outjson_certificate *c = vj->x509_certs[i];
        if (c && c->dedup_key && strcmp(c->dedup_key, key) == 0) return 1;
    }
    return 0;
}

static outjson_error_group *get_or_create_signature_error_group(outjson_verify *vj, int sig_index)
{
    if (!vj) return NULL;

    for (size_t i = 0; i < vj->signature_errors_count; i++) {
        outjson_error_group *g = vj->signature_errors[i];
        if (g && g->signature_index == sig_index)
            return g;
    }

    outjson_error_group *g = (outjson_error_group *)calloc(1, sizeof(outjson_error_group));
    if (!g) return NULL;
    g->signature_index = sig_index;

    if (!arr_push_ptr((void ***)&vj->signature_errors, &vj->signature_errors_count, g)) {
        outjson_error_group_free(g);
        return NULL;
    }
    return g;
}

/* ----------------- API impl ----------------- */

outjson_verify *outjson_verify_new(void) {
    outjson_verify *vj = (outjson_verify *)calloc(1, sizeof(outjson_verify));
    if (!vj) return NULL;

    vj->pe_checksum = 0;
    return vj;
}

void outjson_verify_free(outjson_verify *vj) {
    if (!vj) return;

    /* signatures */
    if (vj->signatures) {
        for (size_t i = 0; i < vj->signatures_count; i++) {
            outjson_signature *sig = vj->signatures[i];
            if (!sig) continue;

            free_str_list(sig->errors, sig->errors_count);
            free(sig->signers);
            free(sig->countersigners);
            xfree0(sig->digest_algorithm);
            xfree0(sig->digest_encryption_algorithm);
            xfree0(sig->message_digest_current);
            xfree0(sig->message_digest_calculated);
            xfree0(sig->signing_time);
            xfree0(sig->text_description);
            free(sig);
        }
        free(vj->signatures);
    }

    /* global certs */
    if (vj->x509_certs) {
        for (size_t i = 0; i < vj->x509_certs_count; i++) {
            outjson_cert_free(vj->x509_certs[i]);
        }
        free(vj->x509_certs);
    }

    /* signature_errors (grouped) */
    if (vj->signature_errors) {
        for (size_t i = 0; i < vj->signature_errors_count; i++) {
            outjson_error_group_free(vj->signature_errors[i]);
        }
        free(vj->signature_errors);
    }

    free_str_list(vj->errors, vj->errors_count);

    free(vj);
}

/* -------- setters -------- */

void outjson_set_pe_checksum(outjson_verify *vj, uint32_t checksum) {
    if (vj) {
        char checksum_hex[9];
        sprintf(checksum_hex, "%08X", checksum);
        set_str_once(&vj->pe_checksum, checksum_hex);
    }
}
void outjson_set_signed(outjson_verify *vj, int flag) { if (vj) vj->signed_flag = flag ? 1 : 0; }
void outjson_set_valid(outjson_verify *vj, int flag) { if (vj) vj->valid_flag = flag ? 1 : 0; }
void outjson_set_verified_signature_count(outjson_verify *vj, int count) { if (vj) vj->verified_signature_count = count; }

void outjson_add_error(outjson_verify *vj, const char *msg) {
    if (!vj) return;

    (void)arr_push_str(&vj->errors, &vj->errors_count, msg ? msg : "");
}

/* -------- signature -------- */
outjson_signature *outjson_sig_begin(outjson_verify *vj, int index) {
    if (!vj) return NULL;

    /* File has a signature, mark it as signed */
    if (!vj->signed_flag)
        outjson_set_signed(vj, 1);

    outjson_signature *sig = (outjson_signature *)calloc(1, sizeof(outjson_signature));
    if (!sig) return NULL;
    sig->index = index;
    sig->verified = 0;

    if (!arr_push_ptr((void ***)&vj->signatures, &vj->signatures_count, sig)) {
        free(sig);
        return NULL;
    }

    outjson_sig_curr_set(sig);
    return sig;
}

void outjson_sig_set_verified(outjson_signature *sig, int flag) {
    if (!sig) return;
    sig->verified = flag ? 1 : 0;
}

void outjson_sig_add_error(outjson_signature *sig, const char *msg) {
    if (!sig) return;
    (void)arr_push_str(&sig->errors, &sig->errors_count, msg ? msg : "");
}

void outjson_sig_add_openssl_errors(outjson_signature *sig)
{
    unsigned long err;
    char buf[256];

    if (!sig)
        return;

    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        outjson_sig_add_error(sig, buf);
    }
}

void outjson_sig_set_digest_algorithm(outjson_signature *sig, const char *s) {
    if (sig) set_str_once(&sig->digest_algorithm, s);
}

void outjson_sig_set_digest_encryption_algorithm(outjson_signature *sig, const char *s) {
    if (sig) set_str_once(&sig->digest_encryption_algorithm, s);
}

void outjson_sig_set_message_digest_current(outjson_signature *sig, const char *s) {
    if (sig) set_str_once(&sig->message_digest_current, s);
}

void outjson_sig_set_message_digest_calculated(outjson_signature *sig, const char *s) {
    if (sig) set_str_once(&sig->message_digest_calculated, s);
}

void outjson_sig_set_signing_time(outjson_signature *sig, const char *s) {
    if (sig) set_str_once(&sig->signing_time, s);
}

void outjson_sig_set_timestamp_time(outjson_signature *sig, const char *s) {
    if (sig) set_str_once(&sig->signing_time, s);
}

void outjson_sig_set_text_description(outjson_signature *sig, const char *s) {
    if (sig) set_str_once(&sig->text_description, s);
}

void outjson_sig_set_original_signer(outjson_verify *vj, outjson_signature *sig,
                                     outjson_certificate *cert, int add_global) {
    if (!vj || !sig || !cert) return;
    sig->original_signer = cert;
    if (add_global) (void)outjson_add_x509_cert_dedup(vj, cert);
}

void outjson_sig_add_signer(outjson_verify *vj, outjson_signature *sig,
                            outjson_certificate *cert, int add_global) {
    if (!vj || !sig || !cert) return;
    (void)arr_push_ptr((void ***)&sig->signers, &sig->signers_count, cert);
    if (add_global) (void)outjson_add_x509_cert_dedup(vj, cert);
}

void outjson_sig_add_countersigner(outjson_verify *vj, outjson_signature *sig,
                                   outjson_certificate *cert, int add_global) {
    if (!vj || !sig || !cert) return;
    (void)arr_push_ptr((void ***)&sig->countersigners, &sig->countersigners_count, cert);
    if (add_global) (void)outjson_add_x509_cert_dedup(vj, cert);
}

/* ----------------- wrapper functions ----------------- */

void outfmt_ERR_print_errors_fp(FILE *fp)
{
    if (outjson_global_is_enabled() && outjson_sig_has_curr()) {
        outjson_sig_add_openssl_errors(outjson_sig_curr_get());
        return;
    }
    #undef ERR_print_errors_fp
    ERR_print_errors_fp(fp ? fp : stderr);
}

int outfmt_err_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    if (outjson_global_is_enabled()) {
        outjson_verify *vj = outjson_global_get();

        if (vj) {
            va_list ap2;
            va_copy(ap2, ap);

            int needed = vsnprintf(NULL, 0, fmt ? fmt : "", ap2);
            va_end(ap2);

            if (needed < 0) {
                outjson_add_error(vj, "stderr formatting error");
                va_end(ap);
                return 0;
            }

            char *buf = (char *)malloc((size_t)needed + 1);
            if (!buf) {
                outjson_add_error(vj, "stderr OOM");
                va_end(ap);
                return 0;
            }

            vsnprintf(buf, (size_t)needed + 1, fmt ? fmt : "", ap);
            outjson_add_error(vj, buf);
            free(buf);

            va_end(ap);
            return needed;
        }
    }

    #undef fprintf
    int r = vfprintf(stderr, fmt ? fmt : "", ap);
    va_end(ap);
    return r;
}

void outfmt_misc_sigerr_printf(const char *msg, ...)
{
    if (outjson_global_is_enabled() && outjson_sig_has_curr()) {
        char buf[1024];

        va_list ap;
        va_start(ap, msg);
        vsnprintf(buf, sizeof(buf), msg ? msg : "", ap);
        va_end(ap);

        outjson_sig_add_error(outjson_sig_curr_get(), buf);
        return;
    }
}

/* -------- certificate -------- */

outjson_certificate *outjson_cert_new(
    int signer_index,
    const char *subject_cn,
    const char *subject,
    const char *issuer_cn,
    const char *issuer,
    const char *serial,
    const char *signature_algo,
    const char *fp_md5,
    const char *fp_sha1,
    const char *fp_sha256,
    const char *valid_usage,
    const char *not_before,
    const char *not_after
) {
    outjson_certificate *c = (outjson_certificate *)calloc(1, sizeof(outjson_certificate));
    if (!c) return NULL;

    c->signer_index = signer_index;

    c->subject_cn = xstrdup0(subject_cn ? subject_cn : "");
    c->subject = xstrdup0(subject ? subject : "");
    c->issuer_cn = xstrdup0(issuer_cn ? issuer_cn : "");
    c->issuer = xstrdup0(issuer ? issuer : "");
    c->serial = xstrdup0(serial ? serial : "");
    c->signature_algo = xstrdup0(signature_algo ? signature_algo : "");

    c->fp_md5 = xstrdup0(fp_md5 ? fp_md5 : "");
    c->fp_sha1 = xstrdup0(fp_sha1 ? fp_sha1 : "");
    c->fp_sha256 = xstrdup0(fp_sha256 ? fp_sha256 : "");

    c->not_before = xstrdup0(not_before ? not_before : "");
    c->not_after = xstrdup0(not_after ? not_after : "");
    c->valid_usage = xstrdup0(valid_usage ? valid_usage : "");

    if (!c->subject_cn || !c->subject || !c->issuer_cn || !c->issuer || !c->serial ||
        !c->signature_algo || !c->fp_md5 || !c->fp_sha1 || !c->fp_sha256 ||
        !c->not_before || !c->not_after) {
        outjson_cert_free(c);
        return NULL;
    }

    c->dedup_key = make_dedup_key(c);
    if (!c->dedup_key) {
        outjson_cert_free(c);
        return NULL;
    }

    return c;
}

void outjson_cert_free(outjson_certificate *cert) {
    if (!cert) return;

    xfree0(cert->subject_cn);
    xfree0(cert->subject);
    xfree0(cert->issuer_cn);
    xfree0(cert->issuer);
    xfree0(cert->serial);
    xfree0(cert->signature_algo);

    xfree0(cert->fp_md5);
    xfree0(cert->fp_sha1);
    xfree0(cert->fp_sha256);

    xfree0(cert->not_before);
    xfree0(cert->not_after);

    xfree0(cert->valid_usage);

    xfree0(cert->dedup_key);

    free(cert);
}

int outjson_add_x509_cert_dedup(outjson_verify *vj, outjson_certificate *cert) {
    if (!vj || !cert || !cert->dedup_key) return 0;
    if (seen_key(vj, cert->dedup_key)) return 0;
    return arr_push_ptr((void ***)&vj->x509_certs, &vj->x509_certs_count, cert) ? 1 : 0;
}

/* ----------------- serialization ----------------- */

static cJSON *json_cert(const outjson_certificate *c) {
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;

    cJSON_AddNumberToObject(o, "index", c ? c->signer_index : 0);
    cJSON_AddStringToObject(o, "subject_cn", (c && c->subject_cn) ? c->subject_cn : "");
    cJSON_AddStringToObject(o, "subject", (c && c->subject) ? c->subject : "");
    cJSON_AddStringToObject(o, "issuer_cn", (c && c->issuer_cn) ? c->issuer_cn : "");
    cJSON_AddStringToObject(o, "issuer", (c && c->issuer) ? c->issuer : "");
    cJSON_AddStringToObject(o, "serial", (c && c->serial) ? c->serial : "");
    cJSON_AddStringToObject(o, "signature_algo", (c && c->signature_algo) ? c->signature_algo : "");

    cJSON *fps = cJSON_AddArrayToObject(o, "fingerprints");
    if (fps) {
        cJSON *m = cJSON_CreateObject();
        cJSON *s1 = cJSON_CreateObject();
        cJSON *s256 = cJSON_CreateObject();
        if (m && s1 && s256) {
            cJSON_AddStringToObject(m, "md5", (c && c->fp_md5) ? c->fp_md5 : "");
            cJSON_AddStringToObject(s1, "sha1", (c && c->fp_sha1) ? c->fp_sha1 : "");
            cJSON_AddStringToObject(s256, "sha256", (c && c->fp_sha256) ? c->fp_sha256 : "");
            cJSON_AddItemToArray(fps, m);
            cJSON_AddItemToArray(fps, s1);
            cJSON_AddItemToArray(fps, s256);
        } else {
            if (m) cJSON_Delete(m);
            if (s1) cJSON_Delete(s1);
            if (s256) cJSON_Delete(s256);
        }
    }

    cJSON_AddStringToObject(o, "not_before", (c && c->not_before) ? c->not_before : "");
    cJSON_AddStringToObject(o, "not_after", (c && c->not_after) ? c->not_after : "");
    cJSON_AddStringToObject(o, "valid_usage", (c && c->valid_usage ? c->valid_usage : ""));

    return o;
}

static cJSON *json_sig(const outjson_signature *sig) {
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;

    cJSON_AddNumberToObject(o, "index", sig ? sig->index : 0);
    cJSON_AddStringToObject(o, "digest_algorithm", sig->digest_algorithm ? sig->digest_algorithm : "");
    cJSON_AddStringToObject(o, "digest_encryption_algorithm", sig->digest_encryption_algorithm ? sig->digest_encryption_algorithm : "");
    cJSON_AddStringToObject(o, "message_digest_current", sig->message_digest_current ? sig->message_digest_current : "");
    cJSON_AddStringToObject(o, "message_digest_calculated", sig->message_digest_calculated ? sig->message_digest_calculated : "");
    cJSON_AddStringToObject(o, "signing_time", sig->signing_time ? sig->signing_time : "");
    cJSON_AddStringToObject(o, "text_description", sig->text_description ? sig->text_description : "");

    if (sig && sig->original_signer) {
        cJSON_AddItemToObject(o, "original_signer", json_cert(sig->original_signer));
    } else {
        cJSON_AddNullToObject(o, "original_signer");
    }

    cJSON *signers = cJSON_AddArrayToObject(o, "signers");
    if (signers && sig) {
        for (size_t i = 0; i < sig->signers_count; i++) {
            cJSON_AddItemToArray(signers, json_cert(sig->signers[i]));
        }
    }

    cJSON *cs = cJSON_AddArrayToObject(o, "countersigners");
    if (cs && sig) {
        for (size_t i = 0; i < sig->countersigners_count; i++) {
            cJSON_AddItemToArray(cs, json_cert(sig->countersigners[i]));
        }
    }

    cJSON_AddBoolToObject(o, "verified", sig ? sig->verified : 0);

    cJSON *errs = cJSON_AddArrayToObject(o, "errors");
    if (errs && sig) {
        for (size_t i = 0; i < sig->errors_count; i++) {
            cJSON_AddItemToArray(errs, cJSON_CreateString(sig->errors[i] ? sig->errors[i] : ""));
        }
    }

    return o;
}

void outjson_verify_collect_signature_errors(outjson_verify *vj)
{
    if (!vj || !vj->signatures)
        return;

    for (size_t i = 0; i < vj->signatures_count; i++) {
        outjson_signature *sig = vj->signatures[i];
        if (!sig || !sig->errors || sig->errors_count == 0)
            continue;

        outjson_error_group *g = get_or_create_signature_error_group(vj, sig->index);
        if (!g) continue;

        for (size_t j = 0; j < sig->errors_count; j++) {
            const char *msg = sig->errors[j] ? sig->errors[j] : "";
            (void)arr_push_str(&g->errors, &g->errors_count, msg);
        }
    }
}

int outjson_verify_print(const outjson_verify *vj, FILE *fp) {
    if (!vj || !fp) return 0;

    cJSON *root = cJSON_CreateObject();
    if (!root) return 0;

    cJSON_AddStringToObject(root, "pe_checksum", vj->pe_checksum);
    cJSON_AddNumberToObject(root, "verified_signature_count", vj->verified_signature_count);

    cJSON *sigs = cJSON_AddArrayToObject(root, "signatures");
    if (sigs) {
        for (size_t i = 0; i < vj->signatures_count; i++) {
            cJSON_AddItemToArray(sigs, json_sig(vj->signatures[i]));
        }
    }

    cJSON *x509 = cJSON_AddArrayToObject(root, "x509_certs");
    if (x509) {
        for (size_t i = 0; i < vj->x509_certs_count; i++) {
            /* Don't add root certs to the x509 cert list */
            if (strcmp(vj->x509_certs[i]->issuer_cn, vj->x509_certs[i]->subject_cn))
                cJSON_AddItemToArray(x509, json_cert(vj->x509_certs[i]));
        }
    }

    cJSON_AddBoolToObject(root, "signed", vj->signed_flag ? 1 : 0);
    cJSON_AddBoolToObject(root, "valid", vj->valid_flag ? 1 : 0);

    cJSON *sig_errs = cJSON_AddArrayToObject(root, "signature_errors");
    if (sig_errs) {
        for (size_t i = 0; i < vj->signature_errors_count; i++) {
            outjson_error_group *g = vj->signature_errors[i];
            if (!g || !g->errors || g->errors_count == 0)
                continue;

            cJSON *obj = cJSON_CreateObject();
            cJSON *arr = cJSON_CreateArray();
            if (!obj || !arr) {
                if (arr) cJSON_Delete(arr);
                if (obj) cJSON_Delete(obj);
                continue;
            }

            cJSON_AddNumberToObject(obj, "index", g->signature_index);
            for (size_t j = 0; j < g->errors_count; j++) {
                cJSON_AddItemToArray(arr, cJSON_CreateString(g->errors[j] ? g->errors[j] : ""));
            }
            cJSON_AddItemToObject(obj, "errors", arr);
            cJSON_AddItemToArray(sig_errs, obj);
        }
    }

    cJSON *errs = cJSON_AddArrayToObject(root, "cmd_errors");
    if (errs) {
        for (size_t i = 0; i < vj->errors_count; i++) {
            cJSON_AddItemToArray(errs, cJSON_CreateString(vj->errors[i] ? vj->errors[i] : ""));
        }
    }

    char *out = cJSON_PrintUnformatted(root);
    if (!out) {
        cJSON_Delete(root);
        return 0;
    }

    fputs(out, fp);
    fputc('\n', fp);

    free(out);
    cJSON_Delete(root);
    return 1;
}
