#ifndef OSSL_SIGNCODE_OUTJSON_H
#define OSSL_SIGNCODE_OUTJSON_H

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <openssl/err.h>

#define ERR_print_errors_fp(fp) outfmt_ERR_print_errors_fp((fp))

typedef struct outjson_certificate_st {
    int signer_index;
    char *subject_cn;
    char *subject;
    char *issuer_cn;
    char *issuer;
    char *serial;
    char *signature_algo;
    char *fp_md5;
    char *fp_sha1;
    char *fp_sha256;
    char *not_before;
    char *not_after;
    char *valid_usage;
    char *dedup_key;
} outjson_certificate;

typedef struct outjson_error_group_st {
    int signature_index;
    char **errors;
    size_t errors_count;
} outjson_error_group;

typedef struct outjson_signature_st {
    int index;
    char *digest_algorithm;
    char *digest_encryption_algorithm;
    char *message_digest_current;
    char *message_digest_calculated;
    char *signing_time;
    char *text_description;
    outjson_certificate *original_signer;
    outjson_certificate **signers;
    size_t signers_count;
    outjson_certificate **countersigners;
    size_t countersigners_count;
    int verified;
    char **errors;
    size_t errors_count;
} outjson_signature;

typedef struct outjson_verify_st {
    char *pe_checksum;
    int verified_signature_count;
    outjson_signature **signatures;
    size_t signatures_count;
    outjson_certificate **x509_certs;
    size_t x509_certs_count;
    int signed_flag;
    int valid_flag;
    outjson_error_group **signature_errors;
    size_t signature_errors_count;
    char **errors;
    size_t errors_count;
} outjson_verify;


/* -------- Global-mode helpers -------- */

void outjson_global_enable(void);
int  outjson_global_is_enabled(void);
outjson_verify *outjson_global_get(void);
int  outjson_global_begin(void);
void outjson_global_finish_and_print(FILE *fp);
void outjson_global_disable(void);

/* -------- Current signature globals -------- */

outjson_signature *outjson_sig_curr_get(void);
int outjson_sig_has_curr(void);
void outjson_sig_curr_set(outjson_signature *sig);
void outjson_sig_finish(void);

/* -------- lifecycle -------- */

outjson_verify *outjson_verify_new(void);
void outjson_verify_free(outjson_verify *vj);
void outjson_verify_collect_signature_errors(outjson_verify *vj);
int outjson_verify_print(const outjson_verify *vj, FILE *fp);

/* -------- top-level setters (strings are copied) -------- */

void outjson_set_pe_checksum(outjson_verify *vj, uint32_t checksum);
void outjson_set_signed(outjson_verify *vj, int flag);
void outjson_set_valid(outjson_verify *vj, int flag);
void outjson_set_verified_signature_count(outjson_verify *vj, int count);
void outjson_add_error(outjson_verify *vj, const char *msg);

/* -------- signature creation / mutation -------- */

outjson_signature *outjson_sig_begin(outjson_verify *vj, int index);
void outjson_sig_set_digest_algorithm(outjson_signature *sig, const char *s);
void outjson_sig_set_digest_encryption_algorithm(outjson_signature *sig, const char *s);
void outjson_sig_set_message_digest_current(outjson_signature *sig, const char *s);
void outjson_sig_set_message_digest_calculated(outjson_signature *sig, const char *s);
void outjson_sig_set_signing_time(outjson_signature *sig, const char *s);
void outjson_sig_set_timestamp_time(outjson_signature *sig, const char *s);
void outjson_sig_set_text_description(outjson_signature *sig, const char *s);
void outjson_sig_set_verified(outjson_signature *sig, int flag);
void outjson_sig_add_error(outjson_signature *sig, const char *msg);
void outjson_sig_add_openssl_errors(outjson_signature *sig);
void outjson_sig_set_original_signer(outjson_verify *vj, outjson_signature *sig,
                                     outjson_certificate *cert, int add_global);
void outjson_sig_add_signer(outjson_verify *vj, outjson_signature *sig,
                            outjson_certificate *cert, int add_global);
void outjson_sig_add_countersigner(outjson_verify *vj, outjson_signature *sig,
                                   outjson_certificate *cert, int add_global);

/* -------- JSON capture wrapper for ERR_print_errors_fp -------- */

void outfmt_ERR_print_errors_fp(FILE *fp);

/* -------- JSON capture wrapper for fprintf(stderr, "...") -------- */

int outfmt_err_printf(const char *fmt, ...); /* stderr wrapper */
#define fprintf(stream, ...) \
    ((stream) == stderr ? outfmt_err_printf(__VA_ARGS__) \
                         : fprintf(stream, __VA_ARGS__))

/* -------- JSON capture wrapper for misc err outputs that use printf("...") -------- */

void outfmt_misc_sigerr_printf(const char *msg, ...);

/* -------- certificate creation -------- */

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
);

void outjson_cert_free(outjson_certificate *cert);
int outjson_add_x509_cert_dedup(outjson_verify *vj, outjson_certificate *cert);

#endif /* OSSL_SIGNCODE_OUTJSON_H */
