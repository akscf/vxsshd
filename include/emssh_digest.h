/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_DIGEST_H
#define EMSSH_DIGEST_H

#include <vxWorks.h>
#include "emssh_ctype.h"

#define EM_SSH_DIGEST_MD5       0
#define EM_SSH_DIGEST_SHA1      1
#define EM_SSH_DIGEST_SHA256    2

#define EM_SSH_DIGEST_MD5_LENGTH    16
#define EM_SSH_DIGEST_SHA1_LENGTH   20
#define EM_SSH_DIGEST_SHA256_LENGTH 32
#define EM_SSH_DIGEST_LENGTH_MAX    64

/* ------------------------------------------------------------------------------------------ */
struct _MD5_CTX;
typedef struct _MD5_CTX em_ssh_md5_ctx_t;

size_t em_ssh_md5_digest_len();
size_t em_ssh_md5_block_len();
size_t em_ssh_md5_ctx_size();
int em_ssh_md5_init(em_ssh_md5_ctx_t **ctx);
int em_ssh_md5_update(em_ssh_md5_ctx_t *ctx, const void *data, size_t data_size);
int em_ssh_md5_digest(const void *input, size_t input_len, uint8_t *digest, size_t digest_len);

/* ------------------------------------------------------------------------------------------ */
struct _SHA1_CTX;
typedef struct _SHA1_CTX em_ssh_sha1_ctx_t;

size_t em_ssh_sha1_digest_len();
size_t em_ssh_sha1_block_len();
size_t em_ssh_sha1_ctx_size();
int em_ssh_sha1_init(em_ssh_sha1_ctx_t **ctx);
int em_ssh_sha1_update(em_ssh_sha1_ctx_t *ctx, const void *data, size_t data_size);
int em_ssh_sha1_final(em_ssh_sha1_ctx_t *ctx, uint8_t *digest);
int em_ssh_sha1_digest(const void *input, size_t input_len, uint8_t *digest, size_t digest_len);

/* ------------------------------------------------------------------------------------------ */
struct _SHA256_CTX;
typedef struct _SHA256_CTX em_ssh_sha256_ctx_t;

size_t em_ssh_sha256_digest_len();
size_t em_ssh_sha256_block_len();
size_t em_ssh_sha256_ctx_size();
int em_ssh_sha256_init(em_ssh_sha256_ctx_t **ctx);
int em_ssh_sha256_update(em_ssh_sha256_ctx_t *ctx, const void *data, size_t data_size);
int em_ssh_sha256_final(em_ssh_sha256_ctx_t *ctx, uint8_t *digest);
int em_ssh_sha256_digest(const void *input, size_t input_len, uint8_t *digest, size_t digest_len);

/* ------------------------------------------------------------------------------------------ */
typedef struct {
    int     alg;
    size_t  digest_len;
    size_t  block_length;
    void    *ctx;
} em_ssh_digest_ctx_t;

size_t em_ssh_digest_bytes(int alg);
size_t em_ssh_digest_block_size(int alg);

int em_ssh_digest_alloc(em_ssh_digest_ctx_t **ctx, int alg);
int em_ssh_digest_update(em_ssh_digest_ctx_t *ctx, void *data, size_t data_len);
int em_ssh_digest_final(em_ssh_digest_ctx_t *ctx, uint8_t *digest, size_t digest_len);
int em_ssh_digest_memory(int alg, const void *m, size_t mlen, uint8_t *d, size_t dlen);
int em_ssh_digest_copy_state(em_ssh_digest_ctx_t *from, em_ssh_digest_ctx_t *to);


#endif

