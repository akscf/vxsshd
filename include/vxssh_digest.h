/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_DIGEST_H
#define VXSSH_DIGEST_H

#include <vxWorks.h>
#include "vxssh_ctype.h"

#define VXSSH_DIGEST_MD5       0
#define VXSSH_DIGEST_SHA1      1
#define VXSSH_DIGEST_SHA256    2

#define VXSSH_DIGEST_MD5_LENGTH    16
#define VXSSH_DIGEST_SHA1_LENGTH   20
#define VXSSH_DIGEST_SHA256_LENGTH 32
#define VXSSH_DIGEST_LENGTH_MAX    64

/* ------------------------------------------------------------------------------------------ */
struct _MD5_CTX;
typedef struct _MD5_CTX vxssh_md5_ctx_t;

size_t vxssh_md5_digest_len();
size_t vxssh_md5_block_len();
size_t vxssh_md5_ctx_size();
int vxssh_md5_init(vxssh_md5_ctx_t **ctx);
int vxssh_md5_update(vxssh_md5_ctx_t *ctx, const void *data, size_t data_size);
int vxssh_md5_digest(const void *input, size_t input_len, uint8_t *digest, size_t digest_len);

/* ------------------------------------------------------------------------------------------ */
struct _SHA1_CTX;
typedef struct _SHA1_CTX vxssh_sha1_ctx_t;

size_t vxssh_sha1_digest_len();
size_t vxssh_sha1_block_len();
size_t vxssh_sha1_ctx_size();
int vxssh_sha1_init(vxssh_sha1_ctx_t **ctx);
int vxssh_sha1_update(vxssh_sha1_ctx_t *ctx, const void *data, size_t data_size);
int vxssh_sha1_final(vxssh_sha1_ctx_t *ctx, uint8_t *digest);
int vxssh_sha1_digest(const void *input, size_t input_len, uint8_t *digest, size_t digest_len);

/* ------------------------------------------------------------------------------------------ */
struct _SHA256_CTX;
typedef struct _SHA256_CTX vxssh_sha256_ctx_t;

size_t vxssh_sha256_digest_len();
size_t vxssh_sha256_block_len();
size_t vxssh_sha256_ctx_size();
int vxssh_sha256_init(vxssh_sha256_ctx_t **ctx);
int vxssh_sha256_update(vxssh_sha256_ctx_t *ctx, const void *data, size_t data_size);
int vxssh_sha256_final(vxssh_sha256_ctx_t *ctx, uint8_t *digest);
int vxssh_sha256_digest(const void *input, size_t input_len, uint8_t *digest, size_t digest_len);

/* ------------------------------------------------------------------------------------------ */
typedef struct {
    int     alg;
    size_t  digest_len;
    size_t  block_length;
    void    *ctx;
} vxssh_digest_ctx_t;

size_t vxssh_digest_bytes(int alg);
size_t vxssh_digest_block_size(int alg);

int vxssh_digest_alloc(vxssh_digest_ctx_t **ctx, int alg);
int vxssh_digest_update(vxssh_digest_ctx_t *ctx, void *data, size_t data_len);
int vxssh_digest_final(vxssh_digest_ctx_t *ctx, uint8_t *digest, size_t digest_len);
int vxssh_digest_memory(int alg, const void *m, size_t mlen, uint8_t *d, size_t dlen);
int vxssh_digest_copy_state(vxssh_digest_ctx_t *from, vxssh_digest_ctx_t *to);


#endif

