/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_HMAC_H
#define VXSSH_HMAC_H
#include <vxWorks.h>
#include "vxssh_digest.h"

typedef struct {
    int         alg;
    uint8_t     *buf;
    size_t      buf_len;
    vxssh_digest_ctx_t *ictx;
    vxssh_digest_ctx_t *octx;
    vxssh_digest_ctx_t *digest;
} vxssh_hmac_ctx_t;

size_t vxssh_hmac_bytes(int alg);

int vxssh_hmac_alloc(vxssh_hmac_ctx_t **ctx, int alg);
int vxssh_hmac_init(vxssh_hmac_ctx_t *ctx, void *key, size_t klen);
int vxssh_hmac_update(vxssh_hmac_ctx_t *ctx, void *m, size_t mlen);
int vxssh_hmac_final(vxssh_hmac_ctx_t *ctx, uint8_t *d, size_t dlen);


#endif

