/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_HMAC_H
#define EMSSH_HMAC_H
#include <vxWorks.h>
#include "emssh_digest.h"

typedef struct {
    int         alg;
    uint8_t     *buf;
    size_t      buf_len;
    em_ssh_digest_ctx_t *ictx;
    em_ssh_digest_ctx_t *octx;
    em_ssh_digest_ctx_t *digest;
} em_ssh_hmac_ctx_t;

size_t em_ssh_hmac_bytes(int alg);

int em_ssh_hmac_alloc(em_ssh_hmac_ctx_t **ctx, int alg);
int em_ssh_hmac_init(em_ssh_hmac_ctx_t *ctx, void *key, size_t klen);
int em_ssh_hmac_update(em_ssh_hmac_ctx_t *ctx, void *m, size_t mlen);
int em_ssh_hmac_final(em_ssh_hmac_ctx_t *ctx, uint8_t *d, size_t dlen);


#endif

