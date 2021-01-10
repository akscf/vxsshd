/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_MAC_H
#define VXSSH_MAC_H
#include <vxWorks.h>
#include "vxssh_hmac.h"

#define VXSSH_MAC_DIGEST   1

typedef struct {
    int         type;
    uint8_t     *key;
    size_t      key_len;
    size_t      mac_len;
    int         etm;
    vxssh_hmac_ctx_t *hmac_ctx;
} vxssh_mac_ctx_t;


int vxssh_mac_alloc(vxssh_mac_ctx_t **ctx, vxssh_mac_alg_props_t *mac_props);
int vxssh_mac_init(vxssh_mac_ctx_t *ctx);
int vxssh_mac_compute(vxssh_mac_ctx_t *ctx, uint32_t seqno, const uint8_t *data, size_t datalen, uint8_t *digest, size_t dlen);
int vxssh_mac_check(vxssh_mac_ctx_t *ctx, uint32_t seqno, const uint8_t *data, size_t dlen, const uint8_t *theirmac, size_t mlen);

#endif

