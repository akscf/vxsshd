/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_MAC_H
#define EMSSH_MAC_H
#include <vxWorks.h>
#include "emssh_hmac.h"

#define EM_SSH_MAC_DIGEST   1

typedef struct {
    int         type;
    uint8_t     *key;
    size_t      key_len;
    size_t      mac_len;
    int         etm;
    em_ssh_hmac_ctx_t *hmac_ctx;
} em_ssh_mac_ctx_t;


int em_ssh_mac_alloc(em_ssh_mac_ctx_t **ctx, em_ssh_mac_alg_props_t *mac_props);
int em_ssh_mac_init(em_ssh_mac_ctx_t *ctx);
int em_ssh_mac_compute(em_ssh_mac_ctx_t *ctx, uint32_t seqno, const uint8_t *data, size_t datalen, uint8_t *digest, size_t dlen);
int em_ssh_mac_check(em_ssh_mac_ctx_t *ctx, uint32_t seqno, const uint8_t *data, size_t dlen, const uint8_t *theirmac, size_t mlen);

#endif

