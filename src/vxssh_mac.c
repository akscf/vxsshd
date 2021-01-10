/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

static void mem_destructor_vxssh_mac_ctx_t(void *data) {
    vxssh_mac_ctx_t *mac = data;

#ifdef VXSSH_CLEAR_MEMORY_ON_DEREF
    if(mac->key) {
        explicit_bzero(mac->key, mac->key_len);
    }
#endif
    vxssh_mem_deref(mac->key);
    vxssh_mem_deref(mac->hmac_ctx);
}


/**
 *
 **/
int vxssh_mac_alloc(vxssh_mac_ctx_t **ctx, vxssh_mac_alg_props_t *mac_props) {
    int err = OK;
    vxssh_mac_ctx_t *mac = NULL;

    if(!ctx || !mac_props) {
        return EINVAL;
    }

    if((mac = vxssh_mem_zalloc(sizeof(vxssh_mac_ctx_t), mem_destructor_vxssh_mac_ctx_t)) == NULL) {
        err = ENOMEM;
        goto out;
    }

    mac->type = mac_props->mac_type;

    switch(mac->type) {
        case VXSSH_MAC_DIGEST: {
            err = vxssh_hmac_alloc(&mac->hmac_ctx, mac_props->mac_alg);
            if(err != OK) {
                goto out;
            }
            mac->key_len = vxssh_hmac_bytes(mac_props->mac_alg);
            mac->mac_len = vxssh_hmac_bytes(mac_props->mac_alg);
            break;
        }
        default:
            vxssh_log_error("unsupported mac: %i", mac->type);
            err = EINVAL;
            goto out;
    }

    if (mac_props->truncatebits != 0) {
        mac->mac_len = mac_props->truncatebits / 8;
        mac->etm = mac_props->etm;
    }

    *ctx = mac;

out:
    if(err != OK) {
        vxssh_mem_deref(mac);
    }
    return err;
}

/**
 * ctx must be filled in
 **/
int vxssh_mac_init(vxssh_mac_ctx_t *ctx) {
    int err = OK;

    if(!ctx) {
        return EINVAL;
    }

    switch (ctx->type) {
        case VXSSH_MAC_DIGEST: {
            if(ctx->hmac_ctx == NULL) {
                vxssh_log_warn("ctx->hmac_ctx == null");
                err = ERROR;
                goto out;
            }
            if((err = vxssh_hmac_init(ctx->hmac_ctx, ctx->key, ctx->key_len)) != OK) {
                goto out;
            }
            break;
    }
    default:
        return EINVAL;
    }
out:
    return err;
}

/**
 *
 **/
int vxssh_mac_compute(vxssh_mac_ctx_t *ctx, uint32_t seqno, const uint8_t *data, size_t datalen, uint8_t *digest, size_t dlen) {
    uint8_t m[VXSSH_DIGEST_LENGTH_MAX];
    uint8_t b[4];
    int err = OK;

    if (ctx->mac_len > sizeof(m)) {
        vxssh_log_warn("ctx->mac_len > sizeof(u)");
        return ERROR;
    }

    switch (ctx->type) {
        case VXSSH_MAC_DIGEST: {
            /* seqno */
            b[0] = (uint8_t)(seqno >> 24) & 0xff;
            b[1] = (uint8_t)(seqno >> 16) & 0xff;
            b[2] = (uint8_t)(seqno >> 8) & 0xff;
            b[3] = (uint8_t)seqno & 0xff;
            /* reset HMAC context */
            if((err = vxssh_hmac_init(ctx->hmac_ctx, NULL, 0)) != OK) {
                goto out;
            }
            if((err = vxssh_hmac_update(ctx->hmac_ctx, b, sizeof(b))) != OK) {
                goto out;
            }
            if((err = vxssh_hmac_update(ctx->hmac_ctx, (void *) data, datalen)) != OK) {
                goto out;
            }
            if((err = vxssh_hmac_final(ctx->hmac_ctx, m, sizeof(m))) != OK) {
                goto out;
            }
            break;
        }
        default:
            return EINVAL;
    }

    if (digest != NULL) {
        if (dlen > ctx->mac_len) { dlen = ctx->mac_len; }
        memcpy(digest, m, dlen);
    }
out:
    return err;
}

/**
 *
 **/
int vxssh_mac_check(vxssh_mac_ctx_t *ctx, uint32_t seqno, const uint8_t *data, size_t dlen, const uint8_t *theirmac, size_t mlen) {
    uint8_t ourmac[VXSSH_DIGEST_LENGTH_MAX];
    int err = OK;

    if (ctx->mac_len > mlen) {
        return EINVAL;
    }

    if((err = vxssh_mac_compute(ctx, seqno, data, dlen, ourmac, sizeof(ourmac))) != OK) {
        return err;
    }

    if(timingsafe_bcmp(ourmac, theirmac, ctx->mac_len) != 0) {
        return VXSSH_ERR_MAC_MISMATCH;
    }

    return OK;
}
