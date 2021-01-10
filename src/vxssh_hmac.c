/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

static void mem_destructor_vxssh_hmac_ctx_t(void *data) {
    vxssh_hmac_ctx_t *hmac = data;

#ifdef VXSSH_CLEAR_MEMORY_ON_DEREF
    if(hmac->buf) {
        explicit_bzero(hmac->buf, hmac->buf_len);
    }
#endif
    vxssh_mem_deref(hmac->buf);
    vxssh_mem_deref(hmac->ictx);
    vxssh_mem_deref(hmac->octx);
    vxssh_mem_deref(hmac->digest);
}

/**
 *
 **/
int vxssh_hmac_alloc(vxssh_hmac_ctx_t **ctx, int alg) {
    int err = OK;
    vxssh_hmac_ctx_t *hmac = NULL;

    if(!ctx) {
        return EINVAL;
    }

    if((hmac = vxssh_mem_zalloc(sizeof(vxssh_hmac_ctx_t), mem_destructor_vxssh_hmac_ctx_t)) == NULL) {
        err = ENOMEM;
        goto out;
    }

    if((err = vxssh_digest_alloc(&hmac->ictx, alg)) != OK) {
        goto out;
    }
    if((err = vxssh_digest_alloc(&hmac->octx, alg)) != OK) {
        goto out;
    }
    if((err = vxssh_digest_alloc(&hmac->digest, alg)) != OK) {
        goto out;
    }

    hmac->alg = alg;
    hmac->buf_len = hmac->ictx->block_length;

    if((hmac->buf = vxssh_mem_zalloc(hmac->buf_len, NULL)) == NULL) {
        err = ENOMEM;
        goto out;
    }

    *ctx = hmac;

out:
    if(err != OK) {
        vxssh_mem_deref(hmac);
    }
    return err;
}

/**
 *
 **/
int vxssh_hmac_init(vxssh_hmac_ctx_t *ctx, void *key, size_t klen) {
    int err = OK;
    size_t i;

    if(!ctx) {
        return EINVAL;
    }
    /* reset ictx and octx if no is key given */
    if (key != NULL) {
        if (klen <= ctx->buf_len) {
            memcpy(ctx->buf, key, klen);
        } else {
            if((err = vxssh_digest_memory(ctx->alg, key, klen, ctx->buf, ctx->buf_len)) != OK) {
                return err;
            }
        }
        /* ipad */
        for (i = 0; i < ctx->buf_len; i++) {
            ctx->buf[i] ^= 0x36;
        }
        if ((err = vxssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len)) != OK) {
            return err;
        }
        /* opad */
        for (i = 0; i < ctx->buf_len; i++) {
            ctx->buf[i] ^= 0x36 ^ 0x5c;
        }
        if ((err = vxssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len)) != OK) {
            return err;
        }

        explicit_bzero(ctx->buf, ctx->buf_len);
    }
    /* start with ictx */
    if((err = vxssh_digest_copy_state(ctx->ictx, ctx->digest)) != OK) {
        return err;
    }

    return OK;
}

/**
 *
 **/
int vxssh_hmac_update(vxssh_hmac_ctx_t *ctx, void *m, size_t mlen) {
    return vxssh_digest_update(ctx->digest, m, mlen);
}

/**
 *
 **/
int vxssh_hmac_final(vxssh_hmac_ctx_t *ctx, uint8_t *d, size_t dlen) {
    int err = OK;
    size_t len;

    len = vxssh_digest_bytes(ctx->alg);
    if(dlen < len) {
        return ERANGE;
    }
    if((err = vxssh_digest_final(ctx->digest, ctx->buf, len)) != OK) {
        return err;
    }
    /* switch to octx */
    if((err = vxssh_digest_copy_state(ctx->octx, ctx->digest)) != OK) {
        return err;
    }
    if((err = vxssh_digest_update(ctx->digest, ctx->buf, len)) != OK) {
        return err;
    }
    if((err = vxssh_digest_final(ctx->digest, d, dlen)) != OK) {
        return err;
    }

    return OK;
}

/**
 *
 **/
size_t vxssh_hmac_bytes(int alg) {
    return vxssh_digest_bytes(alg);
}
