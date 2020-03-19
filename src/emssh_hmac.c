/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

static void mem_destructor_em_ssh_hmac_ctx_t(void *data) {
    em_ssh_hmac_ctx_t *hmac = data;

#ifdef EM_SSH_USE_MEMORY_CLEARING
    if(hmac->buf) {
        explicit_bzero(hmac->buf, hmac->buf_len);
    }
#endif
    em_ssh_mem_deref(hmac->buf);
    em_ssh_mem_deref(hmac->ictx);
    em_ssh_mem_deref(hmac->octx);
    em_ssh_mem_deref(hmac->digest);
}

/**
 *
 **/
int em_ssh_hmac_alloc(em_ssh_hmac_ctx_t **ctx, int alg) {
    int err = OK;
    em_ssh_hmac_ctx_t *hmac = NULL;

    if(!ctx) {
        return EINVAL;
    }

    if((hmac = em_ssh_mem_zalloc(sizeof(em_ssh_hmac_ctx_t), mem_destructor_em_ssh_hmac_ctx_t)) == NULL) {
        err = ENOMEM;
        goto out;
    }

    if((err = em_ssh_digest_alloc(&hmac->ictx, alg)) != OK) {
        goto out;
    }
    if((err = em_ssh_digest_alloc(&hmac->octx, alg)) != OK) {
        goto out;
    }
    if((err = em_ssh_digest_alloc(&hmac->digest, alg)) != OK) {
        goto out;
    }

    hmac->alg = alg;
    hmac->buf_len = hmac->ictx->block_length;

    if((hmac->buf = em_ssh_mem_zalloc(hmac->buf_len, NULL)) == NULL) {
        err = ENOMEM;
        goto out;
    }

    *ctx = hmac;

out:
    if(err != OK) {
        em_ssh_mem_deref(hmac);
    }
    return err;
}

/**
 *
 **/
int em_ssh_hmac_init(em_ssh_hmac_ctx_t *ctx, void *key, size_t klen) {
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
            if((err = em_ssh_digest_memory(ctx->alg, key, klen, ctx->buf, ctx->buf_len)) != OK) {
                return err;
            }
        }
        /* ipad */
        for (i = 0; i < ctx->buf_len; i++) {
            ctx->buf[i] ^= 0x36;
        }
        if ((err = em_ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len)) != OK) {
            return err;
        }
        /* opad */
        for (i = 0; i < ctx->buf_len; i++) {
            ctx->buf[i] ^= 0x36 ^ 0x5c;
        }
        if ((err = em_ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len)) != OK) {
            return err;
        }

        explicit_bzero(ctx->buf, ctx->buf_len);
    }
    /* start with ictx */
    if((err = em_ssh_digest_copy_state(ctx->ictx, ctx->digest)) != OK) {
        return err;
    }

    return OK;
}

/**
 *
 **/
int em_ssh_hmac_update(em_ssh_hmac_ctx_t *ctx, void *m, size_t mlen) {
    return em_ssh_digest_update(ctx->digest, m, mlen);
}

/**
 *
 **/
int em_ssh_hmac_final(em_ssh_hmac_ctx_t *ctx, uint8_t *d, size_t dlen) {
    int err = OK;
    size_t len;

    len = em_ssh_digest_bytes(ctx->alg);
    if(dlen < len) {
        return ERANGE;
    }
    if((err = em_ssh_digest_final(ctx->digest, ctx->buf, len)) != OK) {
        return err;
    }
    /* switch to octx */
    if((err = em_ssh_digest_copy_state(ctx->octx, ctx->digest)) != OK) {
        return err;
    }
    if((err = em_ssh_digest_update(ctx->digest, ctx->buf, len)) != OK) {
        return err;
    }
    if((err = em_ssh_digest_final(ctx->digest, d, dlen)) != OK) {
        return err;
    }

    return OK;
}

/**
 *
 **/
size_t em_ssh_hmac_bytes(int alg) {
    return em_ssh_digest_bytes(alg);
}
