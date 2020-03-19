/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

static void mem_destructor_em_ssh_cipher_ctx_t(void *data) {
    em_ssh_cipher_ctx_t *cip = data;

#ifdef EM_SSH_USE_MEMORY_CLEARING
    if(cip->iv) {
        explicit_bzero(cip->iv, cip->iv_len);
    }
    if(cip->key) {
        explicit_bzero(cip->key, cip->key_len);
    }
#endif
    em_ssh_mem_deref(cip->key);
    em_ssh_mem_deref(cip->iv);
    em_ssh_mem_deref(cip->cipher);
}

/**
 *
 **/
int em_ssh_cipher_alloc(em_ssh_cipher_ctx_t **ctx, em_ssh_cipher_alg_props_t *cipher_props, bool decrypt) {
    int err = OK;
    em_ssh_cipher_ctx_t *tctx = NULL;

    if(!ctx || !cipher_props) {
        return EINVAL;
    }

    if((tctx = em_ssh_mem_zalloc(sizeof(em_ssh_cipher_ctx_t), mem_destructor_em_ssh_cipher_ctx_t)) == NULL) {
        err = ENOMEM;
        goto out;
    }

    tctx->type = cipher_props->type;
    tctx->mode = cipher_props->mode;
    tctx->key_len = cipher_props->key_len;
    tctx->block_len = cipher_props->block_len;
    tctx->iv_len = tctx->block_len;
    tctx->decrypt = decrypt;

    switch(tctx->type) {
    case EM_SSH_CIPHER_AES: {
        if((err = em_ssh_aes_alloc((void *)&tctx->cipher)) != OK) {
            goto out;
        }
        break;
    }
    default:
        em_ssh_log_warn("unsupported cipher: %i", tctx->type);
        err = EINVAL;
        goto out;
    }

    switch(tctx->mode) {
    case EM_SSH_CIPHER_MODE_CBC: {
        break;
    }
    case EM_SSH_CIPHER_MODE_CTR: {
        break;
    }
    }

    *ctx = tctx;
out:
    if(err != OK) {
        em_ssh_mem_deref(tctx);
    }
    return err;
}

/**
 * ctx must be filled in (key,iv)
 **/
int em_ssh_cipher_init(em_ssh_cipher_ctx_t *ctx) {
    int err = OK;

    if(!ctx) {
        return EINVAL;
    }

    if(ctx->key == NULL || ctx->key_len == 0) {
        em_ssh_log_warn("ctx->key or ctx->key_len invalid");
        return EINVAL;
    }

    if(ctx->type == EM_SSH_CIPHER_AES) {
        em_ssh_aes_ctx_t *aes_ctx = (em_ssh_aes_ctx_t *) ctx->cipher;
        bool decrypt = (ctx->decrypt && ctx->mode == EM_SSH_CIPHER_MODE_CTR) ? false : ctx->decrypt; /* use encrypt for aes/ctr */
        if((err = em_ssh_aes_init(aes_ctx, ctx->key, ctx->key_len, decrypt)) != OK) {
            em_ssh_log_warn("em_ssh_aes_init() failed (%i)", err);
            goto out;
        }
    } else {
        err = EINVAL;
        goto out;
    }

out:
    return err;
}

/**
 * block encrypt
 **/
int em_ssh_cipher_encrypt(em_ssh_cipher_ctx_t *ctx, uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    int i, err = OK;
    uint8_t *tmp = NULL;

    if(!ctx || !in || !out) {
        return EINVAL;
    }
    if(inlen < ctx->block_len || outlen < ctx->block_len) {
        return EINVAL;
    }
    /* CBC */
    if(ctx->mode == EM_SSH_CIPHER_MODE_CBC) {
        for(i = 0; i < ctx->block_len; i++) {
            ctx->iv[i] ^= in[i];
        }
        if(ctx->type == EM_SSH_CIPHER_AES) {
            if((err = em_ssh_aes_process_block((em_ssh_aes_ctx_t *)ctx->cipher, ctx->iv, ctx->block_len, out, ctx->block_len)) != OK) {
                goto out;
            }
            memcpy(ctx->iv, out, ctx->block_len);
        }
        goto out;
    }
    /* CTR */
    if(ctx->mode == EM_SSH_CIPHER_MODE_CTR) {
        if((tmp = em_ssh_mem_zalloc(ctx->block_len, NULL)) == NULL) {
            err = ENOMEM;
            goto out;
        }
        if(ctx->type == EM_SSH_CIPHER_AES) {
            if((err = em_ssh_aes_process_block((em_ssh_aes_ctx_t *)ctx->cipher, ctx->iv, ctx->block_len, tmp, ctx->block_len)) != OK) {
                goto out;
            }
            for(i = 0; i < ctx->block_len; i++) {
                out[i] = in[i] ^ tmp[i];
            }
        }
#ifndef EM_SSH_CONSTANT_TIME_INCREMENT
        for (i = ctx->block_len - 1; i >= 0; i--) {
            if (++ctx->iv[i]) { break; }
        }
#else
        uint8_t x, add = 1;
        for (i = ctx->block_len - 1; i >= 0; i--) {
            ctx->iv[i] += add;
            /* constant time for: x = ctr[i] ? 1 : 0 */
            x = ctx->iv[i];
            x = (x | (x >> 4)) & 0xf;
            x = (x | (x >> 2)) & 0x3;
            x = (x | (x >> 1)) & 0x1;
            add *= (x^1);
        }
#endif
        goto out;
    }
out:
    if(tmp) {
        em_ssh_mem_deref(tmp);
    }
    return err;
}

/**
 * block decrypt
 **/
int em_ssh_cipher_decrypt(em_ssh_cipher_ctx_t *ctx, uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    int i, err = OK;
    uint8_t *tmp = NULL;

    if(!ctx || !in || !out) {
        return EINVAL;
    }
    if(inlen < ctx->block_len || outlen < ctx->block_len) {
        return EINVAL;
    }
    if((tmp = em_ssh_mem_zalloc(ctx->block_len, NULL)) == NULL) {
        err = ENOMEM;
        goto out;
    }
    /* CBC */
    if(ctx->mode == EM_SSH_CIPHER_MODE_CBC) {
        memcpy(tmp, in, ctx->block_len);
        if(ctx->type == EM_SSH_CIPHER_AES) {
            if((err = em_ssh_aes_process_block((em_ssh_aes_ctx_t *)ctx->cipher, in, ctx->block_len, out, ctx->block_len)) != OK) {
                goto out;
            }
        }
        for(i = 0; i < ctx->block_len; i++) {
            out[i] ^= ctx->iv[i];
        }
        memcpy(ctx->iv, tmp, ctx->block_len);
        goto out;
    }
    /* CTR */
    if(ctx->mode == EM_SSH_CIPHER_MODE_CTR) {
        if(ctx->type == EM_SSH_CIPHER_AES) {
            if((err = em_ssh_aes_process_block((em_ssh_aes_ctx_t *)ctx->cipher, ctx->iv, ctx->block_len, tmp, ctx->block_len)) != OK) {
                goto out;
            }
            for(i = 0; i < ctx->block_len; i++) {
                out[i] = in[i] ^ tmp[i];
            }
        }
#ifndef EM_SSH_CONSTANT_TIME_INCREMENT
        for (i = ctx->block_len - 1; i >= 0; i--) {
            if (++ctx->iv[i]) { break; }
        }
#else
        uint8_t x, add = 1;
        for (i = ctx->block_len - 1; i >= 0; i--) {
            ctx->iv[i] += add;
            /* constant time for: x = ctr[i] ? 1 : 0 */
            x = ctx->iv[i];
            x = (x | (x >> 4)) & 0xf;
            x = (x | (x >> 2)) & 0x3;
            x = (x | (x >> 1)) & 0x1;
            add *= (x^1);
        }
#endif
        goto out;
    }
out:
    em_ssh_mem_deref(tmp);
    return err;
}
