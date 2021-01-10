/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"
#include "vxssh_crypto.h"

static void destructor_vxssh_digest_ctx_t(void *data) {
    vxssh_digest_ctx_t *md = data;

#ifdef VXSSH_CLEAR_MEMORY_ON_DEREF
    switch(md->alg) {
        case VXSSH_DIGEST_MD5 : {
            vxssh_md5_ctx_t *mdctx = (vxssh_md5_ctx_t *)md->ctx;
            if(mdctx) explicit_bzero(mdctx, vxssh_md5_ctx_size());
            break;
        }
        case VXSSH_DIGEST_SHA1 : {
            vxssh_sha1_ctx_t *mdctx = (vxssh_sha1_ctx_t *)md->ctx;
            if(mdctx) explicit_bzero(mdctx, vxssh_sha1_ctx_size());
            break;
        }
        case VXSSH_DIGEST_SHA256 : {
            vxssh_sha256_ctx_t *mdctx = (vxssh_sha256_ctx_t *)md->ctx;
            if(mdctx) explicit_bzero(mdctx, vxssh_sha256_ctx_size());
            break;
        }
    }
#endif
    vxssh_mem_deref(md->ctx);
}

/**
 *
 **/
int vxssh_digest_alloc(vxssh_digest_ctx_t **ctx, int alg) {
    int err = OK;
    vxssh_digest_ctx_t *tctx = NULL;

    if(!ctx) {
        return EINVAL;
    }

    tctx = vxssh_mem_alloc(sizeof(vxssh_digest_ctx_t), destructor_vxssh_digest_ctx_t);
    if(tctx == NULL) {
        err = ENOMEM;
        goto out;
    }
    tctx->alg = alg;
    switch(tctx->alg) {
        case VXSSH_DIGEST_MD5 : {
            tctx->digest_len = vxssh_md5_digest_len();
            tctx->block_length = vxssh_md5_block_len();
            if((err = vxssh_md5_init((void *)&tctx->ctx)) != OK) {
                goto out;
            }
            break;
        }
        case VXSSH_DIGEST_SHA1 : {
            tctx->digest_len = vxssh_sha1_digest_len();
            tctx->block_length = vxssh_sha1_block_len();
            if((err = vxssh_sha1_init((void *)&tctx->ctx)) != OK) {
                goto out;
            }
            break;
        }
        case VXSSH_DIGEST_SHA256 : {
            tctx->digest_len = vxssh_sha256_digest_len();
            tctx->block_length = vxssh_sha256_block_len();
            if((err = vxssh_sha256_init((void *)&tctx->ctx)) != OK) {
                goto out;
            }
            break;
        }
        default:
            vxssh_log_warn("unknown digest: %i", alg);
            err = EINVAL;
            goto out;
    }
    *ctx = tctx;
out:
    if(err != OK) {
        vxssh_mem_deref(tctx);
    }
    return err;
}

/**
 *
 **/
int vxssh_digest_update(vxssh_digest_ctx_t *ctx, void *data, size_t data_len) {
    int err = OK;

    if(!ctx || !data) {
        return EINVAL;
    }
    switch(ctx->alg) {
        case VXSSH_DIGEST_MD5 : {
            vxssh_md5_ctx_t *mdctx = (vxssh_md5_ctx_t *)ctx->ctx;
            err = vxssh_md5_update(mdctx, data, data_len);
            break;
        }
        case VXSSH_DIGEST_SHA1 : {
            vxssh_sha1_ctx_t *mdctx = (vxssh_sha1_ctx_t *)ctx->ctx;
            err = vxssh_sha1_update(mdctx, data, data_len);
            break;
        }
        case VXSSH_DIGEST_SHA256 : {
            vxssh_sha256_ctx_t *mdctx = (vxssh_sha256_ctx_t *)ctx->ctx;
            err = vxssh_sha256_update(mdctx, data, data_len);
            break;
        }
        default:
            err = EINVAL;
    }
    return err;
}

/**
 *
 **/
int vxssh_digest_final(vxssh_digest_ctx_t *ctx, uint8_t *digest, size_t digest_len) {
    int err = OK;

    if(!ctx || !digest) {
        return EINVAL;
    }
    if(digest_len < ctx->digest_len) {
        return ERANGE;
    }
    switch(ctx->alg) {
        case VXSSH_DIGEST_MD5 : {
            vxssh_md5_ctx_t *mdctx = (vxssh_md5_ctx_t *)ctx->ctx;
            err = vxssh_md5_final(mdctx, digest);
            break;
        }
        case VXSSH_DIGEST_SHA1 : {
            vxssh_sha1_ctx_t *mdctx = (vxssh_sha1_ctx_t *)ctx->ctx;
            err = vxssh_sha1_final(mdctx, digest);
            break;
        }
        case VXSSH_DIGEST_SHA256 : {
            vxssh_sha256_ctx_t *mdctx = (vxssh_sha256_ctx_t *)ctx->ctx;
            err = vxssh_sha256_final(mdctx, digest);
            break;
        }
        default:
            err = EINVAL;
    }
    return err;
}

/**
 *
 **/
int vxssh_digest_copy_state(vxssh_digest_ctx_t *from, vxssh_digest_ctx_t *to) {
    int err = OK;

    if(!from || !to || from->alg != to->alg) {
        return EINVAL;
    }

    switch(from->alg) {
        case VXSSH_DIGEST_MD5 : {
            vxssh_md5_ctx_t *sctx = (vxssh_md5_ctx_t *)from->ctx;
            vxssh_md5_ctx_t *dctx = (vxssh_md5_ctx_t *)to->ctx;
            size_t sz  = vxssh_md5_ctx_size();
            explicit_bzero(dctx, sz);
            memcpy(dctx, sctx, sz);
            break;
        }
        case VXSSH_DIGEST_SHA1 : {
            vxssh_sha1_ctx_t *sctx = (vxssh_sha1_ctx_t *)from->ctx;
            vxssh_sha1_ctx_t *dctx = (vxssh_sha1_ctx_t *)to->ctx;
            size_t sz  = vxssh_sha1_ctx_size();
            explicit_bzero(dctx, sz);
            memcpy(dctx, sctx, sz);
            break;
        }
        case VXSSH_DIGEST_SHA256 : {
            vxssh_sha256_ctx_t *sctx = (vxssh_sha256_ctx_t *)from->ctx;
            vxssh_sha256_ctx_t *dctx = (vxssh_sha256_ctx_t *)to->ctx;
            size_t sz  = vxssh_sha256_ctx_size();
            explicit_bzero(dctx, sz);
            memcpy(dctx, sctx, sz);
            break;
        }
        default:
            err = EINVAL;
    }

    return err;
}

/**
 *
 **/
size_t vxssh_digest_bytes(int alg) {

    switch(alg) {
        case VXSSH_DIGEST_MD5 :
            return vxssh_md5_digest_len();

        case VXSSH_DIGEST_SHA1 :
            return vxssh_sha1_digest_len();

        case VXSSH_DIGEST_SHA256 :
            return vxssh_sha256_digest_len();
    }

    return 0;
}

/**
 *
 **/
size_t vxssh_digest_block_size(int alg) {

    switch(alg) {
        case VXSSH_DIGEST_MD5 :
            return vxssh_md5_block_len();

        case VXSSH_DIGEST_SHA1 :
            return vxssh_sha1_block_len();

        case VXSSH_DIGEST_SHA256 :
            return vxssh_sha256_block_len();
    }

    return 0;
}

/**
 *
 **/

int vxssh_digest_memory(int alg, const void *m, size_t mlen, u_char *d, size_t dlen) {

    if(!m || !d) {
        return EINVAL;
    }

    switch(alg) {
        case VXSSH_DIGEST_MD5 :
            return vxssh_md5_digest(m, mlen, d, dlen);

        case VXSSH_DIGEST_SHA1 :
            return vxssh_sha1_digest(m, mlen, d, dlen);

        case VXSSH_DIGEST_SHA256 :
            return vxssh_sha256_digest(m, mlen, d, dlen);
    }

    return ERROR;
}
