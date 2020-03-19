/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"
#include "emssh_crypto.h"

static void destructor_em_ssh_digest_ctx_t(void *data) {
    em_ssh_digest_ctx_t *md = data;

#ifdef EM_SSH_USE_MEMORY_CLEARING
    switch(md->alg) {
        case EM_SSH_DIGEST_MD5 : {
            em_ssh_md5_ctx_t *mdctx = (em_ssh_md5_ctx_t *)md->ctx;
            if(mdctx) explicit_bzero(mdctx, em_ssh_md5_ctx_size());
            break;
        }
        case EM_SSH_DIGEST_SHA1 : {
            em_ssh_sha1_ctx_t *mdctx = (em_ssh_sha1_ctx_t *)md->ctx;
            if(mdctx) explicit_bzero(mdctx, em_ssh_sha1_ctx_size());
            break;
        }
        case EM_SSH_DIGEST_SHA256 : {
            em_ssh_sha256_ctx_t *mdctx = (em_ssh_sha256_ctx_t *)md->ctx;
            if(mdctx) explicit_bzero(mdctx, em_ssh_sha256_ctx_size());
            break;
        }
    }
#endif
    em_ssh_mem_deref(md->ctx);
}

/**
 *
 **/
int em_ssh_digest_alloc(em_ssh_digest_ctx_t **ctx, int alg) {
    int err = OK;
    em_ssh_digest_ctx_t *tctx = NULL;

    if(!ctx) {
        return EINVAL;
    }

    tctx = em_ssh_mem_alloc(sizeof(em_ssh_digest_ctx_t), destructor_em_ssh_digest_ctx_t);
    if(tctx == NULL) {
        err = ENOMEM;
        goto out;
    }
    tctx->alg = alg;
    switch(tctx->alg) {
        case EM_SSH_DIGEST_MD5 : {
            tctx->digest_len = em_ssh_md5_digest_len();
            tctx->block_length = em_ssh_md5_block_len();
            if((err = em_ssh_md5_init((void *)&tctx->ctx)) != OK) {
                goto out;
            }
            break;
        }
        case EM_SSH_DIGEST_SHA1 : {
            tctx->digest_len = em_ssh_sha1_digest_len();
            tctx->block_length = em_ssh_sha1_block_len();
            if((err = em_ssh_sha1_init((void *)&tctx->ctx)) != OK) {
                goto out;
            }
            break;
        }
        case EM_SSH_DIGEST_SHA256 : {
            tctx->digest_len = em_ssh_sha256_digest_len();
            tctx->block_length = em_ssh_sha256_block_len();
            if((err = em_ssh_sha256_init((void *)&tctx->ctx)) != OK) {
                goto out;
            }
            break;
        }
        default:
            em_ssh_log_warn("unknown digest: %i", alg);
            err = EINVAL;
            goto out;
    }
    *ctx = tctx;
out:
    if(err != OK) {
        em_ssh_mem_deref(tctx);
    }
    return err;
}

/**
 *
 **/
int em_ssh_digest_update(em_ssh_digest_ctx_t *ctx, void *data, size_t data_len) {
    int err = OK;

    if(!ctx || !data) {
        return EINVAL;
    }
    switch(ctx->alg) {
        case EM_SSH_DIGEST_MD5 : {
            em_ssh_md5_ctx_t *mdctx = (em_ssh_md5_ctx_t *)ctx->ctx;
            err = em_ssh_md5_update(mdctx, data, data_len);
            break;
        }
        case EM_SSH_DIGEST_SHA1 : {
            em_ssh_sha1_ctx_t *mdctx = (em_ssh_sha1_ctx_t *)ctx->ctx;
            err = em_ssh_sha1_update(mdctx, data, data_len);
            break;
        }
        case EM_SSH_DIGEST_SHA256 : {
            em_ssh_sha256_ctx_t *mdctx = (em_ssh_sha256_ctx_t *)ctx->ctx;
            err = em_ssh_sha256_update(mdctx, data, data_len);
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
int em_ssh_digest_final(em_ssh_digest_ctx_t *ctx, uint8_t *digest, size_t digest_len) {
    int err = OK;

    if(!ctx || !digest) {
        return EINVAL;
    }
    if(digest_len < ctx->digest_len) {
        return ERANGE;
    }
    switch(ctx->alg) {
        case EM_SSH_DIGEST_MD5 : {
            em_ssh_md5_ctx_t *mdctx = (em_ssh_md5_ctx_t *)ctx->ctx;
            err = em_ssh_md5_final(mdctx, digest);
            break;
        }
        case EM_SSH_DIGEST_SHA1 : {
            em_ssh_sha1_ctx_t *mdctx = (em_ssh_sha1_ctx_t *)ctx->ctx;
            err = em_ssh_sha1_final(mdctx, digest);
            break;
        }
        case EM_SSH_DIGEST_SHA256 : {
            em_ssh_sha256_ctx_t *mdctx = (em_ssh_sha256_ctx_t *)ctx->ctx;
            err = em_ssh_sha256_final(mdctx, digest);
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
int em_ssh_digest_copy_state(em_ssh_digest_ctx_t *from, em_ssh_digest_ctx_t *to) {
    int err = OK;

    if(!from || !to || from->alg != to->alg) {
        return EINVAL;
    }

    switch(from->alg) {
        case EM_SSH_DIGEST_MD5 : {
            em_ssh_md5_ctx_t *sctx = (em_ssh_md5_ctx_t *)from->ctx;
            em_ssh_md5_ctx_t *dctx = (em_ssh_md5_ctx_t *)to->ctx;
            size_t sz  = em_ssh_md5_ctx_size();
            explicit_bzero(dctx, sz);
            memcpy(dctx, sctx, sz);
            break;
        }
        case EM_SSH_DIGEST_SHA1 : {
            em_ssh_sha1_ctx_t *sctx = (em_ssh_sha1_ctx_t *)from->ctx;
            em_ssh_sha1_ctx_t *dctx = (em_ssh_sha1_ctx_t *)to->ctx;
            size_t sz  = em_ssh_sha1_ctx_size();
            explicit_bzero(dctx, sz);
            memcpy(dctx, sctx, sz);
            break;
        }
        case EM_SSH_DIGEST_SHA256 : {
            em_ssh_sha256_ctx_t *sctx = (em_ssh_sha256_ctx_t *)from->ctx;
            em_ssh_sha256_ctx_t *dctx = (em_ssh_sha256_ctx_t *)to->ctx;
            size_t sz  = em_ssh_sha256_ctx_size();
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
size_t em_ssh_digest_bytes(int alg) {

    switch(alg) {
        case EM_SSH_DIGEST_MD5 :
            return em_ssh_md5_digest_len();

        case EM_SSH_DIGEST_SHA1 :
            return em_ssh_sha1_digest_len();

        case EM_SSH_DIGEST_SHA256 :
            return em_ssh_sha256_digest_len();
    }

    return 0;
}

/**
 *
 **/
size_t em_ssh_digest_block_size(int alg) {

    switch(alg) {
        case EM_SSH_DIGEST_MD5 :
            return em_ssh_md5_block_len();

        case EM_SSH_DIGEST_SHA1 :
            return em_ssh_sha1_block_len();

        case EM_SSH_DIGEST_SHA256 :
            return em_ssh_sha256_block_len();
    }

    return 0;
}

/**
 *
 **/

int em_ssh_digest_memory(int alg, const void *m, size_t mlen, u_char *d, size_t dlen) {

    if(!m || !d) {
        return EINVAL;
    }

    switch(alg) {
        case EM_SSH_DIGEST_MD5 :
            return em_ssh_md5_digest(m, mlen, d, dlen);

        case EM_SSH_DIGEST_SHA1 :
            return em_ssh_sha1_digest(m, mlen, d, dlen);

        case EM_SSH_DIGEST_SHA256 :
            return em_ssh_sha256_digest(m, mlen, d, dlen);
    }

    return ERROR;
}
