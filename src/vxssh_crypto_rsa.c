/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"
#define RSA_TYPE_NAME "ssh-rsa"

/**
 *
 **/
int vxssh_rsa_encode_public_key(vxssh_mbuf_t *mb, vxssh_crypto_rsa_public_key_t *key) {
    int err = OK;

    if(!mb || !key) {
        return EINVAL;
    }
    /* type */
    err = vxssh_mbuf_write_str_sz(mb, RSA_TYPE_NAME);
    if(err != OK) {
        return err;
    }
    /* rsa e */
    err = vxssh_mbuf_write_mpint(mb, key->e);
    if(err != OK) {
        return err;
    }
    /* rsa n */
    err = vxssh_mbuf_write_mpint(mb, key->n);
    if(err != OK) {
        return err;
    }

    return err;
}

/**
 * from private key
 **/
int vxssh_rsa_encode_public_key2(vxssh_mbuf_t *mb, vxssh_crypto_rsa_private_key_t *key) {
    int err = OK;

    if(!mb || !key) {
        return EINVAL;
    }
    /* type */
    err = vxssh_mbuf_write_str_sz(mb, RSA_TYPE_NAME);
    if(err != OK) {
        return err;
    }
    /* rsa e */
    err = vxssh_mbuf_write_mpint(mb, key->e);
    if(err != OK) {
        return err;
    }
    /* rsa n */
    err = vxssh_mbuf_write_mpint(mb, key->n);
    if(err != OK) {
        return err;
    }

    return err;
}

/**
 *
 **/
int vxssh_rsa_decode_public_key(vxssh_mbuf_t *mb, vxssh_crypto_rsa_public_key_t *key) {
    int err = OK;
    char *tbuf = NULL;
    size_t klen = 0, sz = 0;

    if(!mb || !key) {
        return EINVAL;
    }
    /* key len */
    klen = vxssh_mbuf_read_u32(mb);
    if(klen == 0 || klen > mb->size) {
        err = ERROR; goto out;
    }
    /* type */
    sz = vxssh_mbuf_read_u32(mb);
    if(sz == 0 || sz > klen) {
        err = ERROR; goto out;
    }
    if((tbuf = vxssh_mem_zalloc(sz, NULL)) == NULL) {
        err = ENOMEM; goto out;
    }
    if((err = vxssh_mbuf_read_mem(mb, (uint8_t *)tbuf, &sz)) != OK) {
        goto out;
    }
    if(sz != strlen(RSA_TYPE_NAME) || strncmp(RSA_TYPE_NAME, tbuf, strlen(RSA_TYPE_NAME)) != 0) {
        vxssh_log_error("RSA: invalid key type");
        err = ERROR; goto out;
    }
    /* rsa e */
    err = vxssh_mbuf_read_mpint(mb, key->e);
    if(err != OK) {
        return err;
    }
    /* rsa n */
    err = vxssh_mbuf_read_mpint(mb, key->n);
    if(err != OK) {
        return err;
    }
out:
    vxssh_mem_deref(tbuf);
    return err;
}

/**
 *
 **/
int vxssh_rsa_encode_signature(vxssh_mbuf_t *mb, vxssh_crypto_rsa_signature_t *sign) {
    int err = OK, bits = 0;
    uint8_t *tbuf = NULL;
    size_t sz =0;

    if(!mb || !sign) {
        return EINVAL;
    }

    bits = mpz_sizeinbase (sign->s, 2);
    sz = (bits / 8 + (bits % 8 ? 1 : 0));
    if(sz == 0) {
        err = ERROR; goto out;
    }
    if((tbuf = vxssh_mem_zalloc(sz, NULL)) == NULL) {
        err = ENOMEM; goto out;
    }
    /* type */
    err = vxssh_mbuf_write_str_sz(mb, RSA_TYPE_NAME);
    if(err != OK) {
        goto out;
    }
    /* rsa s */
    mpz_export(tbuf, &sz, 1, 1, 0, 0, sign->s);
    if (tbuf[0] == 0x0) {
        vxssh_mbuf_write_u32(mb, sz - 1);
        vxssh_mbuf_write_mem(mb, tbuf + 1, sz - 1);
    } else {
        vxssh_mbuf_write_u32(mb, sz);
        vxssh_mbuf_write_mem(mb, tbuf, sz);
    }
out:
    vxssh_mem_deref(tbuf);
    return err;
}

/**
 *
 **/
int vxssh_rsa_decode_signature(vxssh_mbuf_t *mb, vxssh_crypto_rsa_signature_t *sign) {
    int err = OK;
    char *tbuf = NULL;
    size_t slen = 0, sz = 0;

    if(!mb || !sign) {
        return EINVAL;
    }
    /* sign len */
    slen = vxssh_mbuf_read_u32(mb);
    if(slen == 0 || slen > mb->size) {
        err = ERROR; goto out;
    }
    /* type */
    sz = vxssh_mbuf_read_u32(mb);
    if(sz == 0 || sz > slen) {
        err = ERROR; goto out;
    }
    if((tbuf = vxssh_mem_zalloc(sz, NULL)) == NULL) {
        err = ENOMEM; goto out;
    }
    if((err = vxssh_mbuf_read_mem(mb, (uint8_t *)tbuf, &sz)) != OK) {
        goto out;
    }
    if(sz != strlen(RSA_TYPE_NAME) || strncmp(RSA_TYPE_NAME, tbuf, strlen(RSA_TYPE_NAME)) != 0) {
        vxssh_log_error("RSA: invalid sign type");
        err = ERROR; goto out;
    }
    /* rsa s */
    err = vxssh_mbuf_read_mpint(mb, sign->s);
    if(err != OK) {
        goto out;
    }
out:
    vxssh_mem_deref(tbuf);
    return err;
}

/**
* sing the data
**/
int vxssh_rsa_sign(vxssh_crypto_rsa_private_key_t *key, const uint8_t *data, size_t data_len, vxssh_crypto_object_t **signature)  {
    static const uint8_t hdr[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
    uint8_t digest[VXSSH_DIGEST_SHA1_LENGTH];
    size_t digest_len = VXSSH_DIGEST_SHA1_LENGTH;
    int err = OK, i=0;
    size_t block_len, pad_len;
    vxssh_crypto_object_t *sigobj=NULL;
    vxssh_crypto_rsa_signature_t *sigref=NULL;
    vxssh_mbuf_t *sigmb = NULL;
    mpz_t m;

    if(!key || !data || !signature) {
        return EINVAL;
    }
    err = vxssh_crypto_object_alloc(&sigobj, CRYPTO_OBJECT_RSA_SIGNATURE);
    if(err != OK) {
        goto out;
    }
    sigref = (vxssh_crypto_rsa_signature_t *) sigobj->obj;

    if((err = vxssh_digest_memory(VXSSH_DIGEST_SHA1, data, data_len, digest, digest_len)) != OK) {
        goto out;
    }
    block_len = ((mpz_sizeinbase(key->n, 2) + 7) / 8);
    pad_len = block_len - (sizeof(hdr) + digest_len + 2) - 1;
    if (pad_len < 8) {
        vxssh_log_error("RSA: message too long");
        err = ERROR; goto out;
    }

    if((err = vxssh_mbuf_alloc(&sigmb, (sizeof(hdr) + digest_len + pad_len + 2))) != OK) {
        goto out;
    }
    if((err = vxssh_mbuf_write_u8(sigmb, 0x1)) != OK) {
        goto out;
    }
    if((err = vxssh_mbuf_fill(sigmb, 0xff, pad_len)) != OK) {
        goto out;
    }
    if((err = vxssh_mbuf_write_u8(sigmb, 0x0)) != OK) {
        goto out;
    }
    if((err = vxssh_mbuf_write_mem(sigmb, hdr, sizeof(hdr))) != OK) {
        goto out;
    }
    if((err = vxssh_mbuf_write_mem(sigmb, digest, digest_len)) != OK) {
        goto out;
    }
    mpz_init(m);
    mpz_import(m, sigmb->pos, 1, 1, 0, 0, sigmb->buf);
    mpz_powm(sigref->s, m, key->d, key->n);
out:
    if(err != OK) {
        vxssh_mem_deref(sigobj);
    } else {
        *signature = sigobj;
    }
    mpz_clear(m);
    explicit_bzero(digest, VXSSH_DIGEST_SHA1_LENGTH);
    vxssh_mem_deref(sigmb);
    return err;
}

/**
 *
 **/
int vxssh_rsa_sign_verfy(vxssh_crypto_rsa_public_key_t *key, vxssh_crypto_object_t *signature, const uint8_t *data, size_t data_len)  {

    if(!key || !data || !signature) {
        return EINVAL;
    }
    /*
    * todo
    */
    return ENOSYS;
}
