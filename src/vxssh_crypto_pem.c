/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

static const char *RSA_PRIVATE_KEY_HEADER_BEGIN  = "-----BEGIN RSA PRIVATE KEY-----";
static const char *RSA_PRIVATE_KEY_HEADER_END    = "-----END RSA PRIVATE KEY-----";
static const char *RSA_PUBLIC_KEY_HEADER_BEGIN   = "-----BEGIN RSA PUBLIC KEY-----";
static const char *RSA_PUBLIC_KEY_HEADER_END     = "-----END RSA PUBLIC KEY-----";

static int decode_rsa_private_key(vxssh_mbuf_t *mb, vxssh_crypto_object_t **crypto_object) {
    int err = OK;
    mpz_t _kver;
    vxssh_crypto_object_t *cobj = NULL;
    vxssh_crypto_rsa_private_key_t *rsa_key = NULL;

    if((err = vxssh_crypto_object_alloc(&cobj, CRYPTO_OBJECT_RSA_PRIVATE_KEY)) != OK) {
        goto out;
    }
    rsa_key = (vxssh_crypto_rsa_private_key_t *) cobj->obj;

    /* RSA key version (should be 0 or 1) */
    err = vxssh_asn1_get_integer(mb, _kver);
    if(err != OK || (mpz_cmp_ui(_kver, 0) != 0 && mpz_cmp_ui(_kver, 1) != 0)) {
        vxssh_log_error("Incorrect key version");
        goto out;
    }
    /* RSA n */
    err = vxssh_asn1_get_integer(mb, rsa_key->n);
    if(err != OK) {
        vxssh_log_error("Ivalid RSA key (n)");
        goto out;
    }
    /* RSA e */
    err = vxssh_asn1_get_integer(mb, rsa_key->e);
    if(err != OK) {
        vxssh_log_error("Ivalid RSA key (e)");
        goto out;
    }
    /* RSA d */
    err = vxssh_asn1_get_integer(mb, rsa_key->d);
    if(err != OK) {
        vxssh_log_error("Ivalid RSA key (d)");
        goto out;
    }
out:
    mpz_clear(_kver);
    if(err != OK) {
        vxssh_mem_deref(cobj);
    } else {
        *crypto_object = cobj;
    }
    return err;
}

static int decode_rsa_public_key(vxssh_mbuf_t *mb, vxssh_crypto_object_t **crypto_object) {
    int err = OK;
    vxssh_crypto_object_t *cobj = NULL;
    vxssh_crypto_rsa_public_key_t *rsa_key = NULL;

    if((err = vxssh_crypto_object_alloc(&cobj, CRYPTO_OBJECT_RSA_PUBLIC_KEY)) != OK) {
        goto out;
    }
    rsa_key = (vxssh_crypto_rsa_public_key_t *) cobj->obj;

    /* RSA n */
    err = vxssh_asn1_get_integer(mb, rsa_key->n);
    if(err != OK) {
        vxssh_log_error("Ivalid RSA key (n)");
        goto out;
    }
    /* RSA e */
    err = vxssh_asn1_get_integer(mb, rsa_key->e);
    if(err != OK) {
        vxssh_log_error("Ivalid RSA key (e)");
        goto out;
    }
out:
    if(err != OK) {
        vxssh_mem_deref(cobj);
    } else {
        *crypto_object = cobj;
    }
    return err;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// public
// -----------------------------------------------------------------------------------------------------------------------------------------
/**
 *
 **/
int vxssh_pem_decode(char *buffer, size_t buffer_len, char *passphrase, vxssh_crypto_object_t **key) {
    int obj_type = CRYPTO_OBJECT_NONE;
    int err = OK, i, j, bstart, bsz;
    size_t tsz;
    char *p = NULL, *tbuf = NULL;
    vxssh_mbuf_t *pem_mb = NULL;
    vxssh_crypto_object_t *cobj = NULL;

    if(!buffer || !buffer_len) {
        return EINVAL;
    }
    if(passphrase) {
        vxssh_log_error("key encription not yet implement");
        return ENOSYS;
    }

    /* looking for headers */
    bstart = vxssh_str_index(buffer, buffer_len, RSA_PRIVATE_KEY_HEADER_BEGIN, strlen(RSA_PRIVATE_KEY_HEADER_BEGIN));
    if(bstart >= 0) {
        obj_type = CRYPTO_OBJECT_RSA_PRIVATE_KEY;
        bstart += strlen(RSA_PRIVATE_KEY_HEADER_BEGIN);
        p = (buffer + bstart);
        bsz = vxssh_str_index(p, buffer_len - bstart, RSA_PRIVATE_KEY_HEADER_END, strlen(RSA_PRIVATE_KEY_HEADER_END));
        if(bsz < 0) {
            return EINVAL;
        }
    }
    if(obj_type == CRYPTO_OBJECT_NONE) {
        bstart = vxssh_str_index(buffer, buffer_len, RSA_PUBLIC_KEY_HEADER_BEGIN, strlen(RSA_PUBLIC_KEY_HEADER_BEGIN));
        if(bstart >= 0) {
            obj_type = CRYPTO_OBJECT_RSA_PUBLIC_KEY;
            bstart += strlen(RSA_PUBLIC_KEY_HEADER_BEGIN);
            p = (buffer + bstart);
            bsz = vxssh_str_index(p, buffer_len - bstart, RSA_PUBLIC_KEY_HEADER_END, strlen(RSA_PUBLIC_KEY_HEADER_END));
            if(bsz < 0) {
                return EINVAL;
            }

        }
    }
    if(obj_type == CRYPTO_OBJECT_NONE) {
        return ENOSYS;
    }

    /* copy base64 part and cut \n \r */
    if((tbuf = vxssh_mem_alloc(bsz + 1, NULL)) == NULL) {
        err = ENOMEM;
        goto out;
    }
    for(i = 0, j = 0; i < bsz; i++) {
        if(p[i] == '\n' || p[i] == '\r') { continue; }
        tbuf[j++] = p[i];
    }
    tbuf[j] = '\0';

    /* decode b64 */
    if((err = vxssh_mbuf_alloc(&pem_mb, 3 * (j / 4))) != OK) {
        goto out;
    }
    vxssh_mbuf_base64_decode(pem_mb, tbuf, j);
    vxssh_mbuf_set_pos(pem_mb, 0);
    vxssh_mem_deref(tbuf);

    if(obj_type == CRYPTO_OBJECT_RSA_PRIVATE_KEY) {
        err = vxssh_asn1_get_sequece(pem_mb, &tbuf, &tsz);
        if(err != OK || vxssh_mbuf_get_left(pem_mb) > 0) {
            vxssh_log_error("Invalid DER format");
            goto out;
        }
        vxssh_mbuf_clear(pem_mb);
        vxssh_mbuf_write_mem(pem_mb, (uint8_t *)tbuf, tsz);
        vxssh_mbuf_set_pos(pem_mb, 0);
        vxssh_mem_deref(tbuf);
        /* decode */
        err = decode_rsa_private_key(pem_mb, &cobj);

    } else if(obj_type == CRYPTO_OBJECT_RSA_PUBLIC_KEY) {
        err = vxssh_asn1_get_sequece(pem_mb, &tbuf, &tsz);
        if(err != OK || vxssh_mbuf_get_left(pem_mb) > 0) {
            vxssh_log_error("Invalid DER format");
            goto out;
        }
        vxssh_mbuf_clear(pem_mb);
        vxssh_mbuf_write_mem(pem_mb, (uint8_t *)tbuf, tsz);
        vxssh_mbuf_set_pos(pem_mb, 0);
        /* OID */
        err = vxssh_asn1_get_sequece(pem_mb, &tbuf, &tsz);
        if(err != OK) {
            vxssh_log_error("Invalid DER format (oid)");
            goto out;
        }
        vxssh_mem_deref(tbuf);

        err = vxssh_asn1_get_bitstr(pem_mb, &tbuf, &tsz);
        if(err != OK || !tsz) {
            vxssh_log_error("Invalid DER format (key)");
            goto out;
        }
        vxssh_mbuf_clear(pem_mb);
        vxssh_mbuf_write_mem(pem_mb, (uint8_t *)tbuf, tsz);
        vxssh_mbuf_set_pos(pem_mb, 0);
        vxssh_mem_deref(tbuf);
        uint8_t ubits = vxssh_mbuf_read_u8(pem_mb);
        /* pub key */
        err = vxssh_asn1_get_sequece(pem_mb, &tbuf, &tsz);
        vxssh_mbuf_clear(pem_mb);
        vxssh_mbuf_write_mem(pem_mb, (uint8_t *)tbuf, tsz);
        vxssh_mbuf_set_pos(pem_mb, 0);
        vxssh_mem_deref(tbuf);
        /* decode */
        err = decode_rsa_public_key(pem_mb, &cobj);
    }
out:
    vxssh_mem_deref(tbuf);
    vxssh_mem_deref(pem_mb);

    if(err == OK && cobj) {
        *key = cobj;
    }

    return err;
}
