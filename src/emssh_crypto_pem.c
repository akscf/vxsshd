/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"
static const char *RSA_PRIVATE_KEY_HEADER_BEGIN  = "-----BEGIN RSA PRIVATE KEY-----";
static const char *RSA_PRIVATE_KEY_HEADER_END    = "-----END RSA PRIVATE KEY-----";
static const char *RSA_PUBLIC_KEY_HEADER_BEGIN   = "-----BEGIN RSA PUBLIC KEY-----";
static const char *RSA_PUBLIC_KEY_HEADER_END     = "-----END RSA PUBLIC KEY-----";

static int decode_rsa_private_key(em_ssh_mbuf_t *mb, em_ssh_crypto_object_t **crypto_object) {
    int err = OK;
    mpz_t _kver;
    em_ssh_crypto_object_t *cobj = NULL;
    em_ssh_crypto_rsa_private_key_t *rsa_key = NULL;

    if((err = em_ssh_crypto_object_alloc(&cobj, CRYPTO_OBJECT_RSA_PRIVATE_KEY)) != OK) {
        goto out;
    }
    rsa_key = (em_ssh_crypto_rsa_private_key_t *) cobj->obj;

    /* RSA key version (should be 0 or 1) */
    err = em_ssh_asn1_get_integer(mb, _kver);
    if(err != OK || (mpz_cmp_ui(_kver, 0) != 0 && mpz_cmp_ui(_kver, 1) != 0)) {
        em_ssh_log_error("Incorrect key version");
        goto out;
    }
    /* RSA n */
    err = em_ssh_asn1_get_integer(mb, rsa_key->n);
    if(err != OK) {
        em_ssh_log_error("Ivalid RSA key (n)");
        goto out;
    }
    /* RSA e */
    err = em_ssh_asn1_get_integer(mb, rsa_key->e);
    if(err != OK) {
        em_ssh_log_error("Ivalid RSA key (e)");
        goto out;
    }
    /* RSA d */
    err = em_ssh_asn1_get_integer(mb, rsa_key->d);
    if(err != OK) {
        em_ssh_log_error("Ivalid RSA key (d)");
        goto out;
    }
out:
    mpz_clear(_kver);
    if(err != OK) {
        em_ssh_mem_deref(cobj);
    } else {
        *crypto_object = cobj;
    }
    return err;
}

static int decode_rsa_public_key(em_ssh_mbuf_t *mb, em_ssh_crypto_object_t **crypto_object) {
    int err = OK;
    em_ssh_crypto_object_t *cobj = NULL;
    em_ssh_crypto_rsa_public_key_t *rsa_key = NULL;

    if((err = em_ssh_crypto_object_alloc(&cobj, CRYPTO_OBJECT_RSA_PUBLIC_KEY)) != OK) {
        goto out;
    }
    rsa_key = (em_ssh_crypto_rsa_public_key_t *) cobj->obj;

    /* RSA n */
    err = em_ssh_asn1_get_integer(mb, rsa_key->n);
    if(err != OK) {
        em_ssh_log_error("Ivalid RSA key (n)");
        goto out;
    }
    /* RSA e */
    err = em_ssh_asn1_get_integer(mb, rsa_key->e);
    if(err != OK) {
        em_ssh_log_error("Ivalid RSA key (e)");
        goto out;
    }
out:
    if(err != OK) {
        em_ssh_mem_deref(cobj);
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
int em_ssh_pem_decode(char *buffer, size_t buffer_len, char *passphrase, em_ssh_crypto_object_t **key) {
    int obj_type = CRYPTO_OBJECT_NONE;
    int err = OK, i, j, bstart, bsz;
    size_t tsz;
    char *p = NULL, *tbuf = NULL;
    em_ssh_mbuf_t *pem_mb = NULL;
    em_ssh_crypto_object_t *cobj = NULL;

    if(!buffer || !buffer_len) {
        return EINVAL;
    }
    if(passphrase) {
        em_ssh_log_error("key decription not yet implement");
        return ENOSYS;
    }

    /* looking for headers */
    bstart = em_ssh_str_index(buffer, buffer_len, RSA_PRIVATE_KEY_HEADER_BEGIN, strlen(RSA_PRIVATE_KEY_HEADER_BEGIN));
    if(bstart >= 0) {
        obj_type = CRYPTO_OBJECT_RSA_PRIVATE_KEY;
        bstart += strlen(RSA_PRIVATE_KEY_HEADER_BEGIN);
        p = (buffer + bstart);
        bsz = em_ssh_str_index(p, buffer_len - bstart, RSA_PRIVATE_KEY_HEADER_END, strlen(RSA_PRIVATE_KEY_HEADER_END));
        if(bsz < 0) {
            return EINVAL;
        }
    }
    if(obj_type == CRYPTO_OBJECT_NONE) {
        bstart = em_ssh_str_index(buffer, buffer_len, RSA_PUBLIC_KEY_HEADER_BEGIN, strlen(RSA_PUBLIC_KEY_HEADER_BEGIN));
        if(bstart >= 0) {
            obj_type = CRYPTO_OBJECT_RSA_PUBLIC_KEY;
            bstart += strlen(RSA_PUBLIC_KEY_HEADER_BEGIN);
            p = (buffer + bstart);
            bsz = em_ssh_str_index(p, buffer_len - bstart, RSA_PUBLIC_KEY_HEADER_END, strlen(RSA_PUBLIC_KEY_HEADER_END));
            if(bsz < 0) {
                return EINVAL;
            }

        }
    }
    if(obj_type == CRYPTO_OBJECT_NONE) {
        return ENOSYS;
    }

    /* copy base64 part and cut \n \r */
    if((tbuf = em_ssh_mem_alloc(bsz + 1, NULL)) == NULL) {
        err = ENOMEM;
        goto out;
    }
    for(i = 0, j = 0; i < bsz; i++) {
        if(p[i] == '\n' || p[i] == '\r') { continue; }
        tbuf[j++] = p[i];
    }
    tbuf[j] = '\0';

    /* decode b64 */
    if((err = em_ssh_mbuf_alloc(&pem_mb, 3 * (j / 4))) != OK) {
        goto out;
    }
    em_ssh_mbuf_base64_decode(pem_mb, tbuf, j);
    em_ssh_mbuf_set_pos(pem_mb, 0);
    em_ssh_mem_deref(tbuf);

    if(obj_type == CRYPTO_OBJECT_RSA_PRIVATE_KEY) {
        err = em_ssh_asn1_get_sequece(pem_mb, &tbuf, &tsz);
        if(err != OK || em_ssh_mbuf_get_left(pem_mb) > 0) {
            em_ssh_log_error("Invalid DER format");
            goto out;
        }
        em_ssh_mbuf_clear(pem_mb);
        em_ssh_mbuf_write_mem(pem_mb, (uint8_t *)tbuf, tsz);
        em_ssh_mbuf_set_pos(pem_mb, 0);
        em_ssh_mem_deref(tbuf);
        /* decode */
        err = decode_rsa_private_key(pem_mb, &cobj);

    } else if(obj_type == CRYPTO_OBJECT_RSA_PUBLIC_KEY) {
        err = em_ssh_asn1_get_sequece(pem_mb, &tbuf, &tsz);
        if(err != OK || em_ssh_mbuf_get_left(pem_mb) > 0) {
            em_ssh_log_error("Invalid DER format");
            goto out;
        }
        em_ssh_mbuf_clear(pem_mb);
        em_ssh_mbuf_write_mem(pem_mb, (uint8_t *)tbuf, tsz);
        em_ssh_mbuf_set_pos(pem_mb, 0);
        /* OID */
        err = em_ssh_asn1_get_sequece(pem_mb, &tbuf, &tsz);
        if(err != OK) {
            em_ssh_log_error("Invalid DER format (oid)");
            goto out;
        }
        em_ssh_mem_deref(tbuf);

        err = em_ssh_asn1_get_bitstr(pem_mb, &tbuf, &tsz);
        if(err != OK || !tsz) {
            em_ssh_log_error("Invalid DER format (key)");
            goto out;
        }
        em_ssh_mbuf_clear(pem_mb);
        em_ssh_mbuf_write_mem(pem_mb, (uint8_t *)tbuf, tsz);
        em_ssh_mbuf_set_pos(pem_mb, 0);
        em_ssh_mem_deref(tbuf);
        uint8_t ubits = em_ssh_mbuf_read_u8(pem_mb);
        /* pub key */
        err = em_ssh_asn1_get_sequece(pem_mb, &tbuf, &tsz);
        em_ssh_mbuf_clear(pem_mb);
        em_ssh_mbuf_write_mem(pem_mb, (uint8_t *)tbuf, tsz);
        em_ssh_mbuf_set_pos(pem_mb, 0);
        em_ssh_mem_deref(tbuf);
        /* decode */
        err = decode_rsa_public_key(pem_mb, &cobj);
    }
out:
    em_ssh_mem_deref(tbuf);
    em_ssh_mem_deref(pem_mb);

    if(err == OK && cobj) {
        *key = cobj;
    }

    return err;
}
