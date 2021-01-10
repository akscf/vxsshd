/**
 *
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

static void mem_destructor_vxssh_crypto_object_t(void *data) {
    vxssh_crypto_object_t *p = (vxssh_crypto_object_t *) data;

    switch(p->type) {
        case CRYPTO_OBJECT_NONE:
        break;

        case CRYPTO_OBJECT_RSA_PRIVATE_KEY: {
            vxssh_crypto_rsa_private_key_t *key = p->obj;
            if(key) {
                mpz_clear(key->e);
                mpz_clear(key->n);
                mpz_clear(key->d);
            }
            vxssh_mem_deref(key);
            break;
        }
        case CRYPTO_OBJECT_RSA_PUBLIC_KEY: {
            vxssh_crypto_rsa_public_key_t *key = (vxssh_crypto_rsa_public_key_t *) p->obj;
            if(key) {
                mpz_clear(key->e);
                mpz_clear(key->n);
            }
            vxssh_mem_deref(key);
            break;
        }
        case CRYPTO_OBJECT_RSA_SIGNATURE: {
            vxssh_crypto_rsa_signature_t *sig = (vxssh_crypto_rsa_signature_t *) p->obj;
            if(sig) {
                mpz_clear(sig->s);
            }
            vxssh_mem_deref(sig);
            break;
        }
    }
}

/**
 * object fctory
 **/
int vxssh_crypto_object_alloc(vxssh_crypto_object_t **object, int type) {
    int err = OK;
    vxssh_crypto_object_t *lobj = NULL;

    if(!object) {
        return EINVAL;
    }

    lobj = vxssh_mem_alloc(sizeof(vxssh_crypto_object_t), mem_destructor_vxssh_crypto_object_t);
    if(!lobj) {
        err = ENOMEM;
        goto out;
    }

    lobj->type = type;
    switch(lobj->type) {
        case CRYPTO_OBJECT_NONE:{
            lobj->obj = NULL;
            break;
        }
        case CRYPTO_OBJECT_RSA_PRIVATE_KEY: {
            lobj->obj = vxssh_mem_zalloc(sizeof(vxssh_crypto_rsa_private_key_t), NULL);
            if(!lobj->obj) {
                err = ENOMEM;
                goto out;
            }
            vxssh_crypto_rsa_private_key_t *ref = lobj->obj;
            mpz_init(ref->e);
            mpz_init(ref->n);
            mpz_init(ref->d);
            break;
        }
        case CRYPTO_OBJECT_RSA_PUBLIC_KEY: {
            lobj->obj = vxssh_mem_zalloc(sizeof(vxssh_crypto_rsa_public_key_t), NULL);
            if(!lobj->obj) {
                err = ENOMEM;
                goto out;
            }
            vxssh_crypto_rsa_public_key_t *ref = lobj->obj;
            mpz_init(ref->e);
            mpz_init(ref->n);
            break;
        }
        case CRYPTO_OBJECT_RSA_SIGNATURE: {
            lobj->obj = vxssh_mem_zalloc(sizeof(vxssh_crypto_rsa_signature_t), NULL);
            if(!lobj->obj) {
                err = ENOMEM;
                goto out;
            }
            vxssh_crypto_rsa_signature_t *ref = lobj->obj;
            mpz_init(ref->s);
            break;
        }
        default:
            err = ENOSYS;
    }
out:
    if(err != OK) {
        vxssh_mem_deref(lobj);
    } else {
        *object = lobj;
    }
    return err;
}
