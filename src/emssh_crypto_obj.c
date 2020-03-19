/**
 *
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

static void mem_destructor_em_ssh_crypto_object_t(void *data) {
    em_ssh_crypto_object_t *p = (em_ssh_crypto_object_t *) data;

    switch(p->type) {
        case CRYPTO_OBJECT_NONE:
        break;

        case CRYPTO_OBJECT_RSA_PRIVATE_KEY: {
            em_ssh_crypto_rsa_private_key_t *key = p->obj;
            if(key) {
                mpz_clear(key->e);
                mpz_clear(key->n);
                mpz_clear(key->d);
            }
            em_ssh_mem_deref(key);
            break;
        }
        case CRYPTO_OBJECT_RSA_PUBLIC_KEY: {
            em_ssh_crypto_rsa_public_key_t *key = (em_ssh_crypto_rsa_public_key_t *) p->obj;
            if(key) {
                mpz_clear(key->e);
                mpz_clear(key->n);
            }
            em_ssh_mem_deref(key);
            break;
        }
        case CRYPTO_OBJECT_RSA_SIGNATURE: {
            em_ssh_crypto_rsa_signature_t *sig = (em_ssh_crypto_rsa_signature_t *) p->obj;
            if(sig) {
                mpz_clear(sig->s);
            }
            em_ssh_mem_deref(sig);
            break;
        }
    }
}

/**
 * object fctory
 **/
int em_ssh_crypto_object_alloc(em_ssh_crypto_object_t **object, int type) {
    int err = OK;
    em_ssh_crypto_object_t *lobj = NULL;

    if(!object) {
        return EINVAL;
    }

    lobj = em_ssh_mem_alloc(sizeof(em_ssh_crypto_object_t), mem_destructor_em_ssh_crypto_object_t);
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
            lobj->obj = em_ssh_mem_zalloc(sizeof(em_ssh_crypto_rsa_private_key_t), NULL);
            if(!lobj->obj) {
                err = ENOMEM;
                goto out;
            }
            em_ssh_crypto_rsa_private_key_t *ref = lobj->obj;
            mpz_init(ref->e);
            mpz_init(ref->n);
            mpz_init(ref->d);
            break;
        }
        case CRYPTO_OBJECT_RSA_PUBLIC_KEY: {
            lobj->obj = em_ssh_mem_zalloc(sizeof(em_ssh_crypto_rsa_public_key_t), NULL);
            if(!lobj->obj) {
                err = ENOMEM;
                goto out;
            }
            em_ssh_crypto_rsa_public_key_t *ref = lobj->obj;
            mpz_init(ref->e);
            mpz_init(ref->n);
            break;
        }
        case CRYPTO_OBJECT_RSA_SIGNATURE: {
            lobj->obj = em_ssh_mem_zalloc(sizeof(em_ssh_crypto_rsa_signature_t), NULL);
            if(!lobj->obj) {
                err = ENOMEM;
                goto out;
            }
            em_ssh_crypto_rsa_signature_t *ref = lobj->obj;
            mpz_init(ref->s);
            break;
        }
        default:
            err = ENOSYS;
    }
out:
    if(err != OK) {
        em_ssh_mem_deref(lobj);
    } else {
        *object = lobj;
    }
    return err;
}
