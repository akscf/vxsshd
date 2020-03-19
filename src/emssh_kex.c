/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

static void mem_destructor_em_ssh_kex_t(void *data) {
    em_ssh_kex_t *kex = data;

    em_ssh_mem_deref(kex->client_version);
    em_ssh_mem_deref(kex->server_version);

    em_ssh_mem_deref(kex->client_kex_init);
    em_ssh_mem_deref(kex->server_kex_init);

    em_ssh_mem_deref(kex->session_id);

    /* keys */
    em_ssh_mem_deref(kex->keys_in.enc);
    em_ssh_mem_deref(kex->keys_in.mac);
    em_ssh_mem_deref(kex->keys_out.enc);
    em_ssh_mem_deref(kex->keys_out.mac);
}

static int derive_key(em_ssh_kex_t *kex, int id, size_t need, uint8_t *hash, size_t hashlen, uint8_t *shared_secret, size_t shared_secret_len, uint8_t **keyp) {
    em_ssh_digest_ctx_t *hashctx = NULL;
    uint8_t *digest = NULL;
    int err = OK;
    char c = id;
    uint32_t have;
    size_t mdsz;
    int r;

    if(!kex) {
        return EINVAL;
    }

    if((mdsz = em_ssh_digest_bytes(kex->hash_alg)) == 0) {
        return EINVAL;
    }

    if((digest = em_ssh_mem_alloc(ROUNDUP(need, mdsz), NULL)) == NULL) {
        return ENOMEM;
    }

    /* K1 = HASH(K || H || "A" || session_id) */
    if((err = em_ssh_digest_alloc(&hashctx, kex->hash_alg)) != OK) {
        goto out;
    }
    if((err = em_ssh_digest_update(hashctx, shared_secret, shared_secret_len)) != OK) {
        goto out;
    }
    if((err = em_ssh_digest_update(hashctx, hash, hashlen)) != OK) {
        goto out;
    }
    if((err = em_ssh_digest_update(hashctx, &c, 1)) != OK) {
        goto out;
    }
    if((err = em_ssh_digest_update(hashctx, kex->session_id, kex->session_id_len)) != OK) {
        goto out;
    }
    if((err = em_ssh_digest_final(hashctx, digest, mdsz)) != OK) {
        goto out;
    }
    em_ssh_mem_deref(hashctx);

    /* expand key:
     * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
     * Key = K1 || K2 || ... || Kn
     */
    for (have = mdsz; need > have; have += mdsz) {
        if((err = em_ssh_digest_alloc(&hashctx, kex->hash_alg)) != OK) {
            goto out;
        }
        if((err = em_ssh_digest_update(hashctx, shared_secret, shared_secret_len)) != OK) {
            goto out;
        }
        if((err = em_ssh_digest_update(hashctx, hash, hashlen)) != OK) {
            goto out;
        }
        if((err = em_ssh_digest_update(hashctx, digest, have)) != OK) {
            goto out;
        }
        if((err = em_ssh_digest_final(hashctx, digest + have, mdsz)) != OK) {
            goto out;
        }
        em_ssh_mem_deref(hashctx);
    }

    *keyp = digest;

out:
    if(err != OK) {
        em_ssh_mem_deref(digest);
    }
    em_ssh_mem_deref(hashctx);
    return err;
}

// ----------------------------------------------------------------------------------------------------------------------------------------
// public api
// ----------------------------------------------------------------------------------------------------------------------------------------
/**
 * free old  data and allocate new
 **/
int em_ssh_kex_newkeys_realloc(em_ssh_kex_t *kex) {
    int err = OK;

    if(!kex) {
        return EINVAL;
    }

    /* IN ----------------------------------------------------- */
    if(kex->keys_in.mac) {
        em_ssh_mem_deref(kex->keys_in.mac);
    }
    if((err = em_ssh_mac_alloc(&kex->keys_in.mac, kex->mac_algorithm)) != OK) {
        em_ssh_log_warn("newkeys: mac-in alloc failed (%i)", err);
        goto out;
    }

    if(kex->keys_in.enc) {
        em_ssh_mem_deref(kex->keys_in.enc);
    }
    if((err = em_ssh_cipher_alloc(&kex->keys_in.enc, kex->cipher_algorithm, true)) != OK) {
        em_ssh_log_warn("newkeys: enc-in alloc (%i)", err);
        goto out;
    }

    /* OUT --------------------------------------------------- */
    if(kex->keys_out.mac) {
        em_ssh_mem_deref(kex->keys_out.mac);
    }
    if((err = em_ssh_mac_alloc(&kex->keys_out.mac, kex->mac_algorithm)) != OK) {
        em_ssh_log_warn("newkeys: mac-out alloc failed (%i)", err);
        goto out;
    }

    if(kex->keys_out.enc) {
        em_ssh_mem_deref(kex->keys_out.enc);
    }
    if((err = em_ssh_cipher_alloc(&kex->keys_out.enc, kex->cipher_algorithm, false)) != OK) {
        em_ssh_log_warn("newkeys: enc-out alloc failed (%i)", err);
        goto out;
    }

out:
    return err;
}

/**
 * int mac/chipher context
 **/
int em_ssh_kex_newkeys_init(em_ssh_kex_t *kex) {
    int err = OK;

    if(!kex) {
        return EINVAL;
    }

    if(kex->keys_in.mac == NULL || kex->keys_in.enc == NULL || !kex->keys_in.enc->block_len) {
        em_ssh_log_warn("newkeys: keys_in not initialized");
        err = EINVAL; goto out;
    }
    if(kex->keys_out.mac == NULL || kex->keys_out.enc == NULL || !kex->keys_out.enc->block_len) {
        em_ssh_log_warn("newkeys: keys_out not initialized");
        err = EINVAL; goto out;
    }

    /* IN ----------------------------------------------------- */
    if((err = em_ssh_mac_init(kex->keys_in.mac)) != OK) {
        em_ssh_log_warn("newkeys: mac_init(#1) failed (%i)", err);
        goto out;
    }
    if((err = em_ssh_cipher_init(kex->keys_in.enc)) != OK) {
        em_ssh_log_warn("newkeys: cipher_init(#1) failed (%i)", err);
        goto out;
    }

    /* OUT --------------------------------------------------- */
    if((err = em_ssh_mac_init(kex->keys_out.mac)) != OK) {
        em_ssh_log_warn("newkeys: mac_init(#2) failed (%i)", err);
        goto out;
    }
    if((err = em_ssh_cipher_init(kex->keys_out.enc)) != OK) {
        em_ssh_log_warn("newkeys: cipher_init(#2) failed (%i)", err);
        goto out;
    }

#ifdef EM_SSH_DEBUG_KEX_KEYS
    if(kex->keys_in->mac) {
       em_ssh_log_debug("C2S mac.cfg...: mac_len=%i, key_len=%i, emt=%i", kex->keys_in.mac->mac_len, kex->keys_in.mac->key_len, kex->keys_in.mac->etm);
        em_ssh_hexdump2("C2S data......: ", kex->keys_in.mac->key, kex->keys_in.mac->key_len);
    } else {
       em_ssh_log_debug("C2S mac.......: not initialized!");
    }
    if(kex->keys_in->enc) {
       em_ssh_log_debug("C2S enc.cfg...: iv_len=%i, key_len=%i, block_len=%i", kex->keys_in.enc->iv_len, kex->keys_in.enc->key_len, kex->keys_in.enc->block_len);
        em_ssh_hexdump2("C2S enc.iv....: ", kex->keys_in.enc->iv, kex->keys_in.enc->iv_len);
        em_ssh_hexdump2("C2S enc.key...: ", kex->keys_in.enc->key, kex->keys_in.enc->key_len);
    } else {
       em_ssh_log_debug("C2S enc.......: not initialized!");
    }
    // ----------------------------------------------------------
    if(kex->keys_out->mac) {
       em_ssh_log_debug("C2S mac.cfg...: mac_len=%i, key_len=%i, emt=%i", kex->keys_out.mac->mac_len, kex->keys_out.mac->key_len, kex->keys_out.mac->etm);
        em_ssh_hexdump2("C2S data......: ", kex->keys_out.mac->key, kex->keys_out.mac->key_len);
    } else {
       em_ssh_log_debug("C2S mac.......: not initialized!");
    }
    if(kex->keys_out->enc) {
       em_ssh_log_debug("C2S enc.cfg...: iv_len=%i, key_len=%i, block_len=%i", kex->keys_out.enc->iv_len, kex->keys_out.enc->key_len, kex->keys_out.enc->block_len);
        em_ssh_hexdump2("C2S enc.iv....: ", kex->keys_out.enc->iv, kex->keys_out.enc->iv_len);
        em_ssh_hexdump2("C2S enc.key...: ", kex->keys_out.enc->key, kex->keys_out.enc->key_len);
    } else {
       em_ssh_log_debug("C2S enc.......: not initialized!");
    }
#endif

out:
    return err;
}

/**
 *
 **/
int em_ssh_kex_alloc(em_ssh_kex_t **kex) {
    em_ssh_kex_t *tkex = NULL;

    if(!kex) {
        return EINVAL;
    }

    if((tkex = em_ssh_mem_zalloc(sizeof(em_ssh_kex_t), mem_destructor_em_ssh_kex_t)) == NULL) {
        return ENOMEM;
    }

    *kex = tkex;
    return OK;
}

/**
 *
 **/
int em_ssh_kex_derive_keys(em_ssh_kex_t *kex, uint8_t *hash, size_t hashlen, uint8_t *shared_secret, size_t shared_secret_len) {
    int i, err = OK;

    if(kex->keys_in.enc == NULL || kex->keys_in.mac == NULL) {
        em_ssh_log_warn("derive_keys: keys_in not initialized");
        return EINVAL;
    }
    if(kex->keys_out.enc == NULL || kex->keys_out.mac == NULL) {
        em_ssh_log_warn("derive_keys: keys_out not");
        return EINVAL;
    }

    for (i = 0; i < 6; i++) {
        uint8_t *key = NULL;
        if((err = derive_key(kex, 'A' + i, kex->we_need, hash, hashlen, shared_secret, shared_secret_len, &key)) != OK) {
            em_ssh_mem_deref(key);
            break;
        }
        /* C2S */
        if(i == 0) kex->keys_in.enc->iv = key;
        if(i == 2) kex->keys_in.enc->key = key;
        if(i == 4) kex->keys_in.mac->key = key;
        /* S2C */
        if(i == 1) kex->keys_out.enc->iv = key;
        if(i == 3) kex->keys_out.enc->key = key;
        if(i == 5) kex->keys_out.mac->key = key;
    }

    return err;
}

