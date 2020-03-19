/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

static em_ssh_skey_alg_props_t  EM_SSH_SERVER_KEY_ALGORITHMS[] = {
    {"ssh-rsa"}
};
#define EM_SSH_SERVER_KEY_ALGORITHMS_SIZE ARRAY_SIZE(EM_SSH_SERVER_KEY_ALGORITHMS)

/* --------------------------------------------------------------------------------------------- */
static em_ssh_kex_alg_props_t  EM_SSH_KEX_ALGORITHMS[] = {
      {"curve25519-sha256@libssh.org", EM_SSH_KEX_C25519_SHA256, EM_SSH_DIGEST_SHA256, EM_SSH_DIGEST_SHA256_LENGTH }
};
#define EM_SSH_KEX_ALGORITHMS_SIZE ARRAY_SIZE(EM_SSH_KEX_ALGORITHMS)

/* --------------------------------------------------------------------------------------------- */
static em_ssh_mac_alg_props_t  EM_SSH_MAC_ALGORITHMS[] = {
/*     name          | type              | digest alg        | digest len               | truncatebits */
    {"hmac-sha1-96"  , EM_SSH_MAC_DIGEST, EM_SSH_DIGEST_SHA1, EM_SSH_DIGEST_SHA1_LENGTH, 96},
    {"hmac-sha1"     , EM_SSH_MAC_DIGEST, EM_SSH_DIGEST_SHA1, EM_SSH_DIGEST_SHA1_LENGTH, 00},
    {"hmac-md5-96"   , EM_SSH_MAC_DIGEST, EM_SSH_DIGEST_MD5,  EM_SSH_DIGEST_MD5_LENGTH,  96},
    {"hmac-md5"      , EM_SSH_MAC_DIGEST, EM_SSH_DIGEST_MD5,  EM_SSH_DIGEST_MD5_LENGTH,  00}
};
#define EM_SSH_MAC_ALGORITHMS_SIZE ARRAY_SIZE(EM_SSH_MAC_ALGORITHMS)

/* --------------------------------------------------------------------------------------------- */
static em_ssh_cipher_alg_props_t  EM_SSH_CHIPHER_ALGORITHMS[] = {
/*     name        | type              | mode                  | block size                  | key len | flags */
    {"aes256-cbc"  , EM_SSH_CIPHER_AES, EM_SSH_CIPHER_MODE_CBC, EM_SSH_CIPHER_AES_BLOCK_SIZE, 32      , 0},
    {"aes192-cbc"  , EM_SSH_CIPHER_AES, EM_SSH_CIPHER_MODE_CBC, EM_SSH_CIPHER_AES_BLOCK_SIZE, 24      , 0},
    {"aes128-cbc"  , EM_SSH_CIPHER_AES, EM_SSH_CIPHER_MODE_CBC, EM_SSH_CIPHER_AES_BLOCK_SIZE, 16      , 0},
    {"aes256-ctr"  , EM_SSH_CIPHER_AES, EM_SSH_CIPHER_MODE_CTR, EM_SSH_CIPHER_AES_BLOCK_SIZE, 32      , 0},
    {"aes192-ctr"  , EM_SSH_CIPHER_AES, EM_SSH_CIPHER_MODE_CTR, EM_SSH_CIPHER_AES_BLOCK_SIZE, 24      , 0},
    {"aes128-ctr"  , EM_SSH_CIPHER_AES, EM_SSH_CIPHER_MODE_CTR, EM_SSH_CIPHER_AES_BLOCK_SIZE, 16      , 0}
};
#define EM_SSH_CHIPHER_ALGORITHMS_SIZE ARRAY_SIZE(EM_SSH_CHIPHER_ALGORITHMS)

/* --------------------------------------------------------------------------------------------- */
static em_ssh_compression_alg_props_t  EM_SSH_COMPRESSION_ALGORITHMS[] = {
    {"none", EM_SSH_COMPRESS_NONE},
};
#define EM_SSH_COMPRESSION_ALGORITHMS_SIZE ARRAY_SIZE(EM_SSH_COMPRESSION_ALGORITHMS)

/**
 *
 **/
int em_ssh_neg_get_server_key_algorithms(em_ssh_mbuf_t *mb, bool clean_mbuf) {
    uint32_t i;

    if(!mb) {
        return EINVAL;
    }

    if(clean_mbuf) {
        em_ssh_mbuf_clear(mb);
    }
    for(i = 0; i < EM_SSH_SERVER_KEY_ALGORITHMS_SIZE; i++) {
        if(i) {
            em_ssh_mbuf_write_str(mb, ",");
        }
        em_ssh_mbuf_write_str(mb, EM_SSH_SERVER_KEY_ALGORITHMS[i].name);
    }
    em_ssh_mbuf_set_pos(mb, 0);
    return OK;
}

/**
 *
 **/
em_ssh_skey_alg_props_t* em_ssh_neg_select_server_key_algorithm(em_ssh_mbuf_t *mb, size_t blen) {
    em_ssh_skey_alg_props_t *result = NULL;
    const char *buf = (void *) mb->buf + mb->pos;
    int slen = 0, tlen, i;

    if(!mb || !mb->end) {
        return NULL;
    }

    tlen = blen;
    while(true) {
        const char *s = (const char *) em_ssh_str_split(buf, tlen, ',', &slen);
        if(slen == 0) { break; }
        for(i = 0; i < EM_SSH_SERVER_KEY_ALGORITHMS_SIZE; i++) {
            const char *op = EM_SSH_SERVER_KEY_ALGORITHMS[i].name;
            if(op != NULL && em_ssh_str_equal(s, slen, op, strlen(op)))  {
                result = &EM_SSH_SERVER_KEY_ALGORITHMS[i];
                break;
            }
        }
        if(result != NULL) {
            break;
        }
        tlen -= (slen + 1);
        if(tlen <= 0) { break; }
        buf = (void *) s + slen + 1;
    }
    return result;
}

/**
 *
 **/
int em_ssh_neg_get_kex_algorithms(em_ssh_mbuf_t *mb, bool clean_mbuf) {
    uint32_t i;

    if(!mb) {
        return EINVAL;
    }

    if(clean_mbuf) {
        em_ssh_mbuf_clear(mb);
    }
    for(i = 0; i < EM_SSH_KEX_ALGORITHMS_SIZE; i++) {
        if(i) {
            em_ssh_mbuf_write_str(mb, ",");
        }
        em_ssh_mbuf_write_str(mb, EM_SSH_KEX_ALGORITHMS[i].name);
    }
    em_ssh_mbuf_set_pos(mb, 0);
    return OK;
}

/**
 *
 **/
em_ssh_kex_alg_props_t* em_ssh_neg_select_kex_algorithm(em_ssh_mbuf_t *mb, size_t blen) {
    em_ssh_kex_alg_props_t *result = NULL;
    const char *buf = (void *) mb->buf + mb->pos;
    int slen = 0, tlen, i;

    if(!mb || !mb->end) {
        return NULL;
    }

    tlen = blen;
    while(true) {
        const char *s = (const char *) em_ssh_str_split(buf, tlen, ',', &slen);
        if(slen == 0) { break; }
        for(i = 0; i < EM_SSH_KEX_ALGORITHMS_SIZE; i++) {
            const char *op = EM_SSH_KEX_ALGORITHMS[i].name;
            if(op != NULL && em_ssh_str_equal(s, slen, op, strlen(op)))  {
                result = &EM_SSH_KEX_ALGORITHMS[i];
                break;
            }
        }
        if(result != NULL) {
            break;
        }
        tlen -= (slen + 1);
        if(tlen <= 0) { break; }
        buf = (void *) s + slen + 1;
    }
    return result;
}

/**
 *
 **/
int em_ssh_neg_get_mac_algorithms(em_ssh_mbuf_t *mb, bool clean_mbuf) {
    uint32_t i;

    if(!mb) {
        return EINVAL;
    }

    if(clean_mbuf) {
        em_ssh_mbuf_clear(mb);
    }

    for(i = 0; i < EM_SSH_MAC_ALGORITHMS_SIZE; i++) {
        if(i) {
            em_ssh_mbuf_write_str(mb, ",");
        }
        em_ssh_mbuf_write_str(mb, EM_SSH_MAC_ALGORITHMS[i].name);
    }
    em_ssh_mbuf_set_pos(mb, 0);
    return OK;
}

/**
 *
 **/
em_ssh_mac_alg_props_t* em_ssh_neg_select_mac_algorithm(em_ssh_mbuf_t *mb, size_t blen) {
    em_ssh_mac_alg_props_t *result = NULL;
    char *buf = (void *) mb->buf + mb->pos;
    int slen = 0, tlen = 0, i;

    if(!mb || !mb->end) {
        return NULL;
    }

    tlen = blen;
    while(true) {
        const char *s = (const char *) em_ssh_str_split(buf, tlen, ',', &slen);
        if(slen == 0) { break; }
        for(i = 0; i < EM_SSH_MAC_ALGORITHMS_SIZE; i++) {
            const char *op = EM_SSH_MAC_ALGORITHMS[i].name;
            if(op != NULL && em_ssh_str_equal(s, slen, op, strlen(op)))  {
                result = &EM_SSH_MAC_ALGORITHMS[i];
                break;
            }
        }
        if(result != NULL) {
            break;
        }
        tlen -= (slen + 1);
        if(tlen <= 0) { break; }
        buf = (void *) s + slen + 1;
    }
    return result;
}

/**
 *
 **/
int em_ssh_neg_get_cipher_algorithms(em_ssh_mbuf_t *mb, bool clean_mbuf) {
    uint32_t i;

    if(!mb) {
        return EINVAL;
    }

    if(clean_mbuf) {
        em_ssh_mbuf_clear(mb);
    }
    for(i = 0; i < EM_SSH_CHIPHER_ALGORITHMS_SIZE; i++) {
        if(i) {
            em_ssh_mbuf_write_str(mb, ",");
        }
        em_ssh_mbuf_write_str(mb, EM_SSH_CHIPHER_ALGORITHMS[i].name);
    }
    em_ssh_mbuf_set_pos(mb, 0);
    return OK;
}

/**
 *
 **/
em_ssh_cipher_alg_props_t* em_ssh_neg_select_chipher_algorithm(em_ssh_mbuf_t *mb, size_t blen) {
    em_ssh_cipher_alg_props_t *result = NULL;
    const char *buf = (void *) mb->buf + mb->pos;
    int slen = 0, tlen, i;

    if(!mb || !mb->end) {
        return NULL;
    }

    tlen = blen;
    while(true) {
        const char *s = (const char *) em_ssh_str_split(buf, tlen, ',', &slen);
        if(slen == 0) { break; }
        for(i = 0; i < EM_SSH_CHIPHER_ALGORITHMS_SIZE; i++) {
            const char *op = EM_SSH_CHIPHER_ALGORITHMS[i].name;
            if(op != NULL && em_ssh_str_equal(s, slen, op, strlen(op)))  {
                result = &EM_SSH_CHIPHER_ALGORITHMS[i];
                break;
            }
        }
        if(result != NULL) {
            break;
        }
        tlen -= (slen + 1);
        if(tlen <= 0) { break; }
        buf = (void *) s + slen + 1;

    }
    return result;
}


/**
 *
 **/
int em_ssh_neg_get_compression_algorithms(em_ssh_mbuf_t *mb, bool clean_mbuf) {
    uint32_t i;

    if(!mb) {
        return EINVAL;
    }

    if(clean_mbuf) {
        em_ssh_mbuf_clear(mb);
    }
    for(i = 0; i < EM_SSH_COMPRESSION_ALGORITHMS_SIZE; i++) {
        if(i) {
            em_ssh_mbuf_write_str(mb, ",");
        }
        em_ssh_mbuf_write_str(mb, EM_SSH_COMPRESSION_ALGORITHMS[i].name);
    }
    em_ssh_mbuf_set_pos(mb, 0);
    return OK;
}

/**
 *
 **/
em_ssh_compression_alg_props_t* em_ssh_neg_select_compression_algorithm(em_ssh_mbuf_t *mb, size_t blen) {
    em_ssh_compression_alg_props_t *result = NULL;
    const char *buf = (void *) mb->buf + mb->pos;
    int slen, tlen, i;

    if(!mb || !mb->end) {
        return NULL;
    }

    tlen = blen;
    while(true) {
        const char *s = (const char *) em_ssh_str_split(buf, tlen, ',', &slen);
        if(slen == 0) { break; }
        for(i = 0; i < EM_SSH_COMPRESSION_ALGORITHMS_SIZE; i++) {
            const char *op = EM_SSH_COMPRESSION_ALGORITHMS[i].name;
            if(op != NULL && em_ssh_str_equal(s, slen, op, strlen(op)))  {
                result = &EM_SSH_COMPRESSION_ALGORITHMS[i];
                break;
            }
        }
        if(result != NULL) {
            break;
        }
        tlen -= (slen + 1);
        if(tlen <= 0) { break; }
        buf = (void *) s + slen + 1;
    }
    return result;
}
