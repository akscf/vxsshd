/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

static vxssh_skey_alg_props_t  VXSSH_SERVER_KEY_ALGORITHMS[] = {
    {"ssh-rsa"}
};
#define VXSSH_SERVER_KEY_ALGORITHMS_SIZE ARRAY_SIZE(VXSSH_SERVER_KEY_ALGORITHMS)

/* --------------------------------------------------------------------------------------------- */
static vxssh_kex_alg_props_t  VXSSH_KEX_ALGORITHMS[] = {
      {"curve25519-sha256@libssh.org", VXSSH_KEX_C25519_SHA256, VXSSH_DIGEST_SHA256, VXSSH_DIGEST_SHA256_LENGTH }
};
#define VXSSH_KEX_ALGORITHMS_SIZE ARRAY_SIZE(VXSSH_KEX_ALGORITHMS)

/* --------------------------------------------------------------------------------------------- */
static vxssh_mac_alg_props_t  VXSSH_MAC_ALGORITHMS[] = {
/*     name          | type            | digest alg       | digest len              | truncatebits */
    {"hmac-sha1-96"  , VXSSH_MAC_DIGEST, VXSSH_DIGEST_SHA1, VXSSH_DIGEST_SHA1_LENGTH, 96},
    {"hmac-sha1"     , VXSSH_MAC_DIGEST, VXSSH_DIGEST_SHA1, VXSSH_DIGEST_SHA1_LENGTH, 00},
    {"hmac-md5-96"   , VXSSH_MAC_DIGEST, VXSSH_DIGEST_MD5,  VXSSH_DIGEST_MD5_LENGTH,  96},
    {"hmac-md5"      , VXSSH_MAC_DIGEST, VXSSH_DIGEST_MD5,  VXSSH_DIGEST_MD5_LENGTH,  00}
};
#define VXSSH_MAC_ALGORITHMS_SIZE ARRAY_SIZE(VXSSH_MAC_ALGORITHMS)

/* --------------------------------------------------------------------------------------------- */
static vxssh_cipher_alg_props_t  VXSSH_CHIPHER_ALGORITHMS[] = {
/*     name        | type            | mode                 | block size                 | key len | flags */
    {"aes256-cbc"  , VXSSH_CIPHER_AES, VXSSH_CIPHER_MODE_CBC, VXSSH_CIPHER_AES_BLOCK_SIZE, 32      , 0},
    {"aes192-cbc"  , VXSSH_CIPHER_AES, VXSSH_CIPHER_MODE_CBC, VXSSH_CIPHER_AES_BLOCK_SIZE, 24      , 0},
    {"aes128-cbc"  , VXSSH_CIPHER_AES, VXSSH_CIPHER_MODE_CBC, VXSSH_CIPHER_AES_BLOCK_SIZE, 16      , 0},
    {"aes256-ctr"  , VXSSH_CIPHER_AES, VXSSH_CIPHER_MODE_CTR, VXSSH_CIPHER_AES_BLOCK_SIZE, 32      , 0},
    {"aes192-ctr"  , VXSSH_CIPHER_AES, VXSSH_CIPHER_MODE_CTR, VXSSH_CIPHER_AES_BLOCK_SIZE, 24      , 0},
    {"aes128-ctr"  , VXSSH_CIPHER_AES, VXSSH_CIPHER_MODE_CTR, VXSSH_CIPHER_AES_BLOCK_SIZE, 16      , 0}
};
#define VXSSH_CHIPHER_ALGORITHMS_SIZE ARRAY_SIZE(VXSSH_CHIPHER_ALGORITHMS)

/* --------------------------------------------------------------------------------------------- */
static vxssh_compression_alg_props_t  VXSSH_COMPRESSION_ALGORITHMS[] = {
    {"none", VXSSH_COMPRESS_NONE},
};
#define VXSSH_COMPRESSION_ALGORITHMS_SIZE ARRAY_SIZE(VXSSH_COMPRESSION_ALGORITHMS)

/**
 *
 **/
int vxssh_neg_get_server_key_algorithms(vxssh_mbuf_t *mb, bool clean_mbuf) {
    uint32_t i;

    if(!mb) {
        return EINVAL;
    }

    if(clean_mbuf) {
        vxssh_mbuf_clear(mb);
    }
    for(i = 0; i < VXSSH_SERVER_KEY_ALGORITHMS_SIZE; i++) {
        if(i) {
            vxssh_mbuf_write_str(mb, ",");
        }
        vxssh_mbuf_write_str(mb, VXSSH_SERVER_KEY_ALGORITHMS[i].name);
    }
    vxssh_mbuf_set_pos(mb, 0);
    return OK;
}

/**
 *
 **/
vxssh_skey_alg_props_t* vxssh_neg_select_server_key_algorithm(vxssh_mbuf_t *mb, size_t blen) {
    vxssh_skey_alg_props_t *result = NULL;
    const char *buf = (void *) mb->buf + mb->pos;
    int slen = 0, tlen, i;

    if(!mb || !mb->end) {
        return NULL;
    }

    tlen = blen;
    while(true) {
        const char *s = (const char *) vxssh_str_split(buf, tlen, ',', &slen);
        if(slen == 0) { break; }
        for(i = 0; i < VXSSH_SERVER_KEY_ALGORITHMS_SIZE; i++) {
            const char *op = VXSSH_SERVER_KEY_ALGORITHMS[i].name;
            if(op != NULL && vxssh_str_equal(s, slen, op, strlen(op)))  {
                result = &VXSSH_SERVER_KEY_ALGORITHMS[i];
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
int vxssh_neg_get_kex_algorithms(vxssh_mbuf_t *mb, bool clean_mbuf) {
    uint32_t i;

    if(!mb) {
        return EINVAL;
    }

    if(clean_mbuf) {
        vxssh_mbuf_clear(mb);
    }
    for(i = 0; i < VXSSH_KEX_ALGORITHMS_SIZE; i++) {
        if(i) {
            vxssh_mbuf_write_str(mb, ",");
        }
        vxssh_mbuf_write_str(mb, VXSSH_KEX_ALGORITHMS[i].name);
    }
    vxssh_mbuf_set_pos(mb, 0);
    return OK;
}

/**
 *
 **/
vxssh_kex_alg_props_t* vxssh_neg_select_kex_algorithm(vxssh_mbuf_t *mb, size_t blen) {
    vxssh_kex_alg_props_t *result = NULL;
    const char *buf = (void *) mb->buf + mb->pos;
    int slen = 0, tlen, i;

    if(!mb || !mb->end) {
        return NULL;
    }

    tlen = blen;
    while(true) {
        const char *s = (const char *) vxssh_str_split(buf, tlen, ',', &slen);
        if(slen == 0) { break; }
        for(i = 0; i < VXSSH_KEX_ALGORITHMS_SIZE; i++) {
            const char *op = VXSSH_KEX_ALGORITHMS[i].name;
            if(op != NULL && vxssh_str_equal(s, slen, op, strlen(op)))  {
                result = &VXSSH_KEX_ALGORITHMS[i];
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
int vxssh_neg_get_mac_algorithms(vxssh_mbuf_t *mb, bool clean_mbuf) {
    uint32_t i;

    if(!mb) {
        return EINVAL;
    }

    if(clean_mbuf) {
        vxssh_mbuf_clear(mb);
    }

    for(i = 0; i < VXSSH_MAC_ALGORITHMS_SIZE; i++) {
        if(i) {
            vxssh_mbuf_write_str(mb, ",");
        }
        vxssh_mbuf_write_str(mb, VXSSH_MAC_ALGORITHMS[i].name);
    }
    vxssh_mbuf_set_pos(mb, 0);
    return OK;
}

/**
 *
 **/
vxssh_mac_alg_props_t* vxssh_neg_select_mac_algorithm(vxssh_mbuf_t *mb, size_t blen) {
    vxssh_mac_alg_props_t *result = NULL;
    char *buf = (void *) mb->buf + mb->pos;
    int slen = 0, tlen = 0, i;

    if(!mb || !mb->end) {
        return NULL;
    }

    tlen = blen;
    while(true) {
        const char *s = (const char *) vxssh_str_split(buf, tlen, ',', &slen);
        if(slen == 0) { break; }
        for(i = 0; i < VXSSH_MAC_ALGORITHMS_SIZE; i++) {
            const char *op = VXSSH_MAC_ALGORITHMS[i].name;
            if(op != NULL && vxssh_str_equal(s, slen, op, strlen(op)))  {
                result = &VXSSH_MAC_ALGORITHMS[i];
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
int vxssh_neg_get_cipher_algorithms(vxssh_mbuf_t *mb, bool clean_mbuf) {
    uint32_t i;

    if(!mb) {
        return EINVAL;
    }

    if(clean_mbuf) {
        vxssh_mbuf_clear(mb);
    }
    for(i = 0; i < VXSSH_CHIPHER_ALGORITHMS_SIZE; i++) {
        if(i) {
            vxssh_mbuf_write_str(mb, ",");
        }
        vxssh_mbuf_write_str(mb, VXSSH_CHIPHER_ALGORITHMS[i].name);
    }
    vxssh_mbuf_set_pos(mb, 0);
    return OK;
}

/**
 *
 **/
vxssh_cipher_alg_props_t* vxssh_neg_select_chipher_algorithm(vxssh_mbuf_t *mb, size_t blen) {
    vxssh_cipher_alg_props_t *result = NULL;
    const char *buf = (void *) mb->buf + mb->pos;
    int slen = 0, tlen, i;

    if(!mb || !mb->end) {
        return NULL;
    }

    tlen = blen;
    while(true) {
        const char *s = (const char *) vxssh_str_split(buf, tlen, ',', &slen);
        if(slen == 0) { break; }
        for(i = 0; i < VXSSH_CHIPHER_ALGORITHMS_SIZE; i++) {
            const char *op = VXSSH_CHIPHER_ALGORITHMS[i].name;
            if(op != NULL && vxssh_str_equal(s, slen, op, strlen(op)))  {
                result = &VXSSH_CHIPHER_ALGORITHMS[i];
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
int vxssh_neg_get_compression_algorithms(vxssh_mbuf_t *mb, bool clean_mbuf) {
    uint32_t i;

    if(!mb) {
        return EINVAL;
    }

    if(clean_mbuf) {
        vxssh_mbuf_clear(mb);
    }
    for(i = 0; i < VXSSH_COMPRESSION_ALGORITHMS_SIZE; i++) {
        if(i) {
            vxssh_mbuf_write_str(mb, ",");
        }
        vxssh_mbuf_write_str(mb, VXSSH_COMPRESSION_ALGORITHMS[i].name);
    }
    vxssh_mbuf_set_pos(mb, 0);
    return OK;
}

/**
 *
 **/
vxssh_compression_alg_props_t* vxssh_neg_select_compression_algorithm(vxssh_mbuf_t *mb, size_t blen) {
    vxssh_compression_alg_props_t *result = NULL;
    const char *buf = (void *) mb->buf + mb->pos;
    int slen, tlen, i;

    if(!mb || !mb->end) {
        return NULL;
    }

    tlen = blen;
    while(true) {
        const char *s = (const char *) vxssh_str_split(buf, tlen, ',', &slen);
        if(slen == 0) { break; }
        for(i = 0; i < VXSSH_COMPRESSION_ALGORITHMS_SIZE; i++) {
            const char *op = VXSSH_COMPRESSION_ALGORITHMS[i].name;
            if(op != NULL && vxssh_str_equal(s, slen, op, strlen(op)))  {
                result = &VXSSH_COMPRESSION_ALGORITHMS[i];
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
