/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_CONF_H
#define VXSSH_CONF_H
#include <vxWorks.h>
#include "vxssh_ctype.h"

typedef struct {
    char        *name;
} vxssh_skey_alg_props_t;

typedef struct {
    char    *name;
    int     type;
    int     hash_alg;
    int     digest_len;
} vxssh_kex_alg_props_t;

typedef struct {
    char    *name;
    int     mac_type;       /* mac/hmac/umac/... */
    int     mac_alg;        /* md5/sha1/sha2/... */
    int     digest_len;     /* */
    int     truncatebits;   /* truncate digest if != 0 */
    int     etm;            /* Encrypt-then-MAC */
} vxssh_mac_alg_props_t;

typedef struct {
    char   *name;
    int     type;           /* aes/des/chacha/... */
    int     mode;           /* cbc/ctr/... */
    int     block_len;
    int     key_len;
    int     flags;
} vxssh_cipher_alg_props_t;

typedef struct {
    char   *name;
    int     type;
} vxssh_compression_alg_props_t;

int vxssh_neg_get_server_key_algorithms(vxssh_mbuf_t *mb, bool clean_mbuf);
int vxssh_neg_get_kex_algorithms(vxssh_mbuf_t *mb, bool clean_mbuf);
int vxssh_neg_get_mac_algorithms(vxssh_mbuf_t *mb, bool clean_mbuf);
int vxssh_neg_get_cipher_algorithms(vxssh_mbuf_t *mb, bool clean_mbuf);
int vxssh_neg_get_compression_algorithms(vxssh_mbuf_t *mb, bool clean_mbuf);

vxssh_skey_alg_props_t* vxssh_neg_select_server_key_algorithm(vxssh_mbuf_t *mb, size_t blen);
vxssh_kex_alg_props_t* vxssh_neg_select_kex_algorithm(vxssh_mbuf_t *mb, size_t blen);
vxssh_mac_alg_props_t* vxssh_neg_select_mac_algorithm(vxssh_mbuf_t *mb, size_t blen);
vxssh_cipher_alg_props_t* vxssh_neg_select_chipher_algorithm(vxssh_mbuf_t *mb, size_t blen);
vxssh_compression_alg_props_t* vxssh_neg_select_compression_algorithm(vxssh_mbuf_t *mb, size_t blen);

#endif
