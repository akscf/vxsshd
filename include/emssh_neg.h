/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_CONF_H
#define EMSSH_CONF_H
#include <vxWorks.h>
#include "emssh_ctype.h"

typedef struct {
    char        *name;
} em_ssh_skey_alg_props_t;

typedef struct {
    char    *name;
    int     type;
    int     hash_alg;
    int     digest_len;
} em_ssh_kex_alg_props_t;

typedef struct {
    char    *name;
    int     mac_type;       /* mac/hmac/umac/... */
    int     mac_alg;        /* md5/sha1/sha2/... */
    int     digest_len;     /* */
    int     truncatebits;   /* truncate digest if != 0 */
    int     etm;            /* Encrypt-then-MAC */
} em_ssh_mac_alg_props_t;

typedef struct {
    char   *name;
    int     type;           /* aes/des/chacha/... */
    int     mode;           /* cbc/ctr/... */
    int     block_len;
    int     key_len;
    int     flags;
} em_ssh_cipher_alg_props_t;

typedef struct {
    char   *name;
    int     type;
} em_ssh_compression_alg_props_t;

int em_ssh_neg_get_server_key_algorithms(em_ssh_mbuf_t *mb, bool clean_mbuf);
int em_ssh_neg_get_kex_algorithms(em_ssh_mbuf_t *mb, bool clean_mbuf);
int em_ssh_neg_get_mac_algorithms(em_ssh_mbuf_t *mb, bool clean_mbuf);
int em_ssh_neg_get_cipher_algorithms(em_ssh_mbuf_t *mb, bool clean_mbuf);
int em_ssh_neg_get_compression_algorithms(em_ssh_mbuf_t *mb, bool clean_mbuf);

em_ssh_skey_alg_props_t* em_ssh_neg_select_server_key_algorithm(em_ssh_mbuf_t *mb, size_t blen);
em_ssh_kex_alg_props_t* em_ssh_neg_select_kex_algorithm(em_ssh_mbuf_t *mb, size_t blen);
em_ssh_mac_alg_props_t* em_ssh_neg_select_mac_algorithm(em_ssh_mbuf_t *mb, size_t blen);
em_ssh_cipher_alg_props_t* em_ssh_neg_select_chipher_algorithm(em_ssh_mbuf_t *mb, size_t blen);
em_ssh_compression_alg_props_t* em_ssh_neg_select_compression_algorithm(em_ssh_mbuf_t *mb, size_t blen);

#endif
