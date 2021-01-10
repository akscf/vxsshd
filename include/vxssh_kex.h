/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_KEX_H
#define VXSSH_KEX_H

#include <vxWorks.h>
#include "vxssh_ctype.h"
#include "vxssh_crypto.h"

#define VXSSH_KEX_C25519_SHA256  1

typedef struct {
    vxssh_cipher_ctx_t *enc;
    vxssh_mac_ctx_t    *mac;
    //vxssh_comp_ctx_t   *comp;
} vxssh_kex_newkeys_t;

typedef struct {
    int     keyringing;
    int     hash_alg;
    int     we_need;
    vxssh_kex_newkeys_t keys_in;
    vxssh_kex_newkeys_t keys_out;
    //
    uint8_t     *session_id;
    size_t      session_id_len;
    //
    uint8_t     *client_version;
    uint8_t     *server_version;
    size_t      client_version_len;
    size_t      server_version_len;
    //
    uint8_t     *client_kex_init;
    uint8_t     *server_kex_init;
    size_t      client_kex_init_len;
    size_t      server_kex_init_len;
    //
    uint32_t                        first_follows;
    vxssh_kex_alg_props_t          *kex_algorithm;
    vxssh_skey_alg_props_t         *server_key_algorithm;
    vxssh_cipher_alg_props_t       *cipher_algorithm;
    vxssh_mac_alg_props_t          *mac_algorithm;
    vxssh_compression_alg_props_t  *compresion_algorithm;
} vxssh_kex_t;

/* kex */
int vxssh_kex_alloc(vxssh_kex_t **kex);
int vxssh_kex_newkeys_realloc(vxssh_kex_t *kex);
int vxssh_kex_newkeys_init(vxssh_kex_t *kex);

int vxssh_kex_derive_keys(vxssh_kex_t *kex, uint8_t *hash, size_t hashlen, uint8_t *shared_secret, size_t shared_secret_len);

/* kex25519 */
int vxssh_kex_c25519_keygen(uint8_t *key, uint8_t *pub);
int vxssh_kex_c25519_shared_key(const uint8_t *key, const uint8_t *pub, uint8_t **out, size_t *out_len);
int vxssh_kex_c25519_hash(int hash_alg,
    const uint8_t *client_version_string, size_t client_version_string_len,
    const uint8_t *server_version_string, size_t server_version_string_len,
    const uint8_t *ckexinit, size_t ckexinitlen,
    const uint8_t *skexinit, size_t skexinitlen,
    const uint8_t *serverhostkeyblob, size_t sbloblen,
    const uint8_t client_dh_pub[CRYPTO_CURVE25519_SIZE],
    const uint8_t server_dh_pub[CRYPTO_CURVE25519_SIZE],
    const uint8_t *shared_secret, size_t shared_secret_len,
    uint8_t *hash, size_t hashlen);


#endif
