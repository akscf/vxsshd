/**
 * based on OpenSSH
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

/**
 * key - private key
 * pub - public key
 **/
int em_ssh_kex_c25519_keygen(uint8_t key[CRYPTO_CURVE25519_SIZE], uint8_t pub[CRYPTO_CURVE25519_SIZE]) {
    static const uint8_t basepoint[CRYPTO_CURVE25519_SIZE] = {9};

    em_ssh_rnd_bin((char *)key, CRYPTO_CURVE25519_SIZE);
    em_ssh_scalarmult_curve25519(pub, (const unsigned char *)key, basepoint);

    return OK;
}

/**
 * key - server pivate key
 * pub - client public key
 * out - shared secret (wrapped)
 **/
int em_ssh_kex_c25519_shared_key(const uint8_t key[CRYPTO_CURVE25519_SIZE], const uint8_t pub[CRYPTO_CURVE25519_SIZE], uint8_t **out, size_t *out_len) {
    uint8_t shared_key[CRYPTO_CURVE25519_SIZE];
    size_t len = 0, tlen = 0, prepend = 0;
    uint8_t *s = (void *)shared_key;
    uint8_t *t = NULL;

    if(!out) {
        return EINVAL;
    }

    explicit_bzero(shared_key, CRYPTO_CURVE25519_SIZE);
    if (timingsafe_bcmp(pub, shared_key, CRYPTO_CURVE25519_SIZE) == 0) {
        return ERROR;
    }
    em_ssh_scalarmult_curve25519(shared_key, key, pub);

    len = sizeof(shared_key);
    for (; len > 0 && *s == 0; len--, s++){};
    if(len == 0) { return ERROR; }
    prepend = len > 0 && (s[0] & 0x80) != 0;
    tlen = len + prepend;
    if((t = em_ssh_mem_alloc(tlen + 4, NULL)) == NULL) {
        return ENOMEM;
    }
    /* len */
    t[0] = (tlen >> 24) & 0xff;
    t[1] = (tlen >> 16) & 0xff;
    t[2] = (tlen >> 8) & 0xff;
    t[3] = tlen & 0xff;

    /* lead zero */
    if(prepend) t[4] = 0x0;
    memcpy(t + prepend + 4, s, len);

    *out = t;
    *out_len = (tlen + 4);

    explicit_bzero(shared_key, CRYPTO_CURVE25519_SIZE);
    return OK;
}

/**
 *
 **/
int em_ssh_kex_c25519_hash(
    int hash_alg,
    const uint8_t *client_version_string, size_t client_version_string_len,
    const uint8_t *server_version_string, size_t server_version_string_len,
    const uint8_t *ckexinit, size_t ckexinitlen,
    const uint8_t *skexinit, size_t skexinitlen,
    const uint8_t *serverhostkeyblob, size_t sbloblen,
    const uint8_t client_dh_pub[CRYPTO_CURVE25519_SIZE],
    const uint8_t server_dh_pub[CRYPTO_CURVE25519_SIZE],
    const uint8_t *shared_secret, size_t shared_secret_len,
    uint8_t *hash, size_t hashlen) {

    int err = OK;
    em_ssh_mbuf_t *mbuf = NULL;

    if((err = em_ssh_mbuf_alloc(&mbuf, (client_version_string_len + server_version_string_len + ckexinitlen + skexinitlen  + sbloblen + CRYPTO_CURVE25519_SIZE + CRYPTO_CURVE25519_SIZE + shared_secret_len))) != OK) {
        goto out;
    }

    em_ssh_mbuf_write_mem_sz(mbuf, (const uint8_t *)client_version_string, client_version_string_len);
    em_ssh_mbuf_write_mem_sz(mbuf, (const uint8_t *)server_version_string, server_version_string_len);
    /* kexinit c/s*/
    em_ssh_mbuf_write_mem_sz(mbuf, ckexinit, ckexinitlen);
    em_ssh_mbuf_write_mem_sz(mbuf, skexinit, skexinitlen);
    /* hostkey */
    em_ssh_mbuf_write_mem_sz(mbuf, serverhostkeyblob, sbloblen);
    /* session key */
    em_ssh_mbuf_write_mem_sz(mbuf, client_dh_pub, CRYPTO_CURVE25519_SIZE);
    em_ssh_mbuf_write_mem_sz(mbuf, server_dh_pub, CRYPTO_CURVE25519_SIZE);
    /* wrapped */
    em_ssh_mbuf_write_mem(mbuf, shared_secret, shared_secret_len);

    /* make digest */
    err = em_ssh_mbuf_digest(mbuf, hash_alg, hash, hashlen);

out:
    em_ssh_mem_deref(mbuf);
    return err;
}
