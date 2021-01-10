/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_CTYPTO_H
#define VXSSH_CTYPTO_H
#include <vxWorks.h>
#include "vxssh_ctype.h"
#include "mini-gmp.h"

/* ------------------------------------------------------------------------------------------------------------------------------------------- */
/* Objects */
#define CRYPTO_OBJECT_NONE             0x0
#define CRYPTO_OBJECT_RSA_PRIVATE_KEY  0x1
#define CRYPTO_OBJECT_RSA_PUBLIC_KEY   0x2
#define CRYPTO_OBJECT_RSA_SIGNATURE    0x3

typedef struct {
    int     type;
    void    *obj;
} vxssh_crypto_object_t;

typedef struct {
    mpz_t   e;
    mpz_t   n;
} vxssh_crypto_rsa_public_key_t;

typedef struct {
    mpz_t   e;
    mpz_t   n;
    mpz_t   d;
} vxssh_crypto_rsa_private_key_t;

typedef struct {
    mpz_t   s;
} vxssh_crypto_rsa_signature_t;

int vxssh_crypto_object_alloc(vxssh_crypto_object_t **obj, int type);

/* ------------------------------------------------------------------------------------------------------------------------------------------- */
/* RSA */
int vxssh_rsa_encode_public_key(vxssh_mbuf_t *mb, vxssh_crypto_rsa_public_key_t *key);
int vxssh_rsa_encode_public_key2(vxssh_mbuf_t *mb, vxssh_crypto_rsa_private_key_t *key);
int vxssh_rsa_decode_public_key(vxssh_mbuf_t *mb, vxssh_crypto_rsa_public_key_t *key);
int vxssh_rsa_encode_signature(vxssh_mbuf_t *mb, vxssh_crypto_rsa_signature_t *sign);
int vxssh_rsa_decode_signature(vxssh_mbuf_t *mb, vxssh_crypto_rsa_signature_t *sign);
int vxssh_rsa_sign(vxssh_crypto_rsa_private_key_t *key, const uint8_t *data, size_t data_len, vxssh_crypto_object_t **signature);
int vxssh_rsa_sign_verfy(vxssh_crypto_rsa_public_key_t *key, vxssh_crypto_object_t *signature, const uint8_t *data, size_t data_len);

/* ------------------------------------------------------------------------------------------------------------------------------------------- */
/* PEM */
int vxssh_pem_decode(char *buffer, size_t buffer_len, char *passphrase, vxssh_crypto_object_t **key);

/* ------------------------------------------------------------------------------------------------------------------------------------------- */
/* ASN.1 */
int vxssh_asn1_get_sequece(vxssh_mbuf_t *mb, char **buf, size_t *buf_len);
int vxssh_asn1_get_bitstr(vxssh_mbuf_t *mb, char **buf, size_t *buf_len);
int vxssh_asn1_get_integer(vxssh_mbuf_t *mb, mpz_t bn);

/* ------------------------------------------------------------------------------------------------------------------------------------------- */
/* curve25519 */
#define CRYPTO_CURVE25519_SIZE 32
int vxssh_scalarmult_curve25519(unsigned char *q, const unsigned char *n, const unsigned char *p);

/* ------------------------------------------------------------------------------------------------------------------------------------------- */
/* RND */
int vxssh_ran_init();
int vxssh_rnd_bin(char *buf, size_t size);

#endif
