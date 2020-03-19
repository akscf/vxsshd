/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_CTYPTO_H
#define EMSSH_CTYPTO_H
#include <vxWorks.h>
#include "emssh_ctype.h"
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
} em_ssh_crypto_object_t;

typedef struct {
    mpz_t   e;
    mpz_t   n;
} em_ssh_crypto_rsa_public_key_t;

typedef struct {
    mpz_t   e;
    mpz_t   n;
    mpz_t   d;
} em_ssh_crypto_rsa_private_key_t;

typedef struct {
    mpz_t   s;
} em_ssh_crypto_rsa_signature_t;

int em_ssh_crypto_object_alloc(em_ssh_crypto_object_t **obj, int type);

/* ------------------------------------------------------------------------------------------------------------------------------------------- */
/* RSA */
int em_ssh_rsa_encode_public_key(em_ssh_mbuf_t *mb, em_ssh_crypto_rsa_public_key_t *key);
int em_ssh_rsa_encode_public_key2(em_ssh_mbuf_t *mb, em_ssh_crypto_rsa_private_key_t *key);
int em_ssh_rsa_decode_public_key(em_ssh_mbuf_t *mb, em_ssh_crypto_rsa_public_key_t *key);
int em_ssh_rsa_encode_signature(em_ssh_mbuf_t *mb, em_ssh_crypto_rsa_signature_t *sign);
int em_ssh_rsa_decode_signature(em_ssh_mbuf_t *mb, em_ssh_crypto_rsa_signature_t *sign);
int em_ssh_rsa_sign(em_ssh_crypto_rsa_private_key_t *key, const uint8_t *data, size_t data_len, em_ssh_crypto_object_t **signature);
int em_ssh_rsa_sign_verfy(em_ssh_crypto_rsa_public_key_t *key, em_ssh_crypto_object_t *signature, const uint8_t *data, size_t data_len);

/* ------------------------------------------------------------------------------------------------------------------------------------------- */
/* PEM */
int em_ssh_pem_decode(char *buffer, size_t buffer_len, char *passphrase, em_ssh_crypto_object_t **key);

/* ------------------------------------------------------------------------------------------------------------------------------------------- */
/* ASN.1 */
int em_ssh_asn1_get_sequece(em_ssh_mbuf_t *mb, char **buf, size_t *buf_len);
int em_ssh_asn1_get_bitstr(em_ssh_mbuf_t *mb, char **buf, size_t *buf_len);
int em_ssh_asn1_get_integer(em_ssh_mbuf_t *mb, mpz_t bn);

/* ------------------------------------------------------------------------------------------------------------------------------------------- */
/* curve25519 */
#define CRYPTO_CURVE25519_SIZE 32
int em_ssh_scalarmult_curve25519(unsigned char *q, const unsigned char *n, const unsigned char *p);

/* ------------------------------------------------------------------------------------------------------------------------------------------- */
/* RND */
int em_ssh_ran_init();
int em_ssh_rnd_bin(char *buf, size_t size);

#endif
