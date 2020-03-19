/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_CIPHER_H
#define EMSSH_CIPHER_H

#include <vxWorks.h>
#include "emssh_ctype.h"

#define EM_SSH_CIPHER_BLOCK_SIZE_MIN    8
#define EM_SSH_CIPHER_BLOCK_SIZE_MAX    32  /* 64 for chacha */
#define EM_SSH_CIPHER_AES_BLOCK_SIZE    16

#define EM_SSH_CIPHER_MODE_NONE 0
#define EM_SSH_CIPHER_MODE_CBC  1
#define EM_SSH_CIPHER_MODE_CTR  2

#define EM_SSH_CIPHER_AES       1
//#define EM_SSH_CIPHER_CHAHCA    2

/* ------------------------------------------------------------------------------------------ */
struct _RIJNDAEL_CTX;
typedef struct _RIJNDAEL_CTX em_ssh_aes_ctx_t;

size_t em_ssh_aes_block_len();
size_t em_ssh_aes_ctx_size();

int em_ssh_aes_alloc(em_ssh_aes_ctx_t **ctx);
int em_ssh_aes_init(em_ssh_aes_ctx_t *ctx, uint8_t *key, size_t klen, bool decrypt);
int em_ssh_aes_process_block(em_ssh_aes_ctx_t *ctx, uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

/* ------------------------------------------------------------------------------------------ */
typedef struct {
    int         type;
    int         mode;
    bool        decrypt;
    size_t      block_len;
    size_t      key_len;
    size_t      iv_len;
    uint8_t     *key;
    uint8_t     *iv;
    void        *cipher;

} em_ssh_cipher_ctx_t;

int em_ssh_cipher_alloc(em_ssh_cipher_ctx_t **ctx, em_ssh_cipher_alg_props_t *cipher_props, bool decrypt);
int em_ssh_cipher_init(em_ssh_cipher_ctx_t *ctx);
int em_ssh_cipher_encrypt(em_ssh_cipher_ctx_t *ctx, uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);
int em_ssh_cipher_decrypt(em_ssh_cipher_ctx_t *ctx, uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);


#endif

