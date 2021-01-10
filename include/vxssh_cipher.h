/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_CIPHER_H
#define VXSSH_CIPHER_H

#include <vxWorks.h>
#include "vxssh_ctype.h"

#define VXSSH_CIPHER_BLOCK_SIZE_MIN    8
#define VXSSH_CIPHER_BLOCK_SIZE_MAX    32  /* 64 for chacha */
#define VXSSH_CIPHER_AES_BLOCK_SIZE    16

#define VXSSH_CIPHER_MODE_NONE 0
#define VXSSH_CIPHER_MODE_CBC  1
#define VXSSH_CIPHER_MODE_CTR  2

#define VXSSH_CIPHER_AES       1
#define VXSSH_CIPHER_CHAHCA    2

/* ------------------------------------------------------------------------------------------ */
struct _RIJNDAEL_CTX;
typedef struct _RIJNDAEL_CTX vxssh_aes_ctx_t;

size_t vxssh_aes_block_len();
size_t vxssh_aes_ctx_size();

int vxssh_aes_alloc(vxssh_aes_ctx_t **ctx);
int vxssh_aes_init(vxssh_aes_ctx_t *ctx, uint8_t *key, size_t klen, bool decrypt);
int vxssh_aes_process_block(vxssh_aes_ctx_t *ctx, uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

/* ------------------------------------------------------------------------------------------ */
struct vx_ssh_chacha_ctx_s;
typedef struct vx_ssh_chacha_ctx_s vx_ssh_chacha_ctx_t;


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

} vxssh_cipher_ctx_t;

int vxssh_cipher_alloc(vxssh_cipher_ctx_t **ctx, vxssh_cipher_alg_props_t *cipher_props, bool decrypt);
int vxssh_cipher_init(vxssh_cipher_ctx_t *ctx);
int vxssh_cipher_encrypt(vxssh_cipher_ctx_t *ctx, uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);
int vxssh_cipher_decrypt(vxssh_cipher_ctx_t *ctx, uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);


#endif

