/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_MBUF_H
#define VXSSH_MBUF_H

#include <vxWorks.h>

typedef struct {
    uint8_t *buf;
    size_t  size;
    size_t  pos;
    size_t  end;
} vxssh_mbuf_t;

// --------------------------------------------------------------------------------------------------
size_t vxssh_mbuf_get_left(vxssh_mbuf_t *mb);
size_t vxssh_mbuf_get_space(vxssh_mbuf_t *mb);
int vxssh_mbuf_set_pos(vxssh_mbuf_t *mb, size_t pos);

int vxssh_mbuf_alloc(vxssh_mbuf_t **mb, size_t size);
int vxssh_mbuf_resize(vxssh_mbuf_t *mb, size_t size);
int vxssh_mbuf_trim(vxssh_mbuf_t *mb);
int vxssh_mbuf_clear(vxssh_mbuf_t *mb);
int vxssh_mbuf_fill(vxssh_mbuf_t *mb, uint8_t ch, size_t size);
int vxssh_mbuf_strdup(vxssh_mbuf_t *mb, char **strp, size_t *len);
int vxssh_mbuf_digest(vxssh_mbuf_t *mb, int hash_alg, uint8_t *digest, size_t digest_len);

int vxssh_mbuf_write_mem(vxssh_mbuf_t *mb, const uint8_t *buf, size_t size);
int vxssh_mbuf_write_u8(vxssh_mbuf_t *mb, uint8_t v);
int vxssh_mbuf_write_u16(vxssh_mbuf_t *mb, uint16_t v);
int vxssh_mbuf_write_u32(vxssh_mbuf_t *mb, uint32_t v);
int vxssh_mbuf_write_str(vxssh_mbuf_t *mb, const char *str);
int vxssh_mbuf_write_zstr(vxssh_mbuf_t *mb, const char *str);
int vxssh_mbuf_write_zmbuf(vxssh_mbuf_t *mb, const vxssh_mbuf_t *smb);
int vxssh_mbuf_write_str_sz(vxssh_mbuf_t *mb, const char *str);
int vxssh_mbuf_write_mem_sz(vxssh_mbuf_t *mb, const uint8_t *buf, size_t size);
int vxssh_mbuf_write_mbuf_sz(vxssh_mbuf_t *mb, const vxssh_mbuf_t *smb);

int vxssh_mbuf_base64_decode(vxssh_mbuf_t *mb, const char *in, size_t in_len);
int vxssh_mbuf_base64_encode(vxssh_mbuf_t *mb, const char *in, size_t in_len);

int vxssh_mbuf_read_mem(vxssh_mbuf_t *mb, uint8_t *buf, size_t *size);
uint8_t vxssh_mbuf_read_u8(vxssh_mbuf_t *mb);
uint16_t vxssh_mbuf_read_u16(vxssh_mbuf_t *mb);
uint32_t vxssh_mbuf_read_u32(vxssh_mbuf_t *mb);
int vxssh_mbuf_read_str(vxssh_mbuf_t *mb, char *str, size_t *size);

int vxssh_mbuf_write_mpint(vxssh_mbuf_t *mb, const mpz_t bn);
int vxssh_mbuf_read_mpint(vxssh_mbuf_t *mb, mpz_t bn);

#endif
