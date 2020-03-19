/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_MBUF_H
#define EMSSH_MBUF_H

#include <vxWorks.h>

typedef struct {
    uint8_t *buf;
    size_t  size;
    size_t  pos;
    size_t  end;
} em_ssh_mbuf_t;

// --------------------------------------------------------------------------------------------------
size_t em_ssh_mbuf_get_left(em_ssh_mbuf_t *mb);
size_t em_ssh_mbuf_get_space(em_ssh_mbuf_t *mb);
int em_ssh_mbuf_set_pos(em_ssh_mbuf_t *mb, size_t pos);

int em_ssh_mbuf_alloc(em_ssh_mbuf_t **mb, size_t size);
int em_ssh_mbuf_resize(em_ssh_mbuf_t *mb, size_t size);
int em_ssh_mbuf_trim(em_ssh_mbuf_t *mb);
int em_ssh_mbuf_clear(em_ssh_mbuf_t *mb);
int em_ssh_mbuf_fill(em_ssh_mbuf_t *mb, uint8_t ch, size_t size);
int em_ssh_mbuf_strdup(em_ssh_mbuf_t *mb, char **strp, size_t *len);
int em_ssh_mbuf_digest(em_ssh_mbuf_t *mb, int hash_alg, uint8_t *digest, size_t digest_len);

int em_ssh_mbuf_write_mem(em_ssh_mbuf_t *mb, const uint8_t *buf, size_t size);
int em_ssh_mbuf_write_u8(em_ssh_mbuf_t *mb, uint8_t v);
int em_ssh_mbuf_write_u16(em_ssh_mbuf_t *mb, uint16_t v);
int em_ssh_mbuf_write_u32(em_ssh_mbuf_t *mb, uint32_t v);
int em_ssh_mbuf_write_str(em_ssh_mbuf_t *mb, const char *str);
int em_ssh_mbuf_write_zstr(em_ssh_mbuf_t *mb, const char *str);
int em_ssh_mbuf_write_zmbuf(em_ssh_mbuf_t *mb, const em_ssh_mbuf_t *smb);
int em_ssh_mbuf_write_str_sz(em_ssh_mbuf_t *mb, const char *str);
int em_ssh_mbuf_write_mem_sz(em_ssh_mbuf_t *mb, const uint8_t *buf, size_t size);
int em_ssh_mbuf_write_mbuf_sz(em_ssh_mbuf_t *mb, const em_ssh_mbuf_t *smb);

int em_ssh_mbuf_base64_decode(em_ssh_mbuf_t *mb, const char *in, size_t in_len);
int em_ssh_mbuf_base64_encode(em_ssh_mbuf_t *mb, const char *in, size_t in_len);

int em_ssh_mbuf_read_mem(em_ssh_mbuf_t *mb, uint8_t *buf, size_t *size);
uint8_t em_ssh_mbuf_read_u8(em_ssh_mbuf_t *mb);
uint16_t em_ssh_mbuf_read_u16(em_ssh_mbuf_t *mb);
uint32_t em_ssh_mbuf_read_u32(em_ssh_mbuf_t *mb);
int em_ssh_mbuf_read_str(em_ssh_mbuf_t *mb, char *str, size_t *size);

int em_ssh_mbuf_write_mpint(em_ssh_mbuf_t *mb, const mpz_t bn);
int em_ssh_mbuf_read_mpint(em_ssh_mbuf_t *mb, mpz_t bn);

#endif
