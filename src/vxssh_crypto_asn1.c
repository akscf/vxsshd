/**
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

static int get_obj_lenght(vxssh_mbuf_t *mb, size_t *len) {
    size_t _len = 0;
    int i;

    _len = vxssh_mbuf_read_u8(mb);
    if((_len & 0x80) != 0) {
        i = (_len & 0x7f);
        if(!i) { return ERROR; }
        _len = 0x0;
        while (i > 0) {
            _len = _len << 8;
			_len |= vxssh_mbuf_read_u8(mb);
			i--;
		}
    }
    *len = _len;
    return OK;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// public
// -----------------------------------------------------------------------------------------------------------------------------------------
/**
 * type: 0x30
 **/
int vxssh_asn1_get_sequece(vxssh_mbuf_t *mb, char **buf, size_t *buf_len) {
    int err;
    size_t sz;
    char *p;

    if(vxssh_mbuf_read_u8(mb) != 0x30) {
        return ERROR;
    }

    if((err = get_obj_lenght(mb, &sz)) != OK) {
        return err;
    }
    if(!sz) {
        return ERROR;
    }
    if((p = vxssh_mem_zalloc(sz, NULL)) == NULL) {
        return ENOMEM;
    }

    vxssh_mbuf_read_mem(mb, (uint8_t *)p, &sz);
    *buf = p;
    *buf_len = sz;

    return OK;
}

/**
 * type: 0x03
 **/
int vxssh_asn1_get_bitstr(vxssh_mbuf_t *mb, char **buf, size_t *buf_len) {
    int err;
    size_t sz;
    char *p;

    if(vxssh_mbuf_read_u8(mb) != 0x03) {
        return ERROR;
    }

    if((err = get_obj_lenght(mb, &sz)) != OK) {
        return err;
    }
    if(!sz) {
        return ERROR;
    }
    if((p = vxssh_mem_zalloc(sz, NULL)) == NULL) {
        return ENOMEM;
    }

    vxssh_mbuf_read_mem(mb, (uint8_t *)p, &sz);
    *buf = p;
    *buf_len = sz;

    return OK;
}

/**
 * type: 0x02
 **/
int vxssh_asn1_get_integer(vxssh_mbuf_t *mb, mpz_t bn) {
    int err = OK;
    uint8_t *p = NULL;
    size_t sz = 0, npos = 0;

    if(vxssh_mbuf_read_u8(mb) != 0x2) {
        return ERROR;
    }
    if((err = get_obj_lenght(mb, &sz)) != OK) {
        return err;
    }
    if(sz == 0 || (mb->pos + sz) > mb->size || sz > 16384) {
        return ERROR;
    }
    npos = (mb->pos + sz);
    p = (mb->buf + mb->pos);
    if(p[0] == 0) { p++; sz--; }
    //
    mpz_init(bn);
    mpz_import(bn, sz, 1, 1, 0, 0, p);
    vxssh_mbuf_set_pos(mb, npos);
    //
    return err;
}

