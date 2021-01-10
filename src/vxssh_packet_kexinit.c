/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"
#define COOKIE_LENGTH 16

// -----------------------------------------------------------------------------------------------------------------
// public
// -----------------------------------------------------------------------------------------------------------------
/**
 *
 **/
int vxssh_packet_io_kexinit(vxssh_session_t *session, int timeout) {
    vxssh_kex_t *kex = (session ? session->kex : NULL);
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    char cookie[COOKIE_LENGTH];
    int err = OK;
    uint32_t itmp;
    vxssh_mbuf_t *tmbuf = NULL;
    //
    if(!session || !kex) {
        return EINVAL;
    }
    if((err = vxssh_mbuf_alloc(&tmbuf, 512)) != OK) {
        goto out;
    }
    /* --- send --- */
    vxssh_packet_start(mbuf, SSH_MSG_KEXINIT);
    /* cookie */
    vxssh_rnd_bin((char *)cookie, COOKIE_LENGTH);
    vxssh_mbuf_write_mem(mbuf, (uint8_t *)cookie, COOKIE_LENGTH);
    /* kex algorithms */
    vxssh_neg_get_kex_algorithms(tmbuf, true);
    vxssh_mbuf_write_mbuf_sz(mbuf, tmbuf);
    /* server host key algorithms */
    vxssh_neg_get_server_key_algorithms(tmbuf, true);
    vxssh_mbuf_write_mbuf_sz(mbuf, tmbuf);
    /* encryption algorithms */
    vxssh_neg_get_cipher_algorithms(tmbuf, true);
    vxssh_mbuf_write_mbuf_sz(mbuf, tmbuf);   // client to server
    vxssh_mbuf_write_mbuf_sz(mbuf, tmbuf);   // server to client
    /* mac algorithms */
    vxssh_neg_get_mac_algorithms(tmbuf, true);
    vxssh_mbuf_write_mbuf_sz(mbuf, tmbuf);   // client to server
    vxssh_mbuf_write_mbuf_sz(mbuf, tmbuf);   // server to client
    /* comression */
    vxssh_neg_get_compression_algorithms(tmbuf, true);
    vxssh_mbuf_write_mbuf_sz(mbuf, tmbuf);   // client to server
    vxssh_mbuf_write_mbuf_sz(mbuf, tmbuf);   // server to client
    /* other fields */
    vxssh_mbuf_write_str_sz(mbuf, "");     // languages client to server
    vxssh_mbuf_write_str_sz(mbuf, "");     // languages server to client
    vxssh_mbuf_write_u8(mbuf, 0);          // kex first packet follows
    vxssh_mbuf_write_u32(mbuf, 0);         // reserved
    /* copy payload */
    kex->server_kex_init_len = (mbuf->end - 5);
    kex->server_kex_init = (kex->server_kex_init ? vxssh_mem_realloc(kex->server_kex_init, kex->server_kex_init_len) : vxssh_mem_alloc(kex->server_kex_init_len, NULL));
    if(kex->server_kex_init == NULL) { err = ENOMEM; goto out; }
    memcpy(kex->server_kex_init, (mbuf->buf + 5), kex->server_kex_init_len);
    // -------------------
    vxssh_packet_end(session, mbuf);
    if((err = vxssh_packet_send(session, mbuf)) != OK) {
        goto out;
    }
    /* --- receicve --- */
    if((err = vxssh_packet_receive(session, mbuf, timeout)) != OK) {
        goto out;
    }
    if(err = vxssh_packet_expect(mbuf, SSH_MSG_KEXINIT) != OK) {
        goto out;
    }
    /* copy payload */
    kex->client_kex_init_len = (mbuf->end - 5);
    kex->client_kex_init = (kex->client_kex_init ? vxssh_mem_realloc(kex->client_kex_init, kex->client_kex_init_len) : vxssh_mem_alloc(kex->client_kex_init_len, NULL));
    if(kex->client_kex_init == NULL) { err = ENOMEM; goto out; }
    memcpy(kex->client_kex_init, (mbuf->buf + 5), kex->client_kex_init_len);
    // -------------------

    /* skip cookie */
    vxssh_mbuf_set_pos(mbuf, mbuf->pos + COOKIE_LENGTH);

    /* kex algorithm */
    if((itmp = vxssh_mbuf_read_u32(mbuf)) > 0 ) {
        kex->kex_algorithm = vxssh_neg_select_kex_algorithm(mbuf, itmp);
        if(kex->kex_algorithm == NULL) {
            vxssh_log_warn("kex-init: no matching key exchange method found");
            err = ERROR; goto out;
        }
        vxssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* server host key algorithm */
    if((itmp = vxssh_mbuf_read_u32(mbuf)) > 0 ) {
        kex->server_key_algorithm = vxssh_neg_select_server_key_algorithm(mbuf, itmp);
        if(kex->server_key_algorithm == NULL) {
            vxssh_log_warn("kex-init: no matching host key type found");
            err = ERROR; goto out;
        }
        vxssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* chipher c2s algorithm */
    if((itmp = vxssh_mbuf_read_u32(mbuf)) > 0 ) {
        kex->cipher_algorithm = vxssh_neg_select_chipher_algorithm(mbuf, itmp);
        if(kex->cipher_algorithm == NULL) {
            vxssh_log_warn("kex-init: no matching cipher found (c2s)");
            err = ERROR; goto out;
        }
        vxssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* chipher s2c algorithm */
    if((itmp = vxssh_mbuf_read_u32(mbuf)) > 0 ) {
        vxssh_cipher_alg_props_t *t = vxssh_neg_select_chipher_algorithm(mbuf, itmp);
        if(t == NULL || strcmp(t->name, kex->cipher_algorithm->name) != 0) {
            vxssh_log_warn("kex-init: no matching cipher found (s2c)");
            err = ERROR; goto out;
        }
        vxssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* mac c2s algorithm */
    if((itmp = vxssh_mbuf_read_u32(mbuf)) > 0 ) {
        kex->mac_algorithm = vxssh_neg_select_mac_algorithm(mbuf, itmp);
        if(kex->mac_algorithm == NULL) {
            vxssh_log_warn("kex-init: no matching MAC found (c2s)");
            err = ERROR; goto out;
        }
        vxssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* mac s2c algorithm */
    if((itmp = vxssh_mbuf_read_u32(mbuf)) > 0 ) {
        vxssh_mac_alg_props_t *t = vxssh_neg_select_mac_algorithm(mbuf, itmp);
        if(t == NULL || strcmp(t->name, kex->mac_algorithm->name) != 0) {
            vxssh_log_warn("kex-init: no matching MAC found (s2c)");
            err = ERROR; goto out;
        }
        vxssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* compression c2s algorithm */
    if((itmp = vxssh_mbuf_read_u32(mbuf)) > 0 ) {
        kex->compresion_algorithm = vxssh_neg_select_compression_algorithm(mbuf, itmp);
        if(kex->compresion_algorithm == NULL) {
            vxssh_log_warn("kex-init: no matching compression method found (c2s)");
            err = ERROR; goto out;
        }
        vxssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* compression s2c algorithm */
    if((itmp = vxssh_mbuf_read_u32(mbuf)) > 0 ) {
        vxssh_compression_alg_props_t *t = vxssh_neg_select_compression_algorithm(mbuf, itmp);
        if(t == NULL || strcmp(t->name, kex->compresion_algorithm->name) != 0) {
            vxssh_log_warn("kex-init: no matching compression method found (s2c)");
            err = ERROR; goto out;
        }
        vxssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* lanuage c2s (ignore) */
    if((itmp = vxssh_mbuf_read_u32(mbuf)) > 0 ) {
        vxssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* lanuage s2c */
    if((itmp = vxssh_mbuf_read_u32(mbuf)) > 0 ) {
        vxssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* first follows */
    kex->first_follows = vxssh_mbuf_read_u32(mbuf);

    /* */
    kex->hash_alg = kex->kex_algorithm->hash_alg;
    kex->we_need = MAX(kex->we_need, kex->kex_algorithm->digest_len);
    kex->we_need = MAX(kex->we_need, kex->mac_algorithm->digest_len);
    kex->we_need = MAX(kex->we_need, kex->cipher_algorithm->block_len);
    kex->we_need = MAX(kex->we_need, kex->cipher_algorithm->key_len);


#ifdef VXSSH_DEBUG_KEX_INIT
    vxssh_log_debug("kex-init: kex-dh.......: %s", kex->kex_algorithm->name);
    vxssh_log_debug("kex-init: server key...: %s", kex->server_key_algorithm->name);
    vxssh_log_debug("kex-init: cipher.......: %s", kex->cipher_algorithm->name);
    vxssh_log_debug("kex-init: mac..........: %s", kex->mac_algorithm->name);
    vxssh_log_debug("kex-init: compression..: %s", kex->compresion_algorithm->name);
    vxssh_log_debug("kex-init: we_need=%i", kex->we_need);
#endif

out:
    vxssh_mem_deref(tmbuf);
    //
    return err;
}
