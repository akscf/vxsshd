/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"
#define COOKIE_LENGTH 16

// -----------------------------------------------------------------------------------------------------------------
// public
// -----------------------------------------------------------------------------------------------------------------
/**
 *
 **/
int em_ssh_packet_io_kexinit(em_ssh_session_t *session, int timeout) {
    em_ssh_kex_t *kex = (session ? session->kex : NULL);
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    char cookie[COOKIE_LENGTH];
    int err = OK;
    uint32_t itmp;
    em_ssh_mbuf_t *tmbuf = NULL;
    //
    if(!session || !kex) {
        return EINVAL;
    }
    if((err = em_ssh_mbuf_alloc(&tmbuf, 512)) != OK) {
        goto out;
    }
    /* --- send --- */
    em_ssh_packet_start(mbuf, SSH_MSG_KEXINIT);
    /* cookie */
    em_ssh_rnd_bin((char *)cookie, COOKIE_LENGTH);
    em_ssh_mbuf_write_mem(mbuf, (uint8_t *)cookie, COOKIE_LENGTH);
    /* kex algorithms */
    em_ssh_neg_get_kex_algorithms(tmbuf, true);
    em_ssh_mbuf_write_mbuf_sz(mbuf, tmbuf);
    /* server host key algorithms */
    em_ssh_neg_get_server_key_algorithms(tmbuf, true);
    em_ssh_mbuf_write_mbuf_sz(mbuf, tmbuf);
    /* encryption algorithms */
    em_ssh_neg_get_cipher_algorithms(tmbuf, true);
    em_ssh_mbuf_write_mbuf_sz(mbuf, tmbuf);   // client to server
    em_ssh_mbuf_write_mbuf_sz(mbuf, tmbuf);   // server to client
    /* mac algorithms */
    em_ssh_neg_get_mac_algorithms(tmbuf, true);
    em_ssh_mbuf_write_mbuf_sz(mbuf, tmbuf);   // client to server
    em_ssh_mbuf_write_mbuf_sz(mbuf, tmbuf);   // server to client
    /* comression */
    em_ssh_neg_get_compression_algorithms(tmbuf, true);
    em_ssh_mbuf_write_mbuf_sz(mbuf, tmbuf);   // client to server
    em_ssh_mbuf_write_mbuf_sz(mbuf, tmbuf);   // server to client
    /* other fields */
    em_ssh_mbuf_write_str_sz(mbuf, "");     // languages client to server
    em_ssh_mbuf_write_str_sz(mbuf, "");     // languages server to client
    em_ssh_mbuf_write_u8(mbuf, 0);          // kex first packet follows
    em_ssh_mbuf_write_u32(mbuf, 0);         // reserved
    /* copy payload */
    kex->server_kex_init_len = (mbuf->end - 5);
    kex->server_kex_init = (kex->server_kex_init ? em_ssh_mem_realloc(kex->server_kex_init, kex->server_kex_init_len) : em_ssh_mem_alloc(kex->server_kex_init_len, NULL));
    if(kex->server_kex_init == NULL) { err = ENOMEM; goto out; }
    memcpy(kex->server_kex_init, (mbuf->buf + 5), kex->server_kex_init_len);
    // -------------------
    em_ssh_packet_end(session, mbuf);
    if((err = em_ssh_packet_send(session, mbuf)) != OK) {
        goto out;
    }
    /* --- receicve --- */
    if((err = em_ssh_packet_receive(session, mbuf, timeout)) != OK) {
        goto out;
    }
    if(err = em_ssh_packet_expect(mbuf, SSH_MSG_KEXINIT) != OK) {
        goto out;
    }
    /* copy payload */
    kex->client_kex_init_len = (mbuf->end - 5);
    kex->client_kex_init = (kex->client_kex_init ? em_ssh_mem_realloc(kex->client_kex_init, kex->client_kex_init_len) : em_ssh_mem_alloc(kex->client_kex_init_len, NULL));
    if(kex->client_kex_init == NULL) { err = ENOMEM; goto out; }
    memcpy(kex->client_kex_init, (mbuf->buf + 5), kex->client_kex_init_len);
    // -------------------

    /* skip cookie */
    em_ssh_mbuf_set_pos(mbuf, mbuf->pos + COOKIE_LENGTH);

    /* kex algorithm */
    if((itmp = em_ssh_mbuf_read_u32(mbuf)) > 0 ) {
        kex->kex_algorithm = em_ssh_neg_select_kex_algorithm(mbuf, itmp);
        if(kex->kex_algorithm == NULL) {
            em_ssh_log_warn("kex-init: no matching key exchange method found");
            err = ERROR; goto out;
        }
        em_ssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* server host key algorithm */
    if((itmp = em_ssh_mbuf_read_u32(mbuf)) > 0 ) {
        kex->server_key_algorithm = em_ssh_neg_select_server_key_algorithm(mbuf, itmp);
        if(kex->server_key_algorithm == NULL) {
            em_ssh_log_warn("kex-init: no matching host key type found");
            err = ERROR; goto out;
        }
        em_ssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* chipher c2s algorithm */
    if((itmp = em_ssh_mbuf_read_u32(mbuf)) > 0 ) {
        kex->cipher_algorithm = em_ssh_neg_select_chipher_algorithm(mbuf, itmp);
        if(kex->cipher_algorithm == NULL) {
            em_ssh_log_warn("kex-init: no matching cipher found (c2s)");
            err = ERROR; goto out;
        }
        em_ssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* chipher s2c algorithm */
    if((itmp = em_ssh_mbuf_read_u32(mbuf)) > 0 ) {
        em_ssh_cipher_alg_props_t *t = em_ssh_neg_select_chipher_algorithm(mbuf, itmp);
        if(t == NULL || strcmp(t->name, kex->cipher_algorithm->name) != 0) {
            em_ssh_log_warn("kex-init: no matching cipher found (s2c)");
            err = ERROR; goto out;
        }
        em_ssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* mac c2s algorithm */
    if((itmp = em_ssh_mbuf_read_u32(mbuf)) > 0 ) {
        kex->mac_algorithm = em_ssh_neg_select_mac_algorithm(mbuf, itmp);
        if(kex->mac_algorithm == NULL) {
            em_ssh_log_warn("kex-init: no matching MAC found (c2s)");
            err = ERROR; goto out;
        }
        em_ssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* mac s2c algorithm */
    if((itmp = em_ssh_mbuf_read_u32(mbuf)) > 0 ) {
        em_ssh_mac_alg_props_t *t = em_ssh_neg_select_mac_algorithm(mbuf, itmp);
        if(t == NULL || strcmp(t->name, kex->mac_algorithm->name) != 0) {
            em_ssh_log_warn("kex-init: no matching MAC found (s2c)");
            err = ERROR; goto out;
        }
        em_ssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* compression c2s algorithm */
    if((itmp = em_ssh_mbuf_read_u32(mbuf)) > 0 ) {
        kex->compresion_algorithm = em_ssh_neg_select_compression_algorithm(mbuf, itmp);
        if(kex->compresion_algorithm == NULL) {
            em_ssh_log_warn("kex-init: no matching compression method found (c2s)");
            err = ERROR; goto out;
        }
        em_ssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* compression s2c algorithm */
    if((itmp = em_ssh_mbuf_read_u32(mbuf)) > 0 ) {
        em_ssh_compression_alg_props_t *t = em_ssh_neg_select_compression_algorithm(mbuf, itmp);
        if(t == NULL || strcmp(t->name, kex->compresion_algorithm->name) != 0) {
            em_ssh_log_warn("kex-init: no matching compression method found (s2c)");
            err = ERROR; goto out;
        }
        em_ssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* lanuage c2s (ignore) */
    if((itmp = em_ssh_mbuf_read_u32(mbuf)) > 0 ) {
        em_ssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* lanuage s2c */
    if((itmp = em_ssh_mbuf_read_u32(mbuf)) > 0 ) {
        em_ssh_mbuf_set_pos(mbuf, mbuf->pos + itmp);
    }

    /* first follows */
    kex->first_follows = em_ssh_mbuf_read_u32(mbuf);

    /* */
    kex->hash_alg = kex->kex_algorithm->hash_alg;
    kex->we_need = MAX(kex->we_need, kex->kex_algorithm->digest_len);
    kex->we_need = MAX(kex->we_need, kex->mac_algorithm->digest_len);
    kex->we_need = MAX(kex->we_need, kex->cipher_algorithm->block_len);
    kex->we_need = MAX(kex->we_need, kex->cipher_algorithm->key_len);


#ifdef EM_SSH_DEBUG_KEX_INIT
    em_ssh_log_debug("kex-init: kex-dh.......: %s", kex->kex_algorithm->name);
    em_ssh_log_debug("kex-init: server key...: %s", kex->server_key_algorithm->name);
    em_ssh_log_debug("kex-init: cipher.......: %s", kex->cipher_algorithm->name);
    em_ssh_log_debug("kex-init: mac..........: %s", kex->mac_algorithm->name);
    em_ssh_log_debug("kex-init: compression..: %s", kex->compresion_algorithm->name);
    em_ssh_log_debug("kex-init: we_need=%i", kex->we_need);
#endif

out:
    em_ssh_mem_deref(tmbuf);
    //
    return err;
}
