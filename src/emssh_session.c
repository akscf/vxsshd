/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

static  void mem_destructor_em_ssh_session_t(void *data) {
    em_ssh_session_t *session = data;
    //
    if(session->socfd) {
        close(session->socfd);
    }

    em_ssh_mem_deref(session->iobuf);
    em_ssh_mem_deref(session->kex);
    em_ssh_mem_deref(session->peerip);
    em_ssh_mem_deref(session->username);
    em_ssh_mem_deref(session->channel);
}

// ----------------------------------------------------------------------------------------------------------------------------------------
// public api
// ----------------------------------------------------------------------------------------------------------------------------------------
/**
 *
 **/
int em_ssh_session_alloc(em_ssh_session_t **session) {
    int err = OK;
    em_ssh_session_t *tses = NULL;

    if(!session) {
        return EINVAL;
    }

    if((tses = em_ssh_mem_zalloc(sizeof(em_ssh_session_t), mem_destructor_em_ssh_session_t)) == NULL) {
        err = ENOMEM;
        goto out;
    }
    tses->state = EM_SSH_SESSION_STATE_HELLO;
    tses->recv_seq = 0;
    tses->send_seq = 0;

    if((err = em_ssh_mbuf_alloc(&tses->iobuf, 2048)) != OK) {
        goto out;
    }

    if((err = em_ssh_kex_alloc(&tses->kex)) != OK) {
        err = ENOMEM;
        goto out;
    }

    *session = tses;

out:
    if(err != OK) {
        em_ssh_mem_deref(tses);
    }
    return err;
}

/**
 *
 **/
int em_ssh_session_set_peerip(em_ssh_session_t *session, char *ip) {
    size_t len = ip ? strlen(ip) : 0;

    if(!session || !ip || len > 64) {
        return EINVAL;
    }

    if((session->peerip = em_ssh_mem_zalloc(len + 1, NULL)) == NULL) {
        return ENOMEM;
    }

    memcpy(session->peerip, ip, len);

    return OK;
}

