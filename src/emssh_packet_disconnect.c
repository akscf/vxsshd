/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

/**
 *
 **/
int em_ssh_packet_send_disconnect(em_ssh_session_t *session, int reason, char *message) {
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session || !mbuf) {
        return EINVAL;
    }

    em_ssh_packet_start(mbuf, SSH_MSG_DISCONNECT);
    em_ssh_mbuf_write_u32(mbuf, reason);
    em_ssh_mbuf_write_str_sz(mbuf, message);
    em_ssh_mbuf_write_u32(mbuf, 0);
    em_ssh_packet_end(session, mbuf);

    if((err = em_ssh_packet_send(session, mbuf)) != OK) {
        goto out;
    }
out:
    return err;
}

