/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

int em_ssh_packet_send_unimplemented(em_ssh_session_t *session) {
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session || !mbuf) {
        return EINVAL;
    }

    em_ssh_packet_start(mbuf, SSH_MSG_UNIMPLEMENTED);
    em_ssh_mbuf_write_u32(mbuf, session->recv_seq - 1);
    em_ssh_packet_end(session, mbuf);

    if((err = em_ssh_packet_send(session, mbuf)) != OK) {
        goto out;
    }

out:
    return err;
}
