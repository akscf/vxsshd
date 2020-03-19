/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

/**
 *
 **/
int em_ssh_packet_io_hello(em_ssh_session_t *session, int timeout) {
    em_ssh_kex_t *kex = (session ? session->kex : NULL);
    int pos = 0, wr = 0, rd = 0, err = OK;
    char buf[255];
    char ch;
    int bsz = (sizeof(buf) - 1);
    time_t expiry_ts;

    if(!session || !kex) {
        return EINVAL;
    }

#ifndef EM_SSH_HELLO_HIDE_OS_VERSION
    sprintf((char *)buf, "SSH-2.0-emSSH_%s %s\r\n", EM_SSH_VERSION, vxWorksVersion);
#else
    sprintf((char *)buf, "SSH-2.0-emSSH_%s\r\n", EM_SSH_VERSION);
#endif

    if(kex->server_version == NULL) {
        kex->server_version_len = strlen((char *) buf) - 2;
        kex->server_version = em_ssh_mem_alloc(kex->server_version_len, NULL);
        if(kex->server_version == NULL) {
            return ENOMEM;
        }
        memcpy(kex->server_version, (char *)buf, kex->server_version_len);
    }

    wr = write(session->socfd, (char *)buf, strlen(buf));
    if(wr <= 0) { return ERROR; }

    explicit_bzero((char *)buf, sizeof(buf));
    expiry_ts = em_ssh_get_time() + (timeout * 1000L);

    while(!em_ssh_server_is_shutdown()) {
        if(expiry_ts < em_ssh_get_time()) {
            err = ETIME;
            break;
        }

        if(!em_ssh_fd_select_read(session->socfd, 1000)) {
            continue;
        }

        rd = read(session->socfd, &ch, 1);
        if(rd == 1) {
            if(ch == '\n' || pos >= bsz) { break; }
            if(ch == '\r') { continue; }
            buf[pos++] = ch;
        }
    }

    if(err == OK) {
        if(pos >= 7) {
            kex->client_version = (kex->client_version_len > 0 ? em_ssh_mem_realloc(kex->client_version, pos) : em_ssh_mem_alloc(pos, NULL));
            if(kex->client_version == NULL) { return ENOMEM; }
            kex->client_version_len = pos;
            memcpy(kex->client_version, (char *)buf, pos);
            /* cmp */
            err = (strncmp("SSH-2.0", (char *)buf, 7) == 0 ? OK : EPROTO);
        } else {
            err = EPROTO;
        }
    }

    return err;
}


