/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"
#include <loginLib.h>

#define FILED_LENGHT_MAX        128
#define SERVICE_USERAUTH        "ssh-userauth"
#define SERVICE_SSH_CONNECTION  "ssh-connection"
#define METHOD_NONE             "none"
#define METHOD_PASSWORD         "password"
//#define AUTH_METHOD_PUBKEY      "publickey"

static int read_cstr(em_ssh_mbuf_t *mbuf, char **str, size_t *slen) {
    int err = OK;
    char *s = NULL;
    size_t itmp;

    itmp = em_ssh_mbuf_read_u32(mbuf);
    if(!itmp || itmp > FILED_LENGHT_MAX) {
        err = EM_SSH_ERR_PROTO_ERROR;
        goto out;
    }
    if((err = em_ssh_mbuf_strdup(mbuf, &s, &itmp)) != OK) {
        goto out;
    }

    *slen = itmp;
    *str = s;
out:
    return err;

}
// -----------------------------------------------------------------------------------------------------------------
// public
// -----------------------------------------------------------------------------------------------------------------
/**
 *
 **/
int em_ssh_packet_io_auth(em_ssh_session_t *session, int timeout) {
    em_ssh_server_runtime_t *rt = em_ssh_server_get_runtime();
    em_ssh_kex_t *kex = (session ? session->kex : NULL);
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int auth_tries = 0, err = OK;
    bool authorized = false;
    char *service=NULL, *username=NULL, *password=NULL;
    size_t itmp;

    if(!session || !kex) {
        return EINVAL;
    }

    /* wait service request */
    if((err = em_ssh_packet_receive(session, mbuf, timeout)) != OK) {
        goto out;
    }
    if(err = em_ssh_packet_expect(mbuf, SSH_MSG_SERVICE_REQUEST) != OK) {
        goto out;
    }

    /* check service name */
    if((itmp = em_ssh_mbuf_read_u32(mbuf)) != strlen(SERVICE_USERAUTH)) {
        err = ERROR; goto out;
    }
    if((err = em_ssh_mbuf_strdup(mbuf, &service, &itmp)) != OK) {
        goto out;
    }
    if(!em_ssh_str_equal(SERVICE_USERAUTH, itmp, service, itmp)) {
        err = ERROR; goto out;
    }

    /* send service accept */
    em_ssh_packet_start(mbuf, SSH_MSG_SERVICE_ACCEPT);
    em_ssh_mbuf_write_str_sz(mbuf, SERVICE_USERAUTH);
    em_ssh_packet_end(session, mbuf);
    if((err = em_ssh_packet_send(session, mbuf)) != OK) {
        goto out;
    }

    /* auth loop */
    auth_tries = rt->auth_tries_max;
    while(auth_tries > 0 && !em_ssh_server_is_shutdown()) {
        authorized = false;
        em_ssh_mem_deref(service);
        em_ssh_mem_deref(username);
        em_ssh_mem_deref(password);

        /* get request */
        if((err = em_ssh_packet_receive(session, mbuf, timeout)) != OK) {
            break;
        }
        if(err = em_ssh_packet_expect(mbuf, SSH_MSG_USERAUTH_REQUEST) != OK) {
            break;
        }

        /* username */
        if((err = read_cstr(mbuf, &username, &itmp)) != OK) {
            break;
        }

        /* service */
        if((err = read_cstr(mbuf, &service, &itmp)) != OK) {
            break;
        }
        if(!em_ssh_str_equal(service, itmp, SERVICE_SSH_CONNECTION, strlen(SERVICE_SSH_CONNECTION))) {
            err = EM_SSH_ERR_PROTO_ERROR;
            break;
        }

        /* method */
        em_ssh_mem_deref(service);
        if((err = read_cstr(mbuf, &service, &itmp)) != OK) {
            break;
        }
        if(em_ssh_str_equal(service, itmp, METHOD_PASSWORD, strlen(METHOD_PASSWORD))) {
            em_ssh_mbuf_read_u8(mbuf);
            if((err = read_cstr(mbuf, &password, &itmp)) != OK) {
                break;
            }
            if(loginUserVerify(username, password) == OK) {
                session->username = username;
                authorized = true;
                break;
            }

#ifdef EM_SSH_LOG_ERROR_AUTH_ATTEMPTS
            em_ssh_log_warn("authentication failure: '%s' from '%s'", username, session->peerip);
#endif
        }

        /* auth failure */
        em_ssh_packet_start(mbuf, SSH_MSG_USERAUTH_FAILURE);
        em_ssh_mbuf_write_str_sz(mbuf, METHOD_PASSWORD);
        em_ssh_mbuf_write_u8(mbuf, 0);
        em_ssh_packet_end(session, mbuf);
        if((err = em_ssh_packet_send(session, mbuf)) != OK) {
            break;
        }
    }
    if(err != OK) {
        goto out;
    }
    if(!authorized) {
        em_ssh_packet_send_disconnect(session, SSH_DISCONNECT_BY_APPLICATION, "Authentication failure");
    } else {
        em_ssh_packet_start(mbuf, SSH_MSG_USERAUTH_SUCCESS);
        em_ssh_mbuf_write_str_sz(mbuf, SERVICE_SSH_CONNECTION);
        em_ssh_packet_end(session, mbuf);
        if((err = em_ssh_packet_send(session, mbuf)) != OK) {
            goto out;
        }
    }
out:
    if(err == EM_SSH_ERR_PROTO_ERROR) {
        em_ssh_packet_send_disconnect(session, SSH_DISCONNECT_PROTOCOL_ERROR, NULL);
    }
    if(err != OK) {
        em_ssh_mem_deref(username);
    }

    em_ssh_mem_deref(service);
    em_ssh_mem_deref(password);

    return err;
}
