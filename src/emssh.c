/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

LOCAL em_ssh_server_runtime_t *server_runtime = NULL;
LOCAL void em_ssh_connection_mgr_task(void);
LOCAL void em_sshd_sesion_task(em_ssh_session_t *);

LOCAL void mem_destructor_em_ssh_server_runtime_t(void *data) {
    em_ssh_server_runtime_t *rt = data;
    //
    if(rt->srv_sock) {
        close(rt->srv_sock);
    }
    if(rt->sem) {
        semDelete(rt->sem);
    }
    if(rt->server_key) {
        em_ssh_mem_deref(rt->server_key);
    }
    if(rt->user_key) {
        em_ssh_mem_deref(rt->user_key);
    }
}

// ----------------------------------------------------------------------------------------------------------------------------------------
// public api
// ----------------------------------------------------------------------------------------------------------------------------------------
bool em_ssh_server_is_shutdown() {
    if(server_runtime == NULL) {
        return true;
    }
    return server_runtime->fl_do_shutdown || !server_runtime->fl_running;
}

bool em_ssh_server_is_running() {
    if(server_runtime == NULL) {
        return false;
    }
    return server_runtime->fl_running && !server_runtime->fl_do_shutdown;
}

em_ssh_server_runtime_t *em_ssh_server_get_runtime() {
    return server_runtime;
}

#ifdef EM_SSH_INCLUDE_SERVER_TEST
STATUS em_ssh_server_test() {
    int err = OK;
    em_ssh_server_config_t *cfg = NULL;

    if((cfg = em_ssh_mem_zalloc(sizeof(em_ssh_server_config_t), NULL)) == NULL) {
        goto out;
    }
    /* -------------------------------------------------------------------------- */
    cfg->server_key = "-----BEGIN RSA PRIVATE KEY-----"
        "MIICXQIBAAKBgQC+s6sA4tjw9ct7fSuPoIA8KTJisgXuYtyYBX5EsWPtDsRW6h/v"
        "KBy/gFMFeaK9zKhAOEzV1oy/djbXA8qfC4G+2EDsSkV0oW0COulnayNvmVAAWtlL"
        "F17iK/CXLJpT+RQh5ApzF1eezJ1FpScZyAyt8mFTVHulRRGPQh4ssS+NOwIDAQAB"
        "AoGBALuMLWBIuPx5by46ks3FFniUN4ZS+HxS5AnqVR0vrEummzezN8bXlzZK+NtI"
        "neG11b6a4A3p3DAsDZD2nJ5ADc81X4uWlSgUMog6nGfcvQpepNmS6g5UgCEmFnek"
        "jWqMqTwjWWBCqFN2FNYrof6pdUlB1xKqE54zVP728bhgsaPpAkEA4esHwOJxp0DP"
        "O1YcUozX9SrcViDcBfDJ1jSgqnNogAeyuHJ9v84Cptt67jEK09vJbz1fFT7iF9+n"
        "LKhrT9TvZwJBANgYNJwBBsr1268NAIHmNFRTPthyggD7C/o9R9pBlSrb3uzIuw/0"
        "MOq2tphggf1k4Lf3GPp6mX/uupgTo/yXUw0CQGFmciZPuo5QW8gKPRW+EVFrFCmx"
        "6wpIoMxQTkCOlywzpXLuMZbjG7OShrJwxGlIpdTm0bqYLOP8EdgoGHQHqtsCQAjb"
        "RRy3tg2PcgeEouawBqkGGGdKmiVsJJuG83DwiyqMhGB0AaavvWmBP46TNgCqp8Mi"
        "b3WknLHvmNouw+PQV+kCQQCD6J+REpYDxPVfTFgEGCZbEQHXTKh9WnL84IKgHSb2"
        "5n1R/56d/j12+aDKwGjEoHD7B215MgypFld6uEwAU4b2"
        "-----END RSA PRIVATE KEY-----";
    cfg->user_key = NULL;
    /*
    cfg->user_key = "-----BEGIN RSA PUBLIC KEY-----"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+s6sA4tjw9ct7fSuPoIA8KTJi"
        "sgXuYtyYBX5EsWPtDsRW6h/vKBy/gFMFeaK9zKhAOEzV1oy/djbXA8qfC4G+2EDs"
        "SkV0oW0COulnayNvmVAAWtlLF17iK/CXLJpT+RQh5ApzF1eezJ1FpScZyAyt8mFT"
        "VHulRRGPQh4ssS+NOwIDAQAB"
        "-----END RSA PUBLIC KEY-----";
    */

    cfg->listen_address = "0.0.0.0";
    cfg->auth_type = EM_SSH_AUTH_PASSWORD;

    /* -------------------------------------------------------------------------- */
    if((err = em_ssh_server_init(cfg)) != OK) {
        em_ssh_log_error("em_ssh_server_init() failed, err=%i", err);
        goto out;
    }

    if((err = em_ssh_server_start()) != OK) {
        em_ssh_log_error("em_ssh_server_start() failed, err=%i", err);
        goto out;
    }
out:
    em_ssh_mem_deref(cfg);
    return OK;
}

#endif


STATUS em_ssh_server_init(em_ssh_server_config_t *config) {
    int err = OK;

    if(!config) {
        return EINVAL;
    }
    /* init submodules */
    em_ssh_rnd_init();

    /* check options */
    if((server_runtime = em_ssh_mem_zalloc(sizeof(em_ssh_server_runtime_t), mem_destructor_em_ssh_server_runtime_t)) == NULL) {
        return ENOMEM;
    }
    if(config->server_key == NULL) {
        em_ssh_log_error("server_key not set");
        err = ERROR; goto out;
    }
    if(config->user_key == NULL && (config->auth_type == EM_SSH_AUTH_PUBKEY || config->auth_type == EM_SSH_AUTH_BOTH)) {
        em_ssh_log_error("user_key not set");
        err = ERROR; goto out;
    }
    if(config->listen_address == NULL || strlen(config->listen_address) < 7) {
        em_ssh_log_error("incorrect listen_address");
        err = ERROR; goto out;
    }
    /* preload server key */
    err = em_ssh_pem_decode(config->server_key, strlen(config->server_key), NULL, &server_runtime->server_key);
    if(err != OK || server_runtime->server_key->type != CRYPTO_OBJECT_RSA_PRIVATE_KEY) {
        em_ssh_log_error("can't decode server key (%i)", err);
        goto out;
    }
    /* preload user key */
    if(config->auth_type == EM_SSH_AUTH_PUBKEY || config->auth_type == EM_SSH_AUTH_BOTH) {
        err = em_ssh_pem_decode(config->user_key, strlen(config->user_key), NULL, &server_runtime->user_key);
        if(err != OK || server_runtime->user_key->type != CRYPTO_OBJECT_RSA_PUBLIC_KEY) {
            em_ssh_log_error("can't decode user key (%i)", err);
            goto out;
        }
    }

#ifdef EM_SSH_DEBUG_HOST_KEY
    if(server_runtime->server_key) {
        em_ssh_crypto_rsa_private_key_t *pkey = server_runtime->server_key->obj;
        em_ssh_log_debug("server private key...: (d: %s, n: %s)", mpz_get_str(NULL, 0, pkey->d), mpz_get_str(NULL, 0, pkey->n));
        em_ssh_log_debug("server public key....: (e: %s, n: %s)", mpz_get_str(NULL, 0, pkey->e), mpz_get_str(NULL, 0, pkey->n));
    }
#endif
#ifdef EM_SSH_DEBUG_USER_KEY
    if(server_runtime->user_key) {
        em_ssh_crypto_rsa_public_key_t *pkey = server_runtime->user_key->obj;
        em_ssh_log_debug("user key....: (e: %s, n: %s)", mpz_get_str(NULL, 0, pkey->e), mpz_get_str(NULL, 0, pkey->n));
    }
#endif

    server_runtime->sessions_max = 1;  /* restricted by implementation, don't change it! */
    server_runtime->auth_tries_max = EM_SSH_AUTH_TRIES_MAX;
    server_runtime->auth_type = config->auth_type;
    server_runtime->srv_addr.sin_family = AF_INET;
    server_runtime->srv_addr.sin_port = htons(config->listen_port <= 0 ? EM_SSH_DEFAULT_PORT : config->listen_port);
    server_runtime->srv_addr.sin_addr.s_addr = (strcmp(config->listen_address, "0.0.0.0") == 0 ? htonl(INADDR_ANY) : inet_addr(config->listen_address));

    if((server_runtime->sem = semMCreate(SEM_Q_PRIORITY | SEM_DELETE_SAFE | SEM_INVERSION_SAFE)) == NULL) {
        em_ssh_log_error("semMCreate() failed");
        err = ERROR; goto out;
    }

out:
    if(err != OK) {
        em_ssh_mem_deref(server_runtime);
    }
    return err;
}

STATUS em_ssh_server_start() {
    int err = OK;
    int soptval = 0;

    if(!server_runtime) {
        em_ssh_log_error("server isn't initialized");
        return ERROR;
    }

    if(server_runtime->fl_running) {
        em_ssh_log_error("server already started");
        return ERROR;
    }

    if((server_runtime->srv_sock = socket(AF_INET, SOCK_STREAM, 0)) == ERROR) {
        em_ssh_log_error("socket() failed (%i)", errno);
        err = ERROR;
        goto out;
    }
    if ((err = setsockopt(server_runtime->srv_sock, SOL_SOCKET, SO_REUSEADDR, (void *)&soptval, sizeof(soptval))) == ERROR) {
        em_ssh_log_error("setsockopt() failed (%i)", errno);
        goto out;
    }
    if ((err = setsockopt(server_runtime->srv_sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&soptval, sizeof(soptval))) == ERROR) {
        em_ssh_log_error("setsockopt() failed (%i)", errno);
        goto out;
    }
    if ((err = setsockopt(server_runtime->srv_sock, IPPROTO_TCP, TCP_NODELAY, (void *)&soptval, sizeof(soptval))) == ERROR) {
        em_ssh_log_error("setsockopt() failed (%i)", errno);
        goto out;
    }
    if ((err = bind(server_runtime->srv_sock, (struct sockaddr *)&server_runtime->srv_addr, sizeof(server_runtime->srv_addr))) == ERROR) {
        em_ssh_log_error("bind() failed (%i)", errno);
        goto out;
    }
    if ((err = listen(server_runtime->srv_sock, 5)) == ERROR) {
        em_ssh_log_error("listen() failed (%i)", errno);
        goto out;
    }

    em_ssh_fd_set_blocking(server_runtime->srv_sock, false);

    if((server_runtime->con_mgr_tid = taskSpawn("sshd_main", 200, 0, 2048, (FUNCPTR) em_ssh_connection_mgr_task, 0,0,0,0,0,0,0,0,0,0)) == ERROR) {
        em_ssh_log_warn("sshd_main spawn failed: %i", errno);
        err = ERROR; goto out;
    }
    server_runtime->fl_running = true;

out:
    if(err != OK) {
        if(server_runtime->srv_sock) {
            close(server_runtime->srv_sock);
        }
    }
    return err;
}

STATUS em_ssh_server_stop() {
    if(!server_runtime || !server_runtime->fl_running) {
        return ERROR;
    }
    if(!server_runtime->fl_do_shutdown) {
        server_runtime->fl_do_shutdown = true;
    }
    return OK;
}

// ----------------------------------------------------------------------------------------------------------------------------------------
// private
// ----------------------------------------------------------------------------------------------------------------------------------------
LOCAL void em_ssh_connection_mgr_task() {
    int err = OK;
    int cli_sock = 0;

#ifdef EM_SSH_DEBUG_CON_MGR
    em_ssh_log_debug("accept connections on: %s:%i", inet_ntoa(server_runtime->srv_addr.sin_addr), server_runtime->srv_addr.sin_port);
#endif

    while(!server_runtime->fl_do_shutdown) {
        cli_sock = accept(server_runtime->srv_sock, NULL, NULL);
        if (cli_sock < 0) {
            if (errno == EWOULDBLOCK) {
                taskDelay(CLOCKS_PER_SEC / 2);
                continue;
            } else {
                em_ssh_log_error("accept() failed (%i)", errno);
                break;
            }
        } else {
            em_ssh_session_t *session = NULL;
            struct sockaddr_in paddr;
            int csz = sizeof(struct sockaddr_in);

            if(server_runtime->sessions >= server_runtime->sessions_max) {
                em_ssh_log_warn("too many active sessions (%i)", server_runtime->sessions);
                close(cli_sock);
                continue;
            }
            getpeername(cli_sock, (struct sockaddr *) &paddr, &csz);
            em_ssh_fd_set_blocking(cli_sock, false);

            /* create a session */
            if((err = em_ssh_session_alloc(&session)) != OK) {
                goto err;
            }

            if((err = em_ssh_session_set_peerip(session, (char *) inet_ntoa(paddr.sin_addr))) != OK) {
                goto err;
            }
            session->socfd = cli_sock;

            if((err = em_ssh_packet_io_hello(session, 10)) != OK) {
                em_ssh_log_warn("hello failed (%i)", err);
                goto err;
            }

            /* increase session counter */
            semTake(server_runtime->sem, WAIT_FOREVER);
            session->id = server_runtime->sessions;
            server_runtime->sessions++;
            server_runtime->session = session;
            semGive(server_runtime->sem);

            if(taskSpawn("sshd_sess", 200, 0, 16384, (FUNCPTR) em_sshd_sesion_task, (int)session, 0,0,0,0,0,0,0,0,0) != ERROR) {
                continue;
            }
            em_ssh_log_warn("sshd_sess spawn failed: %i", errno);
        err:
            close(cli_sock);
            em_ssh_mem_deref(session);
        }
    }

    /* free resources */
    shutdown(server_runtime->srv_sock, 2);
    server_runtime->fl_running = false;

    while(server_runtime->sessions > 0) {
        taskDelay(CLOCKS_PER_SEC / 2);
    }

    em_ssh_mem_deref(server_runtime);
    exit(OK);
}

LOCAL void em_sshd_sesion_task(em_ssh_session_t *session) {
    int err = OK;
    uint8_t msgid;
    char cbuff[PTY_DEVICE_BUFFER_SIZE];

    if(!session) {
        em_ssh_log_error("session corrupt!");
        server_runtime->fl_do_shutdown = true;
        exit(ERROR);
    }

#ifdef EM_SSH_DEBUG_SESSION
    em_ssh_log_debug("session started: %i (%s)", taskIdSelf(), session->peerip);
#endif

    session->fl_rekeying_done = false;
    session->fl_authorized = false;

rekeying:
    /* kex */
    session->state = EM_SSH_SESSION_STATE_NEG;
    if((err = em_ssh_packet_io_kexinit(session, 20)) != OK) {
        em_ssh_log_warn("kex-init failed (%i)", err);
        goto out;
    }

    em_ssh_kex_newkeys_realloc(session->kex);

    if((err = em_ssh_packet_io_kexecdh(session, 20)) != OK) {
        em_ssh_log_warn("kex-echg failed (%i)", err);
        goto out;
    }

    em_ssh_mem_deref(session->kex->client_kex_init);
    em_ssh_mem_deref(session->kex->server_kex_init);
    em_ssh_kex_newkeys_init(session->kex);
    session->fl_rekeying_done = true;

    /* auth */
    if(!session->fl_authorized) {
        session->state = EM_SSH_SESSION_STATE_AUTH;
        if((err = em_ssh_packet_io_auth(session, 35)) != OK) {
            em_ssh_log_warn("auth failed (%i)", err);
            goto out;
        }
        session->fl_authorized = true;
    }

    session->state = EM_SSH_SESSION_STATE_WORK;

    /* session loop */
    while(true) {
        if(server_runtime->fl_do_shutdown) {
            break;
        }
        if(session->channel) {
            if(session->channel->fl_do_close) {
                taskDelay(CLOCKS_PER_SEC / 2);
                em_ssh_packet_send_disconnect(session, SSH_DISCONNECT_PROTOCOL_ERROR, NULL);
                break;
            }
            if(session->channel->fl_pty_ready && session->channel->fl_shell_ready) {
                if(em_ssh_fd_select_read(session->channel->pty_io_fd_m, 250)) {
                    const int rd = read(session->channel->pty_io_fd_m, cbuff, sizeof(cbuff));
                    if(rd > 0) {
                        em_ssh_packet_send_channel_data(session, session->channel, (uint8_t *)cbuff, rd);
                    }
                }
            }
        }

        if(!em_ssh_fd_select_read(session->socfd, 250)) {
            continue;
        }
        err = em_ssh_packet_receive(session, session->iobuf, 10);
        if(err == ETIME) {
            continue;
        } else if(err != OK) {
            break;
        }
        if(session->iobuf->end < 6) {
            em_ssh_packet_send_disconnect(session, SSH_DISCONNECT_PROTOCOL_ERROR, NULL);
            break;
        }

        msgid = em_ssh_mbuf_read_u8(session->iobuf);
        switch(msgid) {
            case SSH_MSG_KEXINIT: {
                session->fl_rekeying_done = false;
                goto rekeying;
                break;
            }
            case SSH_MSG_CHANNEL_OPEN: {
                em_ssh_mbuf_set_pos(session->iobuf, session->iobuf->pos - 1);
                if((err = em_ssh_packet_do_channel_open(session)) != OK) {
                    em_ssh_log_warn("channel_open() failed (%i)", err);
                    goto out;
                }
                break;
            }
            case SSH_MSG_CHANNEL_CLOSE: {
                em_ssh_mbuf_set_pos(session->iobuf, session->iobuf->pos - 1);
                if((err = em_ssh_packet_do_channel_close(session)) != OK) {
                    em_ssh_log_warn("channel_close() failed (%i)", err);
                    goto out;
                }
                break;
            }
            case SSH_MSG_CHANNEL_EOF: {
                em_ssh_mbuf_set_pos(session->iobuf, session->iobuf->pos - 1);
                if((err = em_ssh_packet_do_channel_eof(session)) != OK) {
                    em_ssh_log_warn("channel_eof() failed (%i)", err);
                    goto out;
                }
                break;
            }
            case SSH_MSG_CHANNEL_REQUEST: {
                em_ssh_mbuf_set_pos(session->iobuf, session->iobuf->pos - 1);
                if((err = em_ssh_packet_do_channel_request(session)) != OK) {
                    em_ssh_log_warn("channel_request() failed (%i)", err);
                    goto out;
                }
                break;
            }
            case SSH_MSG_CHANNEL_DATA: {
                size_t data_len = 0;
                em_ssh_mbuf_set_pos(session->iobuf, session->iobuf->pos - 1);
                if((err = em_ssh_packet_do_channel_data(session, &data_len)) != OK) {
                    em_ssh_log_warn("channel_data() failed (%i)", err);
                    goto out;
                }
                if(data_len > 0) {
                    if(session->channel && session->channel->fl_pty_ready && session->channel->fl_shell_ready) {
                        char *p = (void *)session->iobuf->buf + session->iobuf->pos;
                        write(session->channel->pty_io_fd_m, p, data_len);
                    }
                }
                break;
            }
            case SSH_MSG_CHANNEL_EXTENDED_DATA:
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                break;
            default:
                em_ssh_log_warn("unsupported message: 0x%x", msgid );
                if((err = em_ssh_packet_send_unimplemented(session)) != OK) {
                    break;
                }
        }
    }
out:
    /* free session */
    semTake(server_runtime->sem, WAIT_FOREVER);

    session->state = EM_SSH_SESSION_STATE_TERMINATE;
    em_ssh_mem_deref(session);

    server_runtime->sessions--;
    server_runtime->session = NULL;

    semGive(server_runtime->sem);

#ifdef EM_SSH_DEBUG_SESSION
    em_ssh_log_debug("session finished: %i", taskIdSelf());
#endif

    exit(OK);
}


