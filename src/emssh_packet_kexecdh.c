/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

/**
 * curve25519
 *
 **/
int em_ssh_packet_io_kexecdh(em_ssh_session_t *session, int timeout) {
    em_ssh_server_runtime_t *rt = em_ssh_server_get_runtime();
    em_ssh_kex_t *kex = (session ? session->kex : NULL);
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;
    size_t hash_len, dh_shared_key_len, dh_client_pub_key_len;
    em_ssh_mbuf_t *hk_blob = NULL, *sign_blob = NULL;
    em_ssh_crypto_object_t *signature;
    uint8_t *dh_client_pub_key = NULL;
    uint8_t *dh_shared_key = NULL;
    uint8_t *hash = NULL;
    uint8_t dh_server_prv_key[CRYPTO_CURVE25519_SIZE];
    uint8_t dh_server_pub_key[CRYPTO_CURVE25519_SIZE];

    if(!session || !kex) {
        return EINVAL;
    }
    if((err = em_ssh_mbuf_alloc(&hk_blob, 512)) != OK) {
        goto out;
    }
    if((err = em_ssh_mbuf_alloc(&sign_blob, 255)) != OK) {
        goto out;
    }
    /* generate server key pair */
    em_ssh_kex_c25519_keygen(dh_server_prv_key, dh_server_pub_key);

    /* --- SSH2_MSG_KEX_ECDH_INIT --- */
    if((err = em_ssh_packet_receive(session, mbuf, timeout)) != OK) {
        goto out;
    }
    if(err = em_ssh_packet_expect(mbuf, SSH2_MSG_KEX_ECDH_INIT) != OK) {
        goto out;
    }
    /* Q_C */
    dh_client_pub_key_len = em_ssh_mbuf_read_u32(mbuf);
    if(dh_client_pub_key_len != CRYPTO_CURVE25519_SIZE) {
        em_ssh_log_warn("invalid Q_C len: %i", dh_client_pub_key_len);
        err = ERROR; goto out;
    }
    if((dh_client_pub_key = em_ssh_mem_zalloc(dh_client_pub_key_len, NULL)) == NULL) {
        err = ENOMEM;
        goto out;
    }
    if((err = em_ssh_mbuf_read_mem(mbuf, dh_client_pub_key, &dh_client_pub_key_len)) != OK) {
        goto out;
    }
    /* make shared secret */
    em_ssh_kex_c25519_shared_key(dh_server_prv_key, dh_client_pub_key, &dh_shared_key, &dh_shared_key_len);
    // hostkey
    if((err = em_ssh_rsa_encode_public_key2(hk_blob, (em_ssh_crypto_rsa_private_key_t *)rt->server_key->obj)) != OK) {
        goto out;
    }
    /* calc H */
    if((hash_len = em_ssh_digest_bytes(kex->hash_alg)) == 0) {
        err = ERROR;
        goto out;
    }
    if((hash = em_ssh_mem_zalloc(hash_len, NULL)) == NULL)  {
        err = ENOMEM;
        goto out;
    }
    if((err = em_ssh_kex_c25519_hash(
        kex->hash_alg,
        kex->client_version, kex->client_version_len,
        kex->server_version, kex->server_version_len,
        kex->client_kex_init, kex->client_kex_init_len,
        kex->server_kex_init, kex->server_kex_init_len,
        hk_blob->buf, hk_blob->pos,
        dh_client_pub_key, dh_server_pub_key,
        dh_shared_key, dh_shared_key_len,
        hash, hash_len)) != OK) {
            goto out;
        }
    /* sign hash */
    if((err = em_ssh_rsa_sign((em_ssh_crypto_rsa_private_key_t *)rt->server_key->obj, hash, hash_len, &signature)) != OK) {
        goto out;
    }
    if((err = em_ssh_rsa_encode_signature(sign_blob, ((em_ssh_crypto_rsa_signature_t *)signature->obj))) != OK) {
        goto out;
    }
    /* copy session_id */
    if (kex->session_id == NULL) {
        kex->session_id_len = hash_len;
        if((kex->session_id = em_ssh_mem_alloc(kex->session_id_len, NULL)) == NULL) {
            err = ENOMEM;
            goto out;
        }
        memcpy(kex->session_id, hash, kex->session_id_len);
    }

#ifdef EM_SSH_DEBUG_KEX_DH
    em_ssh_hexdump2("kex-dh: sesion id....: ", kex->session_id, kex->session_id_len);
    em_ssh_hexdump2("kex-dh: client key...: ", dh_client_pub_key, dh_client_pub_key_len);
    em_ssh_hexdump2("kex-dh: server pub...: ", dh_server_pub_key, sizeof(dh_server_pub_key));
    em_ssh_hexdump2("kex-dh: shared key...: ", dh_shared_key, dh_shared_key_len);
#endif

    /* --- SSH2_MSG_KEX_ECDH_REPLY --- */
    em_ssh_packet_start(mbuf, SSH2_MSG_KEX_ECDH_REPLY);
    em_ssh_mbuf_write_mem_sz(mbuf, hk_blob->buf, hk_blob->pos);
    em_ssh_mbuf_write_mem_sz(mbuf, dh_server_pub_key, CRYPTO_CURVE25519_SIZE);
    em_ssh_mbuf_write_mem_sz(mbuf, sign_blob->buf, sign_blob->pos);
    em_ssh_packet_end(session, mbuf);

    if((err = em_ssh_packet_send(session, mbuf)) != OK) {
        goto out;
    }

    /* key derivation */
    if((err = em_ssh_kex_derive_keys(kex, hash, hash_len, dh_shared_key, dh_shared_key_len)) != OK) {
        goto out;
    }

    /* SSH_MSG_NEWKEYS */
    em_ssh_packet_start(mbuf, SSH_MSG_NEWKEYS);
    em_ssh_packet_end(session, mbuf);

    if((err = em_ssh_packet_send(session, mbuf)) != OK) {
        goto out;
    }
    if((err = em_ssh_packet_receive(session, mbuf, timeout)) != OK) {
        goto out;
    }
    if(err = em_ssh_packet_expect(mbuf, SSH_MSG_NEWKEYS) != OK) {
        goto out;
    }

out:
    em_ssh_mem_deref(hk_blob);
    em_ssh_mem_deref(sign_blob);
    em_ssh_mem_deref(signature);
    em_ssh_mem_deref(dh_shared_key);
    em_ssh_mem_deref(dh_client_pub_key);
    em_ssh_mem_deref(hash);

#ifdef EM_SSH_USE_MEMORY_CLEARING
    explicit_bzero(dh_server_prv_key, sizeof(dh_server_prv_key));
#endif

    return err;
}
