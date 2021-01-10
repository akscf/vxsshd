/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

int vxssh_test_aes_cbc() {
    int err = OK;

    vxssh_cipher_alg_props_t cip_cfg = {"aes128-cbc", VXSSH_CIPHER_AES, VXSSH_CIPHER_MODE_CBC, VXSSH_CIPHER_AES_BLOCK_SIZE, 16 , 0};

    uint8_t msg[] = {0x48,0x65,0x6c,0x6c,0x6f,0x77,0x20,0x77,0x6f,0x72,0x6c,0x64,0x20,0x31,0x32,0x33,0x2d,0x34,0x35,0x36,0x2d,0x37,0x38,0x39,0x2d,0x31,0x32,0x33,0x2d,0x34,0x35,0x36};
    uint8_t key[] = {0x31,0x4f,0x78,0x37,0x6e,0x30,0x39,0x73,0x6b,0x50,0x57,0x46,0x58,0x7a,0x36,0x49};
    uint8_t iv[] = {0x34,0x72,0x79,0x6b,0x70,0x35,0x38,0x32,0x53,0x71,0x72,0x78,0x71,0x55,0x31,0x38};
    uint8_t decMsg[32]= {0};
    uint8_t encMsg[32]= {0};

    vxssh_cipher_ctx_t *cip_enc = NULL;
    vxssh_cipher_ctx_t *cip_dec = NULL;

    vxssh_log_debug("Cipher test: AES128-CBC...");

    // encode ----------------------------------------------------------------------------
    if((err = vxssh_cipher_alloc(&cip_enc, &cip_cfg, false)) != OK) {
        vxssh_log_error("vxssh_cipher_alloc(1) fail, err=%i", err);
        goto out;
    }
    cip_enc->iv = vxssh_mem_dup(iv, sizeof(iv));
    cip_enc->key = vxssh_mem_dup(key, sizeof(key));

    if((err = vxssh_cipher_init(cip_enc)) != OK) {
        vxssh_log_error("vxssh_cipher_init(1) fail, err=%i", err);
        goto out;
    }

    err = vxssh_cipher_encrypt(cip_enc, msg, sizeof(msg), encMsg, sizeof(encMsg));
    if(err != OK) {
        vxssh_log_error("vxssh_cipher_encrypt(1) fail, err=%i", err);
        goto out;
    }
    err = vxssh_cipher_encrypt(cip_enc, msg + 16, sizeof(msg), encMsg + 16, sizeof(encMsg));
    if(err != OK) {
        vxssh_log_error("vxssh_cipher_encrypt(2) fail, err=%i", err);
        goto out;
    }

    // decode ------------------------------------------------------------------------------
    if((err = vxssh_cipher_alloc(&cip_dec, &cip_cfg, true)) != OK) {
        vxssh_log_error("vxssh_cipher_alloc(2) fail, err=%i", err);
        goto out;
    }
    cip_dec->iv = vxssh_mem_dup(iv, sizeof(iv));
    cip_dec->key = vxssh_mem_dup(key, sizeof(key));

    if((err = vxssh_cipher_init(cip_dec)) != OK) {
        vxssh_log_error("vxssh_cipher_init(2) fail, err=%i", err);
        goto out;
    }

    err = vxssh_cipher_decrypt(cip_dec, encMsg, sizeof(encMsg), decMsg, sizeof(decMsg));
    if(err != OK) {
        vxssh_log_error("vxssh_cipher_encrypt(1) fail, err=%i", err);
        goto out;
    }
    err = vxssh_cipher_decrypt(cip_dec, encMsg + 16, sizeof(encMsg), decMsg + 16, sizeof(decMsg));
    if(err != OK) {
        vxssh_log_error("vxssh_cipher_encrypt(2) fail, err=%i", err);
        goto out;
    }

    /*
    vxssh_hexdump2("MSG...: ", msg, sizeof(msg));
    vxssh_hexdump2("ENC...: ", encMsg, sizeof(encMsg));
    vxssh_hexdump2("DEC...: ", decMsg, sizeof(decMsg));
    */

    /* check */
    if (memcmp(msg, decMsg, sizeof(decMsg))) {
        vxssh_log_error("decoded message mismatch");

        vxssh_hexdump2("msg: ", msg, sizeof(msg));
        vxssh_hexdump2("dec: ", decMsg, sizeof(decMsg));

        err = ERROR;
    } else {
        err = OK;
    }
    vxssh_log_debug("%s", err == OK ? "SUCCESS" : "FAIL");

out:
    vxssh_mem_deref(cip_enc);
    vxssh_mem_deref(cip_dec);

    return err;
}
