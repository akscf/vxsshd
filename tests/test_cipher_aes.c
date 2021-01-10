/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

int vxssh_test_aes() {
    int err = OK;

    uint8_t k128[16]= {0x31,0x4f,0x78,0x37,0x6e,0x30,0x39,0x73,0x6b,0x50,0x57,0x46,0x58,0x7a,0x36,0x49};
    uint8_t msg[32] = {0x48,0x65,0x6c,0x6c,0x6f,0x77,0x20,0x77,0x6f,0x72,0x6c,0x64,0x20,0x31,0x32,0x33,0x2d,0x34,0x35,0x36,0x2d,0x37,0x38,0x39,0x2d,0x31,0x32,0x33,0x2d,0x34,0x35,0x36};
    uint8_t decMsg[32]= {0};
    uint8_t encMsg[32]= {0};
    vxssh_aes_ctx_t *ectx = NULL;
    vxssh_aes_ctx_t *dctx = NULL;

    vxssh_log_debug("Cipher test: AES128...");

    /* encrypt */
    err = vxssh_aes_alloc(&ectx);
    if(err != OK) {
        vxssh_log_error("vxssh_aes_alloc(1) fail (%i)", err);
        goto out;
    }
    err = vxssh_aes_init(ectx, k128, sizeof(k128), false);
    if(err != OK) {
        vxssh_log_error("vxssh_aes_init(1) fail (%i)", err);
        goto out;
    }

    /* decrypt */
    err = vxssh_aes_alloc(&dctx);
    if(err != OK) {
        vxssh_log_error("vxssh_aes_alloc(2) fail (%i)", err);
        goto out;
    }
    err = vxssh_aes_init(dctx, k128, sizeof(k128), true);
    if(err != OK) {
        vxssh_log_error("vxssh_aes_init(2) fail (%i)", err);
        goto out;
    }

    /* encrypt the message */
    err = vxssh_aes_process_block(ectx, msg, sizeof(msg), encMsg, sizeof(encMsg));
    if(err != OK) {
        vxssh_log_error("vxssh_aes_process_block(1) fail (%i)", err);
        goto out;
    }
    err = vxssh_aes_process_block(ectx, msg + 16, sizeof(msg), encMsg + 16, sizeof(encMsg));
    if(err != OK) {
        vxssh_log_error("vxssh_aes_process_block(2) fail (%i)", err);
        goto out;
    }

    /* decrypt the message */
    err = vxssh_aes_process_block(dctx, encMsg, sizeof(encMsg), decMsg, sizeof(decMsg));
    if(err != OK) {
        vxssh_log_error("vxssh_aes_process_block(3) fail (%i)", err);
        goto out;
    }
    err = vxssh_aes_process_block(dctx, encMsg + 16, sizeof(encMsg), decMsg + 16, sizeof(decMsg));
    if(err != OK) {
        vxssh_log_error("vxssh_aes_process_block(3) fail (%i)", err);
        goto out;
    }

    /*
    vxssh_hexdump2("MSG: ", msg, sizeof(msg));
    vxssh_hexdump2("ENC: ", encMsg, sizeof(encMsg));
    vxssh_hexdump2("DEC: ", decMsg, sizeof(decMsg));
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
    vxssh_mem_deref(ectx);
    vxssh_mem_deref(dctx);

    return err;
}
