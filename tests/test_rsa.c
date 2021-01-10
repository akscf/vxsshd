/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

int vxssh_test_rsa() {
    int err = OK;

    vxssh_log_debug("RSA tests ...");


    vxssh_log_debug("%s", err == OK ? "SUCCESS" : "FAIL");
    return err;
}
