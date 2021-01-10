/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

static inline uint32_t rnd_u32(void) {
    return rand();
}

// ----------------------------------------------------------------------------------------------
/**
 * NOTICE: This is use system srand,
 *         you should replace it to a more quality implementation!
 **/
int vxssh_rnd_init() {
    time_t s = vxssh_get_time();

    srand(s);

    return OK;
}

/**
 * create an array of random bytes
 **/
int vxssh_rnd_bin(char *buf, size_t size) {
    if(!buf || !size) {
        return EINVAL;
    }
    while (size--) {
        buf[size] = (uint8_t) rnd_u32();
    }
    return OK;
}

