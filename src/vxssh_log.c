/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

/**
 *
 **/
void vxssh_log(vxssh_log_type_t tp, const char *fmt, ...) {
    va_list ptr;
    va_start(ptr, fmt);

    switch(tp) {
        case VXSSH_LOG_DEBUG :
            printf("SSHD_DEBUG: ");
            vprintf(fmt, ptr);
            printf("\n\r");
            break;

        case VXSSH_LOG_WARN :
            printf("SSHD_WARN: ");
            vprintf(fmt, ptr);
            printf("\n\r");
            break;

        case VXSSH_LOG_ERROR :
            printf("SSHD_ERROR: ");
            vprintf(fmt, ptr);
            printf("\n\r");
            break;
    }
    va_end(ptr);
}

