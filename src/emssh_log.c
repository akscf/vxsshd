/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

/**
 *
 **/
void em_ssh_log(em_ssh_log_type_t tp, const char *fmt, ...) {
    va_list ptr;
    va_start(ptr, fmt);
    switch(tp) {
        case EM_SSH_LOG_DEBUG :
            printf("[SSH] DEBUG: ");
            vprintf(fmt, ptr);
            printf("\n\r");
            break;
        case EM_SSH_LOG_WARN :
            printf("[SSH] WARN: ");
            vprintf(fmt, ptr);
            printf("\n\r");
            break;
        case EM_SSH_LOG_ERROR :
            printf("[SSH] ERROR: ");
            vprintf(fmt, ptr);
            printf("\n\r");
            break;
    }
    va_end(ptr);
}

