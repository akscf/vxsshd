/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_LOG_H
#define EMSSH_LOG_H
#include <vxWorks.h>

//#define EM_SSH_LOGGER_VXWORKS
#define EM_SSH_LOGGER_BUILDIN

#if defined(EM_SSH_LOGGER_BUILDIN)
 #define em_ssh_log_debug(fmt, ...) do{em_ssh_log(EM_SSH_LOG_DEBUG, fmt, ##__VA_ARGS__);} while (0)
 #define em_ssh_log_warn(fmt, ...)  do{em_ssh_log(EM_SSH_LOG_WARN, fmt, ##__VA_ARGS__);} while (0)
 #define em_ssh_log_error(fmt, ...) do{em_ssh_log(EM_SSH_LOG_ERROR, fmt, ##__VA_ARGS__);} while (0)
#elif defined(EM_SSH_LOGGER_VXWORKS)
 #define em_ssh_log_debug(fmt, ...) do{logMsg("DEBUG: " fmt, ##__VA_ARGS__);} while (0)
 #define em_ssh_log_warn(fmt, ...)  do{logMsg("WARN: " fmt, ##__VA_ARGS__);} while (0)
 #define em_ssh_log_error(fmt, ...) do{logMsg("ERROR: " fmt, ##__VA_ARGS__);} while (0)
#else
 #define em_ssh_log_debug(fmt, ...)
 #define em_ssh_log_warn(fmt, ...)
 #define em_ssh_log_error(fmt, ...)
#endif

typedef enum {
    EM_SSH_LOG_DEBUG,
    EM_SSH_LOG_WARN,
    EM_SSH_LOG_ERROR
} em_ssh_log_type_t;

void em_ssh_log(em_ssh_log_type_t tp, const char *fmt, ...);


#endif
