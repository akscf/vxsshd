/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_LOG_H
#define VXSSH_LOG_H
#include <vxWorks.h>

//#define VXSSH_LOGGER_VXWORKS
#define VXSSH_LOGGER_BUILDIN

#if defined(VXSSH_LOGGER_BUILDIN)
 #define vxssh_log_debug(fmt, ...) do{vxssh_log(VXSSH_LOG_DEBUG, fmt, ##__VA_ARGS__);} while (0)
 #define vxssh_log_warn(fmt, ...)  do{vxssh_log(VXSSH_LOG_WARN, fmt, ##__VA_ARGS__);} while (0)
 #define vxssh_log_error(fmt, ...) do{vxssh_log(VXSSH_LOG_ERROR, fmt, ##__VA_ARGS__);} while (0)
#elif defined(VXSSH_LOGGER_VXWORKS)
 #define vxssh_log_debug(fmt, ...) do{logMsg("DEBUG: " fmt, ##__VA_ARGS__);} while (0)
 #define vxssh_log_warn(fmt, ...)  do{logMsg("WARN: " fmt, ##__VA_ARGS__);} while (0)
 #define vxssh_log_error(fmt, ...) do{logMsg("ERROR: " fmt, ##__VA_ARGS__);} while (0)
#else
 #define vxssh_log_debug(fmt, ...)
 #define vxssh_log_warn(fmt, ...)
 #define vxssh_log_error(fmt, ...)
#endif

typedef enum {
    VXSSH_LOG_DEBUG,
    VXSSH_LOG_WARN,
    VXSSH_LOG_ERROR
} vxssh_log_type_t;

void vxssh_log(vxssh_log_type_t tp, const char *fmt, ...);


#endif
