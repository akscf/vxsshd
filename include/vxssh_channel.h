/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_CHANNEL_H
#define VXSSH_CHANNEL_H
#include <vxWorks.h>
#include "vxssh_ctype.h"

#define PTY_DEVICE_NAME_MAX_LEN 32
#define PTY_DEVICE_BUFFER_SIZE  128

typedef struct {
    uint32_t        id;
    uint32_t        packet_size;
    uint32_t        local_wsz;
    uint32_t        remote_wsz;
    bool            feof;
    bool            fl_shell_ready;
    bool            fl_pty_ready;
    bool            fl_do_close;
    int             shell_tid;
    int             pty_io_fd_s;
    int             pty_io_fd_m;
    int             fd_old_in;
    int             fd_old_out;
    int             fd_old_err;
    char            pty_name[PTY_DEVICE_NAME_MAX_LEN];
} vxssh_channel_t;

int vxssh_channel_alloc(vxssh_channel_t **channel, uint32_t chid, uint32_t win_size, uint32_t packet_size);
int vxssh_channel_eof(vxssh_channel_t *channel);
int vxssh_channel_close(vxssh_channel_t *channel);

int vxssh_channel_start_shell(vxssh_channel_t *channel);
int vxssh_channel_create_pty(vxssh_channel_t *channel);


#endif
