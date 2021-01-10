/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

static void mem_destructor_vxssh_channel_t(void *data) {
    vxssh_channel_t *channel = data;

    if(channel->fl_shell_ready) {
        shellLogoutInstall((FUNCPTR) NULL, 0);

        shellOrigStdSet(STD_IN,  channel->fd_old_in);
        shellOrigStdSet(STD_OUT, channel->fd_old_out);
        shellOrigStdSet(STD_ERR, channel->fd_old_err);

        shellIsRemoteConnectedSet(FALSE);
        shellLock(FALSE);

        excJobAdd(shellRestart, FALSE, 0, 0, 0, 0, 0);
    }

    if(channel->fl_pty_ready) {
        if(channel->pty_io_fd_m) {
            close(channel->pty_io_fd_m);
        }
        if(channel->pty_io_fd_s) {
            close(channel->pty_io_fd_s);
        }
        ptyDevRemove(channel->pty_name);
    }
}

static void shell_exit_handler(vxssh_channel_t *channel) {
    if(!channel) {
        return;
    }
    vxssh_channel_close(channel);
}

// ----------------------------------------------------------------------------------------------------------------------------------------
// public api
// ----------------------------------------------------------------------------------------------------------------------------------------
/**
 *
 **/
int vxssh_channel_alloc(vxssh_channel_t **channel, uint32_t chid, uint32_t win_size, uint32_t packet_size) {
    int err = OK;
    vxssh_channel_t *tch = NULL;

    if(!channel) {
        return EINVAL;
    }

    if((tch = vxssh_mem_zalloc(sizeof(vxssh_channel_t), mem_destructor_vxssh_channel_t)) == NULL) {
        err = ENOMEM;
        goto out;
    }
    tch->id = chid;
    tch->local_wsz = win_size;
    tch->remote_wsz = win_size;
    tch->packet_size = packet_size;

    *channel = tch;

out:
    if(err != OK) {
        vxssh_mem_deref(tch);
    }
    return err;
}

/**
 *
 **/
int vxssh_channel_eof(vxssh_channel_t *channel) {
    int err = OK;

    if(!channel) {
        return EINVAL;
    }

    channel->feof = true;

    return err;
}

/**
 *
 **/
int vxssh_channel_close(vxssh_channel_t *channel) {
    int err = OK;

    if(!channel) {
        return EINVAL;
    }

    channel->fl_do_close = true;

    return err;
}

/**
 *
 **/
int vxssh_channel_create_pty(vxssh_channel_t *channel) {
    char name_s[PTY_DEVICE_NAME_MAX_LEN];
    char name_m[PTY_DEVICE_NAME_MAX_LEN];
    int err = OK;

    if(!channel) {
        return EINVAL;
    }

    explicit_bzero(channel->pty_name, PTY_DEVICE_NAME_MAX_LEN);
    sprintf(channel->pty_name, "/pty/ssh_io_%x.", channel->id);
    sprintf(name_m, "%sM", channel->pty_name);
    sprintf(name_s, "%sS", channel->pty_name);

    if((err = ptyDevCreate(channel->pty_name, PTY_DEVICE_BUFFER_SIZE, PTY_DEVICE_BUFFER_SIZE)) != OK) {
        err = ERROR;
        goto out;
    }
    if((channel->pty_io_fd_m = open(name_m, O_RDWR, 0)) == ERROR) {
        err = ERROR;
        goto out;
    }
    if((channel->pty_io_fd_s = open(name_s, O_RDWR, 0)) == ERROR) {
        err = ERROR;
        goto out;
    }

    channel->fl_pty_ready = true;

out:
    if(err != OK) {
        if(channel->pty_io_fd_m)
            close(channel->pty_io_fd_m);
        if(channel->pty_io_fd_s)
            close(channel->pty_io_fd_s);
        ptyDevRemove(channel->pty_name);
    }
    return err;
}

/**
 * It'll try use tShell process
 **/
int vxssh_channel_start_shell(vxssh_channel_t *channel) {
    int err = OK;

    if(!channel) {
        return EINVAL;
    }

    if((taskNameToId("tShell")) == ERROR) {
        vxssh_log_warn("tShell not started");
        return ERROR;
    }
    if(!shellLock(TRUE)) {
        vxssh_log_warn("The shell is currently in use");
        return ERROR;
    }

    shellLogoutInstall((FUNCPTR) shell_exit_handler, (int) channel);

    channel->fd_old_in = ioGlobalStdGet (STD_IN);
    channel->fd_old_out = ioGlobalStdGet (STD_OUT);
    channel->fd_old_err = ioGlobalStdGet (STD_ERR);

    shellOrigStdSet(STD_IN, channel->pty_io_fd_s);
    shellOrigStdSet(STD_OUT, channel->pty_io_fd_s);
    shellOrigStdSet(STD_ERR, channel->pty_io_fd_s);

    shellIsRemoteConnectedSet(TRUE);

    channel->fl_shell_ready = true;

    printErr("\nThis system *IN USE* via SSH.\n");
    taskDelay(CLOCKS_PER_SEC / 2);
    excJobAdd(shellRestart, TRUE, 0, 0, 0, 0, 0);

out:
    return err;
}

