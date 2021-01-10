/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_STR_H
#define VXSSH_STR_H

#include <vxWorks.h>

time_t vxssh_get_time();
void vxssh_sleep(int sec);

int vxssh_fd_set_blocking(int sockfd, bool flag);
int vxssh_fd_select_read(int sockfd, int usec);

/* openbsd compat */
void explicit_bzero (void *s, size_t len);
int timingsafe_bcmp(const void *b1, const void *b2, size_t n);

#endif

