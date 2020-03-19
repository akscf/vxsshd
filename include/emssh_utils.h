/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_STR_H
#define EMSSH_STR_H

#include <vxWorks.h>

time_t em_ssh_get_time();
void em_ssh_sleep(int sec);

int em_ssh_fd_set_blocking(int sockfd, bool flag);
int em_ssh_fd_select_read(int sockfd, int usec);

/* openbsd compat */
void explicit_bzero (void *s, size_t len);
int timingsafe_bcmp(const void *b1, const void *b2, size_t n);

#endif

