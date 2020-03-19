/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_PACKET_H
#define EMSSH_PACKET_H
#include <vxWorks.h>

#define VXWORKS_TCP_MAX_SIZE            65535
#define EM_SSH_PACKET_SIZE_MAX          35000
#define EM_SSH_PACKET_PAYLOAD_SIZE_MAX  32768

int em_ssh_packet_start(em_ssh_mbuf_t *mbuf, uint8_t type);
int em_ssh_packet_end(em_ssh_session_t *session, em_ssh_mbuf_t *mbuf);
int em_ssh_packet_expect(em_ssh_mbuf_t *mbuf, uint8_t type);

int em_ssh_packet_receive(em_ssh_session_t *session, em_ssh_mbuf_t *mbuf, int timeout);
int em_ssh_packet_send(em_ssh_session_t *session, em_ssh_mbuf_t *mbuf);

int em_ssh_packet_io_hello(em_ssh_session_t *session, int timeout);
int em_ssh_packet_io_kexinit(em_ssh_session_t *session, int timeout);
int em_ssh_packet_io_kexecdh(em_ssh_session_t *session, int timeout);
int em_ssh_packet_io_auth(em_ssh_session_t *session, int timeout);

int em_ssh_packet_do_channel_request(em_ssh_session_t *session);
int em_ssh_packet_do_channel_open(em_ssh_session_t *session);
int em_ssh_packet_do_channel_eof(em_ssh_session_t *session);
int em_ssh_packet_do_channel_close(em_ssh_session_t *session);
int em_ssh_packet_do_channel_data(em_ssh_session_t *session, size_t *data_len);


int em_ssh_packet_send_channel_eof(em_ssh_session_t *session, em_ssh_channel_t *channel);
int em_ssh_packet_send_channel_close(em_ssh_session_t *session, em_ssh_channel_t *channel);
int em_ssh_packet_send_channel_data(em_ssh_session_t *session, em_ssh_channel_t *channel, uint8_t *data, size_t data_len);

int em_ssh_packet_send_disconnect(em_ssh_session_t *session, int reason, char *message);
int em_ssh_packet_send_unimplemented(em_ssh_session_t *session);

#endif
