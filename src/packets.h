/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef PACKETS_H
#define PACKETS_H

#include "noise.h"
#include "messages.h"
#include "socket.h"

#include <linux/types.h>
#include <linux/padata.h>

struct wireguard_device;
struct wireguard_peer;
struct sk_buff;

struct encryption_ctx {
	struct list_head list;
	struct wireguard_peer *peer;
	struct noise_keypair *keypair;
	struct sk_buff_head queue;
	atomic_t state;
};

struct packet_cb {
	struct timespec ts;
	u64 nonce;
	u8 ds;
};
#define PACKET_CB(skb) ((struct packet_cb *)skb->cb)

enum {
	PACKET_TX_NEW,
	PACKET_TX_INITING,
	PACKET_TX_INITED,
	PACKET_TX_ENCRYPTING,
	PACKET_TX_ENCRYPTED,
	PACKET_TX_SENDING,
};

/* receive.c */
void packet_receive(struct wireguard_device *wg, struct sk_buff *skb);
void packet_process_queued_handshake_packets(struct work_struct *work);
void packet_consume_data_done(struct sk_buff *skb, struct wireguard_peer *peer, struct endpoint *endpoint, bool used_new_key);

/* send.c */
void packet_send_keepalive(struct wireguard_peer *peer);
void packet_queue_handshake_initiation(struct wireguard_peer *peer, bool is_retry);
void packet_send_queued_handshakes(struct work_struct *work);
void packet_send_handshake_response(struct wireguard_peer *peer);
void packet_send_handshake_cookie(struct wireguard_device *wg, struct sk_buff *initiating_skb, __le32 sender_index);
void send_keep_key_fresh(struct wireguard_peer *peer);

/* data.c */
void init_packet_worker(struct work_struct *work);
void encrypt_packet_worker(struct work_struct *work);
void transmit_packet_worker(struct work_struct *work);
int packet_enqueue_list(struct wireguard_peer *peer, struct sk_buff_head *queue);
void packet_consume_data(struct sk_buff *skb, struct wireguard_device *wg);

#ifdef CONFIG_WIREGUARD_PARALLEL
int packet_init_data_caches(void);
void packet_deinit_data_caches(void);
#endif

#ifdef DEBUG
bool packet_counter_selftest(void);
#endif

#endif
