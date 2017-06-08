/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "cookie.h"
#include "device.h"
#include "messages.h"
#include "packets.h"
#include "peer.h"
#include "queue.h"
#include "socket.h"
#include "timers.h"

#include <linux/inetdevice.h>
#include <linux/jiffies.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <net/ip_tunnels.h>
#include <net/sock.h>
#include <net/udp.h>

#define MAX_QUEUE_WORK 64

static void packet_send_handshake_initiation(struct wireguard_peer *peer)
{
	struct message_handshake_initiation packet;

	down_write(&peer->handshake.lock);
	if (!time_is_before_jiffies64(peer->last_sent_handshake + REKEY_TIMEOUT)) {
		up_write(&peer->handshake.lock);
		return; /* This function is rate limited. */
	}
	peer->last_sent_handshake = get_jiffies_64();
	up_write(&peer->handshake.lock);

	net_dbg_ratelimited("%s: Sending handshake initiation to peer %Lu (%pISpfsc)\n", netdev_pub(peer->device)->name, peer->internal_id, &peer->endpoint.addr);

	if (noise_handshake_create_initiation(&packet, &peer->handshake)) {
		cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		timers_any_authenticated_packet_traversal(peer);
		socket_send_buffer_to_peer(peer, &packet, sizeof(struct message_handshake_initiation), HANDSHAKE_DSCP);
		timers_handshake_initiated(peer);
	}
}

void packet_send_queued_handshakes(struct work_struct *work)
{
	struct wireguard_peer *peer = container_of(work, struct wireguard_peer, transmit_handshake_work);
	packet_send_handshake_initiation(peer);
	peer_put(peer);
}

void packet_queue_handshake_initiation(struct wireguard_peer *peer, bool is_retry)
{
	if (!is_retry)
		peer->timer_handshake_attempts = 0;

	/* First checking the timestamp here is just an optimization; it will
	 * be caught while properly locked inside the actual work queue. */
	if (!time_is_before_jiffies64(peer->last_sent_handshake + REKEY_TIMEOUT))
		return;

	peer = peer_rcu_get(peer);
	if (unlikely(!peer))
		return;

	/* Queues up calling packet_send_queued_handshakes(peer), where we do a peer_put(peer). */
	if (!queue_work(peer->device->peer_wq, &peer->transmit_handshake_work))
		peer_put(peer); /* If the work was already queued, drop the extra reference. */
}

void packet_send_handshake_response(struct wireguard_peer *peer)
{
	struct message_handshake_response packet;

	net_dbg_ratelimited("%s: Sending handshake response to peer %Lu (%pISpfsc)\n", netdev_pub(peer->device)->name, peer->internal_id, &peer->endpoint.addr);
	peer->last_sent_handshake = get_jiffies_64();

	if (noise_handshake_create_response(&packet, &peer->handshake)) {
		cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		if (noise_handshake_begin_session(&peer->handshake, &peer->keypairs, false)) {
			timers_ephemeral_key_created(peer);
			timers_any_authenticated_packet_traversal(peer);
			socket_send_buffer_to_peer(peer, &packet, sizeof(struct message_handshake_response), HANDSHAKE_DSCP);
		}
	}
}

void packet_send_handshake_cookie(struct wireguard_device *wg, struct sk_buff *initiating_skb, __le32 sender_index)
{
	struct message_handshake_cookie packet;

	net_dbg_skb_ratelimited("%s: Sending cookie response for denied handshake message for %pISpfsc\n", netdev_pub(wg)->name, initiating_skb);
	cookie_message_create(&packet, initiating_skb, sender_index, &wg->cookie_checker);
	socket_send_buffer_as_reply_to_skb(wg, initiating_skb, &packet, sizeof(packet));
}

void packet_send_keepalive(struct wireguard_peer *peer)
{
	struct sk_buff *skb;
	if (skb_queue_empty(&peer->tx_packet_queue.head)) {
		skb = alloc_skb(DATA_PACKET_HEAD_ROOM + MESSAGE_MINIMUM_LENGTH, GFP_ATOMIC);
		if (unlikely(!skb))
			return;
		skb_reserve(skb, DATA_PACKET_HEAD_ROOM);
		skb->dev = netdev_pub(peer->device);
		enqueue_packet(&peer->tx_packet_queue, skb);
		net_dbg_ratelimited("%s: Sending keepalive packet to peer %Lu (%pISpfsc)\n", netdev_pub(peer->device)->name, peer->internal_id, &peer->endpoint.addr);
	} else {
		net_dbg_ratelimited("%s: NOT sending keepalive to peer %Lu (%pISpfsc)\n", netdev_pub(peer->device)->name, peer->internal_id, &peer->endpoint.addr);
	}
	packet_send_queue(peer);
}

static inline void update_send_delay_stats(struct wireguard_peer *peer, struct timespec delay)
{
	struct wireguard_device *wg = peer->device;

	s64 delay_ns = timespec_to_ns(&delay), max_delay, mean_delay, new_delay, sent_packets;

	if (delay_ns <= 0) {
		net_dbg_ratelimited("%s: Negative delay! %lld ns\n", netdev_pub(wg)->name, delay_ns);
		return;
	}
retry:
	sent_packets = atomic64_read(&wg->sent_packets);
	mean_delay = atomic64_read(&wg->mean_send_delay);
	/* Take care to compensate for integer division. */
	new_delay = ((mean_delay + 500) * 999 + delay_ns) / 1000;
	if (atomic64_cmpxchg(&wg->sent_packets, sent_packets, sent_packets + 1) != sent_packets)
		goto retry;
	if (atomic64_cmpxchg(&wg->mean_send_delay, mean_delay, new_delay) != mean_delay) {
		atomic64_dec(&wg->sent_packets);
		goto retry;
	}
	/* Avoid spamming dmesg. */
	if (sent_packets % 100000 == 0)
		net_dbg_ratelimited("%s: Mean delay is %lld ns, qlen is %d %d %d\n", netdev_pub(wg)->name, new_delay,
				atomic_read(&peer->tx_packet_queue.new_packets),
				atomic_read(&peer->tx_packet_queue.initialized_packets),
				atomic_read(&peer->tx_packet_queue.encrypted_packets));
retry2:
	max_delay = atomic64_read(&wg->max_send_delay);
	if (delay_ns > max_delay) {
		if (atomic64_cmpxchg(&wg->max_send_delay, max_delay, delay_ns) != max_delay)
			goto retry2;
		/* Avoid spamming dmesg. */
		if (delay_ns > max_delay + 1000)
			net_dbg_ratelimited("%s: Max delay is %lld ns\n", netdev_pub(wg)->name, delay_ns);
	}
}

static inline void keep_key_fresh(struct wireguard_peer *peer)
{
	struct noise_keypair *keypair;
	bool send = false;

	rcu_read_lock_bh();
	keypair = rcu_dereference_bh(peer->keypairs.current_keypair);
	if (likely(keypair && keypair->sending.is_valid) &&
	   (unlikely(atomic64_read(&keypair->sending.counter.counter) > REKEY_AFTER_MESSAGES) ||
	   (keypair->i_am_the_initiator && unlikely(time_is_before_eq_jiffies64(keypair->sending.birthdate + REKEY_AFTER_TIME)))))
		send = true;
	rcu_read_unlock_bh();

	if (send)
		packet_queue_handshake_initiation(peer, false);
}

static inline unsigned int skb_padding(struct sk_buff *skb)
{
	/* We do this modulo business with the MTU, just in case the networking layer
	 * gives us a packet that's bigger than the MTU. Now that we support GSO, this
	 * shouldn't be a real problem, and this can likely be removed. But, caution! */
	unsigned int last_unit = skb->len % skb->dev->mtu;
	unsigned int padded_size = (last_unit + MESSAGE_PADDING_MULTIPLE - 1) & ~(MESSAGE_PADDING_MULTIPLE - 1);
	if (padded_size > skb->dev->mtu)
		padded_size = skb->dev->mtu;
	return padded_size - last_unit;
}

static inline bool skb_encrypt(struct sk_buff *skb, struct noise_keypair *keypair, bool have_simd)
{
	struct scatterlist sg[MAX_SKB_FRAGS * 2 + 1];
	struct message_data *header;
	unsigned int padding_len, plaintext_len, trailer_len;
	int num_frags;
	struct sk_buff *trailer;

	/* Store the ds bit in the cb */
	PACKET_CB(skb)->ds = ip_tunnel_ecn_encap(0 /* No outer TOS: no leak. TODO: should we use flowi->tos as outer? */, ip_hdr(skb), skb);

	/* Calculate lengths */
	padding_len = skb_padding(skb);
	trailer_len = padding_len + noise_encrypted_len(0);
	plaintext_len = skb->len + padding_len;

	/* Expand data section to have room for padding and auth tag */
	num_frags = skb_cow_data(skb, trailer_len, &trailer);
	if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg)))
		return false;

	/* Set the padding to zeros, and make sure it and the auth tag are part of the skb */
	memset(skb_tail_pointer(trailer), 0, padding_len);

	/* Expand head section to have room for our header and the network stack's headers. */
	if (unlikely(skb_cow_head(skb, DATA_PACKET_HEAD_ROOM) < 0))
		return false;

	/* We have to remember to add the checksum to the innerpacket, in case the receiver forwards it. */
	if (likely(!skb_checksum_setup(skb, true)))
		skb_checksum_help(skb);

	/* Only after checksumming can we safely add on the padding at the end and the header. */
	header = (struct message_data *)skb_push(skb, sizeof(struct message_data));
	header->header.type = cpu_to_le32(MESSAGE_DATA);
	header->key_idx = keypair->remote_index;
	header->counter = cpu_to_le64(PACKET_CB(skb)->nonce);
	pskb_put(skb, trailer, trailer_len);

	/* Now we can encrypt the scattergather segments */
	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, sizeof(struct message_data), noise_encrypted_len(plaintext_len)) <= 0)
		return false;
	return chacha20poly1305_encrypt_sg(sg, sg, plaintext_len, NULL, 0, PACKET_CB(skb)->nonce, keypair->sending.key, have_simd);
}

static inline bool get_encryption_nonce(u64 *nonce, struct noise_symmetric_key *key)
{
	if (unlikely(!key))
		return false;

	if (unlikely(!key->is_valid || time_is_before_eq_jiffies64(key->birthdate + REJECT_AFTER_TIME))) {
		key->is_valid = false;
		return false;
	}

	*nonce = atomic64_inc_return(&key->counter.counter) - 1;
	if (*nonce >= REJECT_AFTER_MESSAGES) {
		key->is_valid = false;
		return false;
	}

	return true;
}

void packet_transmission_worker(struct work_struct *work)
{
	struct sk_buff *next, *skb;
	struct wireguard_peer *peer = container_of(work, struct wireguard_peer, packet_transmit_work);

	while ((skb = dequeue_packets(&peer->tx_packet_queue, PACKET_TX_ENCRYPTED))) {
		bool data_sent = false;

		timers_any_authenticated_packet_traversal(peer);
		do {
			bool is_keepalive = skb->len == message_data_len(0);
			struct timespec now;

			next = skb->next;
			getnstimeofday(&now);
			update_send_delay_stats(peer, timespec_sub(now, PACKET_CB(skb)->ts));
			if (likely(!socket_send_skb_to_peer(peer, skb, PACKET_CB(skb)->ds) && !is_keepalive))
				data_sent = true;
		} while ((skb = next) != NULL);

		if (likely(data_sent))
			timers_data_sent(peer);
	}
	keep_key_fresh(peer);

	/* If there's more work for this stage, enqueue it again. */
	if (atomic_read(&peer->tx_packet_queue.encrypted_packets)) {
		int cpu = get_cpu();
		queue_work_on(cpu, peer->device->crypt_wq, &peer->packet_transmit_work);
		put_cpu();
	}
}

void packet_encryption_worker(struct work_struct *work)
{
	bool have_simd;
	int processed = 0;
	struct sk_buff *next = NULL, *skb;
	struct wireguard_peer *peer = container_of(work, struct percpu_work, work)->peer;

	have_simd = chacha20poly1305_init_simd();
	/* Keep going until we've run out of packets, or we've done the maximum amout of work. */
	while (processed < MAX_QUEUE_WORK) {
		bool success = false;

		/* If we have already claimed a packet, work on that one. Otherwise, start looking
		 * for work at the beginning of the list. */
		if (!(skb = next ? next : claim_first_packet(&peer->tx_packet_queue, PACKET_TX_INITIALIZED)))
			break;

		if (unlikely(!skb_encrypt(skb, PACKET_CB(skb)->keypair, have_simd))) {
			net_dbg_ratelimited("%s: encrypt failed!!!! skb = %p\n", netdev_pub(peer->device)->name, skb);
			goto finished;
		}
		skb_reset(skb);
		noise_keypair_put(PACKET_CB(skb)->keypair);
		success = true;

finished:
		/* Acquire the next packet before releasing this one to avoid needing to lock during
		 * list traversal, but only if we're going to iterate again. */
		if (unlikely(++processed == MAX_QUEUE_WORK))
			next = NULL;
		else
			next = claim_next_packet(&peer->tx_packet_queue, skb, PACKET_TX_INITIALIZED);
		release_packet(&peer->tx_packet_queue, skb, success);
	}
	chacha20poly1305_deinit_simd(have_simd);

	/* Queue the next stage of work. */
	if (processed > 0)
		queue_work_on(next_cpu(&peer->tx_packet_queue.next_transmit_cpu), peer->device->crypt_wq, &peer->packet_transmit_work);

	/* If there's more work for this stage, enqueue it as well. */
	if (atomic_read(&peer->tx_packet_queue.initialized_packets)) {
		int cpu = get_cpu();
		queue_work_on(cpu, peer->device->crypt_wq, per_cpu_ptr(&peer->packet_encrypt_work->work, cpu));
		put_cpu();
	}
}

void packet_init_worker(struct work_struct *work)
{
	int processed = 0;
	struct sk_buff *next = NULL, *skb;
	struct wireguard_peer *peer = container_of(work, struct wireguard_peer, packet_init_work);

	/* Keep going until we've run out of packets, or we've done the maximum amout of work. */
	while (processed < MAX_QUEUE_WORK) {
		bool success = false;
		struct noise_keypair *keypair;

		/* If we have already claimed a packet, work on that one. Otherwise, start looking
		 * for work at the beginning of the list. */
		if (!(skb = next ? next : claim_first_packet(&peer->tx_packet_queue, PACKET_TX_NEW)))
			break;

		rcu_read_lock_bh();
		keypair = noise_keypair_get(rcu_dereference_bh(peer->keypairs.current_keypair));
		rcu_read_unlock_bh();

		if (unlikely(!keypair)) {
			packet_queue_handshake_initiation(peer, false);
			goto finished;
		}
		if (unlikely(!get_encryption_nonce(&PACKET_CB(skb)->nonce, &keypair->sending))) {
			noise_keypair_put(keypair);
			goto finished;
		}
		PACKET_CB(skb)->keypair = keypair;
		success = true;

finished:
		/* Acquire the next packet before releasing this one to avoid needing to lock during
		 * list traversal, but only if we're going to iterate again. */
		if (unlikely(++processed == MAX_QUEUE_WORK))
			next = NULL;
		else
			next = claim_next_packet(&peer->tx_packet_queue, skb, PACKET_TX_NEW);
		release_packet(&peer->tx_packet_queue, skb, success);
	}

	/* Queue the next stage of work. */
	if (processed > 0) {
		int cpus;

		for (cpus = 0; cpus < processed && cpus < cpumask_weight(cpu_online_mask); cpus += 1) {
			int cpu = next_cpu(&peer->tx_packet_queue.next_encrypt_cpu);
			queue_work_on(cpu, peer->device->crypt_wq, per_cpu_ptr(&peer->packet_encrypt_work->work, cpu));
		}
	}

	/* If there's more work for this stage, enqueue it as well. */
	if (atomic_read(&peer->tx_packet_queue.new_packets)) {
		int cpu = get_cpu();
		queue_work_on(cpu, peer->device->crypt_wq, &peer->packet_init_work);
		put_cpu();
	}
}

void packet_send_queue(struct wireguard_peer *peer)
{
	int cpus;

	if (atomic_read(&peer->tx_packet_queue.new_packets))
		queue_work_on(next_cpu(&peer->tx_packet_queue.next_init_cpu), peer->device->crypt_wq, &peer->packet_init_work);
	for (cpus = 0; cpus < atomic_read(&peer->tx_packet_queue.initialized_packets) && cpus < cpumask_weight(cpu_online_mask); cpus += 1) {
		int cpu = next_cpu(&peer->tx_packet_queue.next_encrypt_cpu);
		queue_work_on(cpu, peer->device->crypt_wq, per_cpu_ptr(&peer->packet_encrypt_work->work, cpu));
	}
	if (atomic_read(&peer->tx_packet_queue.encrypted_packets))
		queue_work_on(next_cpu(&peer->tx_packet_queue.next_transmit_cpu), peer->device->crypt_wq, &peer->packet_transmit_work);
}
