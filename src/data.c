/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "noise.h"
#include "device.h"
#include "peer.h"
#include "messages.h"
#include "packets.h"
#include "queue.h"
#include "hashtables.h"

#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/bitmap.h>
#include <linux/scatterlist.h>
#include <net/ip_tunnels.h>
#include <net/xfrm.h>
#include <crypto/algapi.h>

static struct kmem_cache *crypt_ctx_cache __read_mostly;

int __init init_crypt_cache(void)
{
	crypt_ctx_cache = KMEM_CACHE(crypt_ctx, 0);
	if (!crypt_ctx_cache)
		return -ENOMEM;
	return 0;
}

void deinit_crypt_cache(void)
{
	kmem_cache_destroy(crypt_ctx_cache);
}

static void drop_ctx(struct crypt_ctx *ctx, bool sending)
{
	if (!sending)
		noise_keypair_put(ctx->keypair);
	peer_put(ctx->peer);
	if (sending)
		skb_queue_purge(&ctx->queue);
	else
		dev_kfree_skb(ctx->skb);
	kmem_cache_free(crypt_ctx_cache, ctx);
}

static inline int next_cpu(int *next)
{
	int cpu = *next;

	if (cpu >= nr_cpumask_bits || !cpumask_test_cpu(cpu, cpu_online_mask))
		cpu = cpumask_first(cpu_online_mask);
	*next = cpumask_next(cpu, cpu_online_mask);

	return cpu;
}

/* TODO: prevent cpu from going offline while adding to its queue (until the work is queued). */
/* It is unsafe to dereference ctx after the call to list_enqueue_atomic(). */
#define queue_ctx_and_work_on_next_cpu(ctx, wq, queue, cpu) ({ \
	int __cpu = next_cpu(cpu); \
	struct crypt_queue *__queue = per_cpu_ptr(queue, __cpu); \
	list_enqueue_atomic_inc(__queue, &(ctx)->shared_list); \
	queue_work_on(__cpu, wq, &__queue->work); \
})

/* This is RFC6479, a replay detection bitmap algorithm that avoids bitshifts */
static inline bool counter_validate(union noise_counter *counter, u64 their_counter)
{
	bool ret = false;
	unsigned long index, index_current, top, i;
	spin_lock_bh(&counter->receive.lock);

	if (unlikely(counter->receive.counter >= REJECT_AFTER_MESSAGES + 1 || their_counter >= REJECT_AFTER_MESSAGES))
		goto out;

	++their_counter;

	if (unlikely((COUNTER_WINDOW_SIZE + their_counter) < counter->receive.counter))
		goto out;

	index = their_counter >> ilog2(BITS_PER_LONG);

	if (likely(their_counter > counter->receive.counter)) {
		index_current = counter->receive.counter >> ilog2(BITS_PER_LONG);
		top = min_t(unsigned long, index - index_current, COUNTER_BITS_TOTAL / BITS_PER_LONG);
		for (i = 1; i <= top; ++i)
			counter->receive.backtrack[(i + index_current) & ((COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1)] = 0;
		counter->receive.counter = their_counter;
	}

	index &= (COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1;
	ret = !test_and_set_bit(their_counter & (BITS_PER_LONG - 1), &counter->receive.backtrack[index]);

out:
	spin_unlock_bh(&counter->receive.lock);
	return ret;
}
#include "selftest/counter.h"

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

static inline void skb_reset(struct sk_buff *skb)
{
	skb_scrub_packet(skb, false);
	memset(&skb->headers_start, 0, offsetof(struct sk_buff, headers_end) - offsetof(struct sk_buff, headers_start));
	skb->queue_mapping = 0;
	skb->nohdr = 0;
	skb->peeked = 0;
	skb->mac_len = 0;
	skb->dev = NULL;
#ifdef CONFIG_NET_SCHED
	skb->tc_index = 0;
	skb_reset_tc(skb);
#endif
	skb->hdr_len = skb_headroom(skb);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_probe_transport_header(skb, 0);
	skb_reset_inner_headers(skb);
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

static inline bool skb_decrypt(struct sk_buff *skb, struct noise_symmetric_key *key)
{
	struct scatterlist sg[MAX_SKB_FRAGS * 2 + 1];
	struct sk_buff *trailer;
	int num_frags;

	if (unlikely(!key))
		return false;

	if (unlikely(!key->is_valid || time_is_before_eq_jiffies64(key->birthdate + REJECT_AFTER_TIME) || key->counter.receive.counter >= REJECT_AFTER_MESSAGES)) {
		key->is_valid = false;
		return false;
	}

	PACKET_CB(skb)->nonce = le64_to_cpu(((struct message_data *)skb->data)->counter);
	skb_pull(skb, sizeof(struct message_data));
	num_frags = skb_cow_data(skb, 0, &trailer);
	if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg)))
		return false;

	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, 0, skb->len) <= 0)
		return false;

	if (!chacha20poly1305_decrypt_sg(sg, sg, skb->len, NULL, 0, PACKET_CB(skb)->nonce, key->key))
		return false;

	return !pskb_trim(skb, skb->len - noise_encrypted_len(0));
}

static inline bool queue_add_keypair_and_nonces(struct crypt_ctx *ctx)
{
	struct noise_symmetric_key *key;
	struct sk_buff *skb;

	rcu_read_lock_bh();
	ctx->keypair = noise_keypair_get(rcu_dereference_bh(ctx->peer->keypairs.current_keypair));
	rcu_read_unlock_bh();
	if (unlikely(!ctx->keypair))
		return false;
	key = &ctx->keypair->sending;
	if (unlikely(!key || !key->is_valid))
		goto out_nokey;
	if (unlikely(time_is_before_eq_jiffies64(key->birthdate + REJECT_AFTER_TIME)))
		goto out_invalid;

	skb_queue_walk(&ctx->queue, skb) {
		PACKET_CB(skb)->nonce = atomic64_inc_return(&key->counter.counter) - 1;
		if (unlikely(PACKET_CB(skb)->nonce >= REJECT_AFTER_MESSAGES))
			goto out_invalid;
	}

	return true;

out_invalid:
	key->is_valid = false;
out_nokey:
	noise_keypair_put(ctx->keypair);
	return false;
}

void packet_transmission_worker(struct work_struct *work)
{
	struct crypt_ctx *ctx;
	struct wireguard_peer *peer = container_of(work, struct wireguard_peer, packet_transmission_work);

	while ((ctx = list_first_entry_or_null(&peer->send_queue, struct crypt_ctx, peer_list)) != NULL) {
		if (atomic_read(&ctx->state) != CTX_FINISHED)
			break;
		list_dequeue_atomic(&peer->send_queue);
		packet_create_data_done(&ctx->queue, ctx->peer);
		peer_put(ctx->peer);
		kmem_cache_free(crypt_ctx_cache, ctx);
	}
}

void packet_encryption_worker(struct work_struct *work)
{
	bool have_simd;
	struct crypt_ctx *ctx;
	struct crypt_queue *queue = container_of(work, struct crypt_queue, work);
	struct sk_buff *skb, *tmp;
	struct wireguard_peer *peer;

	have_simd = chacha20poly1305_init_simd();
	while ((ctx = list_dequeue_entry_atomic_dec(queue, struct crypt_ctx, shared_list)) != NULL) {
		skb_queue_walk_safe (&ctx->queue, skb, tmp) {
			if (unlikely(!skb_encrypt(skb, ctx->keypair, have_simd))) {
				__skb_unlink(skb, &ctx->queue);
				kfree_skb(skb);
				continue;
			}
			skb_reset(skb);
		}
		noise_keypair_put(ctx->keypair);
		/* Dereferencing ctx is unsafe after ctx->state == CTX_FINISHED. */
		peer = peer_rcu_get(ctx->peer);
		if (unlikely(atomic_cmpxchg(&ctx->state, CTX_NEW, CTX_FINISHED) == CTX_FREEING)) {
			drop_ctx(ctx, true);
			continue;
		}
		queue_work_on(peer->work_cpu, peer->device->crypt_wq, &peer->packet_transmission_work);
		peer_put(peer);
	}
	chacha20poly1305_deinit_simd(have_simd);
}

void packet_initialization_worker(struct work_struct *work)
{
	struct crypt_ctx *ctx;
	struct wireguard_peer *peer = peer_rcu_get(container_of(work, struct wireguard_peer, packet_initialization_work));

	/* We must drop stale packets from within the work function so
	 * list_dequeue_entry_atomic() never runs concurrently with itself. */
	if (unlikely(peer->timer_purge_uninit_packets)) {
		while ((ctx = list_dequeue_entry_atomic(&peer->init_queue, struct crypt_ctx, peer_list)) != NULL)
			drop_ctx(ctx, true);
		peer->timer_purge_uninit_packets = false;
		return;
	}

	while ((ctx = list_first_entry_or_null(&peer->init_queue, struct crypt_ctx, peer_list)) != NULL) {
		if (likely(queue_add_keypair_and_nonces(ctx))) {
			list_dequeue_atomic(&peer->init_queue);
			list_enqueue_atomic(&peer->send_queue, &ctx->peer_list);
			queue_ctx_and_work_on_next_cpu(ctx, peer->device->crypt_wq, peer->device->encrypt_queue, &peer->device->encrypt_cpu);
		} else {
			packet_queue_handshake_initiation(peer, false);
			break;
		}
	}
	peer_put(peer);
}

int packet_create_data(struct sk_buff_head *queue, struct wireguard_peer *peer)
{
	struct crypt_ctx *ctx = kmem_cache_alloc(crypt_ctx_cache, GFP_ATOMIC);
	struct sk_buff *skb;

	if (unlikely(!ctx))
		return -ENOMEM;
	skb_queue_head_init(&ctx->queue);
	skb_queue_splice_tail(queue, &ctx->queue);
	ctx->peer = peer_rcu_get(peer);
	atomic_set(&ctx->state, CTX_NEW);

	/* If there are already ctx's on the init queue, this ctx must go behind
	 * them to maintain packet ordering, so we cannot take the fast path. */
	if (unlikely(!list_empty(&peer->init_queue))) {
		skb_queue_walk (&ctx->queue, skb)
			skb_orphan(skb);
		list_enqueue_atomic(&peer->init_queue, &ctx->peer_list);
		/* Handle a possible race with packet_initialization_worker(). */
		if (list_first_entry_or_null(&peer->init_queue, struct crypt_ctx, peer_list) == ctx)
			queue_work(peer->device->crypt_wq, &peer->packet_initialization_work);
	} else if (unlikely(!queue_add_keypair_and_nonces(ctx))) {
		skb_queue_walk (&ctx->queue, skb)
			skb_orphan(skb);
		list_enqueue_atomic(&peer->init_queue, &ctx->peer_list);
		packet_queue_handshake_initiation(peer, false);
	} else {
		list_enqueue_atomic(&peer->send_queue, &ctx->peer_list);
		queue_ctx_and_work_on_next_cpu(ctx, peer->device->crypt_wq, peer->device->encrypt_queue, &peer->device->encrypt_cpu);
	}

	return 0;
}

void packet_consumption_worker(struct work_struct *work)
{
	struct crypt_ctx *ctx;
	struct sk_buff *skb;
	struct wireguard_peer *peer = container_of(work, struct wireguard_peer, packet_consumption_work);

	while ((ctx = list_first_entry_or_null(&peer->receive_queue, struct crypt_ctx, peer_list)) != NULL) {
		if (atomic_read(&ctx->state) != CTX_FINISHED)
			break;
		list_dequeue_atomic(&peer->receive_queue);
		if (likely(skb = ctx->skb)) {
			if (unlikely(!counter_validate(&ctx->keypair->receiving.counter, PACKET_CB(skb)->nonce))) {
				net_dbg_ratelimited("%s: Packet has invalid nonce %Lu (max %Lu)\n", ctx->peer->device->dev->name, PACKET_CB(ctx->skb)->nonce, ctx->keypair->receiving.counter.receive.counter);
				dev_kfree_skb(skb);
			} else {
				skb_reset(skb);
				packet_consume_data_done(skb, ctx->peer, &ctx->endpoint, noise_received_with_keypair(&ctx->peer->keypairs, ctx->keypair));
			}
		}
		noise_keypair_put(ctx->keypair);
		peer_put(ctx->peer);
		kmem_cache_free(crypt_ctx_cache, ctx);
	}
}

void packet_decryption_worker(struct work_struct *work)
{
	struct crypt_ctx *ctx;
	struct crypt_queue *queue = container_of(work, struct crypt_queue, work);
	struct wireguard_peer *peer;

	while ((ctx = list_dequeue_entry_atomic_dec(queue, struct crypt_ctx, shared_list)) != NULL) {
		if (unlikely(socket_endpoint_from_skb(&ctx->endpoint, ctx->skb) < 0 || !skb_decrypt(ctx->skb, &ctx->keypair->receiving))) {
			dev_kfree_skb(ctx->skb);
			ctx->skb = NULL;
		}
		/* Dereferencing ctx is unsafe after ctx->state == CTX_FINISHED. */
		peer = peer_rcu_get(ctx->peer);
		if (unlikely(atomic_cmpxchg(&ctx->state, CTX_NEW, CTX_FINISHED) == CTX_FREEING))
			drop_ctx(ctx, false);
		else
			queue_work_on(peer->work_cpu, peer->device->crypt_wq, &peer->packet_consumption_work);
		peer_put(peer);
	}
}

void packet_consume_data(struct sk_buff *skb, struct wireguard_device *wg)
{
	struct crypt_ctx *ctx = kmem_cache_alloc(crypt_ctx_cache, GFP_ATOMIC);
	struct noise_keypair *keypair;
	__le32 idx = ((struct message_data *)skb->data)->key_idx;

	if (unlikely(!ctx)) {
		dev_kfree_skb(skb);
		return;
	}
	rcu_read_lock_bh();
	keypair = noise_keypair_get((struct noise_keypair *)index_hashtable_lookup(&wg->index_hashtable, INDEX_HASHTABLE_KEYPAIR, idx));
	rcu_read_unlock_bh();
	if (unlikely(!keypair)) {
		dev_kfree_skb(skb);
		kmem_cache_free(crypt_ctx_cache, ctx);
		return;
	}

	ctx->skb = skb;
	ctx->peer = keypair->entry.peer;
	ctx->keypair = keypair;
	atomic_set(&ctx->state, CTX_NEW);
	list_enqueue_atomic(&ctx->peer->receive_queue, &ctx->peer_list);
	queue_ctx_and_work_on_next_cpu(ctx, wg->crypt_wq, wg->decrypt_queue, &wg->decrypt_cpu);
}

/* This function cannot run concurrently with any of the work functions. */
void peer_purge_queues(struct wireguard_peer *peer)
{
	bool need_cleanup_work;
	int cpu;
	struct crypt_ctx *ctx;

	while ((ctx = list_dequeue_entry_atomic(&peer->init_queue, struct crypt_ctx, peer_list)) != NULL)
		drop_ctx(ctx, true);
	need_cleanup_work = false;
	while ((ctx = list_dequeue_entry_atomic(&peer->send_queue, struct crypt_ctx, peer_list)) != NULL) {
		/* Only drop the ctx here if it is not in the shared queue. */
		if (atomic_xchg(&ctx->state, CTX_FREEING) == CTX_FINISHED)
			drop_ctx(ctx, true);
		else
			need_cleanup_work = true;
	}
	if (need_cleanup_work)
		for_each_online_cpu(cpu)
			queue_work_on(cpu, peer->device->crypt_wq, &per_cpu_ptr(peer->device->encrypt_queue, cpu)->work);
	need_cleanup_work = false;
	while ((ctx = list_dequeue_entry_atomic(&peer->receive_queue, struct crypt_ctx, peer_list)) != NULL) {
		/* Only drop the ctx here if it is not in the shared queue. */
		if (atomic_xchg(&ctx->state, CTX_FREEING) == CTX_FINISHED)
			drop_ctx(ctx, false);
		else
			need_cleanup_work = true;
	}
	if (need_cleanup_work)
		for_each_online_cpu(cpu)
			queue_work_on(cpu, peer->device->crypt_wq, &per_cpu_ptr(peer->device->decrypt_queue, cpu)->work);
}
