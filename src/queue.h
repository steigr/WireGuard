/* Copyright (C) 2017 Samuel Holland <samuel@sholland.org>. All Rights Reserved. */

#ifndef WGQUEUE_H
#define WGQUEUE_H

#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>

#include "packets.h"

struct wireguard_queue {
	struct sk_buff_head head;
	atomic_t available_packets[3];
	atomic_t next_init_cpu;
	atomic_t next_encrypt_cpu;
	atomic_t next_transmit_cpu;
};

#define new_packets available_packets[0]
#define initialized_packets available_packets[1]
#define encrypted_packets available_packets[2]

enum {
	PACKET_TX_NEW = 0,
	PACKET_TX_INITIALIZING,
	PACKET_TX_INITIALIZED,
	PACKET_TX_ENCRYPTING,
	PACKET_TX_ENCRYPTED,
};

/**
 * Return the current CPU number in the shared variable, and update sthe shared
 * variable.
 */
static inline int next_cpu(atomic_t *shared_cpu)
{
	int cpu = atomic_read(shared_cpu);

	if (cpu >= nr_cpumask_bits || !cpumask_test_cpu(cpu, cpu_online_mask))
		cpu = cpumask_first(cpu_online_mask);
	atomic_set(shared_cpu, cpumask_next(cpu, cpu_online_mask));

	return cpu;
}

/**
 * Use this helper to ensure safe traversal of the queue looking for a packet to
 * process. It returns the address of an already-claimed packet, or NULL if no
 * packet with the appropriate state was found.
 */
static inline struct sk_buff *claim_first_packet(struct wireguard_queue *queue,
						 unsigned int state)
{
	struct sk_buff *skb;

	spin_lock_bh(&queue->head.lock);
	skb_queue_walk(&queue->head, skb) {
		/* Marking the packet "in progress" guarantees its lifetime. */
		if (atomic_cmpxchg(&PACKET_CB(skb)->state, state, state + 1) == state) {
			atomic_dec(&queue->available_packets[state / 2]);
			spin_unlock_bh(&queue->head.lock);
			return skb;
		}
	}
	spin_unlock_bh(&queue->head.lock);

	return NULL;
}

/**
 * Call this helper with a packet already claimed.
 */
static inline struct sk_buff *claim_next_packet(struct wireguard_queue *queue,
						struct sk_buff *skb,
						unsigned int state)
{
	skb_queue_walk_from(&queue->head, skb) {
		/* Marking the packet "in progress" guarantees its lifetime. */
		if (atomic_cmpxchg(&PACKET_CB(skb)->state, state, state + 1) == state) {
			atomic_dec(&queue->available_packets[state / 2]);
			return skb;
		}
	}

	return NULL;
}

static inline void release_packet(struct wireguard_queue *queue,
				  struct sk_buff *skb,
				  bool advance)
{
	int state = atomic_read(&PACKET_CB(skb)->state);

	if (advance) {
		atomic_inc(&queue->available_packets[(state + 1) / 2]);
		atomic_inc(&PACKET_CB(skb)->state);
	} else {
		atomic_inc(&queue->available_packets[(state - 1) / 2]);
		atomic_dec(&PACKET_CB(skb)->state);
	}
}

static inline struct sk_buff *dequeue_packets(struct wireguard_queue *queue,
					      unsigned int state)
{
	int removed = 0;
	struct sk_buff *first, *last, *next;

	spin_lock_bh(&queue->head.lock);
	first = next = queue->head.next;
	while (next != (struct sk_buff *)&queue->head && atomic_read(&PACKET_CB(next)->state) == state) {
		removed += 1;
		last = next;
		next = last->next;
	}
	if (!removed) {
		spin_unlock_bh(&queue->head.lock);
		return NULL;
	}
	queue->head.next = next;
	next->prev = (struct sk_buff *)&queue->head;
	spin_unlock_bh(&queue->head.lock);
	atomic_sub(removed, &queue->available_packets[state / 2]);

	/* The returned packets are treated as a singly-linked single-ended list. */
	last->next = NULL;

	return first;
}

static inline void enqueue_packet(struct wireguard_queue *queue,
				  struct sk_buff *skb)
{
	struct sk_buff *last;

	getnstimeofday(&PACKET_CB(skb)->ts);
	atomic_set(&PACKET_CB(skb)->state, PACKET_TX_NEW);
	skb->next = (struct sk_buff *)&queue->head;
	atomic_inc(&queue->available_packets[0]);
	spin_lock_bh(&queue->head.lock);
	last = queue->head.prev;
	skb->prev = last;
	queue->head.prev = skb;
	last->next = skb;
	spin_unlock_bh(&queue->head.lock);
}

static inline void enqueue_packet_list(struct wireguard_queue *queue,
				       struct sk_buff_head *list)
{
	struct sk_buff *last, *skb;

	skb_queue_walk(list, skb) {
		getnstimeofday(&PACKET_CB(skb)->ts);
		atomic_set(&PACKET_CB(skb)->state, PACKET_TX_NEW);
	}
	list->prev->next = (struct sk_buff *)&queue->head;
	atomic_add(list->qlen, &queue->available_packets[0]);
	spin_lock_bh(&queue->head.lock);
	last = queue->head.prev;
	list->next->prev = last;
	queue->head.prev = list->prev;
	last->next = list->next;
	spin_unlock_bh(&queue->head.lock);
}

#endif /* WGQUEUE_H */
