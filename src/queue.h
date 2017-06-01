/* Copyright (C) 2017 Samuel Holland <samuel@sholland.org>. All Rights Reserved. */

#ifndef WGQUEUE_H
#define WGQUEUE_H

#include <linux/kernel.h>
#include <linux/skbuff.h>

enum packet_state {
	PACKET_TX_NEW,
	PACKET_TX_INITIALIZING,
	PACKET_TX_INITIALIZED,
	PACKET_TX_ENCRYPTING,
	PACKET_TX_ENCRYPTED,
};

/**
 * Use this helper to ensure safe traversal of the queue looking for a packet to
 * process. It returns the address of an already-claimed packet, or NULL if no
 * packet with the appropriate state was found.
 */
static inline struct sk_buff *claim_first_packet(struct sk_buff_head *queue,
						 enum packet_state state)
{
	struct sk_buff *skb;

	spin_lock_bh(&queue->lock);
	skb_queue_walk(queue, skb) {
		/* Marking the packet "in progress" guarantees its lifetime. */
		if (atomic_cmpxchg(&PACKET_CB(skb)->state, state, state + 1) == state) {
			spin_unlock_bh(&queue->lock);
			return skb;
		}
	}
	spin_unlock_bh(&queue->lock);

	return NULL;
}

/**
 * Call this helper with a packet already claimed.
 */
static inline struct sk_buff *claim_next_packet(struct sk_buff_head *queue,
						struct sk_buff *skb,
						enum packet_state state)
{
	skb_queue_walk_from(queue, skb) {
		/* Marking the packet "in progress" guarantees its lifetime. */
		if (atomic_cmpxchg(&PACKET_CB(skb)->state, state, state + 1) == state)
			return skb;
	}

	return NULL;
}

static inline void release_packet(struct sk_buff *skb, bool advance)
{
	if (advance)
		atomic_inc(&PACKET_CB(skb)->state);
	else
		atomic_dec(&PACKET_CB(skb)->state);
}

static inline struct sk_buff *dequeue_packets(struct sk_buff_head *queue,
					      enum packet_state state)
{
	int removed = 0;
	struct sk_buff *first, *last, *next;

	spin_lock_bh(&queue->lock);
	first = next = queue->next;
	while (next != (struct sk_buff *)queue && atomic_read(&PACKET_CB(next)->state) == state) {
		removed += 1;
		last = next;
		next = last->next;
	}
	if (!removed) {
		spin_unlock_bh(&queue->lock);
		return NULL;
	}
	queue->qlen -= removed;
	queue->next = next;
	next->prev = (struct sk_buff *)queue;
	spin_unlock_bh(&queue->lock);

	last->next = NULL;

	return first;
}

static inline void enqueue_packet(struct sk_buff_head *queue,
				  struct sk_buff *skb)
{
	struct sk_buff *last;

	getnstimeofday(&PACKET_CB(skb)->ts);
	atomic_set(&PACKET_CB(skb)->state, PACKET_TX_NEW);
	skb->next = (struct sk_buff *)queue;
	spin_lock_bh(&queue->lock);
	last = queue->prev;
	skb->prev = last;
	queue->prev = skb;
	last->next = skb;
	queue->qlen += 1;
	spin_unlock_bh(&queue->lock);
}

static inline void enqueue_packet_list(struct sk_buff_head *queue,
				       struct sk_buff_head *list)
{
	struct sk_buff *head, *last, *skb, *tail;

	skb_queue_walk(list, skb) {
		getnstimeofday(&PACKET_CB(skb)->ts);
		atomic_set(&PACKET_CB(skb)->state, PACKET_TX_NEW);
	}
	head = list->next;
	tail = list->prev;
	tail->next = (struct sk_buff *)queue;
	spin_lock_bh(&queue->lock);
	last = queue->prev;
	head->prev = last;
	queue->prev = tail;
	last->next = head;
	queue->qlen += list->qlen;
	spin_unlock_bh(&queue->lock);
}

#endif /* WGQUEUE_H */
