/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef WGDEVICE_H
#define WGDEVICE_H

#include "noise.h"
#include "routingtable.h"
#include "hashtables.h"
#include "cookie.h"

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/workqueue.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/padata.h>
#include <linux/notifier.h>

struct wireguard_device;
struct handshake_worker {
	struct wireguard_device *wg;
	struct work_struct work;
};

struct wireguard_device {
	struct sock __rcu *sock4, *sock6;
	u16 incoming_port;
	u32 fwmark;
	struct net *creating_net;
	struct kset *kset;
	struct noise_static_identity static_identity;
	struct workqueue_struct *incoming_handshake_wq, *peer_wq;
	struct sk_buff_head incoming_handshakes;
	atomic_t incoming_handshake_seqnr;
	struct handshake_worker __percpu *incoming_handshakes_worker;
	struct cookie_checker cookie_checker;
	struct pubkey_hashtable peer_hashtable;
	struct index_hashtable index_hashtable;
	struct routing_table peer_routing_table;
	struct list_head peer_list;
	struct mutex device_update_lock;
	struct mutex socket_update_lock;
#ifdef CONFIG_PM_SLEEP
	struct notifier_block clear_peers_on_suspend;
#endif
	struct workqueue_struct *crypt_wq;
#ifdef CONFIG_WIREGUARD_PARALLEL
	struct padata_instance *decrypt_pd;
#endif
	atomic64_t sent_packets;
	atomic64_t max_send_delay;
	atomic64_t mean_send_delay;
};

int device_init(void);
void device_uninit(void);

#endif
