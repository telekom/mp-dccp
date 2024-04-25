/*
 * MPDCCP - Path manager architecture
 *
 * A flexible architecture to load arbitrary path managers. The
 * default path manager does nothing.
 *
 * The code in this file is partly derived from the MPTCP project's 
 * mptcp_pm.c and mptcp_fullmesh.c. Derived code is Copyright (C) 
 * the original authors Christoph Paasch et al.
 *
 * Copyright (C) 2018 Andreas Philipp Matz <info@andreasmatz.de>
 * Copyright (C) 2020 Frank Reker <frank@reker.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <net/addrconf.h>
#include <net/net_namespace.h>
#include <net/netns/mpdccp.h>
#include <asm/unaligned.h>

#include "../ccids/ccid2.h"
#include "../dccp.h"
#include <net/mpdccp_link.h>
#include <net/mpdccp.h>
#include "../mpdccp.h"
#include "../mpdccp_pm.h"

static struct kmem_cache *mpdccp_pm_addr_cache __read_mostly;
static struct mpdccp_pm_ops mpdccp_pm_default;

//retransmit unconfirmed options after this many millisecs
#define MPDCCP_CONFIRM_RETRANSMIT_TIMEOUT msecs_to_jiffies(1000)
#define MPDCCP_CONFIRM_RETRANSMIT_TRIES	5

enum {
	MPDCCP_EVENT_ADD = 1,
	MPDCCP_EVENT_DEL,
	MPDCCP_EVENT_MOD,
};

struct pm_local_addr_event {
	struct list_head list;
	unsigned short	family;
	u8	code;
	int	if_idx;
	union inet_addr addr;
};

struct mpdccp_confirm_opt {
	u8 opt[MPDCCP_CONFIRM_SIZE];
	u8 resent_cnt;
	u32 t_init;
	u32 t_timeout;
};

struct pm_retransmit_event {
	struct list_head list;
	struct sock *sk;
	struct mpdccp_confirm_opt *cnf_opt;
};

/* Holds a single local interface address */
struct pm_local_addr {
	struct list_head address_list;

	/* Address family, IPv4/v6 address, Interface ID */
	sa_family_t family;
	union inet_addr addr;
	int if_idx;
	u8 id;

	struct rcu_head rcu;
};

struct mpdccp_addr {
	struct list_head address_list;

	struct mpdccp_confirm_opt cnf_addaddr;
	struct mpdccp_confirm_opt cnf_remaddr;
	struct mpdccp_confirm_opt cnf_prio;

	bool remote;
	sa_family_t family;
	union inet_addr addr;
	u16 port;
	u8 id;

	struct rcu_head rcu;
};

static struct mpdccp_pm_ns *fm_get_ns(const struct net *net)
{
	/* TAG-0.8: Migrate to list implementation */
	return (struct mpdccp_pm_ns *)net->mpdccp.path_managers[MPDCCP_PM_FULLMESH];
}

/* calculate hmac for mp_addaddr and mp_removeaddr */
static int pm_get_addr_hmac(struct mpdccp_cb *mpcb,
							u8 id, sa_family_t family,
							union inet_addr *addr, u16 port,
							bool send, u8 *hmac)
{
	u8 msg[19];		//1:id + 16:ipv6 + 2:port
	int len = 1;
	msg[0] = id;

	if(family == AF_INET){
		put_unaligned_be32(addr->ip, &msg[1]);
		put_unaligned_be16(port, &msg[5]);
		len = 7;
	} else if(family == AF_INET6){
		memcpy(&msg[1], addr->ip6, 16);
		put_unaligned_be16(port, &msg[17]);
		len = 19;
	}
	if((send && mpcb->role == MPDCCP_CLIENT) || (!send && mpcb->role != MPDCCP_CLIENT))
		return mpdccp_hmac_sha256(mpcb->dkeyA, mpcb->dkeylen, msg, len, hmac);
	else
		return mpdccp_hmac_sha256(mpcb->dkeyB, mpcb->dkeylen, msg, len, hmac);
}

/* triggers MP_REMOVEADDR option with next packet */
static void mpdccp_send_remove_path(struct mpdccp_cb *mpcb, u8 addr_id)
{
	struct sock *sk = mpdccp_select_ann_sock(mpcb, addr_id);
	if (sk){
		mpdccp_my_sock(sk)->delpath_id = addr_id;
		dccp_send_keepalive(sk);
	}
}

/* triggers MP_ADDADDR option with next packet */
static void mpdccp_send_add_path(struct pm_local_addr *loc_addr, u16 port, struct mpdccp_cb *mpcb)
{
	struct sock *sk = mpdccp_select_ann_sock(mpcb, 0);
	int len = 1;
	u8 *buf = mpdccp_my_sock(sk)->addpath;
	/* since MP_ADDADDR is variable in size buf[0] will hold the length of the option 
		buf[1] -> buf[n] will hold the contents of the option */

	if (!sk) return;

	buf[len] = loc_addr->id;
	len++;
	if(loc_addr->family == AF_INET){
		put_unaligned_be32(loc_addr->addr.ip, &buf[len]);
		len += 4;
	} else if(loc_addr->family == AF_INET6){
		memcpy(&buf[len], loc_addr->addr.ip6, 16);
		len += 16;
	}

	if(port){
		put_unaligned_be16(port, &buf[len]);
		len += 2;
	}
	buf[0] = len - 1;

	pm_get_addr_hmac(mpcb, loc_addr->id, loc_addr->family, &loc_addr->addr, 
			port, 1, mpdccp_my_sock(sk)->addpath_hmac);

	dccp_send_keepalive(sk);
}

/* Use ip routing functions to figure out default source address and store address in mpcb*/
static void mpdccp_get_mpcb_local_address(struct mpdccp_cb *mpcb, struct sockaddr_in *nexthop)
{
	struct sockaddr_in sin;
	struct sock *sk = mpcb->meta_sk;

	/* check if socket was bound to local ip address,
		otherwise use route.h function for local routing default route */
	if(sk && sk->__sk_common.skc_rcv_saddr){
		sin.sin_addr.s_addr = mpcb->meta_sk->__sk_common.skc_rcv_saddr;
	} else {
		struct flowi4 *fl4;
		struct inet_sock *inet = inet_sk(sk);
		fl4 = &inet->cork.fl.u.ip4;
		ip_route_connect(fl4, nexthop->sin_addr.s_addr, inet->inet_saddr, RT_CONN_FLAGS(sk),
				sk->sk_bound_dev_if, IPPROTO_DCCP, inet->inet_sport, nexthop->sin_port, sk);
		sin.sin_addr.s_addr = fl4->saddr;
	}
	memcpy(&mpcb->mpdccp_local_addr, &sin, sizeof(struct sockaddr_in));
	mpcb->localaddr_len = sizeof(struct sockaddr_in);
	mpcb->has_localaddr = 1;
}

/* stores address to paddress_list if not already in list */
static void pm_add_addr(struct mpdccp_cb *mpcb, sa_family_t family, u8 id, union inet_addr *addr, u16 port, bool is_remote)
{
	struct mpdccp_addr *mp_addr;

	rcu_read_lock();
	list_for_each_entry_rcu(mp_addr, &mpcb->paddress_list, address_list) {
		if (mp_addr->remote == is_remote && family == mp_addr->family) {		//allows to have ipv6 and ipv4 with the same id in memory
			if (id == mp_addr->id ||								//does the id exist?
				(family == AF_INET  &&
				mp_addr->addr.in.s_addr == addr->in.s_addr) ||		//does the ipv4 exist?
				(family == AF_INET6 &&
				ipv6_addr_equal(&mp_addr->addr.in6, &addr->in6)))	//does the ipv6 exist?
			{
				mpdccp_pr_debug("already have an entry for %s address %pI4, id: %u", 
							(is_remote ? "remote" : "local"), &addr->in.s_addr, id);
				return;
			}
		}
	}

	/* not in list add new entry */
	mp_addr = kzalloc(sizeof(*mp_addr), GFP_KERNEL);
	mp_addr->remote = is_remote;
	mp_addr->family = family;
	mp_addr->id = id;
	mp_addr->port = port;

	if (family == AF_INET) {
		mp_addr->addr.in.s_addr = addr->in.s_addr;
		mpdccp_pr_debug("Stored new %s IP %pI4:%u with id: %u", 
				(is_remote ? "remote" : "local"), &addr->in, htons((unsigned)port), id);
	} else {
		mp_addr->addr.in6 = addr->in6;
		mpdccp_pr_debug("Stored new %s IP %pI6:%u with id: %u", 
				(is_remote ? "remote" : "local"), &addr->in6, htons((unsigned)port), id);
	}
	
	list_add_tail_rcu(&mp_addr->address_list, &mpcb->paddress_list);
	if(is_remote) mpcb->cnt_remote_addrs++;
	rcu_read_unlock();
	return;
}

/* remove id from address list, flushing the entire list is also possible */
static void pm_del_addr(struct mpdccp_cb *mpcb, u8 id, bool is_remote, bool flush)
{
	struct mpdccp_addr *mp_addr;
	if(!is_remote && !id) id = mpcb->master_addr_id;
	mpdccp_pr_debug("trying to remove address id %u from addr memory", id);
	list_for_each_entry_rcu(mp_addr, &mpcb->paddress_list, address_list) {
		if( flush || (mp_addr->remote == is_remote && mp_addr->id == id)) {
			mpdccp_pr_debug("removing %s address %pI4", 
					(mp_addr->remote ? "remote" : "local"), &mp_addr->addr.ip);

			list_del_rcu(&mp_addr->address_list);
			kfree_rcu(mp_addr, rcu);
			if(is_remote)
				mpcb->cnt_remote_addrs--;
		}
	}
}

static int pm_get_id_from_ip(struct mpdccp_cb *mpcb, union inet_addr *addr, sa_family_t family, bool is_remote)
{
	struct mpdccp_addr *mp_addr;
	list_for_each_entry_rcu(mp_addr, &mpcb->paddress_list, address_list) {
		if(!mp_addr->remote == is_remote) continue;
		if(family == mp_addr->family){
			if((family == AF_INET && addr->ip == mp_addr->addr.ip) || 
						(family == AF_INET6 && addr->ip6 == mp_addr->addr.ip6))
				return mp_addr->id;
		}
	}
	return -1;
}

/*function that copies address with given ip from pathmanager namespace to mpcb address list, returns id */
static int pm_claim_local_addr(struct mpdccp_cb *mpcb, sa_family_t family, union inet_addr *addr)
{
	struct mpdccp_pm_ns *pm_ns = fm_get_ns(sock_net(mpcb->meta_sk));
	struct pm_local_addr *local_addr;
	bool found;

	rcu_read_lock();
	list_for_each_entry_rcu(local_addr, &pm_ns->plocal_addr_list, address_list) {
		if (local_addr && family == local_addr->family &&
					local_addr->addr.in.s_addr == addr->in.s_addr) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();
	
	if(!local_addr || !found){
		mpdccp_pr_debug("pm was unable to claim address %pI4", &addr->in.s_addr);
		return 0;
	}

	pm_add_addr(mpcb, local_addr->family, local_addr->id, &local_addr->addr, 0, false);
	return local_addr->id;
}

/* remove id from list and closes all subflows with remote id == id learned from MP_REMOVEADDR option*/
static void pm_handle_rm_addr(struct mpdccp_cb *mpcb, u8 id)
{
	struct sock *sk;
	rcu_read_lock();
	/* remove all sockets with id remote_id from subflow list */
	mpdccp_for_each_sk(mpcb, sk) {
		if(mpdccp_my_sock(sk)->remote_addr_id == id){
			/* when we receive MP_REMOVEADDR the subflow is already dead */
			mpdccp_close_subflow(mpcb, sk, 2);
			mpdccp_pr_debug("deleting path with id: %u sk %p", id, sk);
		}
	}
	//remove id from list
	pm_del_addr(mpcb, id, true, false);
	rcu_read_unlock();
}

/* Function is called when receiving mp_confirm for mp_removeaddr.
 * It checks if it possible to free the global address id of the removed subflow */
static void pm_free_id(const struct sock *meta_sk, u8 id) {
	struct mpdccp_cb *mpcb;
	struct sock *sk;
	struct mpdccp_pm_ns *pm_ns;

	mpdccp_for_each_conn(pconnection_list, mpcb) {
		mpdccp_for_each_sk(mpcb, sk) {
			if(mpdccp_my_sock(sk)->local_addr_id == id){
				mpdccp_pr_debug("socket still in use cant free id: %u", id);
				return;
			}
		}
	}

	pm_ns = fm_get_ns(sock_net(meta_sk));
	spin_lock(&pm_ns->plocal_lock);
	mpdccp_pr_debug("loc4_bits %llu removing id: %u", pm_ns->loc4_bits, id);
	pm_ns->loc4_bits &= ~(1 << (id-1));
	spin_unlock(&pm_ns->plocal_lock);
}

/*  handle received mp_prio option - clone link and set prio */
static void pm_handle_rcv_prio(struct sock *sk, u8 prio, u64 seq)
{
	struct mpdccp_link_info *link;

	rcu_read_lock();
	link = mpdccp_ctrl_getlink(sk);

	if(!link || prio == link->mpdccp_prio || 
			seq < mpdccp_my_sock(sk)->last_prio_seq || !mpdccp_accept_prio){
		if(!mpdccp_accept_prio)
			mpdccp_pr_debug("mpdccp configured to ignore incoming mp_prio options");
		if(seq < mpdccp_my_sock(sk)->last_prio_seq)
			mpdccp_pr_debug("outdated mp_prio option detected");

		mpdccp_link_put(link);
		rcu_read_unlock();
		return;
	}

	mpdccp_pr_debug("assigning prio %u - old prio %u to sk (%p)",
			prio, link->mpdccp_prio, sk);
	mpdccp_my_sock(sk)->prio_rcvrd = true;

	if(link->is_devlink)		// create copy and change prio of new copy
		mpdccp_link_cpy_set_prio(sk, prio); 
	else						// change prio of this (virtual) link
		link->mpdccp_prio = prio;

	mpdccp_my_sock(sk)->last_prio_seq = seq;
	mpdccp_link_put(link);
	rcu_read_unlock();
}

static int pm_handle_link_event(struct notifier_block *this,
				   unsigned long event, void *ptr)
{
	if (event != MPDCCP_LINK_CHANGE_PRIO)
		return NOTIFY_DONE;
	else {
		struct mpdccp_link_notifier_info *lni = ptr;
		struct mpdccp_link_info *link = lni->link_info;
		struct sock *sk;
		struct mpdccp_cb *mpcb;

		rcu_read_lock();
		mpdccp_for_each_conn(pconnection_list, mpcb) {
			if(mpcb->fallback_sp) continue;
			mpdccp_for_each_sk(mpcb, sk) {
				if(!mpdccp_my_sock(sk)->prio_rcvrd && 
					    mpdccp_my_sock(sk)->link_info->id == link->id)
					mpdccp_init_announce_prio(sk);
				else
					mpdccp_my_sock(sk)->prio_rcvrd = false;
			}
		}
		rcu_read_unlock();
		return NOTIFY_DONE;
	}
}

static struct notifier_block mpdccp_pm_link_notifier = {
	.notifier_call = pm_handle_link_event,
};


/* this function handles the retransmission queue */
static void pm_retransmit_worker(struct work_struct *work)
{
	const struct delayed_work *delayed_work = container_of(work, struct delayed_work, work);
	struct mpdccp_pm_ns *pm_ns = container_of(delayed_work, struct mpdccp_pm_ns, retransmit_worker);
	struct pm_retransmit_event *event;
	struct mpdccp_confirm_opt *my_opt;
	const u32 now = pm_jiffies32;

next_event:
	event = list_first_entry_or_null(&pm_ns->retransmit, struct pm_retransmit_event, list);
	if (!event)
		return;

	if(event->sk->sk_state != DCCPF_OPEN){
		list_del_rcu(&event->list);
		kfree(event);
		return;
	}

	my_opt = event->cnf_opt;
/* we loop through the list and check if retransmission timeout has surpassed */
	if (now > my_opt->t_timeout){
		u32 delay, age = now - my_opt->t_init;

		/* initiate retransmission of option */
		memcpy(&mpdccp_my_sock(event->sk)->reins_cache, &my_opt->opt[9], my_opt->opt[10]);
		dccp_send_keepalive(event->sk);
		my_opt->resent_cnt++;

		mpdccp_pr_debug("Retransmitting (x%u) unconfirmed option after: %ums, type: %u",
				my_opt->resent_cnt, jiffies_to_msecs(age), my_opt->opt[11]);

		/* check if we still have retransmit tries. if yes, keep event in list and move to tail */
		if (my_opt->resent_cnt < MPDCCP_CONFIRM_RETRANSMIT_TRIES){
			/* calculate new timeout based of original timestamp(age) to remove */
			delay = (my_opt->resent_cnt + 2) * MPDCCP_CONFIRM_RETRANSMIT_TIMEOUT - age;
			my_opt->t_timeout = now + delay;

			/* now calculate timeout for next event in list */
			if (!list_is_singular(&pm_ns->retransmit))
				list_move_tail(&event->list, &pm_ns->retransmit);
		} else {
			/* no retransmit tries left, del event */
			list_del_rcu(&event->list);
			kfree(event);
		}
		goto next_event;
	} else
		/* set new work queue timeout for remaining elements in list and exit */
		queue_delayed_work(mpdccp_wq, &pm_ns->retransmit_worker, event->cnf_opt->t_timeout - now);
}

/*	this function queues a new retransmission event */
static void pm_add_insert_rt_event(struct sock *sk, struct mpdccp_confirm_opt *my_opt){
	struct mpdccp_cb *mpcb = get_mpcb(sk);
	struct mpdccp_pm_ns *pm_ns = fm_get_ns(sock_net(mpcb->meta_sk));
	struct pm_retransmit_event *event = kzalloc(sizeof(*event), GFP_KERNEL);

	event->cnf_opt = my_opt;
	event->sk = sk;
	list_add_tail_rcu(&event->list, &pm_ns->retransmit);
	mpdccp_pr_debug("Added retransmission event to queue");

	/* Create work-queue */
	if (!delayed_work_pending(&pm_ns->retransmit_worker))
		queue_delayed_work(mpdccp_wq, &pm_ns->retransmit_worker, MPDCCP_CONFIRM_RETRANSMIT_TIMEOUT);
}

/*  remove option from reinsertion list. either because it was confirmed or because sk is closing
	if my_opt is used, we only remove this specific option from list
	if sk is used, we remove all options linked to sk from list
	if we remove the first option on the list we also cancel the delayed work */
static void pm_remove_rt_event(struct net *net, struct sock *sk, struct mpdccp_confirm_opt *my_opt){
	struct mpdccp_pm_ns *pm_ns = fm_get_ns(net);
	struct pm_retransmit_event *event;
	bool first = true;

next_event:

	event = list_first_entry_or_null(&pm_ns->retransmit, struct pm_retransmit_event, list);
	if(!event)
		return;

	if(event->cnf_opt == my_opt || event->sk == sk){
		list_del_rcu(&event->list);
		kfree(event);

		if (first && delayed_work_pending(&pm_ns->retransmit_worker))
			cancel_delayed_work(&pm_ns->retransmit_worker);

		first = false;
		mpdccp_pr_debug("Removed retransmission event");
	}
	goto next_event;
}

static void pm_del_retrans(struct net *net, struct sock *sk){
	pm_remove_rt_event(net, sk, NULL);
}

/* returns pointer to right memory that stores info for option confirmation */
static struct mpdccp_confirm_opt* get_cnf_mem(struct mpdccp_cb *mpcb, u8 id, u8 type)
{
	struct mpdccp_addr *mp_addr;

	mpdccp_pr_debug("looking for address id: %u, opt_type %u", id, type);
	list_for_each_entry_rcu(mp_addr, &mpcb->paddress_list, address_list) {
		if (!mp_addr->remote && mp_addr->id == id) {
			switch (type)
			{
				case DCCPO_MP_ADDADDR:
					return &mp_addr->cnf_addaddr;
				case DCCPO_MP_REMOVEADDR:
					return &mp_addr->cnf_remaddr;
				case DCCPO_MP_PRIO:
					return &mp_addr->cnf_prio;
			}
		}
	}
	DCCP_CRIT("couldnt locate confirm memory for id %u", id);
	return NULL;
}

/* Function is called when sending either mp_addaddr, mp_remoeaddr or mp_prio to store a copy */
static void pm_store_confirm_opt(struct sock *sk, u8 *buf, u8 id, u8 type, u8 len)
{
	struct mpdccp_cb *mpcb = get_mpcb(sk);
	u8 real_id = id ? id : mpcb->master_addr_id;		//if id = 0 we store master id
	struct mpdccp_confirm_opt *new_opt = get_cnf_mem(mpcb, real_id, type);

	if (new_opt) {
		__be64 seq = cpu_to_be64((mpcb->mp_oall_seqno << 16));
		rcu_read_lock();
		new_opt->opt[0] = DCCPO_MULTIPATH;
		new_opt->opt[1] = 9;
		new_opt->opt[2] = DCCPO_MP_SEQ;
		memcpy(&new_opt->opt[3], &seq, 6);
		new_opt->opt[9] = DCCPO_MULTIPATH;
		new_opt->opt[10] = len + 3;
		new_opt->opt[11] = type;
		memcpy(&new_opt->opt[12], buf, len);
		
		new_opt->t_init = pm_jiffies32;
		new_opt->t_timeout = new_opt->t_init + MPDCCP_CONFIRM_RETRANSMIT_TIMEOUT;
		new_opt->resent_cnt = 0;
		rcu_read_unlock();

		pm_add_insert_rt_event(sk, new_opt);
	}
}

/*  handle received mp_confirm option */
static int pm_rcv_confirm_opt(struct mpdccp_cb *mpcb, u8 *rcv_opt, u8 id)
{
	u8 len = rcv_opt[10];
	u8 type = rcv_opt[11];
	struct mpdccp_confirm_opt *snt_opt = get_cnf_mem(mpcb, id, type);

	if(!snt_opt){
		DCCP_CRIT("could not recover a matching sent option");
		return 1;
	}

	rcu_read_lock();
	if(snt_opt && len == snt_opt->opt[10] && !memcmp(rcv_opt, snt_opt->opt, len)) {
		mpdccp_pr_debug("mp_confirm matches sent option. txpe: %u, len %u", type, len);

		/* only mp_removeaddr requires action after received confirm */
		if(type == DCCPO_MP_REMOVEADDR) {
			pm_del_addr(mpcb, id, false, false);
			pm_free_id(mpcb->meta_sk, id);
		}
		rcu_read_unlock();
		/* option was confirmed, stop retransmitting the option */
		pm_remove_rt_event(sock_net(mpcb->meta_sk), NULL, snt_opt);
		return 0;
	}

	DCCP_CRIT("mp_confirm does not match any stored option");
	rcu_read_unlock();
	return 1;
}

/* Pathmanager namespace related functions */
/* Find the first free index in the bitfield */
static int mpdccp_find_free_index(u64 bitfield)
{
	int i;
	/* There are anyways no free bits... */
	if (bitfield == 0xff) return -1;

	i = ffs(~bitfield) - 1;
	/* Try from 0 on */
	if (i >= sizeof(bitfield) * 8)
		return mpdccp_find_free_index(bitfield);
	return i;
}

/* The following two functions mpdccp_add_addr and mpdccp_del_addr
 * add or delete an address to/from both the global address list and all
 * existing connections. We assume that every operation produces a 
 * consistent state upon completion, i.e. if an address is not
 * in the list, it is not used in any connection. */
static int mpdccp_add_addr(struct mpdccp_pm_ns *pm_ns,
			      			struct pm_local_addr_event *event)
{
	struct pm_local_addr *local_addr;
	struct mpdccp_cb *mpcb;

	struct sockaddr 			*local;
	struct sockaddr_in 			local_v4_address;
	struct sockaddr_in6 		local_v6_address;

	sa_family_t family 			= event->family;
	union inet_addr *addr 		= &event->addr;
    int if_idx 					= event->if_idx;
	int locaddr_len, loc_id;
	u16 port;

	struct list_head *plocal_addr_list = &pm_ns->plocal_addr_list;

	//rcu_read_lock_bh();
	spin_lock(&pm_ns->plocal_lock);

	/* Add the address to the list of known addresses so that
	 * new connections can use it. If the address is known, it does not
	 * need to be added, as all existing connections already use it. */
	list_for_each_entry_rcu(local_addr, plocal_addr_list, address_list) {
		if (family == local_addr->family &&
		   (!if_idx || if_idx == local_addr->if_idx))
		{
			if ((family == AF_INET  && 
				local_addr->addr.in.s_addr == addr->in.s_addr) ||
				(family == AF_INET6 && 
				ipv6_addr_equal(&local_addr->addr.in6, &addr->in6)))
			{
				spin_unlock(&pm_ns->plocal_lock);
				//rcu_read_unlock_bh();

				return false;
			}
		}
	}

	/* Address is unused, create a new address entry. */
    local_addr = kmem_cache_zalloc(mpdccp_pm_addr_cache, GFP_ATOMIC);
    if (!local_addr) {
    	spin_unlock(&pm_ns->plocal_lock);
	//rcu_read_unlock_bh();

        mpdccp_pr_debug("Failed to allocate memory for new local address.\n");
        
        return false;
    }

    local_addr->family = family;
	local_addr->if_idx = if_idx;

	loc_id = mpdccp_find_free_index(pm_ns->loc4_bits);

	if (loc_id < 0) {
		mpdccp_pr_debug("Failed to find free address id index.\n");
		return false;
	}

	local_addr->id = loc_id + 1;
	pm_ns->loc4_bits |= (1 << loc_id);

	if (family == AF_INET) {
	    local_addr->addr.in.s_addr = addr->in.s_addr;

		mpdccp_pr_debug("updated IP %pI4 on ifidx %u, id: %u loc4: %llu",
			    &addr->in.s_addr, if_idx, local_addr->id, pm_ns->loc4_bits);
	} else {
		local_addr->addr.in6 = addr->in6;

		mpdccp_pr_debug("updated IP %pI6 on ifidx %u, id: %u loc4: %llu",
				&addr->in6, if_idx, local_addr->id, pm_ns->loc4_bits);
	}
	
	list_add_tail_rcu(&local_addr->address_list, plocal_addr_list);

	/* TODO: Is this needed? It might have been a MOD-event. */
	//event->code = MPDCCP_EVENT_ADD;

	/* Set target IPv4/v6 address correctly */
	if (family == AF_INET) {
		local_v4_address.sin_family			= AF_INET;
		local_v4_address.sin_addr.s_addr 	= addr->in.s_addr;
	} else {
		local_v6_address.sin6_family		= AF_INET6;
		local_v6_address.sin6_addr 			= addr->in6;
	}

	/* Iterate over all connections and create new connections via this address */
	mpdccp_for_each_conn(pconnection_list, mpcb) {
		if (family == AF_INET) {
			if(mpcb->role == MPDCCP_CLIENT)
				local_v4_address.sin_port		= 0;
			else
				local_v4_address.sin_port		= htons (mpcb->server_port);

			port = local_v4_address.sin_port;
			local = (struct sockaddr *) &local_v4_address;
			locaddr_len = sizeof (struct sockaddr_in);
		} else {
			if(mpcb->role == MPDCCP_CLIENT)
				local_v6_address.sin6_port		= 0;
			else
				local_v6_address.sin6_port		= htons (mpcb->server_port);

			port = local_v6_address.sin6_port;
			local = (struct sockaddr *) &local_v6_address;
			locaddr_len = sizeof (struct sockaddr_in6);
		}

		switch (mpcb->role) {
		case MPDCCP_CLIENT:
			/* Do not add more subflows if the client in in SP mode */
			if (!(mpcb->fallback_sp && (mpcb->cnt_subflows > 0)))
				mpdccp_add_client_conn(mpcb, local, locaddr_len, if_idx,
						(struct sockaddr*)&mpcb->mpdccp_remote_addr,
						mpcb->remaddr_len);
			break;
		case MPDCCP_SERVER:
			/* send mp_addaddress */
			if (!(mpcb->fallback_sp && (mpcb->cnt_subflows > 0))){
				//add_init_server_conn(mpcb, backlog);
				pm_add_addr(mpcb, family, local_addr->id, &local_addr->addr, port, false);
				mpdccp_send_add_path(local_addr, port, mpcb);
			}
			break;
		default:
			break;
		}
	}
	spin_unlock(&pm_ns->plocal_lock);
	//rcu_read_unlock_bh();

	return true;
}

static bool mpdccp_del_addr(struct mpdccp_pm_ns *pm_ns,
			      struct pm_local_addr_event *event)
{

	struct sock *sk;
	struct mpdccp_cb *mpcb;
	struct 	pm_local_addr *local_addr;

	sa_family_t family 			= event->family;
	union inet_addr *addr 		= &event->addr;
    int if_idx 					= event->if_idx;
    int addr_id;
	bool found 					= false;
	bool in_use					= false;

	struct list_head *plocal_addr_list = &pm_ns->plocal_addr_list;

	//TODO reordering
	pr_info("RO: mpdccp_del_addr triggered...");

	//rcu_read_lock_bh();
	spin_lock_bh(&pm_ns->plocal_lock);

	/* Delete the address from the list of known addresses so that
	 * new connections stop using it. */
	list_for_each_entry_rcu(local_addr, plocal_addr_list, address_list) {
		/* Search for an entry with matching address family and iface ID */
		if (family == local_addr->family &&
		   (!if_idx || if_idx == local_addr->if_idx))
		{
			/* Check for a matching IPv4/v6 address */
			if ((family == AF_INET  && 
				local_addr->addr.in.s_addr == addr->in.s_addr) ||
				(family == AF_INET6 && 
				ipv6_addr_equal(&local_addr->addr.in6, &addr->in6)))
			{
				found = true;
				addr_id = local_addr->id;
				list_del_rcu(&local_addr->address_list);
				kmem_cache_free(mpdccp_pm_addr_cache, local_addr);
			}
		}
	}

	/* Address is unknown, so it can not be used in any connection. */
	if(!found) 
	{
		spin_unlock_bh(&pm_ns->plocal_lock);
		//rcu_read_unlock_bh();
		return false;
	}

	/* Iterate over all connections and remove any socket that still
	 * uses this address */
	mpdccp_for_each_conn(pconnection_list, mpcb) {
		mpdccp_for_each_sk(mpcb, sk) {

			/* Not yet sure if this applies to MPDCCP, too */
			// if (sock_net(sk) != net)
			// 	continue;

			/* If the PM has changed, we are not responsible for this mpcb */
			if (mpcb->pm_ops != &mpdccp_pm_default)
				break;

			/* Does the event family and interface ID match the socket? */
			if (family == sk->__sk_common.skc_family &&
			   (!if_idx || mpdccp_my_sock(sk)->if_idx  == if_idx))
			{
				/* Does the IP address in the event match the socket */
				if ((family == AF_INET  && 
					sk->__sk_common.skc_rcv_saddr == addr->in.s_addr) ||
					(family == AF_INET6 && 
					ipv6_addr_equal(&sk->__sk_common.skc_v6_rcv_saddr, &addr->in6)))
				{
					if(family == AF_INET)
						mpdccp_pr_debug("Deleting subflow socket %p with address %pI4.\n", sk, &sk->__sk_common.skc_rcv_saddr);
					else
						mpdccp_pr_debug("Deleting subflow socket %p with address %pI6.\n", sk, &sk->__sk_common.skc_v6_rcv_saddr);

					addr_id = mpdccp_my_sock(sk)->local_addr_id;
					in_use = true;
					mpdccp_my_sock(sk)->delpath_sent = true;
					mpdccp_close_subflow (mpcb, sk, 2);
					mpdccp_send_remove_path(mpcb, addr_id);
					pm_free_id(mpcb->meta_sk, addr_id);
				}
			}
		}

		mpdccp_for_each_listen_sk(mpcb, sk) {
			/* Not yet sure if this applies to MPDCCP, too */
			// if (sock_net(sk) != net)
			// 	continue;

			/* If the PM has changed, we are not responsible for this mpcb */
			if (mpcb->pm_ops != &mpdccp_pm_default)
				break;

			/* Does the event family and interface ID match the socket? */
			if (family == sk->__sk_common.skc_family &&
			   (!if_idx || mpdccp_my_sock(sk)->if_idx  == if_idx))
			{
				/* Does the IP address in the event match the socket */
				if ((family == AF_INET  && 
					sk->__sk_common.skc_rcv_saddr == addr->in.s_addr) ||
					(family == AF_INET6 && 
					ipv6_addr_equal(&sk->__sk_common.skc_v6_rcv_saddr, &addr->in6)))
				{
					if(family == AF_INET)
						mpdccp_pr_debug("Deleting listening socket %p with address %pI4.\n", sk, &sk->__sk_common.skc_rcv_saddr);
					else
						mpdccp_pr_debug("Deleting listening socket %p with address %pI6.\n", sk, &sk->__sk_common.skc_v6_rcv_saddr);

					//addr_id = mpdccp_my_sock(sk)->local_addr_id;
					//in_use = true;
					mpdccp_close_subflow (mpcb, sk, 1);
				}
			}
		}
	}

	if(!in_use){
		pm_ns->loc4_bits &= ~(1 << (addr_id-1));
		mpdccp_pr_debug("loc4_bits updated: %llu, removed id: %u", pm_ns->loc4_bits, addr_id);
	}

	spin_unlock_bh(&pm_ns->plocal_lock);
	//rcu_read_unlock_bh();

	return true;
}

static void pm_local_address_worker(struct work_struct *work)
{
	const struct delayed_work *delayed_work = container_of(work,
							 struct delayed_work,
							 work);
	struct mpdccp_pm_ns *pm_ns = container_of(delayed_work,
						 struct mpdccp_pm_ns,
						 address_worker);
	struct pm_local_addr_event *event = NULL;

next_event:
	kfree(event);

	/* First, let's dequeue an event from our event-list */
	/* TODO: is _bh REALLY the right thing to do here? */
	//rcu_read_lock_bh();
	event = list_first_entry_or_null(&pm_ns->events,
					 struct pm_local_addr_event, list);
	if (!event) {
		/* No more events to work on */
		//rcu_read_unlock_bh();
		return;
	}

	list_del(&event->list);
	//mpdccp_local = rcu_dereference_bh(pm_ns->local);

	if (event->code == MPDCCP_EVENT_DEL) {
		if( !mpdccp_del_addr(pm_ns, event) ) {
			mpdccp_pr_debug("Delete address failed: Address not found.\n");
		}
	} else {
		/* TODO: Filter link local and TUN devices */
		if( !mpdccp_add_addr(pm_ns, event) ) {
			mpdccp_pr_debug("Add address failed: Address already in use.\n");
		}
	}
	//rcu_read_unlock_bh();

	goto next_event;
}



/***********************************
* IPv4/v6 address event handling
************************************/

static struct pm_local_addr_event *lookup_similar_event(const struct net *net,
						     const struct pm_local_addr_event *event)
{
	struct pm_local_addr_event *eventq;
	struct mpdccp_pm_ns *pm_ns = fm_get_ns(net);

	list_for_each_entry(eventq, &pm_ns->events, list) {
		if (eventq->family != event->family)
			continue;
		if (eventq->if_idx != event->if_idx)
			continue;
		if (event->family == AF_INET) {
			if (eventq->addr.in.s_addr == event->addr.in.s_addr)
				return eventq;
		} else {
			if (ipv6_addr_equal(&eventq->addr.in6, &event->addr.in6))
				return eventq;
		}
	}
	return NULL;
}

/* We already hold the net-namespace MPDCCP-lock */
static void add_pm_event(struct net *net, const struct pm_local_addr_event *event)
{
	struct pm_local_addr_event *eventq = lookup_similar_event(net, event);
	struct mpdccp_pm_ns *pm_ns = fm_get_ns(net);
	int delay = 10;

	if (eventq) {
		switch (event->code) {
		case MPDCCP_EVENT_DEL:
			mpdccp_pr_debug("del old_code %u\n", eventq->code);
			list_del(&eventq->list);
			kfree(eventq);
			break;
		case MPDCCP_EVENT_ADD:
			mpdccp_pr_debug("add old_code %u\n", eventq->code);
			eventq->code = MPDCCP_EVENT_ADD;
			return;
		case MPDCCP_EVENT_MOD:
			mpdccp_pr_debug("mod old_code %u\n", eventq->code);
			eventq->code = MPDCCP_EVENT_MOD;
			return;
		}
	}

	/* OK, we have to add the new address to the wait queue */
	eventq = kmemdup(event, sizeof(struct pm_local_addr_event), GFP_ATOMIC);
	if (!eventq)
		return;

	list_add_tail(&eventq->list, &pm_ns->events);

	/* Create work-queue */
	if (!delayed_work_pending(&pm_ns->address_worker))
		queue_delayed_work(mpdccp_wq, &pm_ns->address_worker, msecs_to_jiffies(delay));
}

static void addr4_event_handler(const struct in_ifaddr *ifa, unsigned long event,
				struct net *net)
{
	const struct net_device *netdev = ifa->ifa_dev->dev;
	struct mpdccp_pm_ns *pm_ns = fm_get_ns(net);
	struct pm_local_addr_event mpevent;

	/* Do not create events for link-local interfaces and TUN devices */
	if ( ifa->ifa_scope > RT_SCOPE_LINK 	||
		 netdev->flags & IFF_POINTOPOINT	||
	     ipv4_is_loopback(ifa->ifa_local) )
		return;

	spin_lock_bh(&pm_ns->plocal_lock);

	mpevent.family = AF_INET;
	mpevent.addr.in.s_addr = ifa->ifa_local;
	mpevent.if_idx  = netdev->ifindex;

	if (event == NETDEV_DOWN || !netif_running(netdev) || netdev->operstate == IF_OPER_DOWN ||
	    !(netdev->flags & IFF_MPDCCPON)|| !(netdev->flags & IFF_UP))
		mpevent.code = MPDCCP_EVENT_DEL;
	else if (event == NETDEV_UP)
		mpevent.code = MPDCCP_EVENT_ADD;
	else if (event == NETDEV_CHANGE)
		mpevent.code = MPDCCP_EVENT_MOD;

	mpdccp_pr_debug("event %lu, running %d flags %u oper %x", event, netif_running(netdev), netdev->flags, netdev->operstate);
    mpdccp_pr_debug("%s created event for %pI4, code %u idx %u\n", __func__,
		    &ifa->ifa_local, mpevent.code, mpevent.if_idx);
	add_pm_event(net, &mpevent);

	spin_unlock_bh(&pm_ns->plocal_lock);
	return;
}

static int mpdccp_pm_inetaddr_event(struct notifier_block *this,
				   unsigned long event, void *ptr)
{
	const struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net *net = dev_net(ifa->ifa_dev->dev);

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	addr4_event_handler(ifa, event, net);

	return NOTIFY_DONE;
}

static struct notifier_block mpdccp_pm_inetaddr_notifier = {
		.notifier_call = mpdccp_pm_inetaddr_event,
};

static int mpdccp_pm_dccp_event(struct notifier_block *this,
				   unsigned long event, void *ptr)
{
	const struct sock *sk_closed = (struct sock *)ptr;

	struct sock *sk;
	struct mpdccp_cb *mpcb;
	struct sockaddr 			*local;
	struct sockaddr_in 			local_v4_address;
	struct sockaddr_in6 		local_v6_address;
	int	locaddr_len;
	int	if_idx;

	if (!sk_closed) return NOTIFY_DONE;

	if(sk_closed->__sk_common.skc_family == AF_INET){
			local_v4_address.sin_family		= AF_INET;
			local_v4_address.sin_addr.s_addr = sk_closed->__sk_common.skc_rcv_saddr;
			local_v4_address.sin_port		= 0;
			local = (struct sockaddr *) &local_v4_address;
			locaddr_len = sizeof (struct sockaddr_in);
		} else {
			local_v6_address.sin6_family		= AF_INET6;
			local_v6_address.sin6_addr 		= sk_closed->__sk_common.skc_v6_rcv_saddr;
			local_v6_address.sin6_port		= 0;
			local = (struct sockaddr *) &local_v6_address;
			locaddr_len = sizeof (struct sockaddr_in6);
		}

	if_idx = sk_closed->__sk_common.skc_bound_dev_if;
	if (event == DCCP_EVENT_CLOSE){
		mpdccp_for_each_conn(pconnection_list, mpcb) {
			if (mpcb->to_be_closed) continue;
			mpdccp_for_each_sk(mpcb, sk) {
#if 0
				/* Handle close events for both the subflow and meta sockets */
				if (mpcb->meta_sk == sk_closed) {
					mpdccp_close_subflow(mpcb, sk, 1);
					mpdccp_pr_debug("close dccp sk %p", sk_closed);
				}
				else
#endif
				if(sk == sk_closed) {
					mpdccp_reconnect_client (sk, 0, local, locaddr_len, if_idx);
					break;
				}
			}
		}
	}
	return NOTIFY_DONE;
}

static struct notifier_block mpdccp_pm_dccp_notifier = {
		.notifier_call = mpdccp_pm_dccp_event,
};

#if IS_ENABLED(CONFIG_IPV6)

/* IPV6-related address/interface watchers */
struct mpdccp_dad_data {
	struct timer_list timer;
	struct inet6_ifaddr *ifa;
};

static void dad_callback(struct timer_list *t);
static int inet6_addr_event(struct notifier_block *this,
				     unsigned long event, void *ptr);

static bool ipv6_dad_finished(const struct inet6_ifaddr *ifa)
{
	return !(ifa->flags & IFA_F_TENTATIVE) ||
	       ifa->state > INET6_IFADDR_STATE_DAD;
}

static void dad_init_timer(struct mpdccp_dad_data *data,
				 struct inet6_ifaddr *ifa)
{
	data->ifa = ifa;
	//data->timer.data = (unsigned long)data;
	data->timer.function = dad_callback;
	if (ifa->idev->cnf.rtr_solicit_delay)
		data->timer.expires = jiffies + ifa->idev->cnf.rtr_solicit_delay;
	else
		data->timer.expires = jiffies + (HZ/10);
}

//static void dad_callback(unsigned long arg)
static void dad_callback(struct timer_list *t)
{
	//struct mpdccp_dad_data *data = (struct mpdccp_dad_data *)arg;
	struct mpdccp_dad_data *data = from_timer(data, t, timer);

	/* DAD failed or IP brought down? */
	if (data->ifa->state == INET6_IFADDR_STATE_ERRDAD ||
	    data->ifa->state == INET6_IFADDR_STATE_DEAD)
		goto exit;

	if (!ipv6_dad_finished(data->ifa)) {
		dad_init_timer(data, data->ifa);
		add_timer(&data->timer);
		return;
	}

	inet6_addr_event(NULL, NETDEV_UP, data->ifa);

exit:
	in6_ifa_put(data->ifa);
	kfree(data);
}

static inline void dad_setup_timer(struct inet6_ifaddr *ifa)
{
	struct mpdccp_dad_data *data;

	data = kmalloc(sizeof(*data), GFP_ATOMIC);

	if (!data)
		return;

	//init_timer(&data->timer);
	timer_setup(&data->timer, NULL, 0);
	dad_init_timer(data, ifa);
	add_timer(&data->timer);
	in6_ifa_hold(ifa);
}

static void addr6_event_handler(const struct inet6_ifaddr *ifa, unsigned long event,
				struct net *net)
{
	const struct net_device *netdev = ifa->idev->dev;
	int addr_type = ipv6_addr_type(&ifa->addr);
	struct mpdccp_pm_ns *pm_ns = fm_get_ns(net);
	struct pm_local_addr_event mpevent;

	if ( ifa->scope > RT_SCOPE_LINK 		||
		 netdev->flags & IFF_POINTOPOINT	||
	     addr_type == IPV6_ADDR_ANY 		||
	    (addr_type & IPV6_ADDR_LOOPBACK) 	||
	    (addr_type & IPV6_ADDR_LINKLOCAL))
		return;

	spin_lock_bh(&pm_ns->plocal_lock);

	mpevent.family = AF_INET6;
	mpevent.addr.in6 = ifa->addr;
	mpevent.if_idx = netdev->ifindex;

	if (event == NETDEV_DOWN || !netif_running(netdev) ||
	    !(netdev->flags & IFF_MPDCCPON)|| !(netdev->flags & IFF_UP))
		mpevent.code = MPDCCP_EVENT_DEL;
	else if (event == NETDEV_UP)
		mpevent.code = MPDCCP_EVENT_ADD;
	else if (event == NETDEV_CHANGE)
		mpevent.code = MPDCCP_EVENT_MOD;

	mpdccp_pr_debug("%s created event for %pI6, code %u idx %u\n", __func__,
		    &ifa->addr, mpevent.code, mpevent.if_idx);
	add_pm_event(net, &mpevent);

	spin_unlock_bh(&pm_ns->plocal_lock);
	return;
}

/* React on IPv6-addr add/rem-events */
static int mpdccp_pm_inet6addr_event(struct notifier_block *this, unsigned long event,
			    void *ptr)
{
	struct inet6_ifaddr *ifa6 = (struct inet6_ifaddr *)ptr;
	struct net *net = dev_net(ifa6->idev->dev);

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	if (!ipv6_dad_finished(ifa6))
		dad_setup_timer(ifa6);
	else
		addr6_event_handler(ifa6, event, net);

	return NOTIFY_DONE;
}

static struct notifier_block mpdccp_pm_inet6addr_notifier = {
		.notifier_call = mpdccp_pm_inet6addr_event,
};
#endif

static int mpdccp_init_net(struct net *net)
{
	struct mpdccp_pm_ns *pm_ns;

	pm_ns = kzalloc(sizeof(*pm_ns), GFP_KERNEL);
	if (!pm_ns)
		return -ENOBUFS;

	INIT_LIST_HEAD(&pm_ns->plocal_addr_list);
	spin_lock_init(&pm_ns->plocal_lock);
	INIT_LIST_HEAD(&pm_ns->events);
	INIT_DELAYED_WORK(&pm_ns->address_worker, pm_local_address_worker);
	INIT_LIST_HEAD(&pm_ns->retransmit);
	INIT_DELAYED_WORK(&pm_ns->retransmit_worker, pm_retransmit_worker);
	pm_ns->net = net;
	net->mpdccp.path_managers[MPDCCP_PM_FULLMESH] = pm_ns;

	return 0;
}

/* Wipe the local address list */
static void dccp_free_local_addr_list(struct mpdccp_pm_ns *pm_ns)
{
	struct pm_local_addr *addr;
	struct list_head *pos, *temp;
	list_for_each_safe(pos, temp, &pm_ns->plocal_addr_list) {
		addr = list_entry(pos, struct pm_local_addr, address_list);
		list_del(pos);
		kfree(addr);
	}
}

static void mpdccp_exit_net(struct net *net)
{
	struct mpdccp_pm_ns *pm_ns;

	pm_ns = net->mpdccp.path_managers[MPDCCP_PM_FULLMESH];
	/* Stop the worker */
	cancel_delayed_work_sync(&pm_ns->address_worker);
	cancel_delayed_work_sync(&pm_ns->retransmit_worker);

	/* Clean and free the list */
	dccp_free_local_addr_list(pm_ns);
	kfree(pm_ns);

/* This is statistics stuff that is not yet supported. */
#if 0
    remove_proc_entry("snmp", net->mpdccp.proc_net_mpdccp);
    remove_proc_entry("mpdccp", net->mpdccp.proc_net_mpdccp);
    remove_proc_subtree("mpdccp_net", net->proc_net);
    free_percpu(net->mpdccp.mpdccp_statistics);
#endif
}

static struct pernet_operations mpdccp_pm_net_ops = {
    .init = mpdccp_init_net,
    .exit = mpdccp_exit_net,
};

/* React on IPv6-addr add/rem-events */
static int inet6_addr_event(struct notifier_block *this, unsigned long event,
			    void *ptr)
{
	struct inet6_ifaddr *ifa6 = (struct inet6_ifaddr *)ptr;
	struct net *net = dev_net(ifa6->idev->dev);

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	if (!ipv6_dad_finished(ifa6))
		dad_setup_timer(ifa6);
	else
		addr6_event_handler(ifa6, event, net);

	return NOTIFY_DONE;
}

/* React on ifup/down-events */
static int netdev_event(struct notifier_block *this, unsigned long event,
			void *ptr)
{
	const struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct in_device *in_dev;
	const struct in_ifaddr *ifa;
#if IS_ENABLED(CONFIG_IPV6)
	struct inet6_dev *in6_dev;
#endif

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	//rcu_read_lock();
	in_dev = __in_dev_get_rtnl(dev);

	if (in_dev) {
		//for_ifa(in_dev) {
		in_dev_for_each_ifa_rcu(ifa, in_dev) {
			mpdccp_pm_inetaddr_event(NULL, event, ifa);
		//} endfor_ifa(in_dev);
		}
	}

#if IS_ENABLED(CONFIG_IPV6)
	in6_dev = __in6_dev_get(dev);

	if (in6_dev) {
		struct inet6_ifaddr *ifa6;
		list_for_each_entry(ifa6, &in6_dev->addr_list, if_list)
			inet6_addr_event(NULL, event, ifa6);
	}
#endif

	//rcu_read_unlock();
	return NOTIFY_DONE;
}

static struct notifier_block mpdccp_pm_netdev_notifier = {
		.notifier_call = netdev_event,
};

/* General initialization of MPDCCP */
static int mpdccp_pm_init(void)
{
    int ret = 0;

    mpdccp_pm_addr_cache = kmem_cache_create("mpdccp_pm_addr", sizeof(struct pm_local_addr),
                       0, SLAB_TYPESAFE_BY_RCU|SLAB_HWCACHE_ALIGN,
                       NULL);
    if (!mpdccp_pm_addr_cache) {
        mpdccp_pr_debug("Failed to create mpcb pm address slab cache.\n");
        ret = -1;
        goto out;
    }

    ret = register_pernet_subsys(&mpdccp_pm_net_ops);
    if (ret) {
        mpdccp_pr_debug("Failed to register pernet subsystem.\n");
        goto err_reg_pernet_subsys;
    }

    ret = register_inetaddr_notifier(&mpdccp_pm_inetaddr_notifier);
    if (ret) {
        mpdccp_pr_debug("Failed to register inet address notifier.\n");
        goto err_reg_inetaddr;
    }

    ret = register_mpdccp_link_notifier(&mpdccp_pm_link_notifier);
    if (ret) {
        mpdccp_pr_debug("Failed to register mpdccp_link notifier.\n");
        goto err_reg_prio;
    }

#if IS_ENABLED(CONFIG_IPV6)
    ret = register_inet6addr_notifier(&mpdccp_pm_inet6addr_notifier);
    if (ret) {
        mpdccp_pr_debug("Failed to register inet6 address notifier.\n");
        goto err_reg_inet6addr;
    }
#endif

    ret = register_netdevice_notifier(&mpdccp_pm_netdev_notifier);
    if (ret) {
        mpdccp_pr_debug("Failed to register netdevice notifier.\n");
        goto err_reg_netdev;
    }

    ret = register_dccp_notifier(&mpdccp_pm_dccp_notifier);
    if (ret) {
        mpdccp_pr_debug("Failed to register dccp notifier.\n");
        goto err_reg_dccp;
    }

out:
    return ret;

    //unregister_netdevice_notifier(&mpdccp_pm_netdev_notifier);
err_reg_dccp: // later change position
	unregister_dccp_notifier(&mpdccp_pm_dccp_notifier);
goto out;

err_reg_netdev:
#if IS_ENABLED(CONFIG_IPV6)
    unregister_inet6addr_notifier(&mpdccp_pm_inet6addr_notifier);
err_reg_inet6addr:
#endif
    unregister_inetaddr_notifier(&mpdccp_pm_inetaddr_notifier);
err_reg_inetaddr:
    unregister_pernet_subsys(&mpdccp_pm_net_ops);
err_reg_prio:
	unregister_mpdccp_link_notifier(&mpdccp_pm_link_notifier);
err_reg_pernet_subsys:
	kmem_cache_destroy(mpdccp_pm_addr_cache);
goto out;
}

static void mpdccp_pm_exit(void)
{
    unregister_dccp_notifier(&mpdccp_pm_dccp_notifier);

    /* TODO: Tear down connections */
    unregister_netdevice_notifier(&mpdccp_pm_netdev_notifier);
#if IS_ENABLED(CONFIG_IPV6)
    unregister_inet6addr_notifier(&mpdccp_pm_inet6addr_notifier);
#endif
    unregister_mpdccp_link_notifier(&mpdccp_pm_link_notifier);
    unregister_inetaddr_notifier(&mpdccp_pm_inetaddr_notifier);
    unregister_pernet_subsys(&mpdccp_pm_net_ops);

    /* TODO: we need to free all mpcb's (slab cache) on exit. */
    kmem_cache_destroy(mpdccp_pm_addr_cache);
#if 0
    /* sk_free (and __sk_free) requires wmem_alloc to be 1.
     * All the rest is set to 0 thanks to __GFP_ZERO above.
     */
    atomic_set(&master_sk->sk_wmem_alloc, 1);
    sk_free(master_sk);
#endif
}

static
int
add_init_client_conn (
	struct mpdccp_cb		*mpcb,
	struct sockaddr			*remote_address,
	int				socklen)
{
	struct pm_local_addr 	*local;
	struct sockaddr 		*local_address;
	struct sockaddr_in		*meta_v4_address;
	struct sockaddr_in 		local_v4_address;
	struct sockaddr_in6 		local_v6_address;
	union inet_addr rema;
	int				locaddr_len;
	int				ret=0, num=0, port=0;
	struct mpdccp_pm_ns		*pm_ns;
	int local_if_idx;
	
	if (!mpcb || !remote_address) return -EINVAL;
	if (mpcb->role != MPDCCP_CLIENT) return -EPERM;
	
	//pm_ns = fm_get_ns (current->nsproxy->net_ns);
	pm_ns = fm_get_ns (read_pnet (&mpcb->net));
	
	memcpy(&mpcb->mpdccp_remote_addr, remote_address, socklen);
	mpcb->remaddr_len = socklen;

	if(remote_address->sa_family == AF_INET){
		struct sockaddr_in *ad4 = (struct sockaddr_in*)remote_address;
		rema.in = ad4->sin_addr;
		port = ad4->sin_port;
	} else if(remote_address->sa_family == AF_INET6) {
		struct sockaddr_in6 *ad6 = (struct sockaddr_in6*)remote_address;
		rema.in6 = ad6->sin6_addr;
		port = ad6->sin6_port;
	}
	pm_add_addr(mpcb, remote_address->sa_family, 0, &rema, port, true);

	if(mpcb->has_localaddr == 0)
		mpdccp_get_mpcb_local_address(mpcb, (struct sockaddr_in *)remote_address);

	meta_v4_address = (struct sockaddr_in *)&mpcb->mpdccp_local_addr;
	mpdccp_pr_debug ("MPDCCP bound to saddr %pI4", &meta_v4_address->sin_addr.s_addr);
	
	//rcu_read_lock_bh();
	/*first create subflow on default path*/
	list_for_each_entry_rcu(local, &pm_ns->plocal_addr_list, address_list) {
		if (local->family == AF_INET && local->addr.in.s_addr == meta_v4_address->sin_addr.s_addr) {
			local_v4_address.sin_family		= AF_INET;
			local_v4_address.sin_addr.s_addr 	= local->addr.in.s_addr;
			local_v4_address.sin_port		= 0;
			local_address = (struct sockaddr *) &local_v4_address;
			ret = mpdccp_add_client_conn (mpcb, local_address, sizeof(struct sockaddr_in),
				local->if_idx, remote_address, socklen);
			if ((ret < 0) && (ret != -EINPROGRESS) ) {
				mpdccp_pr_debug ("error in mpdccp_add_client_conn() for master subflow: %d\n", ret);
				goto out;
			} else {
				num++;
				if (mpcb && mpcb->fallback_sp) {
					mpdccp_pr_debug ("fallback to single path DCCP, don't create more subflows");
					goto out;
				}
				break;
			}
		}
	}

	/* Create subflows with all other local addresses */
	list_for_each_entry_rcu(local, &pm_ns->plocal_addr_list, address_list) {
		/* Set target IPv4/v6 address correctly */
		if (local->family == AF_INET) {
			if(local->addr.in.s_addr == meta_v4_address->sin_addr.s_addr) continue;
			local_v4_address.sin_family		= AF_INET;
			local_v4_address.sin_addr.s_addr 	= local->addr.in.s_addr;
			local_v4_address.sin_port		= 0;
			local_address = (struct sockaddr *) &local_v4_address;
			locaddr_len = sizeof (struct sockaddr_in);
		} else {
			local_v6_address.sin6_family		= AF_INET6;
			local_v6_address.sin6_addr 		= local->addr.in6;
			local_v6_address.sin6_port		= 0;
			local_address = (struct sockaddr *) &local_v6_address;
			locaddr_len = sizeof (struct sockaddr_in6);
		}
		local_if_idx = local->if_idx;
		/* unlock since mpdccp_add_client_conn() can sleep (data from the list entry are now copied locally) */
		//rcu_read_unlock_bh();
		ret = mpdccp_add_client_conn (	mpcb, local_address, locaddr_len,
						local_if_idx, remote_address, socklen);
		if ((ret < 0) && (ret != -EINPROGRESS) ) {
			mpdccp_pr_debug ("error in mpdccp_add_client_conn() for "
					"subflow %d: %d\n", num, ret);
		} else {
			num++;
		}
		/* lock again to continue scanning the list */
		//rcu_read_lock_bh();
	}
	//rcu_read_unlock_bh();

out:
	if (num == 0) {
		mpdccp_pr_debug ("no connection could be established\n");
		return ret == 0 ? -ENOTCONN : ret;
	}

	mpdccp_pr_debug("%d client connections added successfully. There are "
			"%d subflows now.\n", num, mpcb->cnt_subflows);

	return num;
}

static
int
add_init_server_conn (
    struct mpdccp_cb		*mpcb,
    int				backlog)
{
    struct pm_local_addr 	*local;
    struct sockaddr 		*local_address;
    struct sockaddr_in 		local_v4_address;
    struct sockaddr_in6 	local_v6_address;
    int				locaddr_len;
    int				ret;
    struct mpdccp_pm_ns		*pm_ns;
    int				server_port = 0;


    if (!mpcb) return -EINVAL;
    if (mpcb->role != MPDCCP_SERVER) return -EPERM;
    if (!mpcb->has_localaddr) return -EINVAL;

    /* get server port from local addr - to be changed - use full local address instead!! */
    local_address = (struct sockaddr*) &mpcb->mpdccp_local_addr;
    if (local_address->sa_family == AF_INET) {
	server_port = ((struct sockaddr_in*)local_address)->sin_port;
    } else if (local_address->sa_family == AF_INET6) {
	server_port = ((struct sockaddr_in6*)local_address)->sin6_port;
    }
    if (server_port == 0) return -EINVAL;

    //pm_ns = fm_get_ns (current->nsproxy->net_ns);
    pm_ns = fm_get_ns (read_pnet (&mpcb->net));

    mpcb->server_port = server_port;
    mpcb->backlog = backlog;

    /* Create subflows on all local interfaces */
    //rcu_read_lock_bh();
    list_for_each_entry_rcu(local, &pm_ns->plocal_addr_list, address_list) {
    
	/* Set target IPv4/v6 address correctly */
	if (local->family == AF_INET) {
	    local_v4_address.sin_family		= AF_INET;
	    local_v4_address.sin_addr.s_addr 	= local->addr.in.s_addr;
	    local_v4_address.sin_port		= server_port;
	    local_address = (struct sockaddr *) &local_v4_address;
	    locaddr_len = sizeof (struct sockaddr_in);
	} else {
	    local_v6_address.sin6_family	= AF_INET6;
	    local_v6_address.sin6_addr 		= local->addr.in6;
	    local_v6_address.sin6_port		= server_port;
	    local_address = (struct sockaddr *) &local_v6_address;
	    locaddr_len = sizeof (struct sockaddr_in6);
	}
	mpdccp_pr_debug("add listen socket: %pISc:%u\n", local_address, htons((unsigned)server_port));
	ret = mpdccp_add_listen_sock (	mpcb, local_address, locaddr_len,
					local->if_idx);
	if (ret < 0) {
	    mpdccp_pr_debug ("error in mpdccp_add_listen_sock(): %d\n", ret);
    	    //rcu_read_unlock_bh();
	    return ret;
	}
    }
    //rcu_read_unlock_bh();

    mpdccp_pr_debug("all server sockets added successfully. There are %d "
			"listening sockets now.\n", mpcb->cnt_subflows);

    return 0;
}

static struct mpdccp_pm_ops mpdccp_pm_default = {
	.add_init_server_conn	= add_init_server_conn,
	.add_init_client_conn	= add_init_client_conn,

	.claim_local_addr = pm_claim_local_addr,
	.get_id_from_ip = pm_get_id_from_ip,
	.del_addr = pm_del_addr,
	.add_addr = pm_add_addr,

	.rcv_removeaddr_opt	= pm_handle_rm_addr,
	.get_hmac = pm_get_addr_hmac,
	.rcv_prio_opt = pm_handle_rcv_prio,

	.rcv_confirm_opt = pm_rcv_confirm_opt,
	.store_confirm_opt = pm_store_confirm_opt,
	.del_retrans = pm_del_retrans,

	.name 			= "default",
	.owner 			= THIS_MODULE,
};


int mpdccp_pm_default_register(void)
{
	int	ret;

	ret = mpdccp_register_path_manager(&mpdccp_pm_default);
	if (ret < 0) {
		mpdccp_pr_error("Failed to register deault path manager\n");
		return ret;
	}
	/* Register notifier chains for dynamic interface management */
	ret = mpdccp_pm_init();
	if (ret) {
		mpdccp_pr_error("Failed to init default path manager.\n");
		return ret;
	}
	return 0;
}

void mpdccp_pm_default_unregister (void)
{
	mpdccp_pm_exit();
	mpdccp_unregister_path_manager(&mpdccp_pm_default);
}



