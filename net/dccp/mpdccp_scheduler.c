/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 * Copyright (C) 2017 by Andreas Philipp Matz, Deutsche Telekom AG
 * Copyright (C) 2017 by Markus Amend, Deutsche Telekom AG
 * Copyright (C) 2019 by Nathalie Romo, Deutsche Telekom AG
 * Copyright (C) 2020-2021 by Frank Reker, Deutsche Telekom AG
 *
 * MPDCCP - Scheduler Framework
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <linux/module.h>
#include <linux/rculist.h>

#include <net/mpdccp_link.h>
#include <net/mpdccp_link_info.h>
#include "mpdccp.h"
#include "mpdccp_scheduler.h"
#include "mpdccp_version.h"

static struct list_head __rcu mpdccp_sched_list;
DEFINE_SPINLOCK(mpdccp_sched_list_lock);
static struct mpdccp_sched_ops 	*sched_default=NULL;
static struct mpdccp_sched_ops 	*sched_fallback=NULL;

int
mpdccp_scheduler_setup (void)
{
	int	ret;

	rcu_read_lock();

	INIT_LIST_HEAD_RCU(&mpdccp_sched_list);
	mpdccp_sched_default_register();

	/* Initialize default scheduler */
	// The following doesn't work - must not be done during module setup!!! - tbd.
	//ret = mpdccp_set_default_scheduler(CONFIG_DEFAULT_MPDCCP_SCHED);
	ret = mpdccp_set_default_scheduler("default");

	rcu_read_unlock();

	if (ret < 0) {
		mpdccp_pr_error("Failed to set default scheduler \"%s\".\n", CONFIG_DEFAULT_MPDCCP_SCHED);
		return ret;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(mpdccp_scheduler_setup);


/* Check if a flow is fully established, i.e. the handshake is complete. */
bool mpdccp_sk_can_send(struct sock *sk)
{
	struct mpdccp_cb *mpcb = MPDCCP_CB(sk);
	return ((dccp_sk(sk)->auth_done || (mpcb && mpcb->fallback_sp))
			&& (sk->sk_state == DCCP_OPEN || sk->sk_state == DCCP_PARTOPEN));
}
EXPORT_SYMBOL(mpdccp_sk_can_send);

bool mpdccp_packet_fits_in_cwnd(struct sock *sk)
{
	unsigned int space;
	struct dccp_sock *dp;
	struct tcp_info info;
	struct tcp_info *infop = &info;
	
	/* From RFC 4341:
	 * The sender MAY send a data packet when pipe < cwnd but
	 * MUST NOT send a data packet when pipe >= cwnd.
	 *
	 * tx_cwnd is the congestion window size in data packets
	 * tx_pipe is the senders' estimate of packets in flight */
	
	dp = dccp_sk(sk);
	if(dp->dccps_hc_tx_ccid == NULL){
		mpdccp_pr_debug("ccid not yet setup sk %p", sk);
		return false; 
	}
	ccid_hc_tx_get_info(dp->dccps_hc_tx_ccid, sk, infop);
	if (infop->tcpi_segs_out >= infop->tcpi_snd_cwnd) {
		mpdccp_pr_debug( "Socket %p is congestion limited (hc->tx_pipe = %d,\
				hc->tx_cwnd = %d).\n", sk, infop->tcpi_segs_out,
				infop->tcpi_snd_cwnd);
		return false;
	}
	
	/* Check if what is already queued in the subflow socket's
	 * send-queue already fills the cwnd before we even have a 
	 * chance to send anything. Shamelessly adopted from TCP,
	 * inspired by qpolicy_simple_full().
	 */
	
	// Remaining free space in the congestion window
	space = infop->tcpi_snd_cwnd - infop->tcpi_segs_out;
	
	if (sk->sk_write_queue.qlen >= space) {
		mpdccp_pr_debug("Socket %p has a full cwnd.\n", sk);
		return false;
	}
	
	return true;
}
EXPORT_SYMBOL(mpdccp_packet_fits_in_cwnd);

/* This function returns a pointer that is part of a RCU protected
 * structure. It must be called with the rcu_read_lock() held. */
struct sock *mpdccp_return_single_flow(struct mpdccp_cb *mpcb)
{
	struct my_sock  *my_sk;
	struct sock     *sk = NULL;
	
	rcu_read_lock();
	
	my_sk = list_first_or_null_rcu(&mpcb->psubflow_list, struct my_sock, sk_list);
	if( !my_sk ) {
		goto out; /* No socket available */
	}
	
	sk = my_sk->my_sk_sock;
	if(!sk || !mpdccp_sk_can_send(sk) || (!mpdccp_packet_fits_in_cwnd(sk) && !dccp_ack_pending(sk))) {
		rcu_read_unlock();
		dccp_pr_debug("No free pipe available.\n");
		return NULL;
	}

out:
	rcu_read_unlock();
	return sk;
}
EXPORT_SYMBOL(mpdccp_return_single_flow);



struct mpdccp_sched_ops *mpdccp_sched_find(const char *name)
{
	struct mpdccp_sched_ops *e;

	if(!name)
		return NULL;
	
	rcu_read_lock();
	list_for_each_entry_rcu(e, &mpdccp_sched_list, list) {
		if (strcmp(e->name, name) == 0){
			rcu_read_unlock();
	    		return e;
		}
	}
	rcu_read_unlock();

	return NULL;
}
EXPORT_SYMBOL(mpdccp_sched_find);


int mpdccp_register_scheduler(struct mpdccp_sched_ops *sched)
{
	int	ret = 0;

	if (!sched || !sched->get_subflow)
		return -EINVAL;

	rcu_read_lock();
	if (mpdccp_sched_find(sched->name)) {
		pr_notice("%s scheduler already registered\n", sched->name);
		ret = -EEXIST;
		goto out;
	}
	spin_lock(&mpdccp_sched_list_lock);
	list_add_tail_rcu(&sched->list, &mpdccp_sched_list);
	spin_unlock(&mpdccp_sched_list_lock);
	if (!strcasecmp (sched->name, "default"))
		sched_fallback = sched;

	pr_info("%s scheduler registered\n", sched->name);
out:
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(mpdccp_register_scheduler);


void mpdccp_unregister_scheduler(struct mpdccp_sched_ops *sched)
{
	struct mpdccp_cb	*mpcb = NULL; 
	struct mpdccp_sched_ops	*defsched = NULL;

	rcu_read_lock();
	spin_lock(&mpdccp_sched_list_lock);
	list_del_rcu(&sched->list);
	if (sched == sched_default)
		sched_default = list_entry_rcu(mpdccp_sched_list.next, struct mpdccp_sched_ops, list);
	defsched = sched_default ? sched_default : sched_fallback;

	/* reset scheduling ops back to default - this is buggy - tbd. */
	mpdccp_for_each_conn(pconnection_list, mpcb) {
		if (mpcb->sched_ops == sched) {
			lock_sock(mpcb->meta_sk);
			mpdccp_init_scheduler (mpcb);
			release_sock(mpcb->meta_sk);
		}
	}
	spin_unlock(&mpdccp_sched_list_lock);
	rcu_read_unlock();
}
EXPORT_SYMBOL(mpdccp_unregister_scheduler);

void mpdccp_get_default_scheduler(char *name)
{
	struct mpdccp_sched_ops *sched;

	BUG_ON(list_empty(&mpdccp_sched_list));

	rcu_read_lock();
	sched = sched_default ? sched_default : sched_fallback;
	strncpy(name, sched->name, MPDCCP_SCHED_NAME_MAX);
	rcu_read_unlock();
}

int mpdccp_set_default_scheduler(const char *name)
{
	struct mpdccp_sched_ops *sched;
	int ret = -ENOENT;

	if (!name) name = CONFIG_DEFAULT_MPDCCP_SCHED;
	rcu_read_lock();
	sched = mpdccp_sched_find(name);
#ifdef CONFIG_MODULES
	if (!sched && capable(CAP_NET_ADMIN)) {
		request_module("mpdccp_sched_%s", name);
		sched = mpdccp_sched_find(name);
	}
#endif

	if (sched) {
		//spin_lock(&mpdccp_sched_list_lock);
		sched_default = sched;
		//spin_unlock(&mpdccp_sched_list_lock);
		ret = 0;
	} else {
		pr_info("%s is not available\n", name);
	}
	rcu_read_unlock();

	return ret;
}

void mpdccp_init_scheduler(struct mpdccp_cb *mpcb)
{
	struct mpdccp_sched_ops *sched;

	if (!mpcb) return;
	rcu_read_lock();
	sched = sched_default;
	mpcb->do_incr_oallseq = true;
	if (try_module_get(sched->owner)) {
		mpcb->sched_ops = sched;
		if (sched->init_conn)
			sched->init_conn (mpcb);
		mpdccp_pr_debug("sched set to %s", sched->name);
	} else {
		pr_info("cannet init scheduler %s", sched->name);
	}
	rcu_read_unlock();
}

/* Manage refcounts on socket close. */
void mpdccp_cleanup_scheduler(struct mpdccp_cb *mpcb)
{
	module_put(mpcb->sched_ops->owner);
}



