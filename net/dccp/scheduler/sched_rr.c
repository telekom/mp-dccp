/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 * Copyright (C) 2017 by Andreas Philipp Matz, Deutsche Telekom AG
 * Copyright (C) 2017 by Markus Amend, Deutsche Telekom AG
 * Copyright (C) 2021 by Frank Reker, Deutsche Telekom AG
 *
 * MPDCCP - Round-Robin scheduler kernel module
 *
 * A round-robin style scheduler. It will alternate between the available
 * sockets and return one after another that has a free cwnd for both data
 * in send queue and the new skb.
 * Heavily inspired by mpdccp_rr.c
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <linux/module.h>

#include "../mpdccp.h"
#include "../mpdccp_scheduler.h"

// TODO: make this a sysctl variable so it can be changed during runtime
static unsigned char num_segments __read_mostly = 1;
module_param(num_segments, byte, 0644);
MODULE_PARM_DESC(num_segments, "The number of consecutive segments that are part of a burst.\
                                Must be a value between 1 and max(__u32)");
// TODO: not yet implemented
static bool overall_cwnd __read_mostly = 0;
module_param(overall_cwnd, bool, 0644);
MODULE_PARM_DESC(overall_cwnd, "if set to 1, the scheduler is limited by the smallest congestion window");

// Private data, subflow-specific
struct rrsched_priv {
	__u32 quota;
};

static struct rrsched_priv *rrsched_get_priv(struct sock *sk)
{
	struct my_sock *my_sk = (struct my_sock *)sk->sk_user_data;
	
	return (struct rrsched_priv *)&my_sk->sched_priv[0];
}

static struct sock *mpdccp_rrsched (struct mpdccp_cb *mpcb)
{
	struct sock		*sk;
	int			iter = 0, full_flows = 0;
	struct sock		*best_sk = NULL;
	struct rrsched_priv	*rr_priv;
	
	/* if there is only 1 subflow, we bypass scheduling */
	if(mpcb->cnt_subflows == 1) {
		mpdccp_pr_debug("Only 1 socket available. Skipping selection.\n");
		return mpdccp_return_single_flow(mpcb);
	}

retry:
	rcu_read_lock();
	mpdccp_for_each_sk(mpcb, sk) {
		/* Skip sockets that are still in handshake or where
		 * cwnd is full */
		if(!mpdccp_sk_can_send(sk)) {
			mpdccp_pr_debug("Flow %p not established. Continuing...\n", sk);
			continue;
		}
		
		if(!mpdccp_packet_fits_in_cwnd(sk)){ //&& !dccp_ack_pending(sk)
			mpdccp_pr_debug("Packet does not fit in cwnd of %p. Continuing...\n", sk);
			continue;
		}
		
		// Iter counts the sockets we considered for transmission
		iter++;
		rr_priv = rrsched_get_priv(sk);
		
		/* num_segments defines how many packets are sent on a flow before switching
		 * to another one. There are three situations:
		 * 1) We previously started to use this flow, but did not use up num_segments.
		 * 2) We have not started to use this flow. Start sending away :-)
		 * 3) This socket has a full quota. Use another one.
		 */
		if(rr_priv->quota > 0 && rr_priv->quota < num_segments) {
			best_sk = sk;
			break;
		} else if(!rr_priv->quota) {
			best_sk = sk;
		} else if(rr_priv->quota >= num_segments) {
			full_flows++;
		}
	}
	rcu_read_unlock();
	
	if(iter && iter == full_flows) {
		/* If we get here, all sockets have been used to their full quota.
		 * Reset quota and retry. */
		rcu_read_lock();
		mpdccp_for_each_sk(mpcb, sk) {
			rr_priv = rrsched_get_priv(sk);
			rr_priv->quota = 0;
		}
		rcu_read_unlock();
		
		goto retry;
	}
	
	if(best_sk) {
		rr_priv = rrsched_get_priv(best_sk);
		rr_priv->quota++;
		
		mpdccp_pr_debug("Round-Robin returned socket %p\n", best_sk);
		return best_sk;
	}
	
	return NULL;
}


static void rrsched_init_subflow (struct sock *sk)
{
	struct rrsched_priv *rr_priv;

	if (!sk) return;
	rr_priv = rrsched_get_priv(sk);
	rr_priv->quota = 0;
	return;
}

static void rrsched_init_conn(struct mpdccp_cb *mpcb)
{
	struct sock *sk;
	
	rcu_read_lock();
	mpdccp_for_each_sk(mpcb, sk) {
		rrsched_init_subflow (sk);
	}
	rcu_read_unlock();
	
	return;
}


struct mpdccp_sched_ops mpdccp_sched_rr = {
	.get_subflow	= mpdccp_rrsched,
	.init_subflow	= rrsched_init_subflow,
	.init_conn	= rrsched_init_conn,
	.name		= "rr",
	.owner		= THIS_MODULE,
};

static int __init mpdccp_rrsched_register(void)
{
	BUILD_BUG_ON(sizeof(struct rrsched_priv) > MPDCCP_SCHED_SIZE);
	
	if (mpdccp_register_scheduler(&mpdccp_sched_rr))
		return -1;
	return 0;
}

static void mpdccp_rrsched_unregister(void)
{
	mpdccp_unregister_scheduler(&mpdccp_sched_rr);
}

module_init(mpdccp_rrsched_register);
module_exit(mpdccp_rrsched_unregister);

MODULE_AUTHOR("Andreas Ph. Matz");
MODULE_AUTHOR("Markus Amend");
MODULE_AUTHOR("Frank Reker");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Multipath DCCP Round-Robin Scheduler");
MODULE_VERSION(MPDCCP_VERSION);

