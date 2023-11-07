/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 * Copyright (C) 2018 by Andreas Philipp Matz, Deutsche Telekom AG
 * Copyright (C) 2018 by Markus Amend, Deutsche Telekom AG
 *
 * MPDCCP - Redundant scheduler kernel module
 *
 * A redundant scheduler. It will alternate between the available
 * sockets and queue a packet on as many as possible, provided they
 * have a free cwnd for both data in send queue and the new skb.
 * 
 * Note: 
 * This scheduler currently is essentially a hack to get around API 
 * limitations. We can only return one sk to send on, so the scheduler
 * itself will send on all other flows. This will change as soon as 
 * the API is updated.
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


/* One socket is returned by get_subflow operation. For all other flows, 
 * get_subflow will call this function which mimics the behavior of the 
 * original code path so that we can send packets on all flows without 
 * making changes to the API. */
static int redsched_transmit_on_flow(struct mpdccp_cb *mpcb, struct sock *sk)
{
	int		ret;
	struct sock	*meta_sk;
	struct sk_buff 	*skb, *skb2;
	
	if (!mpcb || !mpcb->meta_sk)
		return -EINVAL;

	meta_sk = mpcb->meta_sk;
	skb2 = dccp_qpolicy_top (meta_sk);
	//printk(KERN_INFO "inred skb2 %p", skb2);
	skb = pskb_copy (skb2, GFP_KERNEL);
	if (!skb) {
		mpdccp_pr_debug ("cannot copy skb - dropping packet\n");
		return -ENOMEM;
	}
	DCCP_SKB_CB(skb)->dccpd_mpseq = mpcb->mp_oall_seqno;
	ret = mpdccp_xmit_to_sk (sk, skb);
	if (ret < 0) {
		mpdccp_pr_debug ("error in xmit: %d - dropping packet\n", ret);
		kfree_skb(skb);
		return ret;
	}
	return 0;
}

/* Iterate over all sockets, return one, and queue the packet
 * on the rest. This gives us a redundant behavior without the
 * need to overthrow the entire scheduler API. */
struct sock *mpdccp_redsched(struct mpdccp_cb *mpcb)
{
	int		ret;
	struct sock	*sk, *best_sk = NULL;
	
	/* if there is only 1 subflow, we bypass scheduling */
	mpcb->do_incr_oallseq = false;
	if(mpcb->cnt_subflows == 1) {
		mpdccp_pr_debug("Only 1 socket available. Skipping selection.\n");
		return mpdccp_return_single_flow(mpcb);
	}
	
	rcu_read_lock();
	mpdccp_for_each_sk(mpcb, sk) {
		/* Skip sockets that are still in handshake or where
		 * cwnd is full */
		if(!mpdccp_sk_can_send(sk)) {
			mpdccp_pr_debug("Flow %p not established. Continuing...\n", sk);
			continue;
		}
		
		if(!mpdccp_packet_fits_in_cwnd(sk)){ // && !dccp_ack_pending(sk)
			mpdccp_pr_debug("Packet does not fit in cwnd of %p. Continuing...\n", sk);
			continue;
		}
		
		// save a single socket to return later
		if (!best_sk){
			best_sk = sk;
			continue;
		}

		ret = redsched_transmit_on_flow(mpcb, sk);
		if(ret){
			mpdccp_pr_debug("Transmit failed on sk %p with error %d\n", sk, ret);
		} 
	}

	rcu_read_unlock();
	return best_sk;
}


struct mpdccp_sched_ops mpdccp_sched_red = {
	.get_subflow	= mpdccp_redsched,
	.name		= "redundant",
	.owner		= THIS_MODULE,
};

static int __init mpdccp_redsched_register(void)
{
	if (mpdccp_register_scheduler(&mpdccp_sched_red))
		return -1;
	return 0;
}

static void mpdccp_redsched_unregister(void)
{
	mpdccp_unregister_scheduler(&mpdccp_sched_red);
}

module_init(mpdccp_redsched_register);
module_exit(mpdccp_redsched_unregister);

MODULE_AUTHOR("Andreas Ph. Matz");
MODULE_AUTHOR("Markus Amend");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Multipath DCCP Redundant Scheduler");
MODULE_VERSION(MPDCCP_VERSION);

