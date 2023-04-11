/*  SPDX-License-Identifier: NONE
 *
 * Copyright (C) 2017 by Andreas Philipp Matz, Deutsche Telekom AG
 * Copyright (C) 2020-2021 by Frank Reker, Deutsche Telekom AG
 *
 * MPDCCP - Cheapest-pipe-first scheduler kernel module
 *
 * A cheapest-pipe first scheduler. It will return the cheapest available sk
 * (i.e. highest priority, OR lowest SRTT in case of matching priority values)
 * that has a free cwnd for both the data in send queue and the new skb.
 * Scheduler kernel module management inspired by mptcp_sched.c
 *
 * This is not Open Source software. 
 * This work is made available to you under a source-available license, as 
 * detailed below.
 *
 * Copyright 2022 Deutsche Telekom AG
 *
 * Permission is hereby granted, free of charge, subject to below Commons 
 * Clause, to any person obtaining a copy of this software and associated 
 * documentation files (the "Software"), to deal in the Software without 
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 *
 * “Commons Clause” License Condition v1.0
 *
 * The Software is provided to you by the Licensor under the License, as
 * defined below, subject to the following condition.
 *
 * Without limiting other conditions in the License, the grant of rights under
 * the License will not include, and the License does not grant to you, the
 * right to Sell the Software.
 *
 * For purposes of the foregoing, “Sell” means practicing any or all of the
 * rights granted to you under the License to provide to third parties, for a
 * fee or other consideration (including without limitation fees for hosting 
 * or consulting/ support services related to the Software), a product or 
 * service whose value derives, entirely or substantially, from the
 * functionality of the Software. Any license notice or attribution required
 * by the License must also include this Commons Clause License Condition
 * notice.
 *
 * Licensor: Deutsche Telekom AG
 */

#include <linux/module.h>
#include <linux/rculist.h>

#include <net/mpdccp_link.h>
#include <net/mpdccp_link_info.h>
#include "../mpdccp.h"
#include "../mpdccp_scheduler.h"


static struct mpdccp_sched_ops mpdccp_sched_cpf;

/* This function returns a pointer that is part of a RCU protected
 * structure. It must be called with the rcu_read_lock() held. */
struct sock *mpdccp_cpfsched(struct mpdccp_cb *mpcb)
{
	struct sock             *sk;
	struct sock             *best_sk = NULL;
	struct tcp_info		info;
	struct tcp_info		*infop = &info;
	__u8			priority = 0;
	struct mpdccp_link_info	*link;
	__u8			min_prio   = 1;
	
	/* Initialise to arbitrarily high (max) value */
	u32			min_srtt   = ~((u32)0);
	
	
	//* if there is only 1 subflow, we bypass scheduling */
	if(mpcb->cnt_subflows == 1) {
		//mpdccp_pr_debug("Only 1 socket available. Skipping selection.\n");
		return mpdccp_return_single_flow(mpcb);
	}
	
	mpdccp_for_each_sk(mpcb, sk) {
		/* Skip sockets that are still in handshake or where
		 * cwnd is full */
		if(!mpdccp_sk_can_send(sk)) {
			//mpdccp_pr_debug("Flow %p not established. Continuing...\n", sk);
			continue;
		}
		
		if(!mpdccp_packet_fits_in_cwnd(sk)){
			//mpdccp_pr_debug("Packet does not fit in cwnd of %p. Continuing...\n", sk);
			continue;
		}

		link = mpdccp_ctrl_getlink (sk);
		if (link) {
			priority = link->mpdccp_prio;
			//mpdccp_pr_debug("get link prio %d for sk %p", priority, sk);
		} else {
			priority = 3;
			mpdccp_pr_debug ("cannot get link for sk %p - use prio 3\n", sk);
		}
		mpdccp_link_put (link);
        
		ccid_hc_tx_get_info(dccp_sk(sk)->dccps_hc_tx_ccid, sk, infop);
		if (priority > min_prio ||
			(priority == min_prio && infop->tcpi_rtt < min_srtt)) {
			min_prio = priority;
			min_srtt = infop->tcpi_rtt;
			best_sk  = sk;
		}

		//possible TODO: mptcp_dont_reinject_skb()-style checking if this skb has been
		//enqueued on this subflow
	}
	
	mpdccp_pr_debug("Cheapest pipe first returned socket %p\n", best_sk);
	return best_sk;
}

static void cpfsched_init(void)
{
}


static void cpfsched_init_subflow (struct sock *sk)
{
#ifdef CONFIG_IP_MPDCCP_DEBUG
	struct mpdccp_link_info	*link;

	if (!sk) return;
	mpdccp_pr_debug ("check for priority\n");
	link = mpdccp_ctrl_getlink (sk);
	if (link) {
		mpdccp_pr_debug ("socket(%p) gets prio %d (from link %d (%s))\n",
			sk, link->mpdccp_prio, link->id, link->name);
	} else {
		mpdccp_pr_debug ("no link found!!!! - choose 0\n");
	}
	mpdccp_link_put (link);
#endif
	return;
}

/* Initialize a specific MPDCCP connection */
static void cpfsched_init_conn (struct mpdccp_cb *mpcb)
{
#ifdef CONFIG_IP_MPDCCP_DEBUG
	struct sock		*sk;

	if (!mpcb) return;
	mpdccp_for_each_sk(mpcb, sk) {
		cpfsched_init_subflow (sk);
	}
#endif
	return;
}


static struct mpdccp_sched_ops mpdccp_sched_cpf = {
	.get_subflow	= mpdccp_cpfsched,
	.init_conn	= cpfsched_init_conn,
	.init_subflow	= cpfsched_init_subflow,
	.name		= "cpf",
	.owner		= THIS_MODULE,
};


static int __init mpdccp_cpfsched_register(void)
{
	cpfsched_init();
	if (mpdccp_register_scheduler(&mpdccp_sched_cpf))
		return -1;
	return 0;
}

static void mpdccp_cpfsched_unregister(void)
{
	mpdccp_unregister_scheduler(&mpdccp_sched_cpf);
}

module_init(mpdccp_cpfsched_register);
module_exit(mpdccp_cpfsched_unregister);


MODULE_AUTHOR("Andreas Matz");
MODULE_AUTHOR("Frank Reker");
MODULE_LICENSE("Proprietary");
MODULE_DESCRIPTION("Multipath DCCP Cheapest Path First Scheduler");
MODULE_VERSION(MPDCCP_VERSION);


