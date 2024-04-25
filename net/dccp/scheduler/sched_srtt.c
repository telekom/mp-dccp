/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 * Copyright (C) 2018 by Andreas Philipp Matz, Deutsche Telekom AG
 * Copyright (C) 2018 by Markus Amend, Deutsche Telekom AG
 *
 * MPDCCP - Smoothed-RTT based scheduler kernel module
 *
 * A SRTT based scheduler. It will return the flow with the
 * lowest srtt that has a free cwnd for both the data in send 
 * queue and the new skb.
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
#include <linux/timekeeping.h>

#include "../mpdccp.h"
#include "../mpdccp_scheduler.h"

// Bandwidth and SRTT logging
#define MPDCCP_SRTT_LOG_BW 1

// Private data, connection-specific 
struct srttsched_priv {
	u8		socket_number;
	u64		tx_bytepersecond;
	time64_t	last_timestamp;
};

static struct srttsched_priv *srttsched_get_priv(struct sock *sk)
{
	struct my_sock *my_sk = (struct my_sock *)sk->sk_user_data;
	
	return (struct srttsched_priv *)&my_sk->sched_priv[0];
}

static struct sock *mpdccp_srttsched(struct mpdccp_cb *mpcb)
{
	struct ccid2_hc_tx_sock *hc;
	struct sock		*sk;
	struct sock		*best_sk = NULL;
	
	/* Initialise to arbitrarily high (max) value */
	u32			min_srtt = ~((u32)0);

#if defined MPDCCP_SRTT_LOG_BW && 0
	struct srttsched_priv	*srtt_priv;
	//struct timeval		tv;
	time64_t tstamp
	struct sk_buff		*next_skb;
#endif

	//* if there is only 1 subflow, we bypass scheduling */
	if(mpcb->cnt_subflows == 1) {
		dccp_pr_debug("Only 1 socket available. Skipping selection.\n");
		return mpdccp_return_single_flow(mpcb);
	}
	
	rcu_read_lock();
	mpdccp_for_each_sk(mpcb, sk) {
		/* Skip sockets that are still in handshake or where
		 * cwnd is full */
		if (!mpdccp_sk_can_send(sk)) {
			mpdccp_pr_debug("Flow %p not established. Continuing...\n", sk);
			continue;
		}
		
		if (!mpdccp_packet_fits_in_cwnd(sk)){ // && !dccp_ack_pending(sk)
			mpdccp_pr_debug("Packet does not fit in cwnd of %p. Continuing...\n", sk);
			continue;
		}
		
		hc = ccid2_hc_tx_sk(sk);
		//printk(KERN_ERR "SRTT of flow #%d is %d", i, hc->tx_srtt);
		if (hc->tx_srtt < min_srtt) {
			min_srtt = hc->tx_srtt;
			best_sk  = sk;
#if 0
		} else {
			/*
			 * This is the loosing socket. If we do not get any traffic, how
			 * should we ever know that our path properties changed? 
			 *
			 * After one RTO period without any packets sent, we should give
			 * that socket a chance.
			 */
			if (ccid2_time_stamp > (hc->tx_lsndtime + hc->tx_rto))
				return sk;
#endif
		}
	}
	rcu_read_unlock();

#if defined MPDCCP_SRTT_LOG_BW && 0
	// No best_sk = no socket available
	if(best_sk) {
		next_skb = mpcb && mpcbp->meta_sk ? dccp_qpolicy_top (mpcb->meta_sk) : NULL;
		//do_gettimeofday(&tv);
		tstamp = ktime_get_seconds();

		
		// For each socket, we log time stamp, bandwidth and srtt
		rcu_read_lock();
		mpdccp_for_each_sk(mpcb, sk) {
			srtt_priv = srttsched_get_priv(sk);
			
			if (tstamp == srtt_priv->last_timestamp) {
				if (!next_skb)
					return NULL;
				
				// Count the packet towards the socket it will be sent on
				if (sk == best_sk)
					srtt_priv->tx_bytepersecond += next_skb->len;
			} else {
				printk(KERN_INFO "time: %lld sk: %d bw: %lld srtt: %u", 
					(long long)srtt_priv->last_timestamp, srtt_priv->socket_number, 
					srtt_priv->tx_bytepersecond, ccid2_hc_tx_sk(sk)->tx_srtt);
				
				// Reset byte counter and count the packet towards the socket it will be sent on
				if(sk == best_sk)
					srtt_priv->tx_bytepersecond    = next_skb->len;
				else
					srtt_priv->tx_bytepersecond    = 0;
				
				srtt_priv->last_timestamp      = tstamp;
			}
		}
		rcu_read_unlock();
	}
#endif

	mpdccp_pr_debug("SRTT scheduler returned socket %p\n", best_sk);
	return best_sk;
}



static void srttsched_init_conn(struct mpdccp_cb *mpcb)
{
#ifdef MPDCCP_SRTT_LOG_BW
	struct sock		*sk;
	time64_t tstamp;
	struct srttsched_priv	*srtt_priv;
	int			i = 0;

	mpdccp_pr_debug ("NOTE: Bandwidth logging enabled. See ring buffer for measurement.\n");
	
	rcu_read_lock();
	mpdccp_for_each_sk(mpcb, sk) {
		srtt_priv = srttsched_get_priv(sk);
		
		srtt_priv->socket_number = i;
		i++;
		
		srtt_priv->tx_bytepersecond             = 0;
		
		//do_gettimeofday(&tv);
		tstamp = ktime_get_seconds();
		srttsched_get_priv(sk)->last_timestamp  = tstamp;
	}
	rcu_read_unlock();
#endif
	return;
}

static void srttsched_init_subflow (struct sock *sk)
{
	struct my_sock *my_sk = (struct my_sock *)sk->sk_user_data;
	srttsched_init_conn (my_sk->mpcb);
}

struct mpdccp_sched_ops mpdccp_sched_srtt = {
	.get_subflow	= mpdccp_srttsched,
	.init_subflow	= srttsched_init_subflow,
	.init_conn	= srttsched_init_conn,
	.name		= "srtt",
	.owner		= THIS_MODULE,
};

static int __init mpdccp_srttsched_register(void)
{
	BUILD_BUG_ON(sizeof(struct srttsched_priv) > MPDCCP_SCHED_SIZE);
	
	if (mpdccp_register_scheduler(&mpdccp_sched_srtt))
		return -1;
	return 0;
}

static void mpdccp_srttsched_unregister(void)
{
    mpdccp_unregister_scheduler(&mpdccp_sched_srtt);
}

module_init(mpdccp_srttsched_register);
module_exit(mpdccp_srttsched_unregister);

MODULE_AUTHOR("Andreas Ph. Matz");
MODULE_AUTHOR("Markus Amend");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Multipath DCCP SRTT Scheduler");
MODULE_VERSION(MPDCCP_VERSION);

