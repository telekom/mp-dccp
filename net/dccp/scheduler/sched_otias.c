/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 * Copyright (C) 2018 by Andreas Philipp Matz, Deutsche Telekom AG
 * Copyright (C) 2018 by Markus Amend, Deutsche Telekom AG
 *
 * MPDCCP - OTIAS scheduler kernel module
 *
 * OTIAS - An Out-of-order Transmission for In-order Arrival Scheduler. 
 * It tries to estimate link latencies and schedules packets accordingly 
 * so that packets arrive in order.
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

/* NOTE: Currently, the scheduler will block if this is enabled and a flow is no longer available. */
static bool overall_cwnd __read_mostly = 0;
module_param(overall_cwnd, bool, 0644);
MODULE_PARM_DESC(overall_cwnd, "if set to 1, the scheduler is limited by the smallest congestion window");

static uint log_packet_length __read_mostly = 1228;
module_param(log_packet_length, uint, 0644);
MODULE_PARM_DESC(log_packet_length, "Only log packets with this length. Default 1228 (1200 byte payload + 28 byte header)");


struct sock *mpdccp_otiassched(struct mpdccp_cb *mpcb)
{
	struct sock		*sk;
	struct ccid2_hc_tx_sock	*hc;
	u32			estd_arrival_time, rtt_to_wait, iperf_sequence_number;
	s64			packet_can_be_sent, packets_must_wait;
	struct sock		*meta_sk = mpcb ? mpcb->meta_sk : NULL;
	struct sk_buff		*next_skb;
	struct sock		*best_sk    = NULL;
	
	/* Initialise to arbitrarily high (max) value */
	u32			min_arrival_time  = ~((u32)0);
	
	if(!meta_sk)
		return NULL;

	next_skb = dccp_qpolicy_top (meta_sk);
	
	if(next_skb->len == log_packet_length) {
		memcpy(&iperf_sequence_number, next_skb->data+28, min(next_skb->len, (unsigned int)4));
		iperf_sequence_number = ntohl(iperf_sequence_number);
#if 0
	} else {
		printk(KERN_WARNING "mismatch size %u", next_skb->len);
#endif
	}
	
	/* if there is only 1 subflow, we bypass scheduling */
	if(mpcb->cnt_subflows == 1) {
		mpdccp_pr_debug("Only 1 socket available. Skipping selection.\n");
		return mpdccp_return_single_flow(mpcb);
	}

#if 0	
	/* Warning: Enabling this will stop the transmission if even one out of all
	 * flows is currently unavailable (not established or cwnd full). This will 
	 * halt your transmission. You have been warned. */
	if(unlikely(overall_cwnd)) {
		rcu_read_lock();
		mpdccp_for_each_sk(mpcb, sk) {
		    if(!mpdccp_sk_can_send(sk) || !mpdccp_packet_fits_in_cwnd(sk)) {
		    	mpdccp_pr_debug("Overall congestion window enabled: Halt on full cwnd on sk %p.\n", sk);
		    	return NULL;
		    }
		}
		rcu_read_unlock();
	}
#endif
	
	rcu_read_lock();
	mpdccp_for_each_sk(mpcb, sk) {
		/* Overall cwnd guarantees that all flows are available before even starting
		 * to send (see above). No need to check each socket twice. */
		if(!unlikely(overall_cwnd)) {
			/* Skip sockets that are still in handshake or where
			 * the send queue is full */
			
			if(!mpdccp_sk_can_send(sk)) {
				mpdccp_pr_debug("Flow %p not established. Continuing...\n", sk);
				continue;
			}
			
			if(dccp_qpolicy_full(sk)) {
				mpdccp_pr_debug("Packet does not fit in send queue of %p. Continuing...\n", sk);
				continue;
			}
		}
		
		hc = ccid2_hc_tx_sk(sk);
		
		/* Is there space in the cwnd? */
		packet_can_be_sent  =   hc->tx_cwnd - hc->tx_pipe;
		
		/* How long do we have to wait to send? 
		 * If we have more free cwnd than packets sitting in queue, we don't have to wait at all*/
		packets_must_wait = sk->sk_write_queue.qlen - packet_can_be_sent;
		
		if(packets_must_wait < 0)
			rtt_to_wait = 0;
		else
			rtt_to_wait = packets_must_wait / hc->tx_cwnd;
		
		/* Estimate packet arrival time, choose fastest socket */
		estd_arrival_time   =   (rtt_to_wait * hc->tx_srtt) + (hc->tx_srtt / 2);
		
		if (estd_arrival_time < min_arrival_time) {
			min_arrival_time = estd_arrival_time;
			best_sk = sk;
		}
		if(next_skb->len == log_packet_length)
			printk(KERN_WARNING "OTIAS iperf seq %u: sk %p, srtt %d, buffer %d, "
		    		"cwnd %d, pipe %d, packets_must_wait %lld, estd_arrival_time %d", 
					iperf_sequence_number, sk, hc->tx_srtt, sk->sk_write_queue.qlen,
				hc->tx_cwnd, hc->tx_pipe, packets_must_wait, estd_arrival_time);
	}
	rcu_read_unlock();
	
	if(next_skb->len == log_packet_length)
		printk(KERN_WARNING "OTIAS iperf seq %u: chosen sk %p", iperf_sequence_number, best_sk);
	return best_sk;
}


struct mpdccp_sched_ops mpdccp_sched_otias = {
	.get_subflow	= mpdccp_otiassched,
	.name		= "otias",
	.owner		= THIS_MODULE,
};

static int __init mpdccp_otiassched_register(void)
{
	if (mpdccp_register_scheduler(&mpdccp_sched_otias))
		return -1;
	return 0;
}

static void mpdccp_otiassched_unregister(void)
{
	mpdccp_unregister_scheduler(&mpdccp_sched_otias);
}

module_init(mpdccp_otiassched_register);
module_exit(mpdccp_otiassched_unregister);

MODULE_AUTHOR("Andreas Ph. Matz");
MODULE_AUTHOR("Markus Amend");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Multipath DCCP OTIAS Scheduler");
MODULE_VERSION(MPDCCP_VERSION);

