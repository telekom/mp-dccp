 /*  SPDX-License-Identifier: NONE
 *
 * Copyright (C) 2022 by Alexander Rabitsch, Karlstad University for Deutsche Telekom AG
 *
 * MPDCCP - Adaptive Cheapest Path First scheduler kernel module
 *
 * An adaptive cheapest path first scheduler. In the primary mode, it will
 * return the cheapest available subflow (i.e. lowest priority, OR lowest
 * SRTT in case of matching priority values) that has a free cwnd for both
 * the data in send queue and the new skb. The scheduler dynamically adjusts
 * the fraction of the cwnd that is considered available in order to utilize
 * the available paths earlier than the original cheapest path first scheduler.
 *
 * When all paths are considered fully utilized, the scheduler switches to
 * a scheduling strategy that is similar to the Smoothed-RTT based scheduler.
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

#ifdef CONFIG_IP_DCCP_CCID5
#include "../ccids/ccid5.h"
#endif

#ifdef CONFIG_IP_DCCP_CCID6
#include "../ccids/ccid6.h"
#endif

#define acpfsched_jiffies32	((u32)jiffies)

#define MPDCCP_ACPFSCHED_UNIT 1000

#define MPDCCP_ACPFSCHED_TARGET 10
#define MPDCCP_ACPFSCHED_MIN_TARGET_US 5000
#define MPDCCP_ACPFSCHED_MIN_FRAC 30
#define MPDCCP_ACPFSCHED_FREQ_MS 1

static struct mpdccp_sched_ops mpdccp_sched_acpf;

// Private data, subflow-specific
struct acpfsched_priv {
	u32 cwnd_frac;
	u32 last_stamp;
};

static struct acpfsched_priv *acpfsched_get_priv(struct sock *sk)
{
	struct my_sock *my_sk = (struct my_sock *)sk->sk_user_data;

	return (struct acpfsched_priv *)&my_sk->sched_priv[0];
}

u32 acpfsched_get_min_rtt(struct sock *sk)
{
	u32 min_rtt = 0;
	int ccid;

	ccid = ccid_get_current_tx_ccid(dccp_sk(sk));

#ifdef CONFIG_IP_DCCP_CCID5
	if (ccid == 5) {
		struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
		min_rtt = hc->min_rtt_us;
	}
#endif

#ifdef CONFIG_IP_DCCP_CCID6
	if (ccid == 6) {
		struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
		min_rtt = hc->min_rtt_us;
	}
#endif

	return min_rtt;
}

u32 acpfsched_get_curr_rtt(struct sock *sk)
{
	u32 curr_rtt = 0;
	int ccid;

	ccid = ccid_get_current_tx_ccid(dccp_sk(sk));

#ifdef CONFIG_IP_DCCP_CCID5
	if (ccid == 5) {
		struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
		curr_rtt = hc->rtt_us;
	}
#endif

#ifdef CONFIG_IP_DCCP_CCID6
	if (ccid == 6) {
		struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
		curr_rtt = hc->rtt_us;
	}
#endif

	return curr_rtt;
}

static void acpfsched_manage_cwnd_frac(struct sock *sk, u32 scale)
{
	int ccid = ccid_get_current_tx_ccid(dccp_sk(sk));

	if (ccid == 5 || ccid == 6) {
		u32 cong_perc;
		u32 min_target;
		u32 target;
		u32 new_frac;
		u32 target_adj;

		u32 min_rtt = acpfsched_get_min_rtt(sk);
		u32 curr_rtt = acpfsched_get_curr_rtt(sk);

		u32 max_frac = MPDCCP_ACPFSCHED_UNIT;
		u32 min_frac =
		    MPDCCP_ACPFSCHED_UNIT * MPDCCP_ACPFSCHED_MIN_FRAC / 100;

		//struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
		struct acpfsched_priv *acpf_priv = acpfsched_get_priv(sk);

		if (min_rtt == 0)
			return;

		min_target =
		    (min_rtt +
		     MPDCCP_ACPFSCHED_MIN_TARGET_US * 100) / min_rtt -
		    100;
		target =
		    min_target >
		    MPDCCP_ACPFSCHED_TARGET ? min_target :
		    MPDCCP_ACPFSCHED_TARGET;

		//mpdccp_pr_debug("Socket %p min_rtt_us %d, srtt_us %d\n", sk, min_rtt, current_rtt);

		cong_perc = curr_rtt > min_rtt ?
		    curr_rtt * 100 / min_rtt - 100 : 0;

		if (cong_perc < target) {
			if (acpf_priv->cwnd_frac < max_frac) {
				target_adj = (target - cong_perc);
				target_adj =
				    target_adj * acpf_priv->cwnd_frac * 10 /
				    min_rtt;
				target_adj = target_adj * scale;

				new_frac = acpf_priv->cwnd_frac + target_adj;
				acpf_priv->cwnd_frac = new_frac < max_frac ?
				    new_frac : max_frac;

				mpdccp_pr_debug("target inc %d, new frac %d\n",
						target_adj,
						acpf_priv->cwnd_frac);
			}
		} else {
			if (acpf_priv->cwnd_frac > min_frac) {
				target_adj =
				    (cong_perc - target) * 100 / (100 +
								  cong_perc);
				target_adj =
				    target_adj * acpf_priv->cwnd_frac * 10 /
				    min_rtt;
				target_adj = target_adj * scale;

				new_frac = acpf_priv->cwnd_frac > target_adj ?
				    acpf_priv->cwnd_frac -
				    target_adj : min_frac;
				acpf_priv->cwnd_frac =
				    new_frac > min_frac ? new_frac : min_frac;

				mpdccp_pr_debug("target dec %d, new frac %d\n",
						target_adj,
						acpf_priv->cwnd_frac);
			}

		}
	}
}

static bool acpfsched_packet_fits_in_cwnd(struct sock *sk)
{
	int ccid;
	unsigned int space;
	unsigned int frac;
	unsigned int min_cwnd;
	struct dccp_sock *dp;
	struct tcp_info info;
	struct tcp_info *infop = &info;

#ifdef CONFIG_IP_DCCP_CCID5
	struct ccid5_hc_tx_sock *hc5;
#endif

	/* From RFC 4341:
	 * The sender MAY send a data packet when pipe < cwnd but
	 * MUST NOT send a data packet when pipe >= cwnd.
	 *
	 * tx_cwnd is the congestion window size in data packets
	 * tx_pipe is the senders' estimate of packets in flight */

	dp = dccp_sk(sk);
	ccid_hc_tx_get_info(dp->dccps_hc_tx_ccid, sk, infop);
	if (infop->tcpi_segs_out >= infop->tcpi_snd_cwnd) {
		mpdccp_pr_debug("Socket %p is congestion limited (hc->tx_pipe = %d,\
				hc->tx_cwnd = %d).\n", sk, infop->tcpi_segs_out,
				infop->tcpi_snd_cwnd);
		return false;
	}

	/* Check if what is already queued in the subflow socket's
	 * send-queue already fills the cwnd before we even have a 
	 * chance to send anything. Shamelessly adopted from TCP,
	 * inspired by qpolicy_simple_full().
	 */
	ccid = ccid_get_current_tx_ccid(dccp_sk(sk));

#ifdef CONFIG_IP_DCCP_CCID5
	/* Do not apply the live CWND fraction if CCID5 is in ProbeRTT */
	if (ccid == 5) {
		hc5 = ccid5_hc_tx_sk(sk);

		if (hc5->mode == 3) {
			mpdccp_pr_debug
			    ("Socket %p is in ProbeRTT, special rules.\n", sk);
			space = infop->tcpi_snd_cwnd - infop->tcpi_segs_out;

			if (sk->sk_write_queue.qlen >= space) {
				mpdccp_pr_debug("Socket %p has a full cwnd.\n",
						sk);
				return false;
			}

			return true;
		}
	}
#endif

	// Remaining free space in the "live" congestion window
	min_cwnd = 1;
	frac =
	    DIV_ROUND_UP(infop->tcpi_snd_cwnd *
			 acpfsched_get_priv(sk)->cwnd_frac,
			 MPDCCP_ACPFSCHED_UNIT);
	frac = max(min_cwnd, frac);
	space = frac > infop->tcpi_segs_out ? frac - infop->tcpi_segs_out : 0;

	mpdccp_pr_debug("Socket %p has space %d.\n", sk, space);

	if (sk->sk_write_queue.qlen >= space) {
		mpdccp_pr_debug("Socket %p has a full cwnd.\n", sk);
		return false;
	}

	return true;
}

/* For debugging */
static void log_cwnd(struct mpdccp_cb *mpcb, struct sock *sk)
{
	struct dccp_sock *dp;
	struct tcp_info info;
	struct tcp_info *infop = &info;
	struct mpdccp_link_info *link;

	dp = dccp_sk(sk);
	if (dp->dccps_hc_tx_ccid == NULL)
		return;

	ccid_hc_tx_get_info(dp->dccps_hc_tx_ccid, sk, infop);

	link = mpdccp_ctrl_getlink(sk);
	if (link) {
		mpdccp_pr_debug
		    ("sock %p name %s cwnd %d frac %d in_flight %d srtt %d prio %d subflow_queue %d meta_queue %d\n",
		     sk, link->name, infop->tcpi_snd_cwnd,
		     acpfsched_get_priv(sk)->cwnd_frac * 100 /
		     MPDCCP_ACPFSCHED_UNIT, infop->tcpi_segs_out,
		     jiffies_to_msecs(infop->tcpi_rtt >> 3), link->mpdccp_prio,
		     sk->sk_write_queue.qlen,
		     mpcb->meta_sk->sk_write_queue.qlen);
	}
	mpdccp_link_put(link);
}

static void update_frac(struct sock *sk)
{
	u32 elapsed;
	u32 now = acpfsched_jiffies32;
	struct acpfsched_priv *acpf_priv = acpfsched_get_priv(sk);
	elapsed = jiffies_to_msecs(now - acpf_priv->last_stamp);

	if (elapsed >= MPDCCP_ACPFSCHED_FREQ_MS) {
		acpf_priv->last_stamp = acpfsched_jiffies32;

		acpfsched_manage_cwnd_frac(sk, elapsed);

		mpdccp_pr_debug("sock %p new_stamp %u, delta %u\n", sk,
				acpf_priv->last_stamp, elapsed);
	}
}

static bool is_over_util(struct sock *sk)
{
	int ccid = ccid_get_current_tx_ccid(dccp_sk(sk));

	if (ccid == 5) {
		u32 cong_perc;
		u32 min_target;
		u32 target;

		struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
		if (hc->min_rtt_us == 0)
			return false;

		min_target =
		    (hc->min_rtt_us +
		     MPDCCP_ACPFSCHED_MIN_TARGET_US * 100) / hc->min_rtt_us -
		    100;
		target =
		    min_target >
		    MPDCCP_ACPFSCHED_TARGET ? min_target :
		    MPDCCP_ACPFSCHED_TARGET;

		//mpdccp_pr_debug("Socket %p min_rtt_us %d, srtt_us %d\n", sk, min_rtt, current_rtt);

		cong_perc = hc->rtt_us > hc->min_rtt_us ?
		    hc->rtt_us * 100 / hc->min_rtt_us - 100 : 0;

		if (cong_perc < target)
			return true;

		return false;
	}

	return true;
}

struct sock *schedule_acpf(struct mpdccp_cb *mpcb)
{
	struct sock *sk;
	struct sock *best_sk = NULL;
	struct dccp_sock *dp;
	struct tcp_info info;
	struct tcp_info *infop = &info;
	__u8 priority;
	struct mpdccp_link_info *link;
	__u8 min_prio = 1;

	/* Initialise to arbitrarily high (max) value */
	u32 min_srtt = ~((u32) 0);

	mpdccp_for_each_sk(mpcb, sk) {
		/* Skip sockets that are still in handshake or where
		 * cwnd is full */
		if (!mpdccp_sk_can_send(sk)) {
			//mpdccp_pr_debug("Flow %p not established. Continuing...\n", sk);
			continue;
		}

		dp = dccp_sk(sk);
		if (dp->dccps_hc_tx_ccid == NULL) {
			continue;
		}

		if (!acpfsched_packet_fits_in_cwnd(sk)) {
			//mpdccp_pr_debug("Packet does not fit in cwnd of %p. Continuing...\n", sk);
			continue;
		}

		link = mpdccp_ctrl_getlink(sk);
		if (link) {
			priority = link->mpdccp_prio;
			//mpdccp_pr_debug("socket %p has link prio %d (link %d)", sk, priority, link->id);
		} else {
			priority = 3;
			//mpdccp_pr_debug ("cannot get link for sk %p - use prio 0\n", sk);
		}
		mpdccp_link_put(link);

		ccid_hc_tx_get_info(dp->dccps_hc_tx_ccid, sk, infop);
		if (priority > min_prio ||
		    (priority == min_prio && infop->tcpi_rtt < min_srtt)) {
			min_prio = priority;
			min_srtt = infop->tcpi_rtt;
			best_sk = sk;
		}
	}

	return best_sk;
}

struct sock *schedule_srtt(struct mpdccp_cb *mpcb)
{
	struct sock *sk;
	struct sock *best_sk = NULL;
	struct dccp_sock *dp;
	struct tcp_info info;
	struct tcp_info *infop = &info;

	/* Initialise to arbitrarily high (max) value */
	//__u8                          min_prio = ~((__u8)0);
	u32 min_srtt = ~((u32) 0);

	mpdccp_for_each_sk(mpcb, sk) {
		/* Skip sockets that are still in handshake or where
		 * cwnd is full */
		if (!mpdccp_sk_can_send(sk)) {
			//mpdccp_pr_debug("Flow %p not established. Continuing...\n", sk);
			continue;
		}

		dp = dccp_sk(sk);
		if (dp->dccps_hc_tx_ccid == NULL) {
			continue;
		}

		if (!mpdccp_packet_fits_in_cwnd(sk)) {
			mpdccp_pr_debug
			    ("Packet does not fit in cwnd of %p. Continuing...\n",
			     sk);
			continue;
		}

		ccid_hc_tx_get_info(dp->dccps_hc_tx_ccid, sk, infop);
		if (infop->tcpi_rtt < min_srtt) {
			min_srtt = infop->tcpi_rtt;
			best_sk = sk;
		}
	}

	return best_sk;
}

/* This function returns a pointer that is part of a RCU protected
 * structure. It must be called with the rcu_read_lock() held. */
struct sock *mpdccp_acpfsched(struct mpdccp_cb *mpcb)
{
	struct sock *sk;
	struct sock *best_sk = NULL;
	bool over_util = true;

	/* if there is only 1 subflow, we bypass scheduling */
	if (mpcb->cnt_subflows == 1) {
		return mpdccp_return_single_flow(mpcb);
	}

	rcu_read_lock();

	// Determine ACPF mode
	mpdccp_for_each_sk(mpcb, sk) {
		log_cwnd(mpcb, sk);

		if (!is_over_util(sk)) {
			over_util = false;
			break;
		}
	}

	if (!over_util) {
		best_sk = schedule_acpf(mpcb);
	} else {
		best_sk = schedule_srtt(mpcb);
	}

	// Update live cwnd frac
	mpdccp_for_each_sk(mpcb, sk) {
		update_frac(sk);
	}

	rcu_read_unlock();

	if (best_sk)
		mpdccp_pr_debug("ACPF returned socket %p\n", best_sk);
	return best_sk;
}

static int link_event(struct notifier_block *, unsigned long, void *);
static void acpfsched_reinit(struct mpdccp_link_info *);
static struct notifier_block mpdccp_link_notifier = {
	.notifier_call = link_event,
};

static void acpfsched_init(void)
{
	register_mpdccp_link_notifier(&mpdccp_link_notifier);
}

static void acpfsched_init_subflow(struct sock *sk)
{
	struct mpdccp_link_info *link;
	struct acpfsched_priv *acpf_priv;
	u32 init_frac;

	if (!sk)
		return;

	rcu_read_lock_bh();
#ifdef CONFIG_IP_MPDCCP_DEBUG

	link = mpdccp_ctrl_getlink(sk);
	if (link) {
		mpdccp_pr_debug("socket(%p) gets prio %d (from link %d (%s))\n",
				sk, link->mpdccp_prio, link->id, link->name);
	} else {
		mpdccp_pr_debug("no link found!!!! - choose 0\n");
	}
	mpdccp_link_put(link);
#endif

	init_frac = MPDCCP_ACPFSCHED_UNIT;
	acpf_priv = acpfsched_get_priv(sk);
	acpf_priv->cwnd_frac = init_frac;
	acpf_priv->last_stamp = acpfsched_jiffies32;

	rcu_read_unlock_bh();
	return;
}

/* Initialize a specific MPDCCP connection */
static void acpfsched_init_conn(struct mpdccp_cb *mpcb)
{
	struct sock *sk;

	if (!mpcb)
		goto err;

	mpdccp_for_each_sk(mpcb, sk) {
		acpfsched_init_subflow(sk);
	}

 err:
	return;
}

static void acpfsched_reinit(struct mpdccp_link_info *linkchg)
{
	struct sock *sk;
	struct mpdccp_cb *mpcb;
	struct mpdccp_link_info *link;

	/* Initial priority value */
	mpdccp_pr_debug("reinit connections\n");
	rcu_read_lock_bh();
	mpdccp_for_each_conn(pconnection_list, mpcb) {
		if (mpcb->sched_ops != &mpdccp_sched_acpf)
			continue;
		mpdccp_for_each_sk(mpcb, sk) {
			if (!linkchg) {
				acpfsched_init_subflow(sk);
				continue;
			}
			link = mpdccp_ctrl_getlink(sk);
			if (link->id == linkchg->id) {
				mpdccp_pr_debug
				    ("socket (%p) got new prio (%d) from link %d (%s)\n",
				     sk, link->mpdccp_prio, link->id,
				     link->name);
			}
			mpdccp_link_put(link);
		}
	}
	rcu_read_unlock_bh();
	return;
}

int link_event(struct notifier_block *nblk, unsigned long event, void *ptr)
{
	struct mpdccp_link_notifier_info *info;
	struct mpdccp_link_info *link;

	info = (struct mpdccp_link_notifier_info *)ptr;
	link = info ? info->link_info : NULL;
	switch (event) {
	case MPDCCP_LINK_CHANGE_PRIO:
		acpfsched_reinit(link);
		break;
	default:
		break;
	}
	return NOTIFY_DONE;
}

static struct mpdccp_sched_ops mpdccp_sched_acpf = {
	.get_subflow = mpdccp_acpfsched,
	.init_conn = acpfsched_init_conn,
	.init_subflow = acpfsched_init_subflow,
	.name = "acpf",
	.owner = THIS_MODULE,
};

static int __init mpdccp_acpfsched_register(void)
{
	if (mpdccp_register_scheduler(&mpdccp_sched_acpf))
		goto err;

	acpfsched_init();
	return 0;

 err:
	return -1;
}

static void mpdccp_acpfsched_unregister(void)
{
	mpdccp_unregister_scheduler(&mpdccp_sched_acpf);
}

module_init(mpdccp_acpfsched_register);
module_exit(mpdccp_acpfsched_unregister);

MODULE_AUTHOR("Alexander Rabitsch");
MODULE_LICENSE("Proprietary");
MODULE_DESCRIPTION("Multipath DCCP Adaptive Cheapest Path First Scheduler");
MODULE_VERSION(MPDCCP_VERSION);

