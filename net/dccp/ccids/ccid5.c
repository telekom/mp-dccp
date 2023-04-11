/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 * Copyright (C) 2019 by Nathalie Romo, Deutsche Telekom AG
 *
 * BBR algorithm for the DCCP protocol.
 *
 * The code in this file is derived from net/ipv4/tcp_bbr.c,
 * net/ipv4/tcp_rate.c and net/dccp/ccids/ccid2.c. ccid2 Derived code is
 * Copyright (C) the original authors Andrea Bittau and Arnaldo Carvalho
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


#include <linux/slab.h>
#include "../feat.h"
#include "ccid5.h"

#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define BBR_SCALE 8	/* scaling factor for fractions in BBR (e.g. gains)  ????*/
#define BBR_UNIT (1 << BBR_SCALE)

static const int bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1; // lo del logaritmo base 2
static const int bbr_drain_gain = BBR_UNIT * 1000 / 2885;
static const int bbr_cwnd_gain  = BBR_UNIT * 2;

static const int bbr_pacing_gain[] = {
	BBR_UNIT * 5 / 4,	/* probe for more available bw */
	BBR_UNIT * 3 / 4,	/* drain queue and/or yield bw to other flows */
	BBR_UNIT, BBR_UNIT, BBR_UNIT,	/* cruise at 1.0*bw to utilize pipe, */
	BBR_UNIT, BBR_UNIT, BBR_UNIT	/* without creating excess queue... */
};

static const u32 bbr_cycle_rand = 7;

#define CYCLE_LEN	8	/* number of phases in a pacing gain cycle */
/* Window length of min_rtt filter (in sec): */
static const u32 bbr_min_rtt_win_sec = 10;
static const u32 bbr_probe_rtt_mode_ms = 200;
static const int bbr_min_tso_rate = 1200000;
static const u32 bbr_cwnd_min_target = 4;

/* Window length of bw filter (in rounds): */
static const int bbr_bw_rtts = CYCLE_LEN + 2;

static const u32 bbr_full_bw_thresh = BBR_UNIT * 5 / 4;
static const u32 bbr_full_bw_cnt = 3;

/* "long-term" ("LT") bandwidth estimator parameters... */
/* The minimum number of rounds in an LT bw sampling interval: */
static const u32 bbr_lt_intvl_min_rtts = 4;
/* If lost/delivered ratio > 20%, interval is "lossy" and we may be policed: */
static const u32 bbr_lt_loss_thresh = 50;
/* If 2 intervals have a bw ratio <= 1/8, their bw is "consistent": */
static const u32 bbr_lt_bw_ratio = BBR_UNIT / 8;
/* If 2 intervals have a bw diff <= 4 Kbit/sec their bw is "consistent": */
static const u32 bbr_lt_bw_diff = 4000 / 8;
/* If we estimate we're policed, use lt_bw for this many round trips: */
static const u32 bbr_lt_bw_max_rtts = 48;

enum bbr_mode {
	BBR_STARTUP,	/* ramp up sending rate rapidly to fill pipe */
	BBR_DRAIN,	/* drain any queue created during startup */
	BBR_PROBE_BW,	/* discover, share bw: pace around estimated bw */
	BBR_PROBE_RTT,	/* cut cwnd to min to probe min_rtt */
};


enum dccp_ca_state {
	DCCP_CA_Open = 0,
	DCCP_CA_Disorder = 1,
	DCCP_CA_CWR = 2,
	DCCP_CA_Recovery = 3,
	DCCP_CA_Loss = 4
};
#ifdef CONFIG_IP_DCCP_CCID2_DEBUG
static bool ccid5_debug;
#define ccid5_pr_debug(format, a...)	DCCP_PR_DEBUG(ccid5_debug, format, ##a)
#else
#define ccid5_pr_debug(format, a...)
#endif

/* Function pointer to either get SRTT or MRTT ...*/
//u32 (*get_delay_val)(struct ccid5_hc_tx_sock *hc) = mrtt_as_delay;
//EXPORT_SYMBOL_GPL(get_delay_val);

static int ccid5_hc_tx_alloc_seq(struct ccid5_hc_tx_sock *hc)
{
	//printk(KERN_INFO "natrm: enter ccid5_hc_tx_alloc_seq");
	struct ccid5_seq *seqp;
	int i;

	/* check if we have space to preserve the pointer to the buffer */
	if (hc->tx_seqbufc >= (sizeof(hc->tx_seqbuf) /
			       sizeof(struct ccid5_seq *)))
		return -ENOMEM;

	/* allocate buffer and initialize linked list */
	seqp = kmalloc(CCID5_SEQBUF_LEN * sizeof(struct ccid5_seq), gfp_any());
	if (seqp == NULL)
		return -ENOMEM;

	for (i = 0; i < (CCID5_SEQBUF_LEN - 1); i++) {
		seqp[i].ccid5s_next = &seqp[i + 1];
		seqp[i + 1].ccid5s_prev = &seqp[i];
	}
	seqp[CCID5_SEQBUF_LEN - 1].ccid5s_next = seqp;
	seqp->ccid5s_prev = &seqp[CCID5_SEQBUF_LEN - 1];

	/* This is the first allocation.  Initiate the head and tail.  */
	if (hc->tx_seqbufc == 0)
		hc->tx_seqh = hc->tx_seqt = seqp;
	else {
		/* link the existing list with the one we just created */
		hc->tx_seqh->ccid5s_next = seqp;
		seqp->ccid5s_prev = hc->tx_seqh;

		hc->tx_seqt->ccid5s_prev = &seqp[CCID5_SEQBUF_LEN - 1];
		seqp[CCID5_SEQBUF_LEN - 1].ccid5s_next = hc->tx_seqt;
	}

	/* store the original pointer to the buffer so we can free it */
	hc->tx_seqbuf[hc->tx_seqbufc] = seqp;
	hc->tx_seqbufc++;

	return 0;
}


static void ccid5_change_l_ack_ratio(struct sock *sk, u32 val)
{
	u32 max_ratio = DIV_ROUND_UP(ccid5_hc_tx_sk(sk)->tx_cwnd, 2);

	/*
	 * Ensure that Ack Ratio does not exceed ceil(cwnd/2), which is (2) from
	 * RFC 4341, 6.1.2. We ignore the statement that Ack Ratio 2 is always
	 * acceptable since this causes starvation/deadlock whenever cwnd < 2.
	 * The same problem arises when Ack Ratio is 0 (ie. Ack Ratio disabled).
	 */
	if (val == 0 || val > max_ratio) {
		DCCP_WARN("Limiting Ack Ratio (%u) to %u\n", val, max_ratio);
		val = max_ratio;
	}
	//printk(KERN_INFO "natrm: ccid5 change ack_ratio %lu max %lu", val, max_ratio);
	dccp_feat_signal_nn_change(sk, DCCPF_ACK_RATIO,
				   min_t(u32, val, DCCPF_ACK_RATIO_MAX));
}

static void ccid5_check_l_ack_ratio(struct sock *sk)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);

	/*
	 * After a loss, idle period, application limited period, or RTO we
	 * need to check that the ack ratio is still less than the congestion
	 * window. Otherwise, we will send an entire congestion window of
	 * packets and got no response because we haven't sent ack ratio
	 * packets yet.
	 * If the ack ratio does need to be reduced, we reduce it to half of
	 * the congestion window (or 1 if that's zero) instead of to the
	 * congestion window. This prevents problems if one ack is lost.
	 */

	if (dccp_feat_nn_get(sk, DCCPF_ACK_RATIO) > hc->tx_cwnd)
		ccid5_change_l_ack_ratio(sk, hc->tx_cwnd/2 ? : 1U);
}

static void ccid5_change_l_seq_window(struct sock *sk, u64 val)
{
	dccp_feat_signal_nn_change(sk, DCCPF_SEQUENCE_WINDOW,
				   clamp_val(val, DCCPF_SEQ_WMIN,
						  DCCPF_SEQ_WMAX));
}
static void dccp_tasklet_schedule(struct sock *sk)
{
	struct tasklet_struct *t = &dccp_sk(sk)->dccps_xmitlet;

	if (!test_and_set_bit(TASKLET_STATE_SCHED, &t->state)) {
		sock_hold(sk);
		__tasklet_schedule(t);
	}
}

/*
 *	Congestion window validation (RFC 2861).
 */

static bool ccid5_do_cwv = true;
module_param(ccid5_do_cwv, bool, 0644);
MODULE_PARM_DESC(ccid5_do_cwv, "Perform RFC2861 Congestion Window Validation");

/**
 * ccid2_update_used_window  -  Track how much of cwnd is actually used
 * This is done in addition to CWV. The sender needs to have an idea of how many
 * packets may be in flight, to set the local Sequence Window value accordingly
 * (RFC 4340, 7.5.2). The CWV mechanism is exploited to keep track of the
 * maximum-used window. We use an EWMA low-pass filter to filter out noise.
 */
static void ccid5_update_used_window(struct ccid5_hc_tx_sock *hc, u32 new_wnd)
{
	hc->tx_expected_wnd = (3 * hc->tx_expected_wnd + new_wnd) / 4;
}

/* This borrows the code of tcp_cwnd_application_limited() */
static void ccid5_cwnd_application_limited(struct sock *sk, const u32 now)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	/* don't reduce cwnd below the initial window (IW) */
	u32 init_win = rfc3390_bytes_to_packets(dccp_sk(sk)->dccps_mss_cache),
	    win_used = max(hc->tx_cwnd_used, init_win);

	if (win_used < hc->tx_cwnd) {
		hc->tx_ssthresh = max(hc->tx_ssthresh,
				     (hc->tx_cwnd >> 1) + (hc->tx_cwnd >> 2));
		//hc->tx_cwnd = (hc->tx_cwnd + win_used) >> 1;
		//dccp_pr_debug("%s: tx_cwnd set to %d for sk %p", __func__, hc->tx_cwnd, sk);
	}
	hc->tx_cwnd_used  = 0;
	hc->tx_cwnd_stamp = now;

	ccid5_check_l_ack_ratio(sk);
}

/* This borrows the code of tcp_cwnd_restart() */
static void ccid5_cwnd_restart(struct sock *sk, const u32 now)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	u32 cwnd = hc->tx_cwnd, restart_cwnd,
	    iwnd = rfc3390_bytes_to_packets(dccp_sk(sk)->dccps_mss_cache);

	hc->tx_ssthresh = max(hc->tx_ssthresh, (cwnd >> 1) + (cwnd >> 2));

	/* don't reduce cwnd below the initial window (IW) */
	restart_cwnd = min(cwnd, iwnd);
	cwnd >>= (now - hc->tx_lsndtime) / hc->tx_rto;
	//hc->tx_cwnd = max(cwnd, restart_cwnd);

	hc->tx_cwnd_stamp = now;
	hc->tx_cwnd_used  = 0;

	ccid5_check_l_ack_ratio(sk);
}

static void ccid5_hc_tx_packet_sent(struct sock *sk, unsigned int len)
{
	struct dccp_sock *dp = dccp_sk(sk);
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	const u32 now = ccid5_jiffies32;
	struct ccid5_seq *next;
	hc->bytes_sent += len;
	if (hc->curr_ca_state == DCCP_CA_Loss)
		hc->curr_ca_state = DCCP_CA_Open; 

	/* slow-start after idle periods (RFC 2581, RFC 2861) */
	if (ccid5_do_cwv && !hc->tx_pipe &&
	    (s32)(now - hc->tx_lsndtime) >= hc->tx_rto)
		ccid5_cwnd_restart(sk, now);

	hc->tx_lsndtime = now;

	hc->tx_seqh->sent_mstamp = tcp_clock_us();
	if (!hc->tx_pipe) {
		hc->first_tx_mstamp  = hc->tx_seqh->sent_mstamp;
		hc->delivered_mstamp = hc->first_tx_mstamp;
	}


	hc->tx_seqh->delivered    = hc->delivered;
	hc->tx_seqh->ccid5s_seq   = dp->dccps_gss;
	hc->tx_seqh->ccid5s_acked = 0;
	hc->tx_seqh->ccid5s_sent  = now;
	hc->tx_seqh->first_tx_mstamp   = hc->first_tx_mstamp;
	hc->tx_seqh->delivered_mstamp  = hc->delivered_mstamp;
	hc->tx_seqh->is_app_limited = hc->app_limited ? 1 : 0;

	next = hc->tx_seqh->ccid5s_next;
	/* check if we need to alloc more space */
	if (next == hc->tx_seqt) {
		if (ccid5_hc_tx_alloc_seq(hc)) {
			DCCP_CRIT("packet history - out of memory!");
			/* FIXME: find a more graceful way to bail out */
			return;
		}
		next = hc->tx_seqh->ccid5s_next;
		BUG_ON(next == hc->tx_seqt);
	}
	hc->tx_seqh = next;

	hc->tx_pipe  += 1;

	/* see whether cwnd was fully used (RFC 2861), update expected window */
	if (ccid5_cwnd_network_limited(hc)) {
		ccid5_update_used_window(hc, hc->tx_cwnd);
		hc->tx_cwnd_used  = 0;
		hc->tx_cwnd_stamp = now;
	} else {
		if (hc->tx_pipe > hc->tx_cwnd_used)
			hc->tx_cwnd_used = hc->tx_pipe;

		ccid5_update_used_window(hc, hc->tx_cwnd_used);

		if (ccid5_do_cwv && (s32)(now - hc->tx_cwnd_stamp) >= hc->tx_rto)
			ccid5_cwnd_application_limited(sk, now);
	}

	ccid5_pr_debug("sk=%p cwnd=%d pipe=%d\n", sk, hc->tx_cwnd, hc->tx_pipe);

	/*
	 * FIXME: The code below is broken and the variables have been removed
	 * from the socket struct. The `ackloss' variable was always set to 0,
	 * and with arsent there are several problems:
	 *  (i) it doesn't just count the number of Acks, but all sent packets;
	 *  (ii) it is expressed in # of packets, not # of windows, so the
	 *  comparison below uses the wrong formula: Appendix A of RFC 4341
	 *  comes up with the number K = cwnd / (R^2 - R) of consecutive windows
	 *  of data with no lost or marked Ack packets. If arsent were the # of
	 *  consecutive Acks received without loss, then Ack Ratio needs to be
	 *  decreased by 1 when
	 *	      arsent >=  K * cwnd / R  =  cwnd^2 / (R^3 - R^2)
	 *  where cwnd / R is the number of Acks received per window of data
	 *  (cf. RFC 4341, App. A). The problems are that
	 *  - arsent counts other packets as well;
	 *  - the comparison uses a formula different from RFC 4341;
	 *  - computing a cubic/quadratic equation each time is too complicated.
	 *  Hence a different algorithm is needed.
	 */
#if 0
	/* Ack Ratio.  Need to maintain a concept of how many windows we sent */
	hc->tx_arsent++;
	/* We had an ack loss in this window... */
	if (hc->tx_ackloss) {
		if (hc->tx_arsent >= hc->tx_cwnd) {
			hc->tx_arsent  = 0;
			hc->tx_ackloss = 0;
		}
	} else {
		/* No acks lost up to now... */
		/* decrease ack ratio if enough packets were sent */
		if (dp->dccps_l_ack_ratio > 1) {
			/* XXX don't calculate denominator each time */
			int denom = dp->dccps_l_ack_ratio * dp->dccps_l_ack_ratio -
				    dp->dccps_l_ack_ratio;

			denom = hc->tx_cwnd * hc->tx_cwnd / denom;

			if (hc->tx_arsent >= denom) {
				ccid2_change_l_ack_ratio(sk, dp->dccps_l_ack_ratio - 1);
				hc->tx_arsent = 0;
			}
		} else {
			/* we can't increase ack ratio further [1] */
			hc->tx_arsent = 0; /* or maybe set it to cwnd*/
		}
	}
#endif

	sk_reset_timer(sk, &hc->tx_rtotimer, jiffies + hc->tx_rto);

}

/**
 * uses the same code from ccid2_rtt_estimator
 */
static void ccid5_rtt_estimator(struct sock *sk, const long mrtt)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	long m = mrtt ? : 1;

	hc->tx_mrtt = mrtt;
	hc->tx_last_ack_recv = ccid5_jiffies32;

	if (hc->tx_srtt == 0) {
		/* First measurement m */
		hc->tx_srtt = m << 3;
		hc->tx_mdev = m << 1;

		hc->tx_mdev_max = max(hc->tx_mdev, tcp_rto_min(sk));
		hc->tx_rttvar   = hc->tx_mdev_max;

		hc->tx_rtt_seq  = dccp_sk(sk)->dccps_gss;
	} else {
		/* Update scaled SRTT as SRTT += 1/8 * (m - SRTT) */
		m -= (hc->tx_srtt >> 3);
		hc->tx_srtt += m;

		/* Similarly, update scaled mdev with regard to |m| */
		if (m < 0) {
			m = -m;
			m -= (hc->tx_mdev >> 2);
			/*
			 * This neutralises RTO increase when RTT < SRTT - mdev
			 * (see P. Sarolahti, A. Kuznetsov,"Congestion Control
			 * in Linux TCP", USENIX 2002, pp. 49-62).
			 */
			if (m > 0)
				m >>= 3;
		} else {
			m -= (hc->tx_mdev >> 2);
		}
		hc->tx_mdev += m;

		if (hc->tx_mdev > hc->tx_mdev_max) {
			hc->tx_mdev_max = hc->tx_mdev;
			if (hc->tx_mdev_max > hc->tx_rttvar)
				hc->tx_rttvar = hc->tx_mdev_max;
		}

		/*
		 * Decay RTTVAR at most once per flight, exploiting that
		 *  1) pipe <= cwnd <= Sequence_Window = W  (RFC 4340, 7.5.2)
		 *  2) AWL = GSS-W+1 <= GAR <= GSS          (RFC 4340, 7.5.1)
		 * GAR is a useful bound for FlightSize = pipe.
		 * AWL is probably too low here, as it over-estimates pipe.
		 */
		if (after48(dccp_sk(sk)->dccps_gar, hc->tx_rtt_seq)) {
			if (hc->tx_mdev_max < hc->tx_rttvar)
				hc->tx_rttvar -= (hc->tx_rttvar -
						  hc->tx_mdev_max) >> 2;
			hc->tx_rtt_seq  = dccp_sk(sk)->dccps_gss;
			hc->tx_mdev_max = tcp_rto_min(sk);
		}
	}

	/*
	 * Set RTO from SRTT and RTTVAR
	 * As in TCP, 4 * RTTVAR >= TCP_RTO_MIN, giving a minimum RTO of 200 ms.
	 * This agrees with RFC 4341, 5:
	 *	"Because DCCP does not retransmit data, DCCP does not require
	 *	 TCP's recommended minimum timeout of one second".
	 */
	hc->tx_rto = (hc->tx_srtt >> 3) + hc->tx_rttvar;

	if (hc->tx_rto > DCCP_RTO_MAX)
		hc->tx_rto = DCCP_RTO_MAX;
}

/************************************************************/
/* BELLOW THE FUNCTIONS WHICH IN TCP ARE PART OF tcp_rate.c */
/************************************************************/

void dccp_rate_skb_delivered(struct sock *sk, struct ccid5_seq *acked,
			    struct rate_sample_ccid5 *rs)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	if (!acked->delivered_mstamp)
		return;

	if (!rs->prior_delivered ||
	    after(acked->delivered, rs->prior_delivered)) { 
		rs->prior_delivered  = acked->delivered;
		rs->prior_mstamp     = acked->delivered_mstamp;
		rs->is_app_limited   = acked->is_app_limited;

		/* Find the duration of the "send phase" of this window: */
		rs->interval_us      = tcp_stamp_us_delta(
						acked->sent_mstamp,
						acked->first_tx_mstamp);
		/* Record send time of most recently ACKed packet: */
		hc->first_tx_mstamp  = acked->sent_mstamp;
		}
}

void dccp_rate_gen(struct sock *sk, u32 delivered, u32 lost, u64 now, struct rate_sample_ccid5 *rs)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	s64 ack_us;
	s64 snd_us;	
	
	/* Clear app limited if bubble is acked and gone. */
	if (hc->app_limited && after(hc->delivered, hc->app_limited))
		hc->app_limited = 0;

	if (delivered) 
		hc->delivered_mstamp = now; 
	
	rs->acked_sacked = delivered;	/* freshly ACKed or SACKed */
	rs->losses = lost;		/* freshly marked lost */

	if (!rs->prior_mstamp) {
		rs->delivered = -1;
		rs->interval_us = -1;
		return;
	}

	rs->delivered   = hc->delivered - rs->prior_delivered;

	//// takes maximum between send_us and ack_us
	snd_us = rs->interval_us;				/* send phase */
	ack_us = tcp_stamp_us_delta(now, rs->prior_mstamp);
	rs->interval_us = max(snd_us, ack_us);

}

void dccp_rate_check_app_limited(struct sock *sk, int tsize)
{
	struct dccp_sock *dp = dccp_sk(sk);
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	if (hc->bytes_att - hc->bytes_sent < dp->dccps_mss_cache &&
		sk_wmem_alloc_get(sk) < tsize &&
	    hc->tx_pipe < hc->tx_cwnd) 
		hc->app_limited =
			(hc->delivered + hc->tx_pipe) ? : 1;
}

/*****************************************************/
/*       FUNCTIONS PART OF tcp_rate.c END HERE       */
/*****************************************************/


/*****************************************************/
/*       FUNCTIONS PART OF tcp_bbr.c START HERE       */
/*****************************************************/

static bool bbr_full_bw_reached(const struct sock *sk)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);

	return hc->full_bw_reached;
}

static u32 bbr_max_bw(const struct sock *sk)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	return minmax_get(&hc->bw);
}

/* Return the estimated bandwidth of the path, in pkts/uS << BW_SCALE. */
static u32 bbr_bw(const struct sock *sk)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	return hc->lt_use_bw ? hc->lt_bw : bbr_max_bw(sk);
}


static u64 bbr_rate_bytes_per_sec(struct sock *sk, u64 rate, int gain)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	rate *= icsk->icsk_pmtu_cookie;
	rate *= gain;
	rate >>= BBR_SCALE;
	rate *= USEC_PER_SEC;
	return rate >> BW_SCALE;
}


/* Convert a BBR bw and gain factor to a pacing rate in bytes per second. */
static u32 bbr_bw_to_pacingrate(struct sock *sk, u32 bw, int gain)
{
	u64 rate = bw;

	rate = bbr_rate_bytes_per_sec(sk, rate, gain);
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	return rate;
}

static void bbr_init_pacingrate(struct sock *sk)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	u64 bw;
	u32 rtt_us;
	if (hc->tx_srtt) {
		rtt_us = max(hc->tx_srtt >> 3, 1U); 
		hc->has_seen_rtt = 1; 
	} else {			 /* no RTT sample yet */
		rtt_us = USEC_PER_MSEC;	 /* use nominal default RTT */
	}
	bw = (u64)hc->tx_cwnd * BW_UNIT;
	do_div(bw, rtt_us);
	sk->sk_pacing_rate = bbr_bw_to_pacingrate(sk, bw, bbr_high_gain);
	hc->pr_init = 1;
}

static void bbr_set_pacingrate(struct sock *sk, u32 bw, int gain)
{
	u32 rate = bbr_bw_to_pacingrate(sk, bw, gain);

	if (bbr_full_bw_reached(sk) || rate > sk->sk_pacing_rate)
		sk->sk_pacing_rate = rate;
}

u32 dccp_tso_autosize(const struct sock *sk, unsigned int mss_now,
		     int min_tso_segs)
{
	u32 bytes, segs;

	bytes = min(sk->sk_pacing_rate >> 10,
		    (u32)(sk->sk_gso_max_size - 1 - MAX_DCCP_HEADER));
	segs = max_t(u32, bytes / mss_now, min_tso_segs);

	return segs;
}

static void bbr_set_tso_segs_goal(struct sock *sk)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	struct dccp_sock *dp = dccp_sk(sk);
	u32 min_segs;

	min_segs = sk->sk_pacing_rate < (bbr_min_tso_rate >> 3) ? 1 : 2;
	hc->tso_segs_goal = min(dccp_tso_autosize(sk, dp->dccps_mss_cache, min_segs),
				 0x7FU);
}

static u32 bbr_target_cwnd(struct sock *sk, u32 bw, int gain)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	u32 cwnd;
	u64 w;

	/* If we've never had a valid RTT sample, cap cwnd at the initial
	 * default. This should only happen when the connection is not using TCP
	 * timestamps and has retransmitted all of the SYN/SYNACK/data packets
	 * ACKed so far. In this case, an RTO can cut cwnd to 1, in which
	 * case we need to slow-start up toward something safe: TCP_INIT_CWND.
	 */
	if (unlikely(hc->min_rtt_us == ~0U))	 /* no valid RTT samples yet? */
		return 4;  /* be safe: cap at default initial cwnd*/

	w = (u64)bw * hc->min_rtt_us;

	/* Apply a gain to the given value, then remove the BW_SCALE shift. */
	cwnd = (((w * gain) >> BBR_SCALE) + BW_UNIT - 1) / BW_UNIT;
	

	/* Allow enough full-sized skbs in flight to utilize end systems. */
	//cwnd += 3 * bbr->tso_segs_goal; WHYYYY loggea en tcp
	cwnd += 3 * hc->tso_segs_goal;
	//cwnd += 3;

	/* Reduce delayed ACKs by rounding up cwnd to the next even number. */
	cwnd = (cwnd + 1) & ~1U;

	return cwnd;
}

static bool bbr_set_cwnd_to_recover_or_restore(
	struct sock *sk, const struct rate_sample_ccid5 *rs, u32 acked, u32 *new_cwnd)
{

	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	u8 prev_state = hc->prev_ca_state, state = hc->curr_ca_state;
	u32 cwnd = hc->tx_cwnd;

	/* An ACK for P pkts should release at most 2*P packets. We do this
	 * in two steps. First, here we deduct the number of lost packets.
	 * Then, in bbr_set_cwnd() we slow start up toward the target cwnd.
	 */
	if (rs->losses > 0)
		cwnd = max_t(s32, cwnd - rs->losses, 1);

	if (state == DCCP_CA_Recovery && prev_state != DCCP_CA_Recovery) {
		/* Starting 1st round of Recovery, so do packet conservation. */
		hc->packet_conservation = 1;
		hc->next_rtt_delivered = hc->delivered;  /* start round now */
		/* Cut unused cwnd from app behavior, TSQ, or TSO deferral: */
		cwnd = hc->tx_pipe + acked;
	} else if (prev_state >= DCCP_CA_Recovery && state < DCCP_CA_Recovery) {
		/* Exiting loss recovery; restore cwnd saved before recovery. */
		hc->restore_cwnd = 1;
		hc->packet_conservation = 0;
	}
	hc->prev_ca_state = state;

	/* Restore cwnd after seq_window */
	if (hc->restore_cwnd && !hc->restore_seqwin) {
		/* Restore cwnd after exiting loss recovery or PROBE_RTT. */
		cwnd = max(cwnd, hc->prior_cwnd);
		hc->restore_cwnd = 0;
	}

	if (hc->packet_conservation) {
		*new_cwnd = max(cwnd, hc->tx_pipe + acked);
		return true;	/* yes, using packet conservation */
	}
	*new_cwnd = cwnd;
	return false;
}


static void bbr_set_cwnd(struct sock *sk, const struct rate_sample_ccid5 *rs,
			 u32 acked, u32 bw, int gain)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	struct dccp_sock *dp = dccp_sk(sk);
	int r_seq_used = hc->tx_cwnd / dp->dccps_l_ack_ratio;
	u32 cwnd = 0, target_cwnd = 0;

	if (!acked)
		return;

	if (bbr_set_cwnd_to_recover_or_restore(sk, rs, acked, &cwnd))
		goto done;

	/* If we're below target cwnd, slow start cwnd toward target cwnd. */

	target_cwnd = bbr_target_cwnd(sk, bw, gain);
	if (bbr_full_bw_reached(sk))  /* only cut cwnd if we filled the pipe */
		cwnd = min(cwnd + acked, target_cwnd);
	else if (cwnd < target_cwnd || hc->delivered < 10)
		cwnd = cwnd + acked;
	cwnd = max(cwnd, bbr_cwnd_min_target);

done:
	hc->tx_cwnd=cwnd;
	if (hc->mode == BBR_PROBE_RTT) {  /* drain queue, refresh min_rtt */
		hc->tx_cwnd = min(hc->tx_cwnd, bbr_cwnd_min_target);
		ccid5_change_l_ack_ratio(sk, 1);
		/* Allow extra packet(s) to let ack_ratio=1 option reaching the peer */
		if (dccp_sk(sk)->dccps_l_ack_ratio != 1U) {
			hc->tx_extrapkt = true;
			dccp_tasklet_schedule(sk);
		}
	}

	/* Do not adjust the ack_ratio if we are restoring it or we are in PROBE_RTT mode */
	if (hc->restore_ackrt) {
		ccid5_change_l_ack_ratio(sk, hc->prior_ackrt);
		/* Restore should end when rx has sent confirmation */
		if (hc->prior_ackrt == dp->dccps_l_ack_ratio) hc->restore_ackrt=0;
	}
	else if (hc->mode != BBR_PROBE_RTT) {
		if (r_seq_used * CCID5_WIN_CHANGE_FACTOR >= dp->dccps_r_seq_win)
			ccid5_change_l_ack_ratio(sk, dp->dccps_l_ack_ratio * 2);
		else if (r_seq_used * CCID5_WIN_CHANGE_FACTOR < dp->dccps_r_seq_win/2)
			ccid5_change_l_ack_ratio(sk, dp->dccps_l_ack_ratio / 2 ? : 1U);
	}

	/* Do not adjust the seq_window if we are restoring it */
	if (hc->restore_seqwin) {
		ccid5_change_l_seq_window(sk, hc->prior_seqwin);
		/* HACK: force local seq_win to new value without waiting confirmation */
		dp->dccps_l_seq_win = hc->prior_seqwin;
		dccp_update_gss(sk, dp->dccps_gss);
		hc->restore_seqwin=0;
	}
	else if (hc->tx_cwnd * CCID5_WIN_CHANGE_FACTOR >= dp->dccps_l_seq_win)
		ccid5_change_l_seq_window(sk, dp->dccps_l_seq_win * 2);
	else if (hc->tx_cwnd * CCID5_WIN_CHANGE_FACTOR < dp->dccps_l_seq_win/2)
		ccid5_change_l_seq_window(sk, dp->dccps_l_seq_win / 2);
}


static bool bbr_is_next_cycle_phase(struct sock *sk,
				    const struct rate_sample_ccid5 *rs)
{

	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	bool is_full_length =
		tcp_stamp_us_delta(hc->delivered_mstamp, hc->cycle_mstamp) >
		hc->min_rtt_us;
	u32 inflight, bw, test;

	/* The pacing_gain of 1.0 paces at the estimated bw to try to fully
	 * use the pipe without increasing the queue.
	 */
	if (hc->pacing_gain == BBR_UNIT)
		return is_full_length;		/* just use wall clock time */

	inflight = rs->prior_in_flight;  /* what was in-flight before ACK? */
	bw = bbr_max_bw(sk);

	/* A pacing_gain > 1.0 probes for bw by trying to raise inflight to at
	 * least pacing_gain*BDP; this may take more than min_rtt if min_rtt is
	 * small (e.g. on a LAN). We do not persist if packets are lost, since
	 * a path with small buffers may not hold that much.
	 */
	if (hc->pacing_gain > BBR_UNIT) {
		test=bbr_target_cwnd(sk, bw, hc->pacing_gain);

		return is_full_length && 
			(rs->losses ||  /* perhaps pacing_gain*BDP won't fit */
			 inflight >= test);
	}
			 

	/* A pacing_gain < 1.0 tries to drain extra queue we added if bw
	 * probing didn't find more bw. If inflight falls to match BDP then we
	 * estimate queue is drained; persisting would underutilize the pipe.
	 */
	return is_full_length ||
		inflight <= bbr_target_cwnd(sk, bw, BBR_UNIT);
}

static void bbr_advance_cycle_phase(struct sock *sk)
{
	
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);

	hc->cycle_idx = (hc->cycle_idx + 1) & (CYCLE_LEN - 1);
	hc->cycle_mstamp = hc->delivered_mstamp;
	hc->pacing_gain = bbr_pacing_gain[hc->cycle_idx];
}

static void bbr_update_cycle_phase(struct sock *sk,
				   const struct rate_sample_ccid5 *rs)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);

	if (hc->mode == BBR_PROBE_BW && bbr_is_next_cycle_phase(sk, rs))
		bbr_advance_cycle_phase(sk);
}

static void bbr_reset_startup_mode(struct ccid5_hc_tx_sock *hc)
{
	hc->mode = BBR_STARTUP;
	hc->pacing_gain = bbr_high_gain;
	hc->cwnd_gain	 = bbr_high_gain;
}

static void bbr_reset_probe_bw_mode(struct sock *sk)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	hc->mode = BBR_PROBE_BW;
	hc->pacing_gain = BBR_UNIT;
	hc->cwnd_gain = bbr_cwnd_gain;
	hc->cycle_idx = CYCLE_LEN - 1 - prandom_u32_max(bbr_cycle_rand);
	bbr_advance_cycle_phase(sk);	/* flip to next phase of gain cycle */
}

static void bbr_reset_mode(struct sock *sk)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	if (!bbr_full_bw_reached(sk))
		bbr_reset_startup_mode(hc);
	else
		bbr_reset_probe_bw_mode(sk);
}

static void bbr_reset_lt_bw_sampling_interval(struct ccid5_hc_tx_sock *hc)
{

	hc->lt_last_stamp = div_u64(hc->delivered_mstamp, USEC_PER_MSEC);
	hc->lt_last_delivered = hc->delivered;
	hc->lt_last_lost = hc->lost;
	hc->lt_rtt_cnt = 0;
}

/* Completely reset long-term bandwidth sampling. */
static void bbr_reset_lt_bw_sampling(struct ccid5_hc_tx_sock *hc)
{

	hc->lt_bw = 0;
	hc->lt_use_bw = 0;
	hc->lt_is_sampling = false;
	bbr_reset_lt_bw_sampling_interval(hc);
}

/* Long-term bw sampling interval is done. Estimate whether we're policed. */
static void bbr_lt_bw_interval_done(struct sock *sk, u32 bw)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	u32 diff;

	if (hc->lt_bw) {  /* do we have bw from a previous interval? */
		/* Is new bw close to the lt_bw from the previous interval? */
		diff = abs(bw - hc->lt_bw);
		if ((diff * BBR_UNIT <= bbr_lt_bw_ratio * hc->lt_bw) ||
		    (bbr_rate_bytes_per_sec(sk, diff, BBR_UNIT) <=
		     bbr_lt_bw_diff)) {
			/* All criteria are met; estimate we're policed. */
			hc->lt_bw = (bw + hc->lt_bw) >> 1;  /* avg 2 intvls */
			hc->lt_use_bw = 1;
			hc->pacing_gain = BBR_UNIT;  /* try to avoid drops */
			hc->lt_rtt_cnt = 0;
			return;
		}
	}
	hc->lt_bw = bw;
	bbr_reset_lt_bw_sampling_interval(hc);
}

static void bbr_lt_bw_sampling(struct sock *sk, const struct rate_sample_ccid5 *rs)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	u32 lost, delivered;
	u64 bw;
	s32 t;

	if (hc->lt_use_bw) {	/* already using long-term rate, lt_bw? */
		if (hc->mode == BBR_PROBE_BW && hc->round_start &&
		    ++hc->lt_rtt_cnt >= bbr_lt_bw_max_rtts) {
			bbr_reset_lt_bw_sampling(hc);    /* stop using lt_bw */
			bbr_reset_probe_bw_mode(sk);  /* restart gain cycling */
		}
		return;
	}

	/* Wait for the first loss before sampling, to let the policer exhaust
	 * its tokens and estimate the steady-state rate allowed by the policer.
	 * Starting samples earlier includes bursts that over-estimate the bw.
	 */
	if (!hc->lt_is_sampling) {
		if (!rs->losses)
			return;
		bbr_reset_lt_bw_sampling_interval(hc);
		hc->lt_is_sampling = true;
	}

	/* To avoid underestimates, reset sampling if we run out of data. */
	if (rs->is_app_limited) {
		bbr_reset_lt_bw_sampling(hc);
		return;
	}

	if (hc->round_start)
		hc->lt_rtt_cnt++;	/* count round trips in this interval */
	if (hc->lt_rtt_cnt < bbr_lt_intvl_min_rtts)
		return;		/* sampling interval needs to be longer */
	if (hc->lt_rtt_cnt > 4 * bbr_lt_intvl_min_rtts) {
		bbr_reset_lt_bw_sampling(hc);  /* interval is too long */
		return;
	}

	/* End sampling interval when a packet is lost, so we estimate the
	 * policer tokens were exhausted. Stopping the sampling before the
	 * tokens are exhausted under-estimates the policed rate.
	 */
	if (!rs->losses)
		return;

	/* Calculate packets lost and delivered in sampling interval. */
	lost = hc->lost - hc->lt_last_lost;
	delivered = hc->delivered - hc->lt_last_delivered;
	/* Is loss rate (lost/delivered) >= lt_loss_thresh? If not, wait. */
	if (!delivered || (lost << BBR_SCALE) < bbr_lt_loss_thresh * delivered)
		return;

	/* Find average delivery rate in this sampling interval. */
	t = (s32)(hc->delivered_mstamp - hc->lt_last_stamp);
	if (t < 1)
		return;		/* interval is less than one jiffy, so wait */
	/* Interval long enough for jiffies_to_usecs() to return a bogus 0? */
	if (t < 1) {
		bbr_reset_lt_bw_sampling(hc);  /* interval too long; reset */
		return;
	}
	bw = (u64)delivered * BW_UNIT;
	do_div(bw, t);
	bbr_lt_bw_interval_done(sk, bw);
}

static void bbr_update_btl_bw(struct sock *sk, const struct rate_sample_ccid5 *rs)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	u64 bw;

	hc->round_start = 0;
	if (rs->delivered < 0 || rs->interval_us <= 0)
		return; /* Not a valid observation */

	/* See if we've reached the next RTT */
	if (!before(rs->prior_delivered, hc->next_rtt_delivered)) {
		hc->next_rtt_delivered = hc->delivered;
		hc->rtt_cnt++;
		hc->round_start = 1;
		hc->packet_conservation = 0;
	}

	bbr_lt_bw_sampling(sk, rs);


	bw = (u64)rs->delivered * BW_UNIT;
	do_div(bw, rs->interval_us);
	/* Don't include bw samples during PROBE_RTT and cwnd/ackrt/seqwin recovery */
	if ((!rs->is_app_limited && !hc->restore_cwnd && !hc->restore_seqwin && !hc->restore_ackrt)
		|| bw >= bbr_max_bw(sk)) {
		/* Incorporate new sample into our max bw filter. */
		minmax_running_max(&hc->bw, bbr_bw_rtts, hc->rtt_cnt, bw); 
	}
}

static void bbr_save_cwnd(struct sock *sk)
{

	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	struct dccp_sock *dp = dccp_sk(sk);

	if (hc->prev_ca_state < DCCP_CA_Recovery && hc->mode != BBR_PROBE_RTT)
		hc->prior_cwnd = hc->tx_cwnd;  /* this cwnd is good enough */
	else  /* loss recovery or BBR_PROBE_RTT have temporarily cut cwnd */
		hc->prior_cwnd = max(hc->prior_cwnd, hc->tx_cwnd);

	/* Save ack_ratio and seq_window as well */
	hc->prior_ackrt = dp->dccps_l_ack_ratio;
	hc->prior_seqwin = dp->dccps_l_seq_win;
}

static void bbr_check_full_bw_reached(struct sock *sk,
				      const struct rate_sample_ccid5 *rs)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	u32 bw_thresh;
	if (bbr_full_bw_reached(sk) || !hc->round_start || rs->is_app_limited)
		return;

	bw_thresh = (u64)hc->full_bw * bbr_full_bw_thresh >> BBR_SCALE;
	if (bbr_max_bw(sk) >= bw_thresh) {
		hc->full_bw = bbr_max_bw(sk);
		hc->full_bw_cnt = 0;
		return;
	}
	// if there is no significant growth increment the count, after 3 counts, it asumes (estimate)
	// the pipe is full
	++hc->full_bw_cnt;
	hc->full_bw_reached = hc->full_bw_cnt >= bbr_full_bw_cnt;
}

static void bbr_check_drain(struct sock *sk, const struct rate_sample_ccid5 *rs)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);

	if (hc->mode == BBR_STARTUP && bbr_full_bw_reached(sk)) {
		hc->mode = BBR_DRAIN;	/* drain queue we created */
		hc->pacing_gain = bbr_drain_gain;	/* pace slow to drain */
		hc->cwnd_gain = BBR_UNIT;	/* don't increase cwnd */
	}	/* fall through to check if in-flight is already small: */
	if (hc->mode == BBR_DRAIN &&
	    hc->tx_pipe <=
	    bbr_target_cwnd(sk, bbr_max_bw(sk), BBR_UNIT))
		bbr_reset_probe_bw_mode(sk);  /* we estimate queue is drained */
}

static void bbr_update_rt_prop(struct sock *sk, const struct rate_sample_ccid5 *rs)
{
	
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	bool filter_expired;
	if (rs->delivered < 0 || rs->interval_us <= 0)
		return; /* Not a valid observation */

	
	filter_expired = false;

	/* Track min RTT seen in the min_rtt_win_sec filter window: */
	filter_expired = after(ccid5_jiffies32,
			       hc->min_rtt_stamp + bbr_min_rtt_win_sec * HZ);

	/* not sure if the following condition is necessary, maybe because my initializarion is wrong*/
	/* it is necessary ut there's got to be a better way*/

	if (hc->min_rtt_us==0 && rs->rtt_us > 0) {
		hc->min_rtt_us = rs->rtt_us;
		hc->min_rtt_stamp = ccid5_jiffies32;	
		}


	if (rs->rtt_us > 0 &&
	    (rs->rtt_us <= hc->min_rtt_us || filter_expired)) {
		hc->min_rtt_us = rs->rtt_us;
		hc->min_rtt_stamp = ccid5_jiffies32;
		}

	if (rs->rtt_us > 0 &&
		hc->max_rtt_us <= rs->rtt_us){
		hc->max_rtt_us = rs->rtt_us;
		hc->max_rtt_stamp = ccid5_jiffies32;
	}

	//Equivalent to check_probe_rtt
	if (bbr_probe_rtt_mode_ms > 0 && filter_expired &&
	    !hc->idle_restart && hc->mode != BBR_PROBE_RTT) {
		hc->mode = BBR_PROBE_RTT;  /* dip, drain queue */
		hc->pacing_gain = BBR_UNIT;
		hc->cwnd_gain = BBR_UNIT;
		bbr_save_cwnd(sk);  /* note cwnd so we can restore it */
		hc->probe_rtt_done_stamp = 0;
		hc->rtprop_fix=0;
	}

	//Equivalent to enter and handle? probe_rtt
	if (hc->mode == BBR_PROBE_RTT) {
		/* Ignore low rate samples during this mode. WHY ??*/
		hc->app_limited =
			(hc->delivered + hc->tx_pipe) ? : 1;
		/* Maintain min packets in flight for max(200 ms, 1 round). */
		if (!hc->probe_rtt_done_stamp &&
		    hc->tx_pipe <= bbr_cwnd_min_target) {
			hc->probe_rtt_done_stamp = ccid5_jiffies32 +
				msecs_to_jiffies(bbr_probe_rtt_mode_ms);
			hc->probe_rtt_round_done = 0;
			hc->next_rtt_delivered = hc->delivered; 
		} else if (hc->probe_rtt_done_stamp) {
			if (hc->round_start)
				hc->probe_rtt_round_done = 1;
			if (hc->probe_rtt_round_done &&
			    after(ccid5_jiffies32, hc->probe_rtt_done_stamp)) {
				hc->min_rtt_stamp = ccid5_jiffies32;
				hc->restore_cwnd = 1;  /* snap to prior_cwnd */
				hc->restore_ackrt = 1;  /* snap to prior_ackrt */
				hc->restore_seqwin = 1;  /* snap to prior_seqwin */
				bbr_reset_mode(sk);
			}
		}
	}
	hc->idle_restart = 0;
}

static void bbr_set_state(struct sock *sk, u8 new_state)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);

	if (new_state == DCCP_CA_Loss) {
		hc->prev_ca_state = DCCP_CA_Loss;
		hc->full_bw = 0;
		hc->round_start = 1;	/* treat RTO like end of a round */
		//bbr_lt_bw_sampling(sk, &rs);
	}
}

/*****************************************************/
/*       FUNCTIONS PART OF tcp_bbr.c END HERE       */
/*****************************************************/


//static void ccid5_hc_tx_rto_expire(unsigned long data)
static void ccid5_hc_tx_rto_expire(struct timer_list *t)
{
	struct ccid5_hc_tx_sock *hc = from_timer(hc, t, tx_rtotimer);
	struct sock *sk = hc->sk;
	//struct sock *sk = (struct sock *)data;
	//struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	const bool sender_was_blocked = ccid5_cwnd_network_limited(hc);

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		sk_reset_timer(sk, &hc->tx_rtotimer, jiffies + HZ / 5);
		goto out;
	}

	if (sk->sk_state == DCCP_CLOSED)
		goto out;

	/* back-off timer */
	hc->tx_rto <<= 1;
	if (hc->tx_rto > DCCP_RTO_MAX)
		hc->tx_rto = DCCP_RTO_MAX;

	/* adjust pipe, cwnd etc */
	hc->tx_ssthresh = hc->tx_cwnd / 2;
	if (hc->tx_ssthresh < 2)
		hc->tx_ssthresh = 2;
	hc->lost += hc->tx_pipe; // not sure
	hc->tx_cwnd	= 1; // not sure
	hc->tx_pipe	= 0; // not sure
	bbr_set_state(sk, DCCP_CA_Loss);

	/* clear state about stuff we sent */
	hc->tx_seqt = hc->tx_seqh;
	hc->tx_packets_acked = 0;

	/* clear ack ratio state. */
	hc->tx_rpseq    = 0;
	hc->tx_rpdupack = -1;
	ccid5_change_l_ack_ratio(sk, 1);

	/* if we were blocked before, we may now send cwnd=1 packet */
	if (sender_was_blocked)
		dccp_tasklet_schedule(sk);
	/* restart backed-off timer */
	sk_reset_timer(sk, &hc->tx_rtotimer, jiffies + hc->tx_rto);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static int ccid5_hc_tx_send_packet(struct sock *sk, struct sk_buff *skb)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	if (!hc->pr_init) {
		bbr_init_pacingrate(sk);
	}
	
	dccp_rate_check_app_limited(sk, skb->truesize); 
	hc->bytes_att += skb->len;
	if (hc->mode==BBR_PROBE_RTT && hc->probe_rtt_done_stamp &&
		    hc->tx_pipe >= bbr_cwnd_min_target && !hc->rtprop_fix) {
		hc->rtprop_fix=1;
	}

	/* Allow extra packet(s) to be sent during the drain phase */
	if (hc->mode==BBR_PROBE_RTT && hc->tx_extrapkt) {
		hc->tx_extrapkt = false;
		return CCID_PACKET_SEND_AT_ONCE;
	}

	if (ccid5_cwnd_network_limited(hc))
		return CCID_PACKET_WILL_DEQUEUE_LATER;
	return CCID_PACKET_SEND_AT_ONCE;
}


static int ccid5_hc_tx_parse_options(struct sock *sk, u8 packet_type,
				     u8 option, u8 *optval, u8 optlen)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);

	switch (option) {
	case DCCPO_ACK_VECTOR_0:
	case DCCPO_ACK_VECTOR_1:
		return dccp_ackvec_parsed_add(&hc->tx_av_chunks, optval, optlen,
					      option - DCCPO_ACK_VECTOR_0);
	}
	return 0;
}

static void ccid5_hc_tx_packet_recv(struct sock *sk, struct sk_buff *skb)
{
	struct dccp_sock *dp = dccp_sk(sk);
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	const bool sender_was_blocked = ccid5_cwnd_network_limited(hc);
	struct dccp_ackvec_parsed *avp;
	u64 ackno, seqno;
	struct ccid5_seq *seqp;
	int done = 0;
	bool not_rst = 0;
	unsigned int maxincr = 0;
	struct rate_sample_ccid5 rs_i = { .prior_delivered = 0 };
	struct rate_sample_ccid5 *rs = &rs_i;
	u32 bw;
	u32 delivered = hc->delivered;
	u32 lost = hc->lost;
	u64 now_mstamp;
	now_mstamp = tcp_clock_us();
	
	rs->prior_in_flight = hc->tx_pipe;

	/* check reverse path congestion */
	seqno = DCCP_SKB_CB(skb)->dccpd_seq;

	/* XXX this whole "algorithm" is broken.  Need to fix it to keep track
	 * of the seqnos of the dupacks so that rpseq and rpdupack are correct
	 * -sorbo.
	 */
	/* need to bootstrap */
	if (hc->tx_rpdupack == -1) {
		hc->tx_rpdupack = 0;
		hc->tx_rpseq    = seqno;
	} else {
		/* check if packet is consecutive */
		if (dccp_delta_seqno(hc->tx_rpseq, seqno) == 1)
			hc->tx_rpseq = seqno;
		/* it's a later packet */
		else if (after48(seqno, hc->tx_rpseq)) {
			hc->tx_rpdupack++;

			/* check if we got enough dupacks */
			if (hc->tx_rpdupack >= NUMDUPACK) {
				hc->tx_rpdupack = -1; /* XXX lame */
				hc->tx_rpseq    = 0;
#ifdef __CCID5_COPES_GRACEFULLY_WITH_ACK_CONGESTION_CONTROL__
				/*
				 * FIXME: Ack Congestion Control is broken; in
				 * the current state instabilities occurred with
				 * Ack Ratios greater than 1; causing hang-ups
				 * and long RTO timeouts. This needs to be fixed
				 * before opening up dynamic changes. -- gerrit
				 */
				ccid5_change_l_ack_ratio(sk, 2 * dp->dccps_l_ack_ratio);
#endif
			}
		}
	}

	/* check forward path congestion */
	if (dccp_packet_without_ack(skb))
		return;

	/* still didn't send out new data packets */
	if (hc->tx_seqh == hc->tx_seqt)
		goto done;

	ackno = DCCP_SKB_CB(skb)->dccpd_ack_seq;
	if (after48(ackno, hc->tx_high_ack))
		hc->tx_high_ack = ackno;

	seqp = hc->tx_seqt;
	while (before48(seqp->ccid5s_seq, ackno)) {
		seqp = seqp->ccid5s_next;
		if (seqp == hc->tx_seqh) {
			seqp = hc->tx_seqh->ccid5s_prev;
			not_rst = 1;
			break;
		}
	}

	/*
	 * In slow-start, cwnd can increase up to a maximum of Ack Ratio/2
	 * packets per acknowledgement. Rounding up avoids that cwnd is not
	 * advanced when Ack Ratio is 1 and gives a slight edge otherwise.
	 */
	if (hc->tx_cwnd < hc->tx_ssthresh)
		maxincr = DIV_ROUND_UP(dp->dccps_l_ack_ratio, 2);

	/* go through all ack vectors */
	list_for_each_entry(avp, &hc->tx_av_chunks, node) {
		/* go through this ack vector */
		for (; avp->len--; avp->vec++) {
			//printk(KERN_INFO "natrm: en el for que no entiendo avp_len %d", avp->len);
			u64 ackno_end_rl = SUB48(ackno,
						 dccp_ackvec_runlen(avp->vec));
			/* if the seqno we are analyzing is larger than the
			 * current ackno, then move towards the tail of our
			 * seqnos.
			 */
			while (after48(seqp->ccid5s_seq, ackno)) {
				if (seqp == hc->tx_seqt) {
					done = 1;
					break;
				}
				seqp = seqp->ccid5s_prev;
			}
			if (done)
				break;

			/* check all seqnos in the range of the vector
			 * run length
			 */
			while (between48(seqp->ccid5s_seq,ackno_end_rl,ackno)) {
				const u8 state = dccp_ackvec_state(avp->vec);

				/* new packet received or marked */
				if (state != DCCPAV_NOT_RECEIVED &&
				    !seqp->ccid5s_acked) {
					if (state == DCCPAV_ECN_MARKED)
						hc->lost++;
					ccid5_rtt_estimator(sk, ccid5_jiffies32 - seqp->ccid5s_sent);
					seqp->ccid5s_acked = 1;
					hc->delivered++;
					hc->tx_pipe--;
					dccp_rate_skb_delivered(sk, seqp, rs);
					if (seqp->ccid5s_seq == ackno)	{ 
						rs->rtt_us = tcp_stamp_us_delta(now_mstamp, seqp->sent_mstamp);
						hc->rtt_us = rs->rtt_us;
					}
				}
				if (seqp == hc->tx_seqt) {
					done = 1;
					break;
				}
				seqp = seqp->ccid5s_prev;
			}
			if (done)
				break;

			ackno = SUB48(ackno_end_rl, 1);
		}
		if (done)
			break;
	}

	/* The state about what is acked should be correct now
	 * Check for NUMDUPACK
	 */
	seqp = hc->tx_seqt;
	while (before48(seqp->ccid5s_seq, hc->tx_high_ack)) {
		seqp = seqp->ccid5s_next;
		if (seqp == hc->tx_seqh) {
			seqp = hc->tx_seqh->ccid5s_prev;
			break;
		}
	}
	done = 0;
	while (1) {
		if (seqp->ccid5s_acked) {
			done++;
			if (done == NUMDUPACK)
				break;
		}
		if (seqp == hc->tx_seqt)
			break;
		seqp = seqp->ccid5s_prev;
	}

	/* If there are at least 3 acknowledgements, anything unacknowledged
	 * below the last sequence number is considered lost
	 */
	if (done == NUMDUPACK) {
		struct ccid5_seq *last_acked = seqp;

		/* check for lost packets */
		while (1) {
			if (!seqp->ccid5s_acked) {
				ccid5_pr_debug("Packet lost: %llu\n",
					       (unsigned long long)seqp->ccid5s_seq);
				/* XXX need to traverse from tail -> head in
				 * order to detect multiple congestion events in
				 * one ack vector.
				 */
				hc->lost++;
				hc->tx_pipe--;
			}
			if (seqp == hc->tx_seqt)
				break;
			seqp = seqp->ccid5s_prev;
		}

		hc->tx_seqt = last_acked;
	}

	/* trim acked packets in tail */
	while (hc->tx_seqt != hc->tx_seqh) {
		if (!hc->tx_seqt->ccid5s_acked)
			break;

		hc->tx_seqt = hc->tx_seqt->ccid5s_next;
	}

	/* restart RTO timer if not all outstanding data has been acked */
	if (hc->tx_pipe == 0)
		sk_stop_timer(sk, &hc->tx_rtotimer);
	else if(!not_rst)
		sk_reset_timer(sk, &hc->tx_rtotimer, jiffies + hc->tx_rto);
	delivered = hc->delivered - delivered;
	lost = hc->lost - lost;	
	dccp_rate_gen(sk, delivered, lost, now_mstamp, rs);

	bbr_update_btl_bw(sk, rs);
	bbr_update_cycle_phase(sk, rs);
	bbr_check_full_bw_reached(sk, rs);
	bbr_check_drain(sk, rs);
	bbr_update_rt_prop(sk, rs);
	bw = bbr_bw(sk);
	bbr_set_pacingrate(sk, bw, hc->pacing_gain);
	bbr_set_tso_segs_goal(sk);
	bbr_set_cwnd(sk, rs, rs->acked_sacked, bbr_max_bw(sk), hc->cwnd_gain);
	ccid5_pr_debug("sk=%p mode=%d min_rtt=%d bw=%d\n", sk, hc->mode, hc->min_rtt_us, bw);
done:
	/* check if incoming Acks allow pending packets to be sent */
	if (sender_was_blocked && !ccid5_cwnd_network_limited(hc))
		dccp_tasklet_schedule(sk);
	dccp_ackvec_parsed_cleanup(&hc->tx_av_chunks);
}


static int ccid5_hc_tx_init(struct ccid *ccid, struct sock *sk)
{
	struct ccid5_hc_tx_sock *hc = ccid_priv(ccid);
	struct dccp_sock *dp = dccp_sk(sk);
	u32 max_ratio;
	ccid5_pr_debug("init ccid5 sk %p", sk);

	/* RFC 4341, 5: initialise ssthresh to arbitrarily high (max) value */
	hc->tx_ssthresh = ~0U;

	/* Use larger initial windows (RFC 4341, section 5). */
	hc->tx_cwnd = 10;
	hc->tx_expected_wnd = hc->tx_cwnd;

	/* Make sure that Ack Ratio is enabled and within bounds. */
	max_ratio = DIV_ROUND_UP(hc->tx_cwnd, 2);
	if (dp->dccps_l_ack_ratio == 0 || dp->dccps_l_ack_ratio > max_ratio)
		dp->dccps_l_ack_ratio = max_ratio;

	/* XXX init ~ to window size... */
	if (ccid5_hc_tx_alloc_seq(hc))
		return -ENOMEM;

	hc->tx_rto	 = DCCP_TIMEOUT_INIT;
	hc->tx_rpdupack  = -1;
	hc->tx_last_cong = hc->tx_lsndtime = hc->tx_cwnd_stamp = ccid5_jiffies32;
	hc->tx_cwnd_used = 0;
	hc->tx_pipe = 0;
	hc->min_rtt_us = 0;
	hc->max_rtt_us = 0;

	hc->prior_cwnd = 0;
	hc->tso_segs_goal = 0;	 /* default segs per skb until first ACK */
	hc->rtt_cnt = 0;
	hc->next_rtt_delivered = 0;
	hc->prev_ca_state = DCCP_CA_Open;
	hc->curr_ca_state = DCCP_CA_Open;
	hc->packet_conservation = 0;

	hc->probe_rtt_done_stamp = 0;
	hc->probe_rtt_round_done = 0;
	hc->min_rtt_stamp = ccid5_jiffies32;
	hc->max_rtt_stamp = ccid5_jiffies32;


	hc->has_seen_rtt = 0;
	hc->pr_init = 0;
	hc->rtprop_fix=0;
	hc->tx_extrapkt=false;
	

	hc->restore_cwnd = 0;
	hc->restore_ackrt = 0;
	hc->restore_seqwin = 0;
	hc->round_start = 0;
	hc->idle_restart = 0;
	hc->full_bw_reached = 0;
	hc->full_bw = 0;
	hc->full_bw_cnt = 0;
	hc->cycle_idx = 0;
	bbr_reset_startup_mode(hc);
	bbr_reset_lt_bw_sampling(hc);

	timer_setup(&hc->tx_rtotimer, ccid5_hc_tx_rto_expire, 0);
	INIT_LIST_HEAD(&hc->tx_av_chunks);

	return 0;
}

static void ccid5_hc_tx_exit(struct sock *sk)
{
	struct ccid5_hc_tx_sock *hc = ccid5_hc_tx_sk(sk);
	int i;

	sk_stop_timer(sk, &hc->tx_rtotimer);

	for (i = 0; i < hc->tx_seqbufc; i++)
		kfree(hc->tx_seqbuf[i]);
	hc->tx_seqbufc = 0;
	dccp_ackvec_parsed_cleanup(&hc->tx_av_chunks);
}

static void ccid5_hc_rx_packet_recv(struct sock *sk, struct sk_buff *skb)
{
	struct ccid5_hc_rx_sock *hc = ccid5_hc_rx_sk(sk);

	if (!dccp_data_packet(skb))
		return;
	if (++hc->rx_num_data_pkts >= dccp_sk(sk)->dccps_r_ack_ratio) {
		dccp_send_ack(sk);
		hc->rx_num_data_pkts = 0;
	}
}

// Function to read h values and make them available for dccp
static void ccid5_hc_tx_get_info(struct sock *sk, struct tcp_info *info)
{
	info->tcpi_rto = ccid5_hc_tx_sk(sk)->tx_rto;
	info->tcpi_rtt = ccid5_hc_tx_sk(sk)->tx_srtt;
	info->tcpi_rttvar = ccid5_hc_tx_sk(sk)->tx_mrtt;
	info->tcpi_segs_out = ccid5_hc_tx_sk(sk)->tx_pipe;
	info->tcpi_snd_cwnd = ccid5_hc_tx_sk(sk)->tx_cwnd;
	info->tcpi_last_data_sent = ccid5_hc_tx_sk(sk)->tx_lsndtime;
	info->tcpi_last_ack_recv = (ccid5_hc_tx_sk(sk)->tx_last_ack_recv > 0) ? ccid5_jiffies32 - ccid5_hc_tx_sk(sk)->tx_last_ack_recv : 0;
	
	info->tcpi_min_rtt = ccid5_hc_tx_sk(sk)->min_rtt_us;
	//calculate time since tx_min_rtt_stamp was set and store it in some unused var.
	info->tcpi_last_ack_sent = (ccid5_hc_tx_sk(sk)->min_rtt_stamp > 0) ? ccid5_jiffies32 - ccid5_hc_tx_sk(sk)->min_rtt_stamp : 0;
	
	info->tcpi_snd_mss = ccid5_hc_tx_sk(sk)->max_rtt_us;
	//calculate time since tx_min_rtt_stamp was set and store it in some unused var.
	info->tcpi_rcv_mss = (ccid5_hc_tx_sk(sk)->max_rtt_stamp > 0) ? ccid5_jiffies32 - ccid5_hc_tx_sk(sk)->max_rtt_stamp : 0;
}

struct ccid_operations ccid5_ops = {
	.ccid_id		  = DCCPC_CCID5,
	.ccid_name		  = "BBR-like",
	.ccid_hc_tx_obj_size	  = sizeof(struct ccid5_hc_tx_sock),
	.ccid_hc_tx_init	  = ccid5_hc_tx_init,
	.ccid_hc_tx_exit	  = ccid5_hc_tx_exit,
	.ccid_hc_tx_send_packet	  = ccid5_hc_tx_send_packet,
	.ccid_hc_tx_packet_sent	  = ccid5_hc_tx_packet_sent,
	.ccid_hc_tx_parse_options = ccid5_hc_tx_parse_options,
	.ccid_hc_tx_packet_recv	  = ccid5_hc_tx_packet_recv,
	.ccid_hc_tx_get_info	   = ccid5_hc_tx_get_info,
	.ccid_hc_rx_obj_size	  = sizeof(struct ccid5_hc_rx_sock),
	.ccid_hc_rx_packet_recv	  = ccid5_hc_rx_packet_recv,
};

#ifdef CONFIG_IP_DCCP_CCID5_DEBUG
module_param(ccid5_debug, bool, 0644);
MODULE_PARM_DESC(ccid5_debug, "Enable CCID-5 debug messages");
#endif
