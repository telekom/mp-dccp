/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 *  Copyright (C) 2022 by Alexander Rabitsch, Karlstad University for Deutsche Telekom AG
 *
 *  This code is a version of the BBR algorithm for the DCCP protocol.
 *	Due to that, it copies and adapts as much code as possible from 
 *	net/ipv4/tcp_bbr.c, net/ipv4/tcp_rate.c, net/dccp/ccids/ccid5.c, 
 *	and net/dccp/ccids/ccid2.c
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * This implementation should follow RFC 4341
 */
#include <linux/slab.h>
#include "../feat.h"
#include "ccid6.h"

struct bbr_context {
    u32 sample_bw;
    u32 target_cwnd;
    u32 log:1;
};

enum bbr_mode {
    BBR_STARTUP,
    BBR_DRAIN,
    BBR_PROBE_BW,
    BBR_PROBE_RTT,
};

enum bbr_ack_phase {
    BBR_ACKS_INIT,
    BBR_ACKS_REFILLING,
    BBR_ACKS_PROBE_STARTING,
    BBR_ACKS_PROBE_FEEDBACK,
    BBR_ACKS_PROBE_STOPPING,
};

enum tcp_bbr2_phase {
    BBR2_PHASE_STARTUP,
    BBR2_PHASE_DRAIN,
    BBR2_PHASE_PROBE_RTT,
    BBR2_PHASE_INVALID,
    BBR2_PHASE_PROBE_BW_UP,
    BBR2_PHASE_PROBE_BW_DOWN,
    BBR2_PHASE_PROBE_BW_CRUISE,
    BBR2_PHASE_PROBE_BW_REFILL,
};

enum dccp_ca_state {
    DCCP_CA_Open = 0,
    DCCP_CA_Disorder = 1,
    DCCP_CA_CWR = 2,
    DCCP_CA_Recovery = 3,
    DCCP_CA_Loss = 4
};

/* Scale factor for rate in pkt/uSec unit to avoid truncation in bandwidth
 * estimation. The rate unit ~= (1500 bytes / 1 usec / 2^24) ~= 715 bps.
 * This handles bandwidths from 0.06pps (715bps) to 256Mpps (3Tbps) in a u32.
 * Since the minimum window is >=4 packets, the lower bound isn't
 * an issue. The upper bound isn't an issue with existing technologies.
 */
#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define BBR_SCALE 8	/* scaling factor for fractions in BBR (e.g. gains) */
#define BBR_UNIT (1 << BBR_SCALE)

#define FLAG_DEBUG_VERBOSE	0x1	/* Verbose debugging messages */
#define FLAG_DEBUG_LOOPBACK	0x2	/* Do NOT skip loopback addr */

#define CYCLE_LEN	8 /* number of phases in a pacing gain cycle */

#define FLAG_ECE 0x40

// ???
/* Window length of min_rtt filter (in sec). Max allowed value is 31 (0x1F) */
static u32 bbr_min_rtt_win_sec = 10;
/* Minimum time (in ms) spent at bbr_cwnd_min_target in BBR_PROBE_RTT mode.
 * Max allowed value is 511 (0x1FF).
 */
static u32 bbr_probe_rtt_mode_ms = 200;
/* Window length of probe_rtt_min_us filter (in ms), and consequently the
 * typical interval between PROBE_RTT mode entries.
 * Note that bbr_probe_rtt_win_ms must be <= bbr_min_rtt_win_sec * MSEC_PER_SEC
 */
static u32 bbr_probe_rtt_win_ms = 5000;
/* Skip TSO below the following bandwidth (bits/sec): */
static int bbr_min_tso_rate = 1200000;
/* Use min_rtt to help adapt TSO burst size, with smaller min_rtt resulting
 * in bigger TSO bursts. By default we cut the RTT-based allowance in half
 * for every 2^9 usec (aka 512 us) of RTT, so that the RTT-based allowance
 * is below 1500 bytes after 6 * ~500 usec = 3ms.
 */
static u32 bbr_tso_rtt_shift = 9;
/* Select cwnd TSO budget approach:
 *  0: padding
 *  1: flooring
 */
static uint bbr_cwnd_tso_budget = 0; // alerab
/* Pace at ~1% below estimated bw, on average, to reduce queue at bottleneck.
 * In order to help drive the network toward lower queues and low latency while
 * maintaining high utilization, the average pacing rate aims to be slightly
 * lower than the estimated bandwidth. This is an important aspect of the
 * design.
 */
static const int bbr_pacing_margin_percent = 1;
/* We use a high_gain value of 2/ln(2) because it's the smallest pacing gain
 * that will allow a smoothly increasing pacing rate that will double each RTT
 * and send the same number of packets per RTT that an un-paced, slow-starting
 * Reno or CUBIC flow would. Max allowed value is 2047 (0x7FF).
 */
static int bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1;
/* The gain for deriving startup cwnd. Max allowed value is 2047 (0x7FF). */
static int bbr_startup_cwnd_gain  = BBR_UNIT * 2885 / 1000 + 1;
/* The pacing gain of 1/high_gain in BBR_DRAIN is calculated to typically drain
 * the queue created in BBR_STARTUP in a single round. Max allowed value
 * is 1023 (0x3FF).
 */
static int bbr_drain_gain = BBR_UNIT * 1000 / 2885;
/* The gain for deriving steady-state cwnd tolerates delayed/stretched ACKs.
 * Max allowed value is 2047 (0x7FF).
 */
static int bbr_cwnd_gain  = BBR_UNIT * 2;

/* The pacing_gain values for the PROBE_BW gain cycle, to discover/share bw.
 * Max allowed value for each element is 1023 (0x3FF).
 */
enum bbr_pacing_gain_phase {
    BBR_BW_PROBE_UP		= 0,	/* push up inflight to probe for bw/vol */
    BBR_BW_PROBE_DOWN	= 1, 	/* drain excess inflight from the queue */
    BBR_BW_PROBE_CRUISE	= 2, 	/* use pipe, w/ headroom in queue/pipe */
    BBR_BW_PROBE_REFILL	= 3, 	/* v2: refill the pipe again to 100% */
};
static int bbr_pacing_gain[] = {
    BBR_UNIT * 5 / 4,	/* probe for more available bw */
    BBR_UNIT * 3 / 4,	/* drain queue and/or yield bw to other flows */
    BBR_UNIT, BBR_UNIT, BBR_UNIT,	/* cruise at 1.0*bw to utilize pipe, */
    BBR_UNIT, BBR_UNIT, BBR_UNIT	/* without creating excess queue... */
};

/* Try to keep at least this many packets in flight, if things go smoothly. For
 * smooth functioning, a sliding window protocol ACKing every other packet
 * needs at least 4 packets in flight. Max allowed value is 15 (0xF).
 */
static u32 bbr_cwnd_min_target = 4;
/* Cwnd to BDP proportion in PROBE_RTT mode scaled by BBR_UNIT. Default: 50%.
 * Use 0 to disable. Max allowed value is 255.
 */
static u32 bbr_probe_rtt_cwnd_gain = BBR_UNIT * 1 / 2;
/* To estimate if BBR_STARTUP mode (i.e. high_gain) has filled pipe... */
/* If bw has increased significantly (1.25x), there may be more bw available.
 * Max allowed value is 1023 (0x3FF).
 */
static u32 bbr_full_bw_thresh = BBR_UNIT * 5 / 4;
/* But after 3 rounds w/o significant bw growth, estimate pipe is full.
 * Max allowed value is 7 (0x7).
 */
static u32 bbr_full_bw_cnt = 3;

//static u32 bbr_flags;	/* Debugging related stuff */
//static bool bbr_debug_with_printk;
//static bool bbr_debug_ftrace;

/* Experiment: each cycle, try to hold sub-unity gain until inflight <= BDP. */
static bool bbr_drain_to_target = false; // alerab
/* Experiment: Flags to control BBR with ECN behavior.
 */
static bool bbr_precise_ece_ack = true;
/* The max rwin scaling shift factor is 14 (RFC 1323), so the max sane rwin is
 * (2^(16+14) B)/(1024 B/packet) = 1M packets.
 */
static u32 bbr_cwnd_warn_val	= 1U << 20;
//static u16 bbr_debug_port_mask;


/* BBR module parameters. These are module parameters only in Google prod.
 * Upstream these are intentionally not module parameters.
 */
//static int bbr_pacing_gain_size = CYCLE_LEN;
/* Gain factor for adding extra_acked to target cwnd: */
static int bbr_extra_acked_gain = 256;
/* Window length of extra_acked window. Max allowed val is 31. */
static u32 bbr_extra_acked_win_rtts = 5;
/* Max allowed val for ack_epoch_acked, after which sampling epoch is reset */
static int bbr_extra_acked_in_startup = 1;
/* Time period for clamping cwnd increment due to ack aggregation */
static bool bbr_usage_based_cwnd = false;
/* For lab testing, researchers can enable BBRv2 ECN support with this flag,
 * when they know that any ECN marks that the connections experience will be
 * DCTCP/L4S-style ECN marks, rather than RFC3168 ECN marks.
 * TODO(ncardwell): Production use of the BBRv2 ECN functionality depends on
 * negotiation or configuration that is outside the scope of the BBRv2
 * alpha release.
 */
static bool bbr_ecn_enable = false;

/* These are module parameters in bbrv2 */
static u32 bbr_extra_acked_max_us = 100 * 1000;
static u32 bbr_ack_epoch_acked_reset_thresh = 1U << 20;
static u32 bbr_beta = BBR_UNIT * 30 / 100;
static u32 bbr_ecn_alpha_gain = BBR_UNIT * 1 / 16; 
static u32 bbr_ecn_alpha_init = BBR_UNIT;	
static u32 bbr_ecn_factor = BBR_UNIT * 1 / 3;	
static u32 bbr_ecn_thresh = BBR_UNIT * 1 / 2; 
static u32 bbr_ecn_max_rtt_us = 5000;
static u32 bbr_ecn_reprobe_gain;
static u32 bbr_loss_thresh = BBR_UNIT * 2 / 100; 
static u32 bbr_full_loss_cnt = 8;
static u32 bbr_full_ecn_cnt = 2;
static u32 bbr_inflight_headroom = BBR_UNIT * 15 / 100;
static u32 bbr_bw_probe_pif_gain = BBR_UNIT * 5 / 4;
static u32 bbr_bw_probe_reno_gain = BBR_UNIT;
static u32 bbr_bw_probe_max_rounds = 63;
static u32 bbr_bw_probe_rand_rounds = 2;
static u32 bbr_bw_probe_base_us = 2 * USEC_PER_SEC; 
static u32 bbr_bw_probe_rand_us = 1 * USEC_PER_SEC; 
static bool bbr_undo = true;
static bool bbr_fast_path = true;	
//static int bbr_fast_ack_mode = 1;
static u32 bbr_refill_add_inc;		

static void bbr2_exit_probe_rtt (struct sock* sk);
static void bbr2_reset_congestion_signals (struct ccid6_hc_tx_sock* hc);
static void bbr_check_probe_rtt_done (struct sock* sk);
static void bbr_cwnd_event(struct sock* sk, enum tcp_ca_event event);

#ifdef CONFIG_IP_DCCP_CCID6_DEBUG
static bool ccid6_debug;
#define ccid6_pr_debug(format, a...)	DCCP_PR_DEBUG(ccid6_debug, format, ##a)
#else
#define ccid6_pr_debug(format, a...)
#endif

static int ccid6_hc_tx_alloc_seq(struct ccid6_hc_tx_sock *hc)
{
	//printk(KERN_INFO "natrm: enter ccid6_hc_tx_alloc_seq");
	struct ccid6_seq *seqp;
	int i;

	/* check if we have space to preserve the pointer to the buffer */
	if (hc->tx_seqbufc >= (sizeof(hc->tx_seqbuf) /
				   sizeof(struct ccid6_seq *)))
		return -ENOMEM;

	/* allocate buffer and initialize linked list */
	seqp = kmalloc(CCID6_SEQBUF_LEN * sizeof(struct ccid6_seq), gfp_any());
	if (seqp == NULL)
		return -ENOMEM;

	for (i = 0; i < (CCID6_SEQBUF_LEN - 1); i++) {
		seqp[i].ccid6s_next = &seqp[i + 1];
		seqp[i + 1].ccid6s_prev = &seqp[i];
	}
	seqp[CCID6_SEQBUF_LEN - 1].ccid6s_next = seqp;
	seqp->ccid6s_prev = &seqp[CCID6_SEQBUF_LEN - 1];

	/* This is the first allocation.  Initiate the head and tail.  */
	if (hc->tx_seqbufc == 0)
		hc->tx_seqh = hc->tx_seqt = seqp;
	else {
		/* link the existing list with the one we just created */
		hc->tx_seqh->ccid6s_next = seqp;
		seqp->ccid6s_prev = hc->tx_seqh;

		hc->tx_seqt->ccid6s_prev = &seqp[CCID6_SEQBUF_LEN - 1];
		seqp[CCID6_SEQBUF_LEN - 1].ccid6s_next = hc->tx_seqt;
	}

	/* store the original pointer to the buffer so we can free it */
	hc->tx_seqbuf[hc->tx_seqbufc] = seqp;
	hc->tx_seqbufc++;

	return 0;
}


static void ccid6_change_l_ack_ratio(struct sock *sk, u32 val)
{
	u32 max_ratio = DIV_ROUND_UP(ccid6_hc_tx_sk(sk)->tx_cwnd, 2);

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
	//printk(KERN_INFO "natrm: ccid6 change ack_ratio %lu max %lu", val, max_ratio);
	dccp_feat_signal_nn_change(sk, DCCPF_ACK_RATIO,
				   min_t(u32, val, DCCPF_ACK_RATIO_MAX));
}

static void ccid6_check_l_ack_ratio(struct sock *sk)
{
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

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
		ccid6_change_l_ack_ratio(sk, hc->tx_cwnd/2 ? : 1U);
}

static void ccid6_change_l_seq_window(struct sock *sk, u64 val)
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

static bool ccid6_do_cwv = true;
module_param(ccid6_do_cwv, bool, 0644);
MODULE_PARM_DESC(ccid6_do_cwv, "Perform RFC2861 Congestion Window Validation");

/**
 * ccid2_update_used_window  -  Track how much of cwnd is actually used
 * This is done in addition to CWV. The sender needs to have an idea of how many
 * packets may be in flight, to set the local Sequence Window value accordingly
 * (RFC 4340, 7.5.2). The CWV mechanism is exploited to keep track of the
 * maximum-used window. We use an EWMA low-pass filter to filter out noise.
 */
static void ccid6_update_used_window(struct ccid6_hc_tx_sock *hc, u32 new_wnd)
{
	hc->tx_expected_wnd = (3 * hc->tx_expected_wnd + new_wnd) / 4;
}

/* This borrows the code of tcp_cwnd_application_limited() */
static void ccid6_cwnd_application_limited(struct sock *sk, const u32 now)
{
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	/* don't reduce cwnd below the initial window (IW) */
	u32 init_win = ccid6_rfc3390_bytes_to_pkts(dccp_sk(sk)->dccps_mss_cache),
		win_used = max(hc->tx_cwnd_used, init_win);

	if (win_used < hc->tx_cwnd) {
		hc->tx_ssthresh = max(hc->tx_ssthresh,
					 (hc->tx_cwnd >> 1) + (hc->tx_cwnd >> 2));
		//hc->tx_cwnd = (hc->tx_cwnd + win_used) >> 1;
		//ccid6_pr_debug("%s: tx_cwnd set to %d for sk %p", __func__, hc->tx_cwnd, sk);
	}
	hc->tx_cwnd_used  = 0;
	hc->tx_cwnd_stamp = now;

	ccid6_check_l_ack_ratio(sk);
}

/* This borrows the code of tcp_cwnd_restart() */
static void ccid6_cwnd_restart(struct sock *sk, const u32 now)
{
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	u32 cwnd = hc->tx_cwnd, restart_cwnd,
		iwnd = ccid6_rfc3390_bytes_to_pkts(dccp_sk(sk)->dccps_mss_cache);

	hc->tx_ssthresh = max(hc->tx_ssthresh, (cwnd >> 1) + (cwnd >> 2));

	/* don't reduce cwnd below the initial window (IW) */
	restart_cwnd = min(cwnd, iwnd);
	cwnd >>= (now - hc->tx_lsndtime) / hc->tx_rto;
	//hc->tx_cwnd = max(cwnd, restart_cwnd);

	hc->tx_cwnd_stamp = now;
	hc->tx_cwnd_used  = 0;

	ccid6_check_l_ack_ratio(sk);
}

static void ccid6_hc_tx_packet_sent(struct sock *sk, unsigned int len)
{
	struct dccp_sock *dp = dccp_sk(sk);
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	const u32 now = ccid6_jiffies32;
	struct ccid6_seq *next;

	//u64 prior_wstamp;
	hc->bytes_sent += len;
	if (hc->curr_ca_state == DCCP_CA_Loss)
		hc->curr_ca_state = DCCP_CA_Open;

	/* slow-start after idle periods (RFC 2581, RFC 2861) */
	if (ccid6_do_cwv && !hc->tx_pipe && (s32)(now - hc->tx_lsndtime) >= hc->tx_rto) {
		// CWND EVENT: TX_START, i.e. return from idle
		bbr_cwnd_event(sk, CA_EVENT_TX_START); //<------------------ 

		ccid6_cwnd_restart(sk, now);
		// This is returning from idle: 
	}

	hc->tx_lsndtime = now;

	hc->tx_seqh->sent_mstamp = tcp_clock_us();
	if (!hc->tx_pipe) {
		hc->first_tx_mstamp  = hc->tx_seqh->sent_mstamp;
		hc->delivered_mstamp = hc->first_tx_mstamp;
	}

	hc->tx_seqh->delivered_ce = hc->delivered_ce;
	hc->tx_seqh->delivered    = hc->delivered;
	hc->tx_seqh->ccid6s_seq   = dp->dccps_gss;
	hc->tx_seqh->ccid6s_acked = 0;
	hc->tx_seqh->ccid6s_sent  = now;
	hc->tx_seqh->first_tx_mstamp   = hc->first_tx_mstamp;
	hc->tx_seqh->delivered_mstamp  = hc->delivered_mstamp;
	hc->tx_seqh->is_app_limited = hc->app_limited ? 1 : 0; // what? this is what tcp does, but I dont get it

	hc->tx_seqh->lost = hc->lost; // <---------

	next = hc->tx_seqh->ccid6s_next;
	/* check if we need to alloc more space */
	if (next == hc->tx_seqt) {
		if (ccid6_hc_tx_alloc_seq(hc)) {
			DCCP_CRIT("packet history - out of memory!");
			/* FIXME: find a more graceful way to bail out */
			return;
		}
		next = hc->tx_seqh->ccid6s_next;
		BUG_ON(next == hc->tx_seqt);
	}
	hc->tx_seqh = next;

	hc->tx_pipe  += 1;

	/* see whether cwnd was fully used (RFC 2861), update expected window */
	if (ccid6_cwnd_network_limited(hc)) {
		ccid6_update_used_window(hc, hc->tx_cwnd);
		hc->tx_cwnd_used  = 0;
		hc->tx_cwnd_stamp = now;
	} else {
		if (hc->tx_pipe > hc->tx_cwnd_used)
			hc->tx_cwnd_used = hc->tx_pipe;

		ccid6_update_used_window(hc, hc->tx_cwnd_used);

		if (ccid6_do_cwv && (s32)(now - hc->tx_cwnd_stamp) >= hc->tx_rto)
			ccid6_cwnd_application_limited(sk, now);
	}

	//ccid6_pr_debug("sk=%p cwnd=%d pipe=%d\n", sk, hc->tx_cwnd, hc->tx_pipe);

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
static void ccid6_rtt_estimator(struct sock *sk, const long mrtt)
{
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	long m = mrtt ? : 1;

	hc->tx_mrtt = mrtt;

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

void ccid6_rate_skb_delivered(struct sock *sk, struct ccid6_seq *acked,
				struct rate_sample_ccid6 *rs)
{
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	if (!acked->delivered_mstamp)
		return;

	if (!rs->prior_delivered || after(acked->delivered, rs->prior_delivered)) {
		rs->prior_delivered_ce = acked->delivered_ce;
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

void ccid6_rate_gen(struct sock *sk, u32 delivered, u32 lost, u64 now, struct rate_sample_ccid6 *rs)
{
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
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

	rs->delivered    = hc->delivered - rs->prior_delivered;
	rs->delivered_ce = hc->delivered_ce - rs->prior_delivered_ce;
	/* delivered_ce occupies less than 32 bits in the skb control block */
	//rs->delivered_ce &= TCPCB_DELIVERED_CE_MASK; // ?

	//// takes maximum between send_us and ack_us
	snd_us = rs->interval_us;				/* send phase */
	ack_us = tcp_stamp_us_delta(now, rs->prior_mstamp);
	rs->interval_us = max(snd_us, ack_us);
}

void ccid6_rate_check_app_limited(struct sock *sk, int tsize)
{
	struct dccp_sock *dp = dccp_sk(sk);
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	if (hc->bytes_att - hc->bytes_sent < dp->dccps_mss_cache &&
			sk_wmem_alloc_get(sk) < tsize && hc->tx_pipe < hc->tx_cwnd) {
		hc->app_limited = (hc->delivered + hc->tx_pipe) ? : 1;
	}

}

/*****************************************************/
/*       FUNCTIONS PART OF tcp_rate.c END HERE       */
/*****************************************************/


/*****************************************************/
/*       FUNCTIONS PART OF tcp_bbrv2.c START HERE       */
/*****************************************************/

static bool bbr_full_bw_reached (const struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	return hc->full_bw_reached;
}

static u32 bbr_max_bw (const struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	return max (hc->bw_hi[0], hc->bw_hi[1]);
} 

static u32 bbr_bw (const struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	return min (bbr_max_bw (sk), hc->bw_lo);
} 

static u16 bbr_extra_acked (const struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	return max (hc->extra_acked[0], hc->extra_acked[1]);
}

static u64 bbr_rate_bytes_per_sec (struct sock* sk, u64 rate, int gain, int margin) {
	struct inet_connection_sock *icsk = inet_csk(sk);
	rate *= icsk->icsk_pmtu_cookie;
	rate *= gain;
	rate >>= BBR_SCALE;
	rate *= USEC_PER_SEC / 100 * (100 - margin);
	rate >>= BW_SCALE;
	rate = max (rate, 1ULL);
	return rate;
}

static u64 bbr_bw_bytes_per_sec (struct sock* sk, u64 rate) {
	return bbr_rate_bytes_per_sec (sk, rate, BBR_UNIT, 0);
}

// Enable for debugging
static u64 bbr_rate_kbps (struct sock* sk, u64 rate) {
	rate = bbr_bw_bytes_per_sec (sk, rate);
	rate *= 8;
	do_div (rate, 1000);
	return rate;
}

static unsigned long bbr_bw_to_pacing_rate (struct sock* sk, u32 bw, int gain) {
	u64 rate = bw;
	rate = bbr_rate_bytes_per_sec (sk, rate, gain, bbr_pacing_margin_percent);
	rate = min_t (u64, rate, sk->sk_max_pacing_rate);
	return rate;
} 

static void bbr_init_pacing_rate_from_rtt (struct sock* sk, struct ccid6_hc_tx_sock *hc) {
	u64 bw;
	u32 rtt_us;
	if (hc->tx_srtt) {
		rtt_us = max (hc->tx_srtt >> 3, 1U);
		hc->has_seen_rtt = 1;
	} else {
		rtt_us = USEC_PER_MSEC;
	}
	bw = (u64)hc->tx_cwnd * BW_UNIT;
	do_div (bw, rtt_us);
	sk->sk_pacing_rate = bbr_bw_to_pacing_rate (sk, bw, hc->params.high_gain);
	hc->pr_init = 1;
}

static void bbr_set_pacing_rate (struct sock* sk, u32 bw, int gain) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	u32 rate = bbr_bw_to_pacing_rate(sk, bw, gain);

	if (unlikely(!hc->has_seen_rtt && hc->tx_srtt))
		bbr_init_pacing_rate_from_rtt(sk, hc);
	if (bbr_full_bw_reached(sk) || rate > sk->sk_pacing_rate)
		sk->sk_pacing_rate = rate;
} 

/*static u32 bbr_min_tso_segs (struct sock* sk) {
	return sk->sk_pacing_rate < (bbr_min_tso_rate >> 3) ? 1 : 2;
}*/

/*static u32 bbr_tso_segs_generic (struct sock* sk, unsigned int mss_now, u32 gso_max_size) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	u32 segs, r;
	u64 bytes = sk->sk_pacing_rate >> sk->sk_pacing_shift;
	if (hc->params.tso_rtt_shift) {
		r = hc->min_rtt_us >> hc->params.tso_rtt_shift;
		if (r < BITS_PER_TYPE(u32))  
			bytes += GSO_MAX_SIZE >> r;
	}
	bytes = min_t (u32, bytes, gso_max_size - 1 - MAX_TCP_HEADER);
	segs = max_t (u32, bytes / mss_now, bbr_min_tso_segs (sk));
	return segs;
}

static u32  bbr_tso_segs (struct sock* sk, unsigned int mss_now) {
	return bbr_tso_segs_generic (sk, mss_now, sk->sk_gso_max_size);
}*/

u32 ccid6_tso_autosize(const struct sock *sk, unsigned int mss_now, int min_tso_segs)
{
	u32 bytes, segs;

	bytes = min(sk->sk_pacing_rate >> 10, (u32)(sk->sk_gso_max_size - 1 - MAX_DCCP_HEADER));
	segs = max_t(u32, bytes / mss_now, min_tso_segs);

	return segs;
}

static u32 bbr_tso_segs_goal (struct sock* sk) {
	struct dccp_sock *dp = dccp_sk(sk);
	u32 min_segs;

	min_segs = sk->sk_pacing_rate < (bbr_min_tso_rate >> 3) ? 1 : 2;
	return min(ccid6_tso_autosize(sk, dp->dccps_mss_cache, min_segs), 0x7FU);
}

static void bbr_save_cwnd (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	struct dccp_sock *dp = dccp_sk(sk);

	if (hc->prev_ca_state < DCCP_CA_Recovery && hc->mode != BBR_PROBE_RTT)
		hc->prior_cwnd = hc->tx_cwnd;  /* this cwnd is good enough */
	else  /* loss recovery or BBR_PROBE_RTT have temporarily cut cwnd */
		hc->prior_cwnd = max(hc->prior_cwnd, hc->tx_cwnd);

	/* From ccid6: Save ack_ratio and seq_window as well (keep?) */
	hc->prior_ackrt = dp->dccps_l_ack_ratio;
	hc->prior_seqwin = dp->dccps_l_seq_win;

} 

static void bbr_cwnd_event (struct sock* sk, enum tcp_ca_event event) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	if (event == CA_EVENT_TX_START && hc->app_limited) {
			hc->idle_restart = 1;
			hc->ack_epoch_mstamp = dccp_sk(sk)->dccps_mstamp;
			hc->ack_epoch_acked = 0;

			if (hc->mode == BBR_PROBE_BW)
				bbr_set_pacing_rate(sk, bbr_bw(sk), BBR_UNIT);
			else if (hc->mode == BBR_PROBE_RTT)
				bbr_check_probe_rtt_done(sk);
	} /* Important for ECN handling! */ 
	/*else if ((event == CA_EVENT_ECN_IS_CE || event == CA_EVENT_ECN_NO_CE) && bbr_ecn_enable && hc->params.precise_ece_ack) {
		u32 state = hc->ce_state;
		dctcp_ece_ack_update(sk, event, &hc->prior_rcv_nxt, &state);
		hc->ce_state = state;
	}*/
}

static u32 bbr_bdp (struct sock* sk, u32 bw, int gain) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	u32 bdp;
	u64 w;
	if (unlikely(hc->min_rtt_us == ~0U)) {
		return hc->init_cwnd; 
	}
	w = (u64)bw * hc->min_rtt_us;
	bdp = (((w * gain) >> BBR_SCALE) + BW_UNIT - 1) / BW_UNIT;

	ccid6_pr_debug("sk=%p bw=%d min_rtt_us=%d gain=%d bdp=%d\n", sk, bw, hc->min_rtt_us, gain, bdp);

	return bdp;
}

static u32 bbr_quantization_budget (struct sock* sk, u32 cwnd) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	u32 tso_segs_goal;
	tso_segs_goal = 3 * bbr_tso_segs_goal (sk);
	/* Allow enough full-sized skbs in flight to utilize end systems. */
	if (hc->params.cwnd_tso_budget == 1) {
		cwnd = max_t(u32, cwnd, tso_segs_goal);
		cwnd = max_t(u32, cwnd, hc->params.cwnd_min_target);
	} else {
		cwnd += tso_segs_goal;

		/* Reduce delayed ACKs by rounding up cwnd to the next even number. */
		cwnd = (cwnd + 1) & ~1U;
	}
	/* Ensure gain cycling gets inflight above BDP even for small BDPs. */
	if (hc->mode == BBR_PROBE_BW && hc->cycle_idx == BBR_BW_PROBE_UP) {
		cwnd += 2;
	}
	return cwnd;
}

static u32 bbr_inflight (struct sock* sk, u32 bw, int gain) {
	u32 inflight;
	inflight = bbr_bdp (sk, bw, gain);
	inflight = bbr_quantization_budget (sk, inflight);
	
	ccid6_pr_debug("sk %p quantization_budget %d", sk, inflight);


	return inflight;
}

static u32 bbr_packets_in_net_at_edt (struct sock* sk, u32 inflight_now) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	struct dccp_sock *dp = dccp_sk(sk);

	u64 now_ns, edt_ns, interval_us;
	u32 interval_delivered, inflight_at_edt;

	now_ns = dp->dccps_clock_cache;
	edt_ns = max (dp->dccps_wstamp_ns, now_ns);
	
	interval_us = div_u64 (edt_ns - now_ns, NSEC_PER_USEC);
	interval_delivered = (u64)bbr_bw (sk) * interval_us >> BW_SCALE;
	inflight_at_edt = inflight_now;
	if (hc->pacing_gain > BBR_UNIT) {
		inflight_at_edt += bbr_tso_segs_goal (sk); 
	}
	if (interval_delivered >= inflight_at_edt) {
		return 0;
	}
	return inflight_at_edt - interval_delivered;
} 

static u32 bbr_ack_aggregation_cwnd (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	u32 max_aggr_cwnd, aggr_cwnd = 0;
	if (hc->params.extra_acked_gain && (bbr_full_bw_reached (sk) || hc->params.extra_acked_in_startup)) {
		max_aggr_cwnd = ((u64)bbr_bw (sk) * bbr_extra_acked_max_us) / BW_UNIT;
		aggr_cwnd = (hc->params.extra_acked_gain * bbr_extra_acked (sk)) >> BBR_SCALE;
		aggr_cwnd = min (aggr_cwnd, max_aggr_cwnd);
	}
	return aggr_cwnd;
} 

static u32 bbr_probe_rtt_cwnd (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	if (hc->params.probe_rtt_cwnd_gain == 0) {
		return hc->params.cwnd_min_target;
	}
	return max_t (u32, hc->params.cwnd_min_target, bbr_bdp (sk, bbr_bw (sk), hc->params.probe_rtt_cwnd_gain));
} 

static void bbr_set_cwnd (struct sock* sk, const struct rate_sample_ccid6* rs, u32 acked, u32 bw, int gain, u32 cwnd, struct bbr_context* ctx) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	struct dccp_sock *dp = dccp_sk(sk);
	int r_seq_used = hc->tx_cwnd / dp->dccps_l_ack_ratio;
	u32 target_cwnd = 0, prev_cwnd = hc->tx_cwnd; //, max_probe;

	if (!acked)
		goto done;

	target_cwnd = bbr_bdp (sk, bw, gain);
	target_cwnd += bbr_ack_aggregation_cwnd (sk);
	target_cwnd = bbr_quantization_budget (sk, target_cwnd);

	hc->debug.target_cwnd = target_cwnd;
	hc->try_fast_path = 0;
	if (bbr_full_bw_reached (sk)) { 
		cwnd += acked;
		if (cwnd >= target_cwnd) {
			cwnd = target_cwnd;
			hc->try_fast_path = 1;
		}
	} else if (cwnd < target_cwnd || cwnd  < 2 * hc->init_cwnd) {
		cwnd += acked;
	} else {
		hc->try_fast_path = 1;
	}

	cwnd = max_t (u32, cwnd, hc->params.cwnd_min_target);

done:
	hc->tx_cwnd = cwnd;
	if (hc->mode == BBR_PROBE_RTT) {  /* drain queue, refresh min_rtt */
		hc->tx_cwnd = min_t(u32, hc->tx_cwnd, bbr_probe_rtt_cwnd(sk));
		ccid6_change_l_ack_ratio(sk, 1);
		/* Allow extra packet(s) to let ack_ratio=1 option reaching the peer */
		if (dccp_sk(sk)->dccps_l_ack_ratio != 1U) {
			hc->tx_extrapkt = true;
			dccp_tasklet_schedule(sk);
		}
	}

	/* Do not adjust the ack_ratio if we are restoring it or we are in PROBE_RTT mode */
	if (hc->restore_ackrt) {
		ccid6_change_l_ack_ratio(sk, hc->prior_ackrt);
		/* Restore should end when rx has sent confirmation */
		if (hc->prior_ackrt == dp->dccps_l_ack_ratio) hc->restore_ackrt=0;
	}
	else if (hc->mode != BBR_PROBE_RTT) {
		if (r_seq_used * CCID6_WIN_CHANGE_FACTOR >= dp->dccps_r_seq_win)
			ccid6_change_l_ack_ratio(sk, dp->dccps_l_ack_ratio * 2);
		else if (r_seq_used * CCID6_WIN_CHANGE_FACTOR < dp->dccps_r_seq_win/2)
			ccid6_change_l_ack_ratio(sk, dp->dccps_l_ack_ratio / 2 ? : 1U);
	}

	/* Do not adjust the seq_window if we are restoring it */
	if (hc->restore_seqwin) {
		ccid6_change_l_seq_window(sk, hc->prior_seqwin);
		/* HACK: force local seq_win to new value without waiting confirmation */
		dp->dccps_l_seq_win = hc->prior_seqwin;
		dccp_update_gss(sk, dp->dccps_gss);
		hc->restore_seqwin=0;
	}
	else if (hc->tx_cwnd * CCID6_WIN_CHANGE_FACTOR >= dp->dccps_l_seq_win)
		ccid6_change_l_seq_window(sk, dp->dccps_l_seq_win * 2);
	else if (hc->tx_cwnd * CCID6_WIN_CHANGE_FACTOR < dp->dccps_l_seq_win/2)
		ccid6_change_l_seq_window(sk, dp->dccps_l_seq_win / 2);

	ctx->target_cwnd = target_cwnd;
	ctx->log = (hc->tx_cwnd != prev_cwnd);
} 

static void bbr_update_round_start (struct sock* sk, const struct rate_sample_ccid6* rs, struct bbr_context* ctx) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	hc->round_start = 0;

	if (rs->interval_us > 0 && !before (rs->prior_delivered, hc->next_rtt_delivered)) {
		hc->next_rtt_delivered = hc->delivered;
		hc->round_start = 1;
	}
}

static void bbr_calculate_bw_sample (struct sock* sk, const struct rate_sample_ccid6* rs, struct bbr_context* ctx) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	u64 bw = 0;
	if (rs->interval_us > 0) {
		if (rs->delivered < 0) {
			return;
		}
		bw = DIV_ROUND_UP_ULL((u64)rs->delivered * BW_UNIT, rs->interval_us);
	}
	ctx->sample_bw = bw;
	hc->debug.rs_bw = bw;
} 

static void bbr_update_ack_aggregation (struct sock* sk,const struct rate_sample_ccid6* rs) {
	u32 epoch_us, expected_acked, extra_acked;
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	u32 extra_acked_win_rtts_thresh = hc->params.extra_acked_win_rtts;
	if (!hc->params.extra_acked_gain || rs->acked_sacked <= 0 || rs->delivered < 0 || rs->interval_us <= 0) {
		return;
	}
	if (hc->round_start) {
		hc->extra_acked_win_rtts = min (0x1F,	hc->extra_acked_win_rtts + 1);
		if (hc->params.extra_acked_in_startup && !bbr_full_bw_reached (sk)) {
			extra_acked_win_rtts_thresh = 1;
		}
		if (hc->extra_acked_win_rtts >= extra_acked_win_rtts_thresh) {
			hc->extra_acked_win_rtts = 0;
			hc->extra_acked_win_idx = hc->extra_acked_win_idx ? 0 : 1;
			hc->extra_acked[hc->extra_acked_win_idx] = 0;
		}
	}
	epoch_us = tcp_stamp_us_delta (hc->delivered_mstamp, hc->ack_epoch_mstamp);
	expected_acked = ((u64)bbr_bw(sk) * epoch_us) / BW_UNIT;
	if (hc->ack_epoch_acked <= expected_acked || (hc->ack_epoch_acked + rs->acked_sacked >= bbr_ack_epoch_acked_reset_thresh)) {
		hc->ack_epoch_acked = 0;
		hc->ack_epoch_mstamp = hc->delivered_mstamp;
		expected_acked = 0;
	}
	hc->ack_epoch_acked = min_t (u32, 0xFFFFF, hc->ack_epoch_acked + rs->acked_sacked);
	extra_acked = hc->ack_epoch_acked - expected_acked;
	extra_acked = min (extra_acked, hc->tx_cwnd);
	if (extra_acked > hc->extra_acked[hc->extra_acked_win_idx]) {
		hc->extra_acked[hc->extra_acked_win_idx] = extra_acked;
	} 
}

static void bbr_check_full_bw_reached (struct sock* sk, const struct rate_sample_ccid6* rs) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	u32 bw_thresh;
	if (bbr_full_bw_reached(sk) || !hc->round_start || rs->is_app_limited)
		return;

	bw_thresh = (u64)hc->full_bw * hc->params.full_bw_thresh >> BBR_SCALE;
	if (bbr_max_bw(sk) >= bw_thresh) {
		hc->full_bw = bbr_max_bw (sk);
		hc->full_bw_cnt = 0;
		return;
	}
	++hc->full_bw_cnt;

	hc->full_bw_reached = hc->full_bw_cnt >= hc->params.full_bw_cnt;
} 

static bool bbr_check_drain (struct sock* sk, const struct rate_sample_ccid6* rs, struct bbr_context* ctx) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	if (hc->mode == BBR_STARTUP && bbr_full_bw_reached (sk)) {
		hc->mode = BBR_DRAIN;
		hc->tx_ssthresh = bbr_inflight (sk, bbr_max_bw (sk), BBR_UNIT);

		bbr2_reset_congestion_signals (hc);
	}	
	if (hc->mode == BBR_DRAIN && bbr_packets_in_net_at_edt (sk, hc->tx_pipe) <= bbr_inflight (sk, bbr_max_bw(sk), BBR_UNIT)) {
		return true; 
	}
	return false;
} 

static void bbr_check_probe_rtt_done (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	ccid6_pr_debug("sk %p hc->probe_rtt_done_stamp %u ccid6_jiffies32 %u", sk, hc->probe_rtt_done_stamp, ccid6_jiffies32);

	if (!(hc->probe_rtt_done_stamp && after (ccid6_jiffies32, hc->probe_rtt_done_stamp))) {
		return;
	}
	hc->probe_rtt_min_stamp = ccid6_jiffies32;

	hc->tx_cwnd = max (hc->tx_cwnd, hc->prior_cwnd);

	bbr2_exit_probe_rtt (sk);
}

static void bbr_update_min_rtt (struct sock* sk, const struct rate_sample_ccid6* rs) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	bool probe_rtt_expired, min_rtt_expired;
	u32 expire;

	if (hc->min_rtt_us == ~0U && rs->rtt_us > 0) {
		hc->min_rtt_us = rs->rtt_us;
		hc->min_rtt_stamp = ccid6_jiffies32;
	}

	expire = hc->probe_rtt_min_stamp + msecs_to_jiffies(hc->params.probe_rtt_win_ms);
	probe_rtt_expired = after (ccid6_jiffies32, expire);
	if (rs->rtt_us >= 0 && (rs->rtt_us <= hc->probe_rtt_min_us || (probe_rtt_expired && !rs->is_ack_delayed))) {
		hc->probe_rtt_min_us = rs->rtt_us;
		hc->probe_rtt_min_stamp = ccid6_jiffies32;
	}
	expire = hc->min_rtt_stamp + hc->params.min_rtt_win_sec * HZ;
	min_rtt_expired = after (ccid6_jiffies32, expire);
	if (hc->probe_rtt_min_us <= hc->min_rtt_us || min_rtt_expired) {
		if (hc->probe_rtt_min_us > 0) /* FIXME */{
			hc->min_rtt_us = hc->probe_rtt_min_us;
			hc->min_rtt_stamp = hc->probe_rtt_min_stamp;
		}
	}
	if (hc->params.probe_rtt_mode_ms > 0 && probe_rtt_expired && !hc->idle_restart && hc->mode != BBR_PROBE_RTT) {
		hc->mode = BBR_PROBE_RTT; 
		bbr_save_cwnd (sk);
		hc->probe_rtt_done_stamp = 0;
		hc->ack_phase = BBR_ACKS_PROBE_STOPPING;
		hc->next_rtt_delivered = hc->delivered;
	}
	if (hc->mode == BBR_PROBE_RTT) {
		hc->app_limited = (hc->delivered + hc->tx_pipe) ? : 1;
		if (!hc->probe_rtt_done_stamp && hc->tx_pipe <= bbr_probe_rtt_cwnd (sk)) {
			hc->probe_rtt_done_stamp = ccid6_jiffies32 + msecs_to_jiffies (hc->params.probe_rtt_mode_ms);
			hc->probe_rtt_round_done = 0;
			hc->next_rtt_delivered = hc->delivered;
		} else if (hc->probe_rtt_done_stamp) {
			if (hc->round_start) {
				hc->probe_rtt_round_done = 1;
			} 
			if (hc->probe_rtt_round_done) {
				bbr_check_probe_rtt_done(sk);
			} 
		}
	}
	if (rs->delivered > 0) {
		hc->idle_restart = 0;
	} 
} 

static void bbr_update_gains (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	switch (hc->mode) {
		case BBR_STARTUP:
			hc->pacing_gain = hc->params.high_gain;
			hc->cwnd_gain = hc->params.startup_cwnd_gain;
			break;
		case BBR_DRAIN:
			hc->pacing_gain = hc->params.drain_gain; 
			hc->cwnd_gain = hc->params.startup_cwnd_gain; 
			break;
		case BBR_PROBE_BW:
			hc->pacing_gain = hc->params.pacing_gain[hc->cycle_idx];
			hc->cwnd_gain = hc->params.cwnd_gain;
			break;
		case BBR_PROBE_RTT:
			hc->pacing_gain = BBR_UNIT;
			hc->cwnd_gain = BBR_UNIT;
			break;
		default:
			break;
	}
} 

/* Double check this, needs to be properly merged with ccid6_hc_tx_init */
static void bbr_init (struct sock* sk, struct ccid6_hc_tx_sock *hc) {
	int i;

	WARN_ON_ONCE(hc->tx_cwnd >= bbr_cwnd_warn_val);

	hc->initialized = 1;
	hc->params.high_gain = min(0x7FF, bbr_high_gain);
	hc->params.drain_gain = min(0x3FF, bbr_drain_gain);
	hc->params.startup_cwnd_gain = min(0x7FF, bbr_startup_cwnd_gain);
	hc->params.cwnd_gain = min(0x7FF, bbr_cwnd_gain);
	hc->params.cwnd_tso_budget = min(0x1U, bbr_cwnd_tso_budget);
	hc->params.cwnd_min_target = min(0xFU, bbr_cwnd_min_target);
	hc->params.min_rtt_win_sec = min(0x1FU, bbr_min_rtt_win_sec);
	hc->params.probe_rtt_mode_ms = min(0x1FFU, bbr_probe_rtt_mode_ms);
	hc->params.full_bw_cnt = min(0x7U, bbr_full_bw_cnt);
	//hc->params.bw_rtts = min(0x1F, bbr_bw_rtts); <----- never used
	hc->params.full_bw_thresh = min(0x3FFU, bbr_full_bw_thresh);
	hc->params.extra_acked_gain = min(0x7FF, bbr_extra_acked_gain);
	hc->params.extra_acked_win_rtts = min(0x1FU, bbr_extra_acked_win_rtts);
	hc->params.drain_to_target = bbr_drain_to_target ? 1 : 0;
	hc->params.precise_ece_ack = bbr_precise_ece_ack ? 1 : 0;
	hc->params.extra_acked_in_startup = bbr_extra_acked_in_startup ? 1 : 0;
	hc->params.probe_rtt_cwnd_gain = min(0xFFU, bbr_probe_rtt_cwnd_gain);
	hc->params.probe_rtt_win_ms = 
		min(0x3FFFU, 
			min_t(u32, bbr_probe_rtt_win_ms,
				  hc->params.min_rtt_win_sec * MSEC_PER_SEC));
	for (i = 0; i < CYCLE_LEN; i++)
		hc->params.pacing_gain[i] = min(0x3FF, bbr_pacing_gain[i]);
	hc->params.usage_based_cwnd = bbr_usage_based_cwnd ? 1 : 0;
	hc->params.tso_rtt_shift =  min(0xFU, bbr_tso_rtt_shift);

	//hc->debug.snd_isn = tp->snd_una; // only used in debug messages
	hc->debug.target_cwnd = 0;
	hc->debug.undo = 0;

	hc->init_cwnd = min(0x7FU, hc->tx_cwnd);
	hc->prior_cwnd = 0;
	// ssthresh (is set in ccid6)
	hc->next_rtt_delivered = 0;
	hc->prev_ca_state = DCCP_CA_Open;
	hc->packet_conservation = 0;

	hc->probe_rtt_done_stamp = 0;
	hc->probe_rtt_round_done = 0;
	hc->probe_rtt_min_us = ~0U; // <-----
	hc->probe_rtt_min_stamp = ccid6_jiffies32;
	hc->min_rtt_us = ~0U; // ?
	hc->min_rtt_stamp = ccid6_jiffies32;

	hc->has_seen_rtt = 0;
	/* We do not call bbr_init_pacing_rate_from_rtt from here, intentionally.
	 * This is done only when a data packet has been sent, 
	 * i.e. in ccid6_hc_tx_send_packet.
	 */

	hc->round_start = 0;
	hc->idle_restart = 0;
	hc->full_bw_reached = 0;
	hc->full_bw = 0;
	hc->full_bw_cnt = 0;
	hc->cycle_mstamp = 0;
	hc->cycle_idx = 0;
	hc->mode = BBR_STARTUP;
	hc->debug.rs_bw = 0;

	hc->ack_epoch_mstamp = dccp_sk(sk)->dccps_mstamp;
	hc->ack_epoch_acked = 0;
	hc->extra_acked_win_rtts = 0;
	hc->extra_acked_win_idx = 0;
	hc->extra_acked[0] = 0;
	hc->extra_acked[1] = 0;

	hc->ce_state = 0;
	//hc->prior_rcv_nxt = dp->dccps_gsr; //or dccps_gsr + 1 ???
	hc->try_fast_path = 0;

	cmpxchg (&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
} 

/* static u32 bbr_sndbuf_expand(struct sock *sk) {
   return 0;
   } */

// ** BBRv2 ******************************************************************************

static void bbr2_take_bw_hi_sample (struct sock* sk, u32 bw) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	hc->bw_hi[1] = max (bw, hc->bw_hi[1]);
} 

static void bbr2_advance_bw_hi_filter (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	if (!hc->bw_hi[1]) {
		return; 
	}
	hc->bw_hi[0] = hc->bw_hi[1];
	hc->bw_hi[1] = 0;
} 

static u32 bbr2_target_inflight (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	u32 bdp = bbr_inflight (sk, bbr_bw (sk), BBR_UNIT);
	return min (bdp, hc->tx_cwnd);
} 

static bool bbr2_is_probing_bandwidth (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	return (hc->mode == BBR_STARTUP) || (hc->mode == BBR_PROBE_BW && (hc->cycle_idx == BBR_BW_PROBE_REFILL || hc->cycle_idx == BBR_BW_PROBE_UP));
}

static bool bbr2_has_elapsed_in_phase (const struct sock* sk, u32 interval_us) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	return tcp_stamp_us_delta (dccp_sk(sk)->dccps_mstamp, hc->cycle_mstamp + interval_us) > 0;
} 

static void bbr2_handle_queue_too_high_in_startup (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	hc->full_bw_reached = 1;
	hc->inflight_hi = bbr_inflight (sk, bbr_max_bw (sk), BBR_UNIT);
}

static void bbr2_check_ecn_too_high_in_startup (struct sock* sk, u32 ce_ratio) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	if (bbr_full_bw_reached (sk) || !hc->ecn_eligible || !hc->params.full_ecn_cnt || !hc->params.ecn_thresh) {
		return;
	}
	if (ce_ratio >= hc->params.ecn_thresh) {
		hc->startup_ecn_rounds++;
	} else {
		hc->startup_ecn_rounds = 0;
	}
	if (hc->startup_ecn_rounds >= hc->params.full_ecn_cnt) {
		bbr2_handle_queue_too_high_in_startup (sk);
		return;
	} 
}

static void bbr2_update_ecn_alpha (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	s32 delivered, delivered_ce;
	u64 alpha, ce_ratio;
	u32 gain;
	if (hc->params.ecn_factor == 0) {
		return;
	}
	delivered = hc->delivered - hc->alpha_last_delivered;
	delivered_ce = hc->delivered_ce - hc->alpha_last_delivered_ce;
	if (delivered == 0) {
		return;
	}
	if (!hc->ecn_eligible && bbr_ecn_enable && (hc->min_rtt_us <= hc->params.ecn_max_rtt_us || !hc->params.ecn_max_rtt_us)) {
		hc->ecn_eligible = 1;
	}
	ce_ratio = (u64)delivered_ce << BBR_SCALE;
	do_div (ce_ratio, delivered);
	gain = hc->params.ecn_alpha_gain;
	alpha = ((BBR_UNIT - gain) * hc->ecn_alpha) >> BBR_SCALE;
	alpha += (gain * ce_ratio) >> BBR_SCALE;
	hc->ecn_alpha = min_t (u32, alpha, BBR_UNIT);
	hc->alpha_last_delivered = hc->delivered;
	hc->alpha_last_delivered_ce = hc->delivered_ce;
	bbr2_check_ecn_too_high_in_startup (sk, ce_ratio);
}

static void bbr2_raise_inflight_hi_slope (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	u32 growth_this_round, cnt;
	growth_this_round = 1 << hc->bw_probe_up_rounds;
	hc->bw_probe_up_rounds = min (hc->bw_probe_up_rounds + 1, 30);
	cnt = hc->tx_cwnd / growth_this_round;
	cnt = max (cnt, 1U);
	hc->bw_probe_up_cnt = cnt;
} 

static void bbr2_probe_inflight_hi_upward (struct sock* sk, const struct rate_sample_ccid6* rs) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	u32 delta;
	// not sure about the below line
	if (!ccid6_cwnd_network_limited(hc) || hc->tx_cwnd < hc->inflight_hi) {	
		hc->bw_probe_up_acks = 0;  
		return;  
	}
	hc->bw_probe_up_acks += rs->acked_sacked;
	if (hc->bw_probe_up_acks >=  hc->bw_probe_up_cnt) {
		delta = hc->bw_probe_up_acks / hc->bw_probe_up_cnt;
		hc->bw_probe_up_acks -= delta * hc->bw_probe_up_cnt;
		hc->inflight_hi += delta;
	}
	if (hc->round_start) {
		bbr2_raise_inflight_hi_slope (sk);
	} 
} 

static bool bbr2_is_inflight_too_high (const struct sock* sk, const struct rate_sample_ccid6 * rs) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	u32 loss_thresh, ecn_thresh;
	if (rs->lost > 0 && rs->tx_in_flight) {
		loss_thresh = (u64)rs->tx_in_flight * hc->params.loss_thresh >> BBR_SCALE;
		if (rs->lost > loss_thresh) {
			return true;
		}
	}
	if (rs->delivered_ce > 0 && rs->delivered > 0 && hc->ecn_eligible && hc->params.ecn_thresh) {
		ecn_thresh = (u64)rs->delivered * hc->params.ecn_thresh >> BBR_SCALE;
		if (rs->delivered_ce >= ecn_thresh) {
			return true;
		}
	}
	return false;
} 

static u32 bbr2_inflight_hi_from_lost_skb (const struct sock* sk, const struct rate_sample_ccid6* rs, u32 pcount) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);		
	u32 loss_thresh = hc->params.loss_thresh;
	u32 divisor, inflight_hi;
	s32 inflight_prev, lost_prev;
	u64 loss_budget, lost_prefix;
	//pcount = tcp_skb_pcount (skb); // This is supposed to keep track of how many actual packets we have, in case of TSO (but no TSO here). Can we assume that this is always equal to 1?

	inflight_prev = rs->tx_in_flight - pcount;
	if (inflight_prev < 0) {
		return ~0U;
	}
	lost_prev = rs->lost - pcount;
	if (lost_prev < 0) {
		return ~0U;
	}
	loss_budget = (u64)inflight_prev * loss_thresh + BBR_UNIT - 1;
	loss_budget >>= BBR_SCALE;
	if (lost_prev >= loss_budget) {
		lost_prefix = 0; 
	} else {
		lost_prefix = loss_budget - lost_prev;
		lost_prefix <<= BBR_SCALE;
		divisor = BBR_UNIT - loss_thresh;
		if (!divisor) { 
			return ~0U;
		}
		do_div (lost_prefix, divisor);
	}
	inflight_hi = inflight_prev + lost_prefix;
	return inflight_hi;
} 

static u32 bbr2_inflight_with_headroom (const struct sock *sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	u32 headroom, headroom_fraction;
	if (hc->inflight_hi == ~0U) {
		return ~0U;
	}
	headroom_fraction = hc->params.inflight_headroom;
	headroom = ((u64)hc->inflight_hi * headroom_fraction) >> BBR_SCALE;
	headroom = max (headroom, 1U);
	return max_t(s32, hc->inflight_hi - headroom, hc->params.cwnd_min_target);
} 

static void bbr2_bound_cwnd_for_inflight_model (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	u32 cap;
	if (!hc->initialized) {
		return;
	}
	cap = ~0U;
	if (hc->mode == BBR_PROBE_BW && hc->cycle_idx != BBR_BW_PROBE_CRUISE) {
		cap = hc->inflight_hi;
	} else {
		if (hc->mode == BBR_PROBE_RTT || (hc->mode == BBR_PROBE_BW && hc->cycle_idx == BBR_BW_PROBE_CRUISE)) {
			cap = bbr2_inflight_with_headroom (sk);
		}
	}
	cap = min (cap, hc->inflight_lo);
	cap = max_t (u32, cap, hc->params.cwnd_min_target);

	hc->tx_cwnd = min (cap, hc->tx_cwnd);
} 

static void bbr2_adapt_lower_bounds (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	u32 ecn_cut, ecn_inflight_lo, beta;

	/* We only use lower-bound estimates when not probing bw.
	 * When probing we need to push inflight higher to probe bw.
	 */
	if (bbr2_is_probing_bandwidth (sk)) {
		return;
	}

	/* ECN response. */
	if (hc->ecn_in_round && hc->ecn_eligible && hc->params.ecn_factor) {
		ecn_cut = (BBR_UNIT - ((hc->ecn_alpha * hc->params.ecn_factor) >> BBR_SCALE));
		if (hc->inflight_lo == ~0U) {
			hc->inflight_lo = hc->tx_cwnd;
		}
		ecn_inflight_lo = (u64)hc->inflight_lo * ecn_cut >> BBR_SCALE;
	} else {
		ecn_inflight_lo = ~0U;
	}

	/* Loss response. */
	if (hc->loss_in_round) {
		ccid6_pr_debug("sk=%p loss_in_round", sk);
		/* Reduce bw and inflight to (1 - beta). */
		if (hc->bw_lo == ~0U) {
			hc->bw_lo = bbr_max_bw(sk);
		}
		if (hc->inflight_lo == ~0U) {
			hc->inflight_lo = hc->tx_cwnd;
		}
		beta = hc->params.beta;
		hc->bw_lo = max_t(u32, hc->bw_latest, (u64)hc->bw_lo * (BBR_UNIT - beta) >> BBR_SCALE);
		hc->inflight_lo = max_t(u32, hc->inflight_latest, (u64)hc->inflight_lo * (BBR_UNIT - beta) >> BBR_SCALE);
		
	}

	/* Adjust to the lower of the levels implied by loss or ECN. */
	hc->inflight_lo = min (hc->inflight_lo, ecn_inflight_lo);
} 

static void bbr2_reset_lower_bounds (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	hc->bw_lo = ~0U;
	hc->inflight_lo = ~0U;
} 

static void bbr2_reset_congestion_signals (struct ccid6_hc_tx_sock *hc) {
	hc->loss_in_round = 0;
	hc->ecn_in_round = 0;
	hc->loss_in_cycle = 0;
	hc->ecn_in_cycle = 0;
	hc->bw_latest = 0;
	hc->inflight_latest = 0;
} 

static void bbr2_update_congestion_signals (struct sock* sk, const struct rate_sample_ccid6* rs, struct bbr_context* ctx) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	u64 bw;
	hc->loss_round_start = 0;
	if (rs->interval_us <= 0 || !rs->acked_sacked) {
		return; 
	}
	bw = ctx->sample_bw;
	if (!rs->is_app_limited || bw >= bbr_max_bw (sk)) {
		bbr2_take_bw_hi_sample (sk, bw);
	}
	hc->loss_in_round |= (rs->losses > 0);
	hc->bw_latest = max_t (u32, hc->bw_latest, ctx->sample_bw);
	hc->inflight_latest = max_t (u32, hc->inflight_latest, rs->delivered);
	if (before (rs->prior_delivered, hc->loss_round_delivered)) {
		return;	
	}
	hc->loss_round_delivered = hc->delivered; 
	hc->loss_round_start = 1;
	bbr2_adapt_lower_bounds (sk);
	hc->loss_in_round = 0;
	hc->ecn_in_round  = 0;
	hc->bw_latest = ctx->sample_bw;
	hc->inflight_latest = rs->delivered;
} 

static bool bbr2_is_reno_coexistence_probe_time (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	u32 inflight, rounds, reno_gain, reno_rounds;
	rounds = hc->params.bw_probe_max_rounds;
	reno_gain = hc->params.bw_probe_reno_gain;
	if (reno_gain) {
		inflight = bbr2_target_inflight (sk);
		reno_rounds = ((u64)inflight * reno_gain) >> BBR_SCALE;
		rounds = min (rounds, reno_rounds);
	}
	return hc->rounds_since_probe >= rounds;
} 

static void bbr2_pick_probe_wait (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	hc->rounds_since_probe = prandom_u32_max (hc->params.bw_probe_rand_rounds);
	hc->probe_wait_us = hc->params.bw_probe_base_us + prandom_u32_max (hc->params.bw_probe_rand_us);
} 

static void bbr2_set_cycle_idx (struct sock* sk, int cycle_idx) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	hc->cycle_idx = cycle_idx;
	hc->try_fast_path = 0;
} 

static void bbr2_start_bw_probe_refill (struct sock* sk, u32 bw_probe_up_rounds) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	bbr2_reset_lower_bounds (sk);
	if (hc->inflight_hi != ~0U) {
		hc->inflight_hi += hc->params.refill_add_inc;
	}
	hc->bw_probe_up_rounds = bw_probe_up_rounds;
	hc->bw_probe_up_acks = 0;
	hc->stopped_risky_probe = 0;
	hc->ack_phase = BBR_ACKS_REFILLING;
	hc->next_rtt_delivered = hc->delivered;
	bbr2_set_cycle_idx(sk, BBR_BW_PROBE_REFILL);
} 

static void bbr2_start_bw_probe_up (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	hc->ack_phase = BBR_ACKS_PROBE_STARTING;
	hc->next_rtt_delivered = hc->delivered;
	hc->cycle_mstamp = dccp_sk(sk)->dccps_mstamp;
	bbr2_set_cycle_idx (sk, BBR_BW_PROBE_UP);
	bbr2_raise_inflight_hi_slope (sk);
} 

static void bbr2_start_bw_probe_down (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	bbr2_reset_congestion_signals (hc);
	hc->bw_probe_up_cnt = ~0U; 
	bbr2_pick_probe_wait (sk);
	hc->cycle_mstamp = dccp_sk(sk)->dccps_mstamp;
	hc->ack_phase = BBR_ACKS_PROBE_STOPPING;
	hc->next_rtt_delivered = hc->delivered;
	bbr2_set_cycle_idx (sk, BBR_BW_PROBE_DOWN);
}

static void bbr2_start_bw_probe_cruise (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	if (hc->inflight_lo != ~0U) {
		hc->inflight_lo = min (hc->inflight_lo, hc->inflight_hi);
	}
	bbr2_set_cycle_idx (sk, BBR_BW_PROBE_CRUISE); 
} 

static void bbr2_handle_inflight_too_high (struct sock* sk, const struct rate_sample_ccid6* rs) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	const u32 beta = hc->params.beta;
	hc->prev_probe_too_high = 1;
	hc->bw_probe_samples = 0;  
	if (!rs->is_app_limited) {
		hc->inflight_hi = max_t(u32, rs->tx_in_flight, (u64)bbr2_target_inflight (sk) * (BBR_UNIT - beta) >> BBR_SCALE);
	}
	if (hc->mode == BBR_PROBE_BW && hc->cycle_idx == BBR_BW_PROBE_UP) {
		bbr2_start_bw_probe_down (sk);
	} 
} 

static bool bbr2_adapt_upper_bounds (struct sock* sk, const struct rate_sample_ccid6* rs) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	if (hc->ack_phase == BBR_ACKS_PROBE_STARTING && hc->round_start) {
		hc->ack_phase = BBR_ACKS_PROBE_FEEDBACK;
	}
	if (hc->ack_phase == BBR_ACKS_PROBE_STOPPING && hc->round_start) {
		hc->bw_probe_samples = 0;
		hc->ack_phase = BBR_ACKS_INIT;
		if (hc->mode == BBR_PROBE_BW && !rs->is_app_limited) {
			bbr2_advance_bw_hi_filter (sk);
		}
		if (hc->mode == BBR_PROBE_BW && hc->stopped_risky_probe && !hc->prev_probe_too_high) {
			bbr2_start_bw_probe_refill (sk, 0);
			return true;  
		}
	}
	if (bbr2_is_inflight_too_high(sk, rs)) {
		if (hc->bw_probe_samples) {
			bbr2_handle_inflight_too_high(sk, rs);
		}
	} else {
		if (hc->inflight_hi == ~0U) {
			return false;
		}
		if (rs->tx_in_flight > hc->inflight_hi) {
			hc->inflight_hi = rs->tx_in_flight;
		}

		if (hc->mode == BBR_PROBE_BW && hc->cycle_idx == BBR_BW_PROBE_UP) {
			bbr2_probe_inflight_hi_upward (sk, rs);
		}
	}

	return false;
} 

static bool bbr2_check_time_to_probe_bw (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	u32 n;
	if (hc->params.ecn_reprobe_gain && hc->ecn_eligible && hc->ecn_in_cycle && !hc->loss_in_cycle && hc->curr_ca_state == DCCP_CA_Open) {
		n = ilog2((((u64)hc->inflight_hi * hc->params.ecn_reprobe_gain) >> BBR_SCALE));
		bbr2_start_bw_probe_refill (sk, n);
		return true;
	}
	if (bbr2_has_elapsed_in_phase (sk, hc->probe_wait_us) || bbr2_is_reno_coexistence_probe_time (sk)) {
		bbr2_start_bw_probe_refill (sk, 0);
		return true;
	}
	return false;
} 

static bool bbr2_check_time_to_cruise (struct sock* sk, u32 inflight, u32 bw) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	bool is_under_bdp, is_long_enough;
	if (inflight > bbr2_inflight_with_headroom (sk)) {
		return false;
	}
	is_under_bdp = inflight <= bbr_inflight (sk, bw, BBR_UNIT);
	if (hc->params.drain_to_target) {
		return is_under_bdp;
	}
	is_long_enough = bbr2_has_elapsed_in_phase (sk, hc->min_rtt_us);

	return is_under_bdp || is_long_enough;
} 

static void bbr2_update_cycle_phase (struct sock* sk, const struct rate_sample_ccid6* rs) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	bool is_risky = false, is_queuing = false;
	u32 inflight, bw;
	if (!bbr_full_bw_reached (sk)) {
		return;
	}
	if (bbr2_adapt_upper_bounds (sk, rs)) {
		return;	
	}
	if (hc->mode != BBR_PROBE_BW) {
		return;
	}
	inflight = bbr_packets_in_net_at_edt (sk, rs->prior_in_flight);
	bw = bbr_max_bw (sk);
	switch (hc->cycle_idx) {
		case BBR_BW_PROBE_CRUISE:
			if (bbr2_check_time_to_probe_bw (sk))
				return;	
			break;
		case BBR_BW_PROBE_REFILL:
			if (hc->round_start) {
				hc->bw_probe_samples = 1;
				bbr2_start_bw_probe_up(sk);
			}
			break;
		case BBR_BW_PROBE_UP:
			if (hc->prev_probe_too_high &&
					inflight >= hc->inflight_hi) {
				hc->stopped_risky_probe = 1;
				is_risky = true;
			} else if (bbr2_has_elapsed_in_phase (sk, hc->min_rtt_us) && inflight >= bbr_inflight (sk, bw, hc->params.bw_probe_pif_gain)) {
				is_queuing = true;
			}
			if (is_risky || is_queuing) {
				hc->prev_probe_too_high = 0;
				bbr2_start_bw_probe_down(sk);
			}
			break;
		case BBR_BW_PROBE_DOWN:
			if (bbr2_check_time_to_probe_bw (sk))
				return;
			if (bbr2_check_time_to_cruise (sk, inflight, bw))
				bbr2_start_bw_probe_cruise (sk);
			break;
		default:
			break;
	}
} 

static void bbr2_exit_probe_rtt (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	bbr2_reset_lower_bounds (sk);
	if (bbr_full_bw_reached (sk)) {
		hc->mode = BBR_PROBE_BW;
		bbr2_start_bw_probe_down (sk);
		bbr2_start_bw_probe_cruise (sk);
	} else {
		hc->mode = BBR_STARTUP;
	}
} 

static void bbr2_check_loss_too_high_in_startup (struct sock* sk, const struct rate_sample_ccid6* rs) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	if (bbr_full_bw_reached (sk)) {
		return;
	}
	if (rs->losses && hc->loss_events_in_round < 0xf) {
		hc->loss_events_in_round++;
	}
	if (hc->params.full_loss_cnt && hc->loss_round_start && hc->curr_ca_state == DCCP_CA_Recovery && hc->loss_events_in_round >= hc->params.full_loss_cnt && bbr2_is_inflight_too_high(sk, rs)) {
		bbr2_handle_queue_too_high_in_startup (sk);
		return;
	}
	if (hc->loss_round_start) {
		hc->loss_events_in_round = 0;
	} 
} 

static void bbr2_check_drain (struct sock* sk, const struct rate_sample_ccid6* rs, struct bbr_context* ctx) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	if (bbr_check_drain (sk, rs, ctx)) {
		hc->mode = BBR_PROBE_BW;
		bbr2_start_bw_probe_down (sk);
	}
} 

static void bbr2_update_model (struct sock* sk, const struct rate_sample_ccid6* rs, struct bbr_context* ctx) {
	bbr2_update_congestion_signals (sk, rs, ctx);
	bbr_update_ack_aggregation (sk, rs);
	bbr2_check_loss_too_high_in_startup (sk, rs);
	bbr_check_full_bw_reached (sk, rs);
	bbr2_check_drain (sk, rs, ctx);
	bbr2_update_cycle_phase (sk, rs);
	bbr_update_min_rtt (sk, rs);
} 

static bool bbr2_fast_path (struct sock* sk, bool* update_model, const struct rate_sample_ccid6* rs, struct bbr_context* ctx) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	u32 prev_min_rtt_us, prev_mode;
	if (hc->params.fast_path && hc->try_fast_path && rs->is_app_limited && ctx->sample_bw < bbr_max_bw (sk) && !hc->loss_in_round && !hc->ecn_in_round) {
		prev_mode = hc->mode;
		prev_min_rtt_us = hc->min_rtt_us;
		bbr2_check_drain (sk, rs, ctx);
		bbr2_update_cycle_phase (sk, rs);
		bbr_update_min_rtt (sk, rs);
		if (hc->mode == prev_mode && hc->min_rtt_us == prev_min_rtt_us && hc->try_fast_path) {
			return true;
		}
		*update_model = false;
	}
	return false;
} 

void bbr2_main (struct sock* sk, const struct rate_sample_ccid6* rs) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	struct bbr_context ctx = { 0 };
	bool update_model = true;
	u32 bw;
	bbr_update_round_start (sk, rs, &ctx);
	if (hc->round_start) {
		hc->rounds_since_probe = min_t (s32, hc->rounds_since_probe + 1, 0xFF);
		bbr2_update_ecn_alpha (sk);
	}

	hc->ecn_in_round |= rs->is_ece;
	bbr_calculate_bw_sample (sk, rs, &ctx);
	
	if (bbr2_fast_path (sk, &update_model, rs, &ctx)) {
		goto out;
	}
	
	if (update_model) {
		bbr2_update_model (sk, rs, &ctx);
	}
	
	bbr_update_gains (sk);
	bw = bbr_bw (sk);
	bbr_set_pacing_rate (sk, bw, hc->pacing_gain);
	bbr_set_cwnd (sk, rs, rs->acked_sacked, bw, hc->cwnd_gain, hc->tx_cwnd, &ctx);
	bbr2_bound_cwnd_for_inflight_model (sk);

	ccid6_pr_debug("sk=%p bw=%d hc->bw_lo=%u, hc->bw_hi[0]=%d, hc->bw_hi[1]=%d, sample_rate=%lldkbps, hc->mode=%d, hc->cycle_idx=%d\n", sk, bw, hc->bw_lo, hc->bw_hi[0], hc->bw_hi[1], bbr_rate_kbps(sk, ctx.sample_bw), hc->mode, hc->cycle_idx);

out:
	hc->prev_ca_state = hc->curr_ca_state;

	hc->loss_in_cycle |= rs->lost > 0;
	hc->ecn_in_cycle |= rs->delivered_ce > 0;

	ccid6_pr_debug("sk=%p mode=%d phase=%d min_rtt=%d cwnd=%d cwnd_gain=%d pacing_gain=%d\n",
	 		sk, hc->mode, hc->cycle_idx, hc->min_rtt_us, 
			hc->tx_cwnd, hc->cwnd_gain, hc->pacing_gain);

}

static void bbr2_init (struct sock* sk, struct ccid6_hc_tx_sock *hc) {	
	bbr_init (sk, hc);
	hc->params.beta = min_t(u32, 0xFFU, bbr_beta);
	hc->params.ecn_alpha_gain = min_t(u32, 0xFFU, bbr_ecn_alpha_gain);
	hc->params.ecn_alpha_init = min_t(u32, BBR_UNIT, bbr_ecn_alpha_init);
	hc->params.ecn_factor = min_t(u32, 0xFFU, bbr_ecn_factor);
	hc->params.ecn_thresh = min_t(u32, 0xFFU, bbr_ecn_thresh);
	hc->params.ecn_max_rtt_us = min_t(u32, 0x7ffffU, bbr_ecn_max_rtt_us);
	hc->params.ecn_reprobe_gain = min_t(u32, 0x1FF, bbr_ecn_reprobe_gain);
	hc->params.loss_thresh = min_t(u32, 0xFFU, bbr_loss_thresh);
	hc->params.full_loss_cnt = min_t(u32, 0xFU, bbr_full_loss_cnt);
	hc->params.full_ecn_cnt = min_t(u32, 0x3U, bbr_full_ecn_cnt);
	hc->params.inflight_headroom = min_t(u32, 0xFFU, bbr_inflight_headroom);
	hc->params.bw_probe_pif_gain = min_t(u32, 0x1FFU, bbr_bw_probe_pif_gain);
	hc->params.bw_probe_reno_gain = min_t(u32, 0x1FFU, bbr_bw_probe_reno_gain);
	hc->params.bw_probe_max_rounds = min_t(u32, 0xFFU, bbr_bw_probe_max_rounds);
	hc->params.bw_probe_rand_rounds = min_t(u32, 0xFU, bbr_bw_probe_rand_rounds);
	hc->params.bw_probe_base_us = min_t(u32, (1 << 26) - 1, bbr_bw_probe_base_us);
	hc->params.bw_probe_rand_us = min_t(u32, (1 << 26) - 1, bbr_bw_probe_rand_us);
	hc->params.undo = bbr_undo;
	hc->params.fast_path = bbr_fast_path ? 1 : 0;
	hc->params.refill_add_inc = min_t(u32, 0x3U, bbr_refill_add_inc);

	/* BBR v2 state: */
	hc->initialized = 1;
	/* Start sampling ECN mark rate after first full flight is ACKed: */
	hc->loss_round_delivered = hc->delivered + 1;
	hc->loss_round_start = 0;
	hc->undo_bw_lo = 0;
	hc->undo_inflight_lo = 0;
	hc->undo_inflight_hi = 0;
	hc->loss_events_in_round = 0;
	hc->startup_ecn_rounds = 0;
	bbr2_reset_congestion_signals(hc);
	hc->bw_lo = ~0U;
	hc->bw_hi[0] = 0;
	hc->bw_hi[1] = 0;
	hc->inflight_lo = ~0U;
	hc->inflight_hi = ~0U;
	hc->bw_probe_up_cnt = ~0U;
	hc->bw_probe_up_acks = 0;
	hc->bw_probe_up_rounds = 0;
	hc->probe_wait_us = 0;
	hc->stopped_risky_probe = 0;
	hc->ack_phase = BBR_ACKS_INIT;
	hc->rounds_since_probe = 0;
	hc->bw_probe_samples = 0;
	hc->prev_probe_too_high = 0;
	hc->ecn_eligible = 0;
	hc->ecn_alpha = hc->params.ecn_alpha_init;
	hc->alpha_last_delivered = 0;
	hc->alpha_last_delivered_ce = 0;

	//tp->fast_ack_mode = min_t(u32, 0x2U, bbr_fast_ack_mode); // NA

	// What to do here?
	/*if((tp->ecn_flags & TCP_ECN_OK) && bbr_ecn_enable)
		tp->ecn_flags |= TCP_ECN_ECT_PERMANENT;*/
}

/* Called when the given skb was just marked lost.*/
static void bbr2_skb_marked_lost (struct sock* sk, const struct ccid6_seq* seqp) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	struct rate_sample_ccid6 rs;
	
	/* Capture "current" data over the full round trip of loss,
	 * to have a better chance to see the full capacity of the path.
	*/
	if (!hc->loss_in_round) /* first loss in this round trip? */ {
		hc->loss_round_delivered = hc->delivered; /* set round trip */
	}
	hc->loss_in_round = 1;
	hc->loss_in_cycle = 1;

	if (!hc->bw_probe_samples) {
		return; /* not an skb sent while probing for bandwidth */
	}
	if (unlikely (!seqp->delivered_mstamp)) {
		return; /* skb was SACKed, reneged, marked lost; ignore it */
	}
	/* We are probing for bandwidth. Construct a rate sample that
	 * estimates what happened in the flight leading up to this lost skb,
	 * then see if the loss rate went too high, and if so at which packet.
	 */
	memset (&rs, 0, sizeof (rs));
	rs.tx_in_flight = seqp->in_flight;

	rs.lost = hc->lost - seqp->lost;
	rs.is_app_limited = seqp->is_app_limited;
	if (bbr2_is_inflight_too_high (sk, &rs)) {
		rs.tx_in_flight = bbr2_inflight_hi_from_lost_skb (sk, &rs, 1);
		bbr2_handle_inflight_too_high (sk, &rs);
	}
}

// When to call this?
/*static u32 bbr2_undo_cwnd (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	hc->debug_undo = 1;
	hc->full_bw = 0;   
	hc->full_bw_cnt = 0;
	hc->loss_in_round = 0;

	if (!hc->params.undo) {
		return hc->tx_cwnd;
	}

	hc->bw_lo = max (hc->bw_lo, hc->undo_bw_lo);
	hc->inflight_lo = max (hc->inflight_lo, hc->undo_inflight_lo);
	hc->inflight_hi = max (hc->inflight_hi, hc->undo_inflight_hi);
	return hc->prior_cwnd;
}*/

// Never called by CCID5
// Called upon entering loss recovery
static u32 bbr2_ssthresh (struct sock* sk) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	bbr_save_cwnd (sk);
	hc->undo_bw_lo	 = hc->bw_lo;
	hc->undo_inflight_lo	= hc->inflight_lo;
	hc->undo_inflight_hi	= hc->inflight_hi;
	return hc->tx_ssthresh;
}

/*static enum tcp_bbr2_phase bbr2_get_phase (struct ccid6_hc_tx_sock *hc) {
	switch (hc->mode) {
		case BBR_STARTUP:
			return BBR2_PHASE_STARTUP;
		case BBR_DRAIN:
			return BBR2_PHASE_DRAIN;
		case BBR_PROBE_BW:
			break;
		case BBR_PROBE_RTT:
			return BBR2_PHASE_PROBE_RTT;
		default:
			return BBR2_PHASE_INVALID;
	}
	switch (hc->cycle_idx) {
		case BBR_BW_PROBE_UP:
			return BBR2_PHASE_PROBE_BW_UP;
		case BBR_BW_PROBE_DOWN:
			return BBR2_PHASE_PROBE_BW_DOWN;
		case BBR_BW_PROBE_CRUISE:
			return BBR2_PHASE_PROBE_BW_CRUISE;
		case BBR_BW_PROBE_REFILL:
			return BBR2_PHASE_PROBE_BW_REFILL;
		default:
			return BBR2_PHASE_INVALID;
	}
}*/

/* static size_t bbr2_get_info (struct sock* sk, u32 ext, int* attr, union tcp_cc_info* info) {
   return 0;
   } */

static void bbr2_set_state (struct sock* sk, u8 new_state) {
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	if (new_state == DCCP_CA_Loss) {
		hc->prev_ca_state = DCCP_CA_Loss;
		hc->full_bw = 0;
		if (!bbr2_is_probing_bandwidth (sk) && hc->inflight_lo == ~0U) {
			hc->inflight_lo = hc->prior_cwnd;
		}
	} else if (hc->prev_ca_state == DCCP_CA_Loss && new_state != DCCP_CA_Loss) {
		hc->tx_cwnd = max (hc->tx_cwnd, hc->prior_cwnd);
		hc->try_fast_path = 0; 
	}
}

/*****************************************************/
/*       FUNCTIONS PART OF tcp_bbr2.c END HERE       */
/*****************************************************/
static void ccid6_hc_tx_rto_expire(struct timer_list *t)
{
	//struct sock *sk = (struct sock *)data;
	//struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	struct ccid6_hc_tx_sock *hc = from_timer(hc, t, tx_rtotimer);
	struct sock *sk = hc->sk;
	const bool sender_was_blocked = ccid6_cwnd_network_limited(hc);

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

	/* Mark loss */
	bbr2_skb_marked_lost(sk, hc->tx_seqt); // is this enough? <---------------------------------

	/* adjust pipe, cwnd etc */
	hc->tx_ssthresh = bbr2_ssthresh(sk);
	if (hc->tx_ssthresh < 2)
		hc->tx_ssthresh = 2;

	hc->lost += hc->tx_pipe; // not sure
	hc->tx_cwnd	= 1; // not sure
	hc->tx_pipe	= 0; // not sure
	bbr2_set_state(sk, DCCP_CA_Loss);

	/* clear state about stuff we sent */
	hc->tx_seqt = hc->tx_seqh;

	/* clear ack ratio state. */
	hc->tx_rpseq    = 0;
	hc->tx_rpdupack = -1;
	ccid6_change_l_ack_ratio(sk, 1);

	/* if we were blocked before, we may now send cwnd=1 packet */
	if (sender_was_blocked)
		dccp_tasklet_schedule(sk);
	/* restart backed-off timer */
	sk_reset_timer(sk, &hc->tx_rtotimer, jiffies + hc->tx_rto);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static int ccid6_hc_tx_send_packet(struct sock *sk, struct sk_buff *skb)
{
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	if (!hc->pr_init) {
		/* alerab: Pacing rate is initialized here, and only here.
		 * This is so that pacing does not block outgoing acks when
		 * data traffic is unidirectional.
		*/
		bbr_init_pacing_rate_from_rtt(sk, hc);
	}
	
	ccid6_rate_check_app_limited(sk, skb->truesize); 
	hc->bytes_att += skb->len;

	/* Allow extra packet(s) to be sent during the drain phase */
	if (hc->mode==BBR_PROBE_RTT && hc->tx_extrapkt) {
		hc->tx_extrapkt = false;
		return CCID_PACKET_SEND_AT_ONCE;
	}

	if (ccid6_cwnd_network_limited(hc))
		return CCID_PACKET_WILL_DEQUEUE_LATER;
	return CCID_PACKET_SEND_AT_ONCE;
}


static int ccid6_hc_tx_parse_options(struct sock *sk, u8 packet_type,
					 u8 option, u8 *optval, u8 optlen)
{
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);

	switch (option) {
	case DCCPO_ACK_VECTOR_0:
	case DCCPO_ACK_VECTOR_1:
		return dccp_ackvec_parsed_add(&hc->tx_av_chunks, optval, optlen,
						  option - DCCPO_ACK_VECTOR_0);
	}
	return 0;
}

static void ccid6_hc_tx_packet_recv(struct sock *sk, struct sk_buff *skb)
{
	struct dccp_sock *dp = dccp_sk(sk);
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	const bool sender_was_blocked = ccid6_cwnd_network_limited(hc);
	struct dccp_ackvec_parsed *avp;
	u64 ackno, seqno;
	struct ccid6_seq *seqp;
	int done = 0;
	bool not_rst = 0;
	unsigned int maxincr = 0;
	struct rate_sample_ccid6 rs_i = { .prior_delivered = 0 };
	struct rate_sample_ccid6 *rs = &rs_i;
	u32 delivered = hc->delivered;
	u32 lost = hc->lost;
	u64 now_mstamp;
	bool loss_event = false;

	/* Get timestamp */
	now_mstamp = dp->dccps_mstamp;

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
#ifdef __CCID6_COPES_GRACEFULLY_WITH_ACK_CONGESTION_CONTROL__
				/*
				 * FIXME: Ack Congestion Control is broken; in
				 * the current state instabilities occurred with
				 * Ack Ratios greater than 1; causing hang-ups
				 * and long RTO timeouts. This needs to be fixed
				 * before opening up dynamic changes. -- gerrit
				 */
				ccid6_change_l_ack_ratio(sk, 2 * dp->dccps_l_ack_ratio);
#endif
			}
		}
	}

	/* check forward path congestion */
	if (dccp_packet_without_ack(skb)) {
		return;
	}

	/* still didn't send out new data packets */
	if (hc->tx_seqh == hc->tx_seqt) {
		/* Is this the reason for the lockups? No, but it helps. */
		goto done;
	}

	ackno = DCCP_SKB_CB(skb)->dccpd_ack_seq;
	if (after48(ackno, hc->tx_high_ack))
		hc->tx_high_ack = ackno;

	seqp = hc->tx_seqt;
	while (before48(seqp->ccid6s_seq, ackno)) {
		seqp = seqp->ccid6s_next;
		if (seqp == hc->tx_seqh) {
			seqp = hc->tx_seqh->ccid6s_prev;
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
			u64 ackno_end_rl = SUB48(ackno,
						 dccp_ackvec_runlen(avp->vec));
			/* if the seqno we are analyzing is larger than the
			 * current ackno, then move towards the tail of our
			 * seqnos.
			 */
			while (after48(seqp->ccid6s_seq, ackno)) {
				if (seqp == hc->tx_seqt) {
					done = 1;
					break;
				}
				seqp = seqp->ccid6s_prev;
			}
			if (done)
				break;

			/* check all seqnos in the range of the vector
			 * run length
			 */
			while (between48(seqp->ccid6s_seq,ackno_end_rl,ackno)) {
				const u8 state = dccp_ackvec_state(avp->vec);

				/* new packet received or marked */
				if (state != DCCPAV_NOT_RECEIVED && !seqp->ccid6s_acked) {
					if (state == DCCPAV_ECN_MARKED) {
						hc->lost++; // technically not lost
						ccid6_pr_debug("skb ecn marked!\n");
					}
					ccid6_rtt_estimator(sk, ccid6_jiffies32 - seqp->ccid6s_sent);
					seqp->ccid6s_acked = 1;
					hc->delivered++;
					hc->tx_pipe--;	

					bbr2_set_state(sk, DCCP_CA_Open); // is this needed ???

					ccid6_rate_skb_delivered(sk, seqp, rs);
					if (seqp->ccid6s_seq == ackno)	{ 
						rs->rtt_us = tcp_stamp_us_delta(now_mstamp, seqp->sent_mstamp);
						hc->rtt_us = rs->rtt_us;
					}
				}
				if (seqp == hc->tx_seqt) {
					done = 1;
					break;
				}
				seqp = seqp->ccid6s_prev;
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
	while (before48(seqp->ccid6s_seq, hc->tx_high_ack)) {
		seqp = seqp->ccid6s_next;
		if (seqp == hc->tx_seqh) {
			seqp = hc->tx_seqh->ccid6s_prev;
			break;
		}
	}
	done = 0;
	while (1) {
		if (seqp->ccid6s_acked) {
			done++;
			if (done == NUMDUPACK)
				break;
		}
		if (seqp == hc->tx_seqt)
			break;
		seqp = seqp->ccid6s_prev;
	}

	/* If there are at least 3 acknowledgements, anything unacknowledged
	 * below the last sequence number is considered lost
	 */
	if (done == NUMDUPACK) {
		struct ccid6_seq *last_acked = seqp;

		/* check for lost packets */
		while (1) {
			if (!seqp->ccid6s_acked) {
				ccid6_pr_debug("Packet lost: %llu\n",
						   (unsigned long long)seqp->ccid6s_seq);
				/* XXX need to traverse from tail -> head in
				 * order to detect multiple congestion events in
				 * one ack vector.
				 */

				bbr2_skb_marked_lost(sk, seqp);
				loss_event = true;

				hc->lost++;
				hc->tx_pipe--;
			}
			if (seqp == hc->tx_seqt)
				break;
			seqp = seqp->ccid6s_prev;
		}

		hc->tx_seqt = last_acked;
	}

	if (loss_event) {
		hc->tx_ssthresh = bbr2_ssthresh(sk);
		if (hc->tx_ssthresh < 2)
			hc->tx_ssthresh = 2;

		if (hc->mode != BBR_STARTUP)
			bbr2_set_state(sk, DCCP_CA_Recovery); // alerab: or DCCP_CA_Loss?
	}

	/* trim acked packets in tail */
	while (hc->tx_seqt != hc->tx_seqh) {
		if (!hc->tx_seqt->ccid6s_acked)
			break;

		hc->tx_seqt = hc->tx_seqt->ccid6s_next;
	}

	/* restart RTO timer if not all outstanding data has been acked */
	if (hc->tx_pipe == 0) {
		sk_stop_timer(sk, &hc->tx_rtotimer);
	}
	else if (!not_rst)
		sk_reset_timer(sk, &hc->tx_rtotimer, jiffies + hc->tx_rto);
	delivered = hc->delivered - delivered;
	lost = hc->lost - lost;	
	ccid6_rate_gen(sk, delivered, lost, now_mstamp, rs);

	bbr2_main(sk, rs);
done:
	/* check if incoming Acks allow pending packets to be sent */
	if (sender_was_blocked && !ccid6_cwnd_network_limited(hc))
		dccp_tasklet_schedule(sk);
	dccp_ackvec_parsed_cleanup(&hc->tx_av_chunks);
}

static int ccid6_hc_tx_init(struct ccid *ccid, struct sock *sk)
{
	struct ccid6_hc_tx_sock *hc = ccid_priv(ccid);
	struct dccp_sock *dp = dccp_sk(sk);
	u32 max_ratio;
	ccid6_pr_debug("init ccid6 sk %p", sk);

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
	if (ccid6_hc_tx_alloc_seq(hc))
		return -ENOMEM;

	hc->tx_rto	 = DCCP_TIMEOUT_INIT;
	hc->tx_rpdupack  = -1;
	hc->tx_last_cong = hc->tx_lsndtime = hc->tx_cwnd_stamp = ccid6_jiffies32;
	hc->tx_cwnd_used = 0;
	hc->tx_pipe = 0;

	hc->curr_ca_state = DCCP_CA_Open;
	
	hc->pr_init = 0;
	//hc->rtprop_fix=0;
	hc->tx_extrapkt=false;
	
	hc->restore_cwnd = 0;
	hc->restore_ackrt = 0;
	hc->restore_seqwin = 0;

	hc->delivered = 0;
	hc->delivered_ce = 0;

	bbr2_init(sk, hc);

	hc->sk		 = sk;
	timer_setup(&hc->tx_rtotimer, ccid6_hc_tx_rto_expire, 0);
	//setup_timer(&hc->tx_rtotimer, ccid6_hc_tx_rto_expire,
	//		(unsigned long)sk);
	INIT_LIST_HEAD(&hc->tx_av_chunks);

	return 0;
}

static void ccid6_hc_tx_exit(struct sock *sk)
{
	struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	int i;

	sk_stop_timer(sk, &hc->tx_rtotimer);

	for (i = 0; i < hc->tx_seqbufc; i++)
		kfree(hc->tx_seqbuf[i]);
	hc->tx_seqbufc = 0;
	dccp_ackvec_parsed_cleanup(&hc->tx_av_chunks);
}

static void ccid6_hc_rx_packet_recv(struct sock *sk, struct sk_buff *skb)
{
	//ccid6_pr_debug("enter %p", sk);

	struct ccid6_hc_rx_sock *hc = ccid6_hc_rx_sk(sk);
	
	//ccid6_mstamp_refresh(ccid6_hc_tx_sk(sk)); // or after the first if-statement?

	if (!dccp_data_packet(skb))
		return;
	if (++hc->rx_num_data_pkts >= dccp_sk(sk)->dccps_r_ack_ratio) {
		//ccid6_pr_debug("%p send ack, ack ratio %ul", sk, dccp_sk(sk)->dccps_r_ack_ratio);
		dccp_send_ack(sk);
		hc->rx_num_data_pkts = 0;
	}
}

// Function to read h values and make them available for dccp
static void ccid6_hc_tx_get_info(struct sock *sk, struct tcp_info *info)
{
	info->tcpi_rto = ccid6_hc_tx_sk(sk)->tx_rto;
	info->tcpi_rtt = ccid6_hc_tx_sk(sk)->tx_srtt;
	info->tcpi_rttvar = ccid6_hc_tx_sk(sk)->tx_mrtt;
	info->tcpi_segs_out = ccid6_hc_tx_sk(sk)->tx_pipe;
	info->tcpi_snd_cwnd = ccid6_hc_tx_sk(sk)->tx_cwnd;
	info->tcpi_last_data_sent = ccid6_hc_tx_sk(sk)->tx_lsndtime;
}

// NOTE: #define DCCP_SOCKOPT_CCID_TX_INFO 192 in include/uapi/linux/dccp.h
// NOTE: #define DCCP_SOCKOPT_CCID_LIM_RTO 193 in include/uapi/linux/dccp.h

struct dccp_ccid6_tx { // Pieska modification, added struct
  u32 tx_cwnd;	
  u32 tx_pipe;	
  u32 tx_srtt;	
  u32 tx_mrtt;	
  u32 tx_rto;
  u32 tx_min_rtt;		
  u32 tx_delivered;	
};

// Pieska modification, added function
static int ccid6_hc_tx_getsockopt(struct sock *sk, const int optname, int len,
				  u32 __user *optval, int __user *optlen)
{
  struct ccid6_hc_tx_sock *hc = ccid6_hc_tx_sk(sk);
	struct dccp_ccid6_tx tx;
	const void *val;

	switch (optname) {
	case DCCP_SOCKOPT_CCID_TX_INFO:
		if (len < sizeof(tx))
			return -EINVAL;
		memset(&tx, 0, sizeof(tx));
		tx.tx_cwnd = hc->tx_cwnd;
		tx.tx_pipe = hc->tx_pipe;
		tx.tx_srtt = hc->tx_srtt;
		tx.tx_mrtt = hc->tx_mrtt;
		tx.tx_rto = hc->tx_rto;
		tx.tx_min_rtt = hc->min_rtt_us;
		tx.tx_delivered = hc->delivered;
		len = sizeof(tx);
		val = &tx;
		break;
	case DCCP_SOCKOPT_CCID_LIM_RTO:
        hc->exp_inc_rtotimer = 0;
        break;
	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen) || copy_to_user(optval, val, len))
		return -EFAULT;

	return 0;
}

struct ccid_operations ccid6_ops = {
	.ccid_id		  			= DCCPC_CCID6,
	.ccid_name		  			= "BBRv2-like",
	.ccid_hc_tx_obj_size		= sizeof(struct ccid6_hc_tx_sock),
	.ccid_hc_tx_init	  		= ccid6_hc_tx_init,
	.ccid_hc_tx_exit	  		= ccid6_hc_tx_exit,
	.ccid_hc_tx_send_packet		= ccid6_hc_tx_send_packet,
	.ccid_hc_tx_packet_sent		= ccid6_hc_tx_packet_sent,
	.ccid_hc_tx_parse_options	= ccid6_hc_tx_parse_options,
	.ccid_hc_tx_packet_recv		= ccid6_hc_tx_packet_recv,
	.ccid_hc_tx_get_info 		= ccid6_hc_tx_get_info,
	.ccid_hc_rx_obj_size	  	= sizeof(struct ccid6_hc_rx_sock),
	.ccid_hc_rx_packet_recv	  	= ccid6_hc_rx_packet_recv,
  .ccid_hc_tx_getsockopt	  = ccid6_hc_tx_getsockopt, // Pieska modification, added operation
};

#ifdef CONFIG_IP_DCCP_CCID6_DEBUG
module_param(ccid6_debug, bool, 0644);
MODULE_PARM_DESC(ccid6_debug, "Enable CCID-6 debug messages");
#endif
