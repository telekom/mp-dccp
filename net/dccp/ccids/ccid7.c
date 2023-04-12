/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 *  Copyright (C) 2022 by Marcus Pieska, Karlstad University for Deutsche Telekom AG
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
 * 
 * CUBIC integrates a new slow start algorithm, called HyStart.
 * The details of HyStart are presented in
 *  Sangtae Ha and Injong Rhee,
 *  "Taming the Elephants: New TCP Slow Start", NCSU TechReport 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/hystart_techreport_2008.pdf
 *
 * All testing results are available from:
 * http://netsrv.csc.ncsu.edu/wiki/index.php/TCP_Testing
 *
 * Unless CUBIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

/*
 * This implementation should follow RFC 4341
 */
#include <linux/slab.h>
#include "../feat.h"
#include "ccid7.h"


#ifdef CONFIG_IP_DCCP_CCID7_DEBUG
static bool ccid7_debug;
#define ccid7_pr_debug(format, a...)	DCCP_PR_DEBUG(ccid7_debug, format, ##a)
#else
#define ccid7_pr_debug(format, a...)
#endif

/* Function pointer to either get SRTT or MRTT ...*/
u32 (*ccid7_get_delay_val)(struct ccid7_hc_tx_sock *hc) = ccid7_mrtt_as_delay;
EXPORT_SYMBOL_GPL(ccid7_get_delay_val);

#define HYSTART_DELAY	0x1
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4U)
#define HYSTART_DELAY_MAX	(16U)
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)

#define CSS_GROWTH_DIVISOR 4 
#define CSS_ROUNDS 5

static int hystart = 1;
static int hystart_detect = HYSTART_DELAY;
static int hystart_low_window = 16;

const static s32 cub_shift = 10;
const static s32 cub_fact = 1024;
const static s32 cub_b = 717; // 0.7 * 1024
const static s32 cub_c = 410; // 0.4 * 1024

static inline u32 bictcp_clock (void) 
{
#if HZ < 1000
	return ktime_to_ms (ktime_get_real());
#else
	return jiffies_to_msecs (jiffies);
#endif
}

static u32 in_slow_start(struct sock *sk)
{
  struct ccid7_hc_tx_sock *hc = ccid7_hc_tx_sk(sk);
  return hc->tx_cwnd < hc->tx_ssthresh;  
}

static u32 cub_root(u64 a) 
{
	u32 x, b, shift;
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64 (a);
	if (b < 7) {
		return ((u32)v[(u32)a] + 35) >> 6;
	}
	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));
	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

static inline u32 get_w_est_rfc8312 (struct ccid7_hc_tx_sock* hc, s64 time) 
{
  /* W_est(t) = W_max*beta_cubic + [3*(1-beta_cubic)/(1+beta_cubic)] * (t/RTT) */
  u32 rtts = (time - hc->ref_t) / ((hc->tx_srtt) >> 1);
  u32 ai = 3*cub_fact*(cub_fact-cub_b)/(cub_fact+cub_b);
  u32 w_est = hc->tx_wmax*cub_b + ai*rtts;
  return w_est >>= cub_shift;
}

static inline u32 get_cwnd_rfc8312 (struct ccid7_hc_tx_sock *hc, s64 time) 
{
  /* W_cubic(t) = C*(t-K)^3 + W_max (Eq. 1) */
  s64 tv = (time - hc->ref_t - hc->cub_k), raw_cwnd;
  raw_cwnd = (cub_b * tv) >> cub_shift; 
  raw_cwnd = (raw_cwnd * tv) >> cub_shift; 
  raw_cwnd = (raw_cwnd * tv) >> cub_shift; 
  raw_cwnd = (raw_cwnd) >> cub_shift;
  raw_cwnd = raw_cwnd + hc->tx_wmax;
  if (raw_cwnd < 4)
    raw_cwnd = 4;
  return (u32)raw_cwnd;
} 

static inline void set_cwnd_rfc8312 (struct ccid7_hc_tx_sock* hc) 
{
  s64 time = bictcp_clock();
  u32 w_est = get_w_est_rfc8312 (hc, time);
  u32 cwnd = get_cwnd_rfc8312 (hc, time);
  hc->tx_cwnd = max(w_est, cwnd);
}

static inline void set_k_rfc8312 (struct ccid7_hc_tx_sock* hc) 
{
  /* K = cub_root(W_max*(1-beta_cubic)/C) */
  hc->cub_k = cub_root (hc->tx_wmax*(cub_fact-cub_b)/cub_c);
  hc->cub_k <<= cub_shift;
} 

static inline void bictcp_hystart_reset(struct sock *sk, struct ccid7_hc_tx_sock *hc)
{
  struct dccp_sock *dp = dccp_sk(sk);
  
  /* have previously found, now in css */
  if (hc->found != 0) {
    hc->css_round_count++;
    if (hc->curr_rtt < hc->prev_rtt) {
      hc->found = hc->css_round_count = 0;
    }  
    else if (hc->css_round_count > CSS_ROUNDS) {
      hc->found = hystart_detect;
      hc->ref_t = bictcp_clock();
      hc->css_round_count = 0;  
      hc->css_pkt_count = 0;  
      hc->cub_k = 0;
      hc->tx_wmax = hc->tx_cwnd; 
      hc->tx_ssthresh = hc->tx_cwnd;
      set_cwnd_rfc8312 (hc);
    }
  }

  hc->round_start = hc->last_ack = bictcp_clock();
	hc->end_seq = dp->dccps_gss + hc->tx_cwnd;
	hc->prev_rtt = hc->curr_rtt;
  hc->curr_rtt = ~0U;
	hc->sample_cnt = 0;
}

static void hystart_update(struct sock *sk, u32 delay)
{
  struct ccid7_hc_tx_sock *hc = ccid7_hc_tx_sk(sk);

  /* obtain the minimum delay of more than sampling packets */
	if (hystart_detect & HYSTART_DELAY) {
		if (hc->sample_cnt < HYSTART_MIN_SAMPLES) {
			hc->sample_cnt++;
      if (hc->curr_rtt > delay)
				hc->curr_rtt = delay;
		} else if (hc->prev_rtt > 0) {
			u32 n = max((hc->prev_rtt >> 4), 2U);
      if (hc->curr_rtt > hc->prev_rtt + n) {
				hc->found |= HYSTART_DELAY;
			}
		}
	}
  
  /* have newly found, need to end cycle and begin css */
  if (hc->found != 0 && hc->css_round_count == 0) {
    bictcp_hystart_reset(sk, hc);
  }
}

static int ccid7_hc_tx_alloc_seq(struct ccid7_hc_tx_sock *hc)
{
	struct ccid7_seq *seqp;
	int i;

	/* check if we have space to preserve the pointer to the buffer */
	if (hc->tx_seqbufc >= (sizeof(hc->tx_seqbuf) /
			       sizeof(struct ccid7_seq *)))
		return -ENOMEM;

	/* allocate buffer and initialize linked list */
	seqp = kmalloc(CCID7_SEQBUF_LEN * sizeof(struct ccid7_seq), gfp_any());
	if (seqp == NULL)
		return -ENOMEM;

	for (i = 0; i < (CCID7_SEQBUF_LEN - 1); i++) {
		seqp[i].ccid7s_next = &seqp[i + 1];
		seqp[i + 1].ccid7s_prev = &seqp[i];
	}
	seqp[CCID7_SEQBUF_LEN - 1].ccid7s_next = seqp;
	seqp->ccid7s_prev = &seqp[CCID7_SEQBUF_LEN - 1];

	/* This is the first allocation.  Initiate the head and tail.  */
	if (hc->tx_seqbufc == 0)
		hc->tx_seqh = hc->tx_seqt = seqp;
	else {
		/* link the existing list with the one we just created */
		hc->tx_seqh->ccid7s_next = seqp;
		seqp->ccid7s_prev = hc->tx_seqh;

		hc->tx_seqt->ccid7s_prev = &seqp[CCID7_SEQBUF_LEN - 1];
		seqp[CCID7_SEQBUF_LEN - 1].ccid7s_next = hc->tx_seqt;
	}

	/* store the original pointer to the buffer so we can free it */
	hc->tx_seqbuf[hc->tx_seqbufc] = seqp;
	hc->tx_seqbufc++;

	return 0;
}

static int ccid7_hc_tx_send_packet(struct sock *sk, struct sk_buff *skb)
{
	if (ccid7_cwnd_network_limited(ccid7_hc_tx_sk(sk)))
		return CCID_PACKET_WILL_DEQUEUE_LATER;
	return CCID_PACKET_SEND_AT_ONCE;
}

static void ccid7_change_l_ack_ratio(struct sock *sk, u32 val)
{
	u32 max_ratio = DIV_ROUND_UP(ccid7_hc_tx_sk(sk)->tx_cwnd, 2);

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
	dccp_feat_signal_nn_change(sk, DCCPF_ACK_RATIO,
				   min_t(u32, val, DCCPF_ACK_RATIO_MAX));
}

static void ccid7_check_l_ack_ratio(struct sock *sk)
{
	struct ccid7_hc_tx_sock *hc = ccid7_hc_tx_sk(sk);

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
		ccid7_change_l_ack_ratio(sk, hc->tx_cwnd/2 ? : 1U);
}

static void ccid7_change_l_seq_window(struct sock *sk, u64 val)
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

static void ccid7_hc_tx_rto_expire(struct timer_list *t)
{
	//struct sock *sk = (struct sock *)data;
	//struct ccid7_hc_tx_sock *hc = ccid7_hc_tx_sk(sk);
	struct ccid7_hc_tx_sock *hc = from_timer(hc, t, tx_rtotimer);
	struct sock *sk = hc->sk;
	const bool sender_was_blocked = ccid7_cwnd_network_limited(hc);

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		sk_reset_timer(sk, &hc->tx_rtotimer, jiffies + HZ / 5);
		goto out;
	}

	ccid7_pr_debug("RTO_EXPIRE\n");

	if (sk->sk_state == DCCP_CLOSED)
		goto out;

	/* back-off timer */
	if (hc->exp_inc_rtotimer) {
    hc->tx_rto <<= 1;
    if (hc->tx_rto > DCCP_RTO_MAX)
      hc->tx_rto = DCCP_RTO_MAX;
  }
  
	/* adjust pipe, cwnd etc */
	hc->tx_ssthresh = hc->tx_cwnd / 2;
	if (hc->tx_ssthresh < 2)
		hc->tx_ssthresh = 2;
	hc->tx_cwnd	= 1;
	hc->tx_pipe	= 0;

	/* clear state about stuff we sent */
	hc->tx_seqt = hc->tx_seqh;
	hc->tx_packets_acked = 0;

	/* clear ack ratio state. */
	hc->tx_rpseq    = 0;
	hc->tx_rpdupack = -1;
	ccid7_change_l_ack_ratio(sk, 1);

	/* if we were blocked before, we may now send cwnd=1 packet */
	if (sender_was_blocked)
		dccp_tasklet_schedule(sk);
	/* restart backed-off timer */
	sk_reset_timer(sk, &hc->tx_rtotimer, jiffies + hc->tx_rto);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 *	Congestion window validation (RFC 2861).
 */
static bool ccid7_do_cwv = true;
module_param(ccid7_do_cwv, bool, 0644);
MODULE_PARM_DESC(ccid7_do_cwv, "Perform RFC2861 Congestion Window Validation");

/**
 * ccid7_update_used_window  -  Track how much of cwnd is actually used
 * This is done in addition to CWV. The sender needs to have an idea of how many
 * packets may be in flight, to set the local Sequence Window value accordingly
 * (RFC 4340, 7.5.2). The CWV mechanism is exploited to keep track of the
 * maximum-used window. We use an EWMA low-pass filter to filter out noise.
 */
static void ccid7_update_used_window(struct ccid7_hc_tx_sock *hc, u32 new_wnd)
{
	hc->tx_expected_wnd = (3 * hc->tx_expected_wnd + new_wnd) / 4;
}

/* This borrows the code of tcp_cwnd_application_limited() */
static void ccid7_cwnd_application_limited(struct sock *sk, const u32 now)
{
	struct ccid7_hc_tx_sock *hc = ccid7_hc_tx_sk(sk);
	/* don't reduce cwnd below the initial window (IW) */
	u32 init_win = rfc3390_bytes_to_packets(dccp_sk(sk)->dccps_mss_cache),
	    win_used = max(hc->tx_cwnd_used, init_win);

	if (win_used < hc->tx_cwnd) {
		hc->tx_ssthresh = max(hc->tx_ssthresh,
				     (hc->tx_cwnd >> 1) + (hc->tx_cwnd >> 2));
		hc->tx_cwnd = (hc->tx_cwnd + win_used) >> 1;
		dccp_pr_debug("%s: tx_cwnd set to %d for sk %p", __func__, hc->tx_cwnd, sk);
	}
	hc->tx_cwnd_used  = 0;
	hc->tx_cwnd_stamp = now;

	ccid7_check_l_ack_ratio(sk);
}

/* This borrows the code of tcp_cwnd_restart() */
static void ccid7_cwnd_restart(struct sock *sk, const u32 now)
{
	struct ccid7_hc_tx_sock *hc = ccid7_hc_tx_sk(sk);
	u32 cwnd = hc->tx_cwnd, restart_cwnd,
	    iwnd = rfc3390_bytes_to_packets(dccp_sk(sk)->dccps_mss_cache);
	s32 delta = now - hc->tx_lsndtime;

	hc->tx_ssthresh = max(hc->tx_ssthresh, (cwnd >> 1) + (cwnd >> 2));

	/* don't reduce cwnd below the initial window (IW) */
	restart_cwnd = min(cwnd, iwnd);

	while ((delta -= hc->tx_rto) >= 0 && cwnd > restart_cwnd)
		cwnd >>= 1;
	hc->tx_cwnd = max(cwnd, restart_cwnd);
	hc->tx_cwnd_stamp = now;
	hc->tx_cwnd_used  = 0;

	ccid7_check_l_ack_ratio(sk);
}

static void ccid7_hc_tx_packet_sent(struct sock *sk, unsigned int len)
{
	struct dccp_sock *dp = dccp_sk(sk);
	struct ccid7_hc_tx_sock *hc = ccid7_hc_tx_sk(sk);
	const u32 now = ccid7_jiffies32;
	struct ccid7_seq *next;

	/* slow-start after idle periods (RFC 2581, RFC 2861) */
	if (ccid7_do_cwv && !hc->tx_pipe &&
	    (s32)(now - hc->tx_lsndtime) >= hc->tx_rto)
		ccid7_cwnd_restart(sk, now);

	hc->tx_lsndtime = now;
	hc->tx_pipe += 1;

	/* see whether cwnd was fully used (RFC 2861), update expected window */
	if (ccid7_cwnd_network_limited(hc)) {
		ccid7_update_used_window(hc, hc->tx_cwnd);
		hc->tx_cwnd_used  = 0;
		hc->tx_cwnd_stamp = now;
	} else {
		if (hc->tx_pipe > hc->tx_cwnd_used)
			hc->tx_cwnd_used = hc->tx_pipe;

		ccid7_update_used_window(hc, hc->tx_cwnd_used);

		if (ccid7_do_cwv && (s32)(now - hc->tx_cwnd_stamp) >= hc->tx_rto)
			ccid7_cwnd_application_limited(sk, now);
	}

	hc->tx_seqh->ccid7s_seq   = dp->dccps_gss;
	hc->tx_seqh->ccid7s_acked = 0;
	hc->tx_seqh->ccid7s_sent  = now;

	next = hc->tx_seqh->ccid7s_next;
	/* check if we need to alloc more space */
	if (next == hc->tx_seqt) {
		if (ccid7_hc_tx_alloc_seq(hc)) {
			DCCP_CRIT("packet history - out of memory!");
			/* FIXME: find a more graceful way to bail out */
			return;
		}
		next = hc->tx_seqh->ccid7s_next;
		BUG_ON(next == hc->tx_seqt);
	}
	hc->tx_seqh = next;

	ccid7_pr_debug("cwnd=%d pipe=%d\n", hc->tx_cwnd, hc->tx_pipe);

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
				ccid7_change_l_ack_ratio(sk, dp->dccps_l_ack_ratio - 1);
				hc->tx_arsent = 0;
			}
		} else {
			/* we can't increase ack ratio further [1] */
			hc->tx_arsent = 0; /* or maybe set it to cwnd*/
		}
	}
#endif

	sk_reset_timer(sk, &hc->tx_rtotimer, jiffies + hc->tx_rto);

#ifdef CONFIG_IP_DCCP_CCID7_DEBUG
	do {
		struct ccid7_seq *seqp = hc->tx_seqt;

		while (seqp != hc->tx_seqh) {
			ccid7_pr_debug("out seq=%llu acked=%d time=%u\n",
				       (unsigned long long)seqp->ccid7s_seq,
				       seqp->ccid7s_acked, seqp->ccid7s_sent);
			seqp = seqp->ccid7s_next;
		}
	} while (0);
	ccid7_pr_debug("=========\n");
#endif
}

/**
 * ccid7_rtt_estimator - Sample RTT and compute RTO using RFC2988 algorithm
 * This code is almost identical with TCP's tcp_rtt_estimator(), since
 * - it has a higher sampling frequency (recommended by RFC 1323),
 * - the RTO does not collapse into RTT due to RTTVAR going towards zero,
 * - it is simple (cf. more complex proposals such as Eifel timer or research
 *   which suggests that the gain should be set according to window size),
 * - in tests it was found to work well with CCID7 [gerrit].
 */
static void ccid7_rtt_estimator(struct sock *sk, const long mrtt)
{
	struct ccid7_hc_tx_sock *hc = ccid7_hc_tx_sk(sk);
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

static void ccid7_new_ack(struct sock *sk, struct ccid7_seq *seqp,
			  unsigned int *maxincr)
{
	struct ccid7_hc_tx_sock *hc = ccid7_hc_tx_sk(sk);
	struct dccp_sock *dp = dccp_sk(sk);
	int r_seq_used = hc->tx_cwnd / dp->dccps_l_ack_ratio;

	if (hc->tx_cwnd < dp->dccps_l_seq_win &&
	    r_seq_used < dp->dccps_r_seq_win) {
		if (hc->tx_cwnd < hc->tx_ssthresh) {
			if (*maxincr > 0 && ++hc->tx_packets_acked >= 2) {
				if (hc->css_round_count > 0) {
          hc->css_pkt_count++;
          if (hc->css_pkt_count >= CSS_GROWTH_DIVISOR) {
            hc->tx_cwnd += 1;
            hc->css_pkt_count = 0;
          }
          *maxincr    -= 1;
          hc->tx_packets_acked = 0;
        }
        else {
				  hc->tx_cwnd += 1;
				  *maxincr    -= 1;
				  hc->tx_packets_acked = 0;
			  }
			}
		} else {
      set_cwnd_rfc8312 (hc);
		}
	}

	/*
	 * Adjust the local sequence window and the ack ratio to allow about
	 * 5 times the number of packets in the network (RFC 4340 7.5.2)
	 */
	if (r_seq_used * CCID7_WIN_CHANGE_FACTOR >= dp->dccps_r_seq_win)
		ccid7_change_l_ack_ratio(sk, dp->dccps_l_ack_ratio * 2);
	else if (r_seq_used * CCID7_WIN_CHANGE_FACTOR < dp->dccps_r_seq_win/2)
		ccid7_change_l_ack_ratio(sk, dp->dccps_l_ack_ratio / 2 ? : 1U);

	if (hc->tx_cwnd * CCID7_WIN_CHANGE_FACTOR >= dp->dccps_l_seq_win)
		ccid7_change_l_seq_window(sk, dp->dccps_l_seq_win * 2);
	else if (hc->tx_cwnd * CCID7_WIN_CHANGE_FACTOR < dp->dccps_l_seq_win/2)
		ccid7_change_l_seq_window(sk, dp->dccps_l_seq_win / 2);

	/*
	 * FIXME: RTT is sampled several times per acknowledgment (for each
	 * entry in the Ack Vector), instead of once per Ack (as in TCP SACK).
	 * This causes the RTT to be over-estimated, since the older entries
	 * in the Ack Vector have earlier sending times.
	 * The cleanest solution is to not use the ccid7s_sent field at all
	 * and instead use DCCP timestamps: requires changes in other places.
	 */
	ccid7_rtt_estimator(sk, ccid7_jiffies32 - seqp->ccid7s_sent);
  
	/* first time call or link delay decreases */
  if (hc->min_rtt > hc->tx_mrtt)
		hc->min_rtt = hc->tx_mrtt;
  
	/* hystart triggers when cwnd is larger than some threshold */
  if (hystart && in_slow_start(sk)) {
    if (hc->tx_cwnd >= hystart_low_window)
      hystart_update(sk, hc->tx_mrtt);
    if (after(seqp->ccid7s_seq, hc->end_seq))
      bictcp_hystart_reset(sk, hc);
  }
}

static void ccid7_congestion_event(struct sock *sk, struct ccid7_seq *seqp)
{
	struct ccid7_hc_tx_sock *hc = ccid7_hc_tx_sk(sk);

	if ((s32)(seqp->ccid7s_sent - hc->tx_last_cong) < 0) {
		ccid7_pr_debug("Multiple losses in an RTT---treating as one\n");
		return;
	}

	hc->tx_last_cong = ccid7_jiffies32;

  hc->tx_wmax = hc->tx_cwnd; 
  hc->tx_ssthresh = (hc->tx_cwnd * cub_b) >> cub_shift;
  hc->tx_ssthresh = hc->tx_ssthresh > 2? hc->tx_ssthresh: 2; 
  hc->tx_cwnd = (hc->tx_cwnd * cub_b) >> cub_shift; 
  if (hc->tx_wmax < hc->tx_wmax_prev) { 
    hc->tx_wmax_prev = hc->tx_wmax; 
    hc->tx_wmax = (hc->tx_wmax * (cub_fact + cub_b)) >> (cub_shift + 1);
  } else {
    hc->tx_wmax_prev = hc->tx_wmax;
  }
  set_k_rfc8312 (hc);
  hc->ca_rx_ct = hc->loss_ct = 0; 
  hc->ref_t = bictcp_clock();
  hc->css_round_count = 0;
	ccid7_check_l_ack_ratio(sk);
}

static int ccid7_hc_tx_parse_options(struct sock *sk, u8 packet_type,
				     u8 option, u8 *optval, u8 optlen)
{
	struct ccid7_hc_tx_sock *hc = ccid7_hc_tx_sk(sk);

	switch (option) {
	case DCCPO_ACK_VECTOR_0:
	case DCCPO_ACK_VECTOR_1:
		return dccp_ackvec_parsed_add(&hc->tx_av_chunks, optval, optlen,
					      option - DCCPO_ACK_VECTOR_0);
	}
	return 0;
}

static void ccid7_hc_tx_packet_recv(struct sock *sk, struct sk_buff *skb)
{
	struct dccp_sock *dp = dccp_sk(sk);
	struct ccid7_hc_tx_sock *hc = ccid7_hc_tx_sk(sk);
	const bool sender_was_blocked = ccid7_cwnd_network_limited(hc);
	struct dccp_ackvec_parsed *avp;
	u64 ackno, seqno;
	struct ccid7_seq *seqp;
	int done = 0;
	bool not_rst = 0;
	unsigned int maxincr = 0;

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
#ifdef __CCID7_COPES_GRACEFULLY_WITH_ACK_CONGESTION_CONTROL__
				/*
				 * FIXME: Ack Congestion Control is broken; in
				 * the current state instabilities occurred with
				 * Ack Ratios greater than 1; causing hang-ups
				 * and long RTO timeouts. This needs to be fixed
				 * before opening up dynamic changes. -- gerrit
				 */
				ccid7_change_l_ack_ratio(sk, 2 * dp->dccps_l_ack_ratio);
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
	while (before48(seqp->ccid7s_seq, ackno)) {
		seqp = seqp->ccid7s_next;
		if (seqp == hc->tx_seqh) {
			seqp = hc->tx_seqh->ccid7s_prev;
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

			ccid7_pr_debug("ackvec %llu |%u,%u|\n",
				       (unsigned long long)ackno,
				       dccp_ackvec_state(avp->vec) >> 6,
				       dccp_ackvec_runlen(avp->vec));
			/* if the seqno we are analyzing is larger than the
			 * current ackno, then move towards the tail of our
			 * seqnos.
			 */
			while (after48(seqp->ccid7s_seq, ackno)) {
				if (seqp == hc->tx_seqt) {
					done = 1;
					break;
				}
				seqp = seqp->ccid7s_prev;
			}
			if (done)
				break;


			/* check all seqnos in the range of the vector
			 * run length
			 */

			while (between48(seqp->ccid7s_seq,ackno_end_rl,ackno)) {
				const u8 state = dccp_ackvec_state(avp->vec);

				/* new packet received or marked */
				if (state != DCCPAV_NOT_RECEIVED &&
				    !seqp->ccid7s_acked) {
					if (state == DCCPAV_ECN_MARKED)
						ccid7_congestion_event(sk,
								       seqp);
					else
						ccid7_new_ack(sk, seqp,
							      &maxincr);

					seqp->ccid7s_acked = 1;
					ccid7_pr_debug("Got ack for %llu\n",
						       (unsigned long long)seqp->ccid7s_seq);
					hc->tx_pipe--;
				}
				if (seqp == hc->tx_seqt) {
					done = 1;
					break;
				}
				seqp = seqp->ccid7s_prev;
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
	while (before48(seqp->ccid7s_seq, hc->tx_high_ack)) {
		seqp = seqp->ccid7s_next;
		if (seqp == hc->tx_seqh) {
			seqp = hc->tx_seqh->ccid7s_prev;
			break;
		}
	}
	done = 0;
	while (1) {
		if (seqp->ccid7s_acked) {
			done++;
			if (done == NUMDUPACK)
				break;
		}
		if (seqp == hc->tx_seqt)
			break;
		seqp = seqp->ccid7s_prev;
	}

	/* If there are at least 3 acknowledgements, anything unacknowledged
	 * below the last sequence number is considered lost
	 */
	if (done == NUMDUPACK) {
		struct ccid7_seq *last_acked = seqp;

		/* check for lost packets */
		while (1) {
			if (!seqp->ccid7s_acked) {
				ccid7_pr_debug("Packet lost: %llu\n",
					       (unsigned long long)seqp->ccid7s_seq);
				/* XXX need to traverse from tail -> head in
				 * order to detect multiple congestion events in
				 * one ack vector.
				 */
				ccid7_congestion_event(sk, seqp);
				hc->tx_pipe--;
			}
			if (seqp == hc->tx_seqt)
				break;
			seqp = seqp->ccid7s_prev;
		}

		hc->tx_seqt = last_acked;
	}

	/* trim acked packets in tail */
	while (hc->tx_seqt != hc->tx_seqh) {
		if (!hc->tx_seqt->ccid7s_acked)
			break;

		hc->tx_seqt = hc->tx_seqt->ccid7s_next;
	}

	/* restart RTO timer if not all outstanding data has been acked */
	if (hc->tx_pipe == 0)
		sk_stop_timer(sk, &hc->tx_rtotimer);
	else if(!not_rst)
		sk_reset_timer(sk, &hc->tx_rtotimer, jiffies + hc->tx_rto);
done:
	/* check if incoming Acks allow pending packets to be sent */
	if (sender_was_blocked && !ccid7_cwnd_network_limited(hc))
		dccp_tasklet_schedule(sk);
	dccp_ackvec_parsed_cleanup(&hc->tx_av_chunks);
}

static int ccid7_hc_tx_init(struct ccid *ccid, struct sock *sk)
{
	struct ccid7_hc_tx_sock *hc = ccid_priv(ccid);
	struct dccp_sock *dp = dccp_sk(sk);
	u32 max_ratio;

	/* RFC 4341, 5: initialise ssthresh to arbitrarily high (max) value */
	hc->tx_ssthresh = ~0U;
  hc->curr_rtt = ~0U;
  hc->min_rtt = ~0U;
  hc->found = 0;
  hc->css_round_count = 0;
  hc->css_pkt_count = 0;
  hc->exp_inc_rtotimer = 0;

	/* Use larger initial windows (RFC 4341, section 5). */
	hc->tx_cwnd = rfc3390_bytes_to_packets(dp->dccps_mss_cache);
	hc->tx_expected_wnd = hc->tx_cwnd;

	/* Make sure that Ack Ratio is enabled and within bounds. */
	max_ratio = DIV_ROUND_UP(hc->tx_cwnd, 2);
	if (dp->dccps_l_ack_ratio == 0 || dp->dccps_l_ack_ratio > max_ratio)
		dp->dccps_l_ack_ratio = max_ratio;

	/* XXX init ~ to window size... */
	if (ccid7_hc_tx_alloc_seq(hc))
		return -ENOMEM;

  hc->ref_t = bictcp_clock();
	hc->tx_rto = DCCP_TIMEOUT_INIT;
	hc->tx_rpdupack  = -1;
	hc->tx_last_cong = hc->tx_lsndtime = hc->tx_cwnd_stamp = ccid7_jiffies32;
	hc->tx_cwnd_used = 0;
	//setup_timer(&hc->tx_rtotimer, ccid7_hc_tx_rto_expire,
	//		(unsigned long)sk);
	hc->sk		 = sk;
	timer_setup(&hc->tx_rtotimer, ccid7_hc_tx_rto_expire, 0);
	INIT_LIST_HEAD(&hc->tx_av_chunks);
  
	if (hystart)
		bictcp_hystart_reset(sk, hc);
  
	return 0;
}

static void ccid7_hc_tx_exit(struct sock *sk)
{
	struct ccid7_hc_tx_sock *hc = ccid7_hc_tx_sk(sk);
	int i;

	sk_stop_timer(sk, &hc->tx_rtotimer);

	for (i = 0; i < hc->tx_seqbufc; i++)
		kfree(hc->tx_seqbuf[i]);
	hc->tx_seqbufc = 0;
	dccp_ackvec_parsed_cleanup(&hc->tx_av_chunks);
}

static void ccid7_hc_rx_packet_recv(struct sock *sk, struct sk_buff *skb)
{
	struct ccid7_hc_rx_sock *hc = ccid7_hc_rx_sk(sk);
	//printk(KERN_INFO "natrm: enter ccid7_hc_rx_packet_recv %p", sk);

	if (!dccp_data_packet(skb))
		return;
	if (++hc->rx_num_data_pkts >= dccp_sk(sk)->dccps_r_ack_ratio) {
		dccp_send_ack(sk);
		hc->rx_num_data_pkts = 0;
	}
}

static void ccid7_hc_tx_get_info(struct sock *sk, struct tcp_info *info)
{
	info->tcpi_rto = ccid7_hc_tx_sk(sk)->tx_rto;
	info->tcpi_rtt = ccid7_hc_tx_sk(sk)->tx_srtt;
	info->tcpi_rttvar = ccid7_hc_tx_sk(sk)->tx_mrtt;
	info->tcpi_segs_out = ccid7_hc_tx_sk(sk)->tx_pipe;
	info->tcpi_snd_cwnd = ccid7_hc_tx_sk(sk)->tx_cwnd;
	info->tcpi_last_data_sent = ccid7_hc_tx_sk(sk)->tx_lsndtime;
}

// NOTE: #define DCCP_SOCKOPT_CCID_TX_INFO 192 in include/uapi/linux/dccp.h
// NOTE: #define DCCP_SOCKOPT_CCID_LIM_RTO 193 in include/uapi/linux/dccp.h

struct dccp_ccid7_tx { // Pieska modification, added struct
  u32 tx_cwnd;	
  u32 tx_pipe;	
  u32 tx_srtt;	
  u32 tx_mrtt;	
  u32 tx_rto;
  u32 tx_min_rtt;		
  u32 tx_delivered;	
};

// Pieska modification, added function
static int ccid7_hc_tx_getsockopt(struct sock *sk, const int optname, int len,
				  u32 __user *optval, int __user *optlen)
{
  struct ccid7_hc_tx_sock *hc = ccid7_hc_tx_sk(sk);
	struct dccp_ccid7_tx tx;
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
		tx.tx_min_rtt = 0;
		tx.tx_delivered = 0;
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

struct ccid_operations ccid7_ops = {
	.ccid_id		  = DCCPC_CCID7,
	.ccid_name		  = "TCP-like",
	.ccid_hc_tx_obj_size	  = sizeof(struct ccid7_hc_tx_sock),
	.ccid_hc_tx_init	  = ccid7_hc_tx_init,
	.ccid_hc_tx_exit	  = ccid7_hc_tx_exit,
	.ccid_hc_tx_send_packet	  = ccid7_hc_tx_send_packet,
	.ccid_hc_tx_packet_sent	  = ccid7_hc_tx_packet_sent,
	.ccid_hc_tx_parse_options = ccid7_hc_tx_parse_options,
	.ccid_hc_tx_packet_recv	  = ccid7_hc_tx_packet_recv,
	.ccid_hc_tx_get_info	  = ccid7_hc_tx_get_info,
	.ccid_hc_rx_obj_size	  = sizeof(struct ccid7_hc_rx_sock),
	.ccid_hc_rx_packet_recv	  = ccid7_hc_rx_packet_recv,
  .ccid_hc_tx_getsockopt	  = ccid7_hc_tx_getsockopt, // Pieska modification, added operation
};

#ifdef CONFIG_IP_DCCP_CCID7_DEBUG
module_param(ccid7_debug, bool, 0644);
MODULE_PARM_DESC(ccid7_debug, "Enable CCID-2 debug messages");
#endif
