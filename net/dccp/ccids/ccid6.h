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
#ifndef _DCCP_CCID6_H_
#define _DCCP_CCID6_H_

#include <linux/timer.h>
#include <linux/types.h>
#include "../ccid.h"
#include "../dccp.h"
#include <linux/win_minmax.h>

/*
 * CCID-6 timestamping faces the same issues as TCP timestamping.
 * Hence we reuse/share as much of the code as possible.
 */
#define ccid6_jiffies32	((u32)jiffies)

/* NUMDUPACK parameter from RFC 4341, p. 6 */
#define NUMDUPACK	3


#define CYCLE_LEN	8

struct ccid6_seq {
	u64			ccid6s_seq;
	u32			ccid6s_sent,
				delivered,
				delivered_ce;
	int			ccid6s_acked;
	bool 		is_app_limited;
	//struct skb_mstamp	 sent_mstamp;
	u64			sent_mstamp;
	//struct skb_mstamp	 first_tx_mstamp;
	u64			first_tx_mstamp;
	//struct skb_mstamp	 delivered_mstamp;
	u64			delivered_mstamp;

    u32         in_flight;
    u32         lost;	/* packets lost so far upon tx of skb */

	struct ccid6_seq	*ccid6s_prev;
	struct ccid6_seq	*ccid6s_next;
};

#define CCID6_SEQBUF_LEN 1024
#define CCID6_SEQBUF_MAX 128

/*
 * Multiple of congestion window to keep the sequence window at
 * (RFC 4340 7.5.2)
 */
#define CCID6_WIN_CHANGE_FACTOR 5

struct ccid6_hc_tx_sock {
	u32			tx_cwnd;
	u32			tx_ssthresh;
	u32			tx_pipe;
	struct ccid6_seq	*tx_seqbuf[CCID6_SEQBUF_MAX];
	int			tx_seqbufc;
	struct ccid6_seq	*tx_seqh;
	struct ccid6_seq	*tx_seqt;
    u32 exp_inc_rtotimer;


	/* RTT measurement: variables/principles are the same as in TCP */
	u32			tx_srtt,
				tx_mrtt,
				tx_mdev,
				tx_mdev_max,
				tx_rttvar,
				tx_rto;
	u64			tx_rtt_seq:48;
	struct timer_list	tx_rtotimer;
	struct sock		*sk;

	/* Congestion Window validation (optional, RFC 2861) */
	u32			tx_cwnd_used,
				tx_expected_wnd,
				tx_cwnd_stamp,
				tx_lsndtime;

	u64			tx_rpseq;
	int			tx_rpdupack;
	u32			tx_last_cong;
	u64			tx_high_ack;
	struct list_head	tx_av_chunks;

	u32                     rtt_us;

	/* Rate sample population for BBR */
	//struct skb_mstamp	 first_tx_mstamp;
	u64			first_tx_mstamp;
	//struct skb_mstamp	 delivered_mstamp;
	u64			delivered_mstamp;
	u32			delivered,
                delivered_ce,
				app_limited;

    /* variables of BBR struct */
	u32			lt_bw;
	u32			lt_last_delivered;   /* LT intvl start: tp->delivered */
	u32			lt_last_stamp;
	u32			lt_last_lost;
	//u32			pacing_gain:10,	/* current gain for setting pacing rate */
	//			cwnd_gain:10,	/* current gain for setting cwnd */
	//			full_bw_reached:1,   /* reached full bw in Startup? */
	//			full_bw_cnt:2,	/* number of rounds without large bw gains */
	//			cycle_idx:3,	/* current index in pacing_gain cycle array */
	//			has_seen_rtt:1, /* have we seen an RTT sample yet? */
	//			unused_b:5;
	//u32			next_rtt_delivered;
	//struct skb_mstamp cycle_mstamp;
	//u64			cycle_mstamp;
	//u32			rtt_cnt;
	struct minmax bw;
	//u32			prior_cwnd;	/* prior cwnd upon entering loss recovery */
	//u32			full_bw;	/* recent bw, to estimate if pipe is full */
	u32 		bytes_att;
	u32 		bytes_sent;
	u32			curr_ca_state; 
	bool		pr_init;
	//bool		rtprop_fix;
	u32			lost;
	bool			tx_extrapkt;
	u64			prior_ackrt;
	u64			prior_seqwin;

    /* New in BBRv2 */
    	u32	min_rtt_us;	        /* min RTT in min_rtt_win_sec window */
	u32	min_rtt_stamp;	        /* timestamp of min_rtt_us */
	u32	probe_rtt_done_stamp;   /* end time for BBR_PROBE_RTT mode */
	u32	probe_rtt_min_us;	/* min RTT in bbr_probe_rtt_win_ms window */
	u32	probe_rtt_min_stamp;	/* timestamp of probe_rtt_min_us*/
	u32     next_rtt_delivered; /* scb->tx.delivered at end of round */
	u32	prior_rcv_nxt;	/* tp->rcv_nxt when CE state last changed */
	u64	cycle_mstamp;	     /* time of this cycle phase start */
	u32     mode:3,		     /* current bbr_mode in state machine */
		prev_ca_state:3,     /* CA state on previous ACK */
		packet_conservation:1,  /* use packet conservation? */
    	restore_cwnd:1,	     /* decided to revert cwnd to old value */
		restore_ackrt:1,     /* decided to revert ack_ratio to old value */
		restore_seqwin:1,    /* decided to revert seq_window to old value */
		round_start:1,	     /* start of packet-timed tx->ack round? */
        //tso_segs_goal:7,     /* segments we want in each skb we send */
		ce_state:1,          /* If most recent data has CE bit set */
		bw_probe_up_rounds:5,   /* cwnd-limited rounds in PROBE_UP */
		try_fast_path:1, 	/* can we take fast path? */
		unused2:8,
		idle_restart:1,	     /* restarting after idle? */
		probe_rtt_round_done:1,  /* a BBR_PROBE_RTT round at 4 pkts? */
		cycle_idx:3,	/* current index in pacing_gain cycle array */
		has_seen_rtt:1;	     /* have we seen an RTT sample yet? */
	u32	pacing_gain:11,	/* current gain for setting pacing rate */
		cwnd_gain:11,	/* current gain for setting cwnd */
		full_bw_reached:1,   /* reached full bw in Startup? */
		full_bw_cnt:2,	/* number of rounds without large bw gains */
		init_cwnd:7;	/* initial cwnd */
	u32	prior_cwnd;	/* prior cwnd upon entering loss recovery */
	u32	full_bw;	/* recent bw, to estimate if pipe is full */

	/* For tracking ACK aggregation: */
	u64	ack_epoch_mstamp;	/* start of ACK sampling epoch */
	u16	extra_acked[2];		/* max excess data ACKed in epoch */
	u32	ack_epoch_acked:20,	/* packets (S)ACKed in sampling epoch */
		extra_acked_win_rtts:5,	/* age of extra_acked, in round trips */
		extra_acked_win_idx:1,	/* current index in extra_acked array */
	/* BBR v2 state: */
		unused1:2,
		startup_ecn_rounds:2,	/* consecutive hi ECN STARTUP rounds */
		loss_in_cycle:1,	/* packet loss in this cycle? */
		ecn_in_cycle:1;		/* ECN in this cycle? */
	u32	loss_round_delivered; /* scb->tx.delivered ending loss round */
	u32	undo_bw_lo;	     /* bw_lo before latest losses */
	u32	undo_inflight_lo;    /* inflight_lo before latest losses */
	u32	undo_inflight_hi;    /* inflight_hi before latest losses */
	u32	bw_latest;	 /* max delivered bw in last round trip */
	u32	bw_lo;		 /* lower bound on sending bandwidth */
	u32	bw_hi[2];	 /* upper bound of sending bandwidth range*/
	u32	inflight_latest; /* max delivered data in last round trip */
	u32	inflight_lo;	 /* lower bound of inflight data range */
	u32	inflight_hi;	 /* upper bound of inflight data range */
	u32	bw_probe_up_cnt; /* packets delivered per inflight_hi incr */
	u32	bw_probe_up_acks;  /* packets (S)ACKed since inflight_hi incr */
	u32	probe_wait_us;	 /* PROBE_DOWN until next clock-driven probe */
	u32	ecn_eligible:1,	/* sender can use ECN (RTT, handshake)? */
		ecn_alpha:9,	/* EWMA delivered_ce/delivered; 0..256 */
		bw_probe_samples:1,    /* rate samples reflect bw probing? */
		prev_probe_too_high:1, /* did last PROBE_UP go too high? */
		stopped_risky_probe:1, /* last PROBE_UP stopped due to risk? */
		rounds_since_probe:8,  /* packet-timed rounds since probed bw */
		loss_round_start:1,    /* loss_round_delivered round trip? */
		loss_in_round:1,       /* loss marked in this round trip? */
		ecn_in_round:1,	       /* ECN marked in this round trip? */
		ack_phase:3,	       /* bbr_ack_phase: meaning of ACKs */
		loss_events_in_round:4,/* losses in STARTUP round */
		initialized:1;	       /* has bbr_init() been called? */
	u32	alpha_last_delivered;	 /* tp->delivered    at alpha update */
	u32	alpha_last_delivered_ce; /* tp->delivered_ce at alpha update */


	/* Params configurable using setsockopt. Refer to correspoding
	 * module param for detailed description of params.
	 */
	struct ccid6_params {
		u32	high_gain:11,		/* max allowed value: 2047 */
			drain_gain:10,		/* max allowed value: 1023 */
			cwnd_gain:11;		/* max allowed value: 2047 */
		u32	cwnd_min_target:4,	/* max allowed value: 15 */
			min_rtt_win_sec:5,	/* max allowed value: 31 */
			probe_rtt_mode_ms:9,	/* max allowed value: 511 */
			full_bw_cnt:3,		/* max allowed value: 7 */
            bw_rtts:5,          
			cwnd_tso_budget:1,	/* allowed values: {0, 1} */
			unused3:1,
			drain_to_target:1,	/* boolean */
			precise_ece_ack:1,	/* boolean */
			extra_acked_in_startup:1, /* allowed values: {0, 1} */
			fast_path:1;		/* boolean */
		u32	full_bw_thresh:10,	/* max allowed value: 1023 */
			startup_cwnd_gain:11,	/* max allowed value: 2047 */
			bw_probe_pif_gain:9,	/* max allowed value: 511 */
			usage_based_cwnd:1, 	/* boolean */
			unused2:1;
		u16	probe_rtt_win_ms:14,	/* max allowed value: 16383 */
			refill_add_inc:2;	/* max allowed value: 3 */
		u16	extra_acked_gain:11,	/* max allowed value: 2047 */
			extra_acked_win_rtts:5; /* max allowed value: 31*/
		u16	pacing_gain[CYCLE_LEN]; /* max allowed value: 1023 */
		/* Mostly BBR v2 parameters below here: */
		u32	ecn_alpha_gain:8,	/* max allowed value: 255 */
			ecn_factor:8,		/* max allowed value: 255 */
			ecn_thresh:8,		/* max allowed value: 255 */
			beta:8;			/* max allowed value: 255 */
		u32	ecn_max_rtt_us:19,	/* max allowed value: 524287 */
			bw_probe_reno_gain:9,	/* max allowed value: 511 */
			full_loss_cnt:4;	/* max allowed value: 15 */
		u32	probe_rtt_cwnd_gain:8,	/* max allowed value: 255 */
			inflight_headroom:8,	/* max allowed value: 255 */
			loss_thresh:8,		/* max allowed value: 255 */
			bw_probe_max_rounds:8;	/* max allowed value: 255 */
		u32	bw_probe_rand_rounds:4, /* max allowed value: 15 */
			bw_probe_base_us:26,	/* usecs: 0..2^26-1 (67 secs) */
			full_ecn_cnt:2;		/* max allowed value: 3 */
		u32	bw_probe_rand_us:26,	/* usecs: 0..2^26-1 (67 secs) */
			undo:1,			/* boolean */
		tso_rtt_shift:4,	/* max allowed value: 15 */
			unused5:1;
		u32	ecn_reprobe_gain:9,	/* max allowed value: 511 */
			unused1:14,
			ecn_alpha_init:9;	/* max allowed value: 256 */
	} params;

	struct {
		u32	snd_isn; 
		u32	rs_bw; 
		u32	target_cwnd; 
		u8	undo:1,
			unused:7;
		char event;
		u16	unused2;
	} debug;
};

struct rate_sample_ccid6 {
	//u32	prior_mstamp;
	//struct	skb_mstamp prior_mstamp; /* starting timestamp for interval */
	u64  prior_mstamp;
	u32  prior_delivered;	/* tp->delivered at "prior_mstamp" */
	s32  delivered;		/* number of packets delivered over interval */
	s64  interval_us;
	//long interval_us;	/* time for tp->delivered to incr "delivered" */
	//long rtt_us;		/* RTT of last (S)ACKed packet (or -1) */
	u32 rtt_us;
	int  losses;		/* number of packets marked lost upon ACK  */
	u32  acked_sacked;	/* number of packets newly (S)ACKed upon ACK */
	u32  prior_in_flight;	/* in flight before this ACK */
	bool is_app_limited;	/* is sample from packet with bubble in pipe? */
	bool is_retrans;	/* is sample from retransmission? */
	bool is_ack_delayed;

	bool is_ece;
	u32 lost;
	u32 prior_delivered_ce;
	u32 delivered_ce;
  	u32 tx_in_flight;
};

static inline bool ccid6_cwnd_network_limited(struct ccid6_hc_tx_sock *hc)
{
	return hc->tx_pipe >= hc->tx_cwnd;
}

/*
 * Convert RFC 3390 larger initial window into an equivalent number of packets.
 * This is based on the numbers specified in RFC 5681, 3.1.
 */
static inline u32 ccid6_rfc3390_bytes_to_pkts(const u32 smss)
{
	return smss <= 1095 ? 4 : (smss > 2190 ? 2 : 3);
}

/**
 * struct ccid6_hc_rx_sock  -  Receiving end of CCID6 half-connection
 * @rx_num_data_pkts: number of data packets received since last feedback
 */
struct ccid6_hc_rx_sock {
	u32	rx_num_data_pkts;
};

static inline struct ccid6_hc_tx_sock *ccid6_hc_tx_sk(const struct sock *sk)
{
	return ccid_priv(dccp_sk(sk)->dccps_hc_tx_ccid);
}

static inline struct ccid6_hc_rx_sock *ccid6_hc_rx_sk(const struct sock *sk)
{
	return ccid_priv(dccp_sk(sk)->dccps_hc_rx_ccid);
}
#endif /* _DCCP_CCID6_H_ */
