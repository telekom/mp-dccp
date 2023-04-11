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

#ifndef _DCCP_CCID5_H_
#define _DCCP_CCID5_H_

#include <linux/timer.h>
#include <linux/types.h>
#include "../ccid.h"
#include "../dccp.h"
#include <linux/win_minmax.h>

/*
 * CCID-2 timestamping faces the same issues as TCP timestamping.
 * Hence we reuse/share as much of the code as possible.
 */
//#define ccid5_time_stamp	tcp_time_stamp
#define ccid5_jiffies32	((u32)jiffies)

/* NUMDUPACK parameter from RFC 4341, p. 6 */
#define NUMDUPACK	3

struct ccid5_seq {
	u64			ccid5s_seq;
	u32			ccid5s_sent,
				delivered;
	int			ccid5s_acked;
	bool 		is_app_limited;
	//struct skb_mstamp	 sent_mstamp;
	u64			sent_mstamp;
	//struct skb_mstamp	 first_tx_mstamp;
	u64			first_tx_mstamp;
	//struct skb_mstamp	 delivered_mstamp;
	u64			delivered_mstamp;
	struct ccid5_seq	*ccid5s_prev;
	struct ccid5_seq	*ccid5s_next;
};

#define CCID5_SEQBUF_LEN 1024
#define CCID5_SEQBUF_MAX 128

/*
 * Multiple of congestion window to keep the sequence window at
 * (RFC 4340 7.5.2)
 */
#define CCID5_WIN_CHANGE_FACTOR 5


struct ccid5_hc_tx_sock {
	u32			tx_cwnd;
	u32			tx_ssthresh;
	u32			tx_pipe;
	u32			tx_packets_acked;
	struct ccid5_seq	*tx_seqbuf[CCID5_SEQBUF_MAX];
	int			tx_seqbufc;
	struct ccid5_seq	*tx_seqh;
	struct ccid5_seq	*tx_seqt;

	/* RTT measurement: variables/principles are the same as in TCP */
	u32			tx_srtt,
				tx_mrtt,
				tx_mdev,
				tx_mdev_max,
				tx_rttvar,
				tx_rto,
				tx_last_ack_recv;
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
				app_limited;

	/* variables of BBR struct */
	u32			min_rtt_us;
	u32			max_rtt_us;
	u32			min_rtt_stamp;	        /* timestamp of min_rtt_us */
	u32			max_rtt_stamp;	        /* timestamp of min_rtt_us */
	u32			probe_rtt_done_stamp;   /* end time for BBR_PROBE_RTT mode */
	u32 		mode:3,		     /* current bbr_mode in state machine */
				prev_ca_state:3,     /* CA state on previous ACK */
				packet_conservation:1,  /* use packet conservation? */
				restore_cwnd:1,	     /* decided to revert cwnd to old value */
				restore_ackrt:1,     /* decided to revert ack_ratio to old value */
				restore_seqwin:1,    /* decided to revert seq_window to old value */
				round_start:1,	     /* start of packet-timed tx->ack round? */
				tso_segs_goal:7,     /* segments we want in each skb we send */
				idle_restart:1,	     /* restarting after idle? */
				probe_rtt_round_done:1,  /* a BBR_PROBE_RTT round at 4 pkts? */
				unused:3,
				lt_is_sampling:1,    /* taking long-term ("LT") samples now? */
				lt_rtt_cnt:7,	     /* round trips in long-term interval */
				lt_use_bw:1;	     /* use lt_bw as our bw estimate? */
	u32			lt_bw;
	u32			lt_last_delivered;   /* LT intvl start: tp->delivered */
	u32			lt_last_stamp;
	u32			lt_last_lost;
	u32			pacing_gain:10,	/* current gain for setting pacing rate */
				cwnd_gain:10,	/* current gain for setting cwnd */
				full_bw_reached:1,   /* reached full bw in Startup? */
				full_bw_cnt:2,	/* number of rounds without large bw gains */
				cycle_idx:3,	/* current index in pacing_gain cycle array */
				has_seen_rtt:1, /* have we seen an RTT sample yet? */
				unused_b:5;
	u32			next_rtt_delivered;
	//struct skb_mstamp cycle_mstamp;
	u64			cycle_mstamp;
	u32			rtt_cnt;
	struct minmax bw;
	u32			prior_cwnd;	/* prior cwnd upon entering loss recovery */
	u32			full_bw;	/* recent bw, to estimate if pipe is full */
	u32 		bytes_att;
	u32 		bytes_sent;
	u32			curr_ca_state; 
	bool		pr_init;
	bool		rtprop_fix;
	u32			lost;
	bool			tx_extrapkt;
	u64			prior_ackrt;
	u64			prior_seqwin;
};

struct rate_sample_ccid5 {
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
};

// TODO reordering
/**
 * Obtain SRTT value form CCID5 TX sock.
 */
static inline u32 ccid5_srtt_as_delay(struct ccid5_hc_tx_sock *hc){
	dccp_pr_debug("srtt value : %u", hc->tx_srtt);
	if(hc){ return hc->tx_srtt;	}
	else{ return 0; }
}

/**
 * Obtain MRTT value form CCID2 TX sock.
 * NOTE: value is scaled by 8 to match SRTT
 */
static inline u32 ccid5_mrtt_as_delay(struct ccid5_hc_tx_sock *hc){
	dccp_pr_debug("mrtt value : %u", hc->tx_mrtt);
	if(hc){ return (hc->tx_mrtt * 8); }
	else{ return 0;	}
}

/* Function pointer to either get SRTT or MRTT ...*/
//extern u32 (*get_delay_val)(struct ccid5_hc_tx_sock *hc);

/**
 * Set function pointer.
 */
//static inline void set_srtt_as_delay(void){
//	get_delay_val = srtt_as_delay;
//}

/**
 * Set function pointer.
 */
//static inline void set_mrtt_as_delay(void){
//	get_delay_val = mrtt_as_delay;
//}


static inline bool ccid5_cwnd_network_limited(struct ccid5_hc_tx_sock *hc)
{
	//printk(KERN_INFO "natrm: net_lim pipe %lu cwnd %lu", hc->tx_pipe, hc->tx_cwnd);
	return hc->tx_pipe >= hc->tx_cwnd;
}

/*
 * Convert RFC 3390 larger initial window into an equivalent number of packets.
 * This is based on the numbers specified in RFC 5681, 3.1.
 */
/*static inline u32 rfc3390_bytes_to_packets(const u32 smss)
{
	return smss <= 1095 ? 4 : (smss > 2190 ? 2 : 3);
}*/

/**
 * struct ccid2_hc_rx_sock  -  Receiving end of CCID-2 half-connection
 * @rx_num_data_pkts: number of data packets received since last feedback
 */
struct ccid5_hc_rx_sock {
	u32	rx_num_data_pkts;
};

static inline struct ccid5_hc_tx_sock *ccid5_hc_tx_sk(const struct sock *sk)
{
	return ccid_priv(dccp_sk(sk)->dccps_hc_tx_ccid);
}

static inline struct ccid5_hc_rx_sock *ccid5_hc_rx_sk(const struct sock *sk)
{
	return ccid_priv(dccp_sk(sk)->dccps_hc_rx_ccid);
}
#endif /* _DCCP_CCID5_H_ */
