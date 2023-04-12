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
 */
#ifndef _DCCP_CCID7_H_
#define _DCCP_CCID7_H_

#include <linux/timer.h>
#include <linux/types.h>
#include "../ccid.h"
#include "../dccp.h"

/*
 * CCID-2 timestamping faces the same issues as TCP timestamping.
 * Hence we reuse/share as much of the code as possible.
 */
#define ccid7_jiffies32	((u32)jiffies)

/* NUMDUPACK parameter from RFC 4341, p. 6 */
#define NUMDUPACK	3

struct ccid7_seq {
	u64			ccid7s_seq;
	u32			ccid7s_sent;
	int			ccid7s_acked;
	struct ccid7_seq	*ccid7s_prev;
	struct ccid7_seq	*ccid7s_next;
};

#define CCID7_SEQBUF_LEN 1024
#define CCID7_SEQBUF_MAX 128

/*
 * Multiple of congestion window to keep the sequence window at
 * (RFC 4340 7.5.2)
 */
#define CCID7_WIN_CHANGE_FACTOR 5

/**
 * struct ccid7_hc_tx_sock - CCID7 TX half connection
 * @tx_{cwnd,ssthresh,pipe}: as per RFC 4341, section 5
 * @tx_packets_acked:	     Ack counter for deriving cwnd growth (RFC 3465)
 * @tx_srtt:		     smoothed RTT estimate, scaled by 2^3
 * @tx_mdev:		     smoothed RTT variation, scaled by 2^2
 * @tx_mdev_max:	     maximum of @mdev during one flight
 * @tx_rttvar:		     moving average/maximum of @mdev_max
 * @tx_rto:		     RTO value deriving from SRTT and RTTVAR (RFC 2988)
 * @tx_rtt_seq:		     to decay RTTVAR at most once per flight
 * @tx_cwnd_used:	     actually used cwnd, W_used of RFC 2861
 * @tx_expected_wnd:	     moving average of @tx_cwnd_used
 * @tx_cwnd_stamp:	     to track idle periods in CWV
 * @tx_lsndtime:	     last time (in jiffies) a data packet was sent
 * @tx_rpseq:		     last consecutive seqno
 * @tx_rpdupack:	     dupacks since rpseq
 * @tx_av_chunks:	     list of Ack Vectors received on current skb
 */
struct ccid7_hc_tx_sock {
	u32			tx_cwnd;
	u32			tx_ssthresh;
	u32			tx_pipe;
	u32			tx_packets_acked;
	struct ccid7_seq	*tx_seqbuf[CCID7_SEQBUF_MAX];
	int			tx_seqbufc;
	struct ccid7_seq	*tx_seqh;
	struct ccid7_seq	*tx_seqt;

	/* RTT measurement: variables/principles are the same as in TCP */
	u32			tx_srtt,
				  tx_mrtt,	/* Raw RTT value as measured by CCID */
				  tx_mdev,
				  tx_mdev_max,
				  tx_rttvar,
				  tx_rto;
	u64			tx_rtt_seq:48;
	struct timer_list	tx_rtotimer;
  struct sock   *sk;

  /* Cubic related */
  u32     css_round_count,
          css_pkt_count,
          round_start,
          sample_cnt,
          min_rtt,
          prev_rtt,
          curr_rtt,
          last_ack,
          end_seq,
          found,
          w_est,
          tx_wmax,
          tx_wmax_prev,
          ca_rx_ct,
          loss_ct;
  s64     cub_c,
          cub_k,
          ref_t;

	/* Congestion Window validation (optional, RFC 2861) */
	u32			exp_inc_rtotimer,
          tx_cwnd_used,
				  tx_expected_wnd,
				  tx_cwnd_stamp,
				  tx_lsndtime;

	u64			tx_rpseq;
	int			tx_rpdupack;
	u32			tx_last_cong;
	u64			tx_high_ack;
	struct list_head	tx_av_chunks;
};

/**
 * Obtain SRTT value form CCID7 TX sock.
 */
static inline u32 ccid7_srtt_as_delay(struct ccid7_hc_tx_sock *hc){
	dccp_pr_debug("srtt value : %u", hc->tx_srtt);
	if(hc){ return hc->tx_srtt;	}
	else{ return 0; }
}

/**
 * Obtain MRTT value form CCID7 TX sock.
 * NOTE: value is scaled by 8 to match SRTT
 */
static inline u32 ccid7_mrtt_as_delay(struct ccid7_hc_tx_sock *hc){
	dccp_pr_debug("mrtt value : %u", hc->tx_mrtt);
	if(hc){ return (hc->tx_mrtt * 8); }
	else{ return 0;	}
}

/* Function pointer to either get SRTT or MRTT ...*/
extern u32 (*ccid7_get_delay_val)(struct ccid7_hc_tx_sock *hc);

static inline void set_ccid7_srtt_as_delay(void){
	ccid7_get_delay_val = ccid7_srtt_as_delay;
}

static inline void set_ccid7_mrtt_as_delay(void){
	ccid7_get_delay_val = ccid7_mrtt_as_delay;
}


static inline bool ccid7_cwnd_network_limited(struct ccid7_hc_tx_sock *hc)
{
	return hc->tx_pipe >= hc->tx_cwnd;
}

/*
 * Convert RFC 3390 larger initial window into an equivalent number of packets.
 * This is based on the numbers specified in RFC 5681, 3.1.
 */
/*static inline u32 ccid7_rfc3390_bytes_to_pkts(const u32 smss)
{
	return smss <= 1095 ? 4 : (smss > 2190 ? 2 : 3);
}*/

/**
 * struct ccid7_hc_rx_sock  -  Receiving end of CCID-2 half-connection
 * @rx_num_data_pkts: number of data packets received since last feedback
 */
struct ccid7_hc_rx_sock {
	u32	rx_num_data_pkts;
};

static inline struct ccid7_hc_tx_sock *ccid7_hc_tx_sk(const struct sock *sk)
{
	return ccid_priv(dccp_sk(sk)->dccps_hc_tx_ccid);
}

static inline struct ccid7_hc_rx_sock *ccid7_hc_rx_sk(const struct sock *sk)
{
	return ccid_priv(dccp_sk(sk)->dccps_hc_rx_ccid);
}
#endif /* _DCCP_CCID7_H_ */
