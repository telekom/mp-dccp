/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 * 
 * Copyright (C) 2018 by Maximilian Schuengel, Deutsche Telekom AG
 * Copyright (C) 2018 by Markus Amend, Deutsche Telekom AG
 * Copyright (C) 2020 by Frank Reker, Deutsche Telekom AG
 *
 * MPDCCP - Generic reordering functions.
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

#ifndef _MPDCCP_REORDERING_H
#define _MPDCCP_REORDERING_H

#include <net/net_namespace.h>
#include <linux/netpoll.h>
#include <linux/rculist.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include "dccp.h"
#include "ccids/ccid2.h"
#include "mpdccp_version.h"
#include <net/mpdccp_link_info.h>
#include <net/mpdccp.h>

/* Maximum lengths for module names */
#define MPDCCP_REORDER_NAME_MAX     16

/* Define reordering return values. */
#define SUCCESS_RO                  0        // success 
#define FAIL_RO                     -1       // unspecific fail 
#define PENDING_RO                  -2       // packet is out-of-order

/* Define macros and scaling factors for reordering purposes */
#define ms2us(ms)                               \
    (ms * 1000)
#define ms2ns(ms)                               \
    (ms * 1000000)

#define DWINDOW_SIZE                5        // window size for directional filter used for reordering


/* Debugging (for reordering) */
extern bool ro_err_state;
extern bool ro_info_state;
extern bool ro_warn_state;
extern int ro_dbug_state;

#define ro_err(fmt, a...)                                                                     \
    if(ro_err_state) pr_err(fmt, ##a)
#define ro_info(fmt, a...)                                                                    \
    if(ro_info_state) pr_info(fmt, ##a)
#define ro_warn(fmt, a...)                                                                    \
    if(ro_warn_state) pr_warn(fmt, ##a)
#define ro_dbug1(fmt, a...)                                                                   \
    MPDCCP_PRINTK (ro_dbug_state, KERN_DEBUG fmt, ##a)
#define ro_dbug2(fmt, a...)                                                                   \
    MPDCCP_PRINTK (ro_dbug_state > 1, KERN_DEBUG fmt, ##a)
// most detailed info output, i.e. output for each packet
#define ro_dbug3(fmt, a...)                                                                   \
    MPDCCP_PRINTK (ro_dbug_state > 2, KERN_DEBUG fmt, ##a)


/* Reordering delay types */
enum {
	MPDCCP_REORDERING_DELAY_MRTT,		// raw_rtt	= 0
	MPDCCP_REORDERING_DELAY_MIN_RTT,	// min_rtt	= 1
	MPDCCP_REORDERING_DELAY_MAX_RTT,	// max_rtt	= 2
	MPDCCP_REORDERING_DELAY_SRTT,		// srtt		= 3
    MPDCCP_REORDERING_DELAY_KRTT     
};


/* 
 * Reordering structures 
 */

/* control block holding subflow specific information */
struct mpdccp_reorder_path_cb {
	struct sock	*sk;
	bool		active;		// activity status of subflow
	
	/* delay vector */
	/* Raw values as obtained from the CCID */
	u32		mrtt; 		/// current mrtt value
	
	/* Kalman filter parameters */
	u32		krtt;		// current krtt value
	u32		x;
	u32		P; 
	u32		x_;
	u32		P_; 
	
	/* Directional filter parameter */
	u32		drtt;
	u32		wnd[DWINDOW_SIZE];
	u32		wnd_raw[DWINDOW_SIZE];
	
	/* receive vector */
	u64		buffed_pkts;
	u64		exp_path_seqno:48;
	u64		oall_seqno:48;	// current received overall sequence number on socket sk
	u64		path_seqno:48;	// current received path sequence number on socket sk
	u8		not_rcv;	// counter to monitor inactivity of socket
};

/*
 * Receive buffer holds information on received MPDCCP packets.
 */
struct rcv_buff
{
	struct delayed_work	dwork;
	
	struct sock		*sk;
	struct sk_buff		*skb;
	struct mpdccp_cb	*mpcb;
	
	u64			oall_seqno:48;
	u32			latency;
	void 			*mpdccp_reorder_cb;
};


/* mpdccp_reorder_ops - MPDCCP reordering operations. 
 * (*init)              Initialize reordering engine
 * (*queue_reorder)     Invoked by packet reception (in interrupt), queues ingress packet in workqueue
 * (*do_reorder)        (legacy) Invoked by workqueue for queued work items
 * (*update_reorder)    Update reordering engine in case of additional/deleted subflows
 * name[]               The name of this algorithm
 * *owner               Useful for memleak detection
 */
struct mpdccp_reorder_ops {
	struct list_head	list;
	
	void			(*init) (struct mpdccp_cb *mpcb);
	void			(*do_reorder) (struct rcv_buff *w);
	void			(*update_pseq) (struct my_sock *, struct sk_buff *);
	
	char			name[MPDCCP_REORDER_NAME_MAX];
	struct module		*owner;
};



/*
 * Reordering functions
 */

/* Generic reordering functions */
int mpdccp_reordering_setup (void);
void mpdccp_reordering_finish (void);

void mpdccp_init_reordering(struct mpdccp_cb *mpcb);
void mpdccp_cleanup_reordering(struct mpdccp_cb *mpcb);
int mpdccp_register_reordering(struct mpdccp_reorder_ops *reorder);
void mpdccp_unregister_reordering(struct mpdccp_reorder_ops *reorder);
struct mpdccp_reorder_ops *mpdccp_reorder_find(const char *name);
void mpdccp_get_default_reordering(char *name);
int mpdccp_set_default_reordering(const char *name);
ktime_t mpdccp_get_now(void);


/* Reordering work queue handling */
int mpdccp_release_rcv_buff(struct rcv_buff **rb);
struct rcv_buff *mpdccp_init_rcv_buff(struct sock *sk, struct sk_buff *skb, struct mpdccp_cb *mpcb);


/* Reordering path cb handling */
struct mpdccp_reorder_path_cb *mpdccp_init_reorder_path_cb(struct sock *sk);
void mpdccp_free_reorder_path_cb(struct mpdccp_reorder_path_cb *pcb);
int mpdccp_path_est(struct mpdccp_reorder_path_cb* pcb, u32 mrtt);


u32 mpdccp_get_lat(struct mpdccp_reorder_path_cb *pcb);
void mpdccp_set_rtt_type(int type);


/* default reordering */
int mpdccp_reorder_default_register(void);
void mpdccp_reorder_default_unregister (void);



#endif /* _MPDCCP_REORDERING_H */

