/*  SPDX-License-Identifier: NONE
 *
 * Copyright (C) 2018 by Maximilian Schuengel, Deutsche Telekom AG
 * Copyright (C) 2021 by Romeo Cane, Deutsche Telekom AG
 *
 * MPDCCP - Active reordering module
 *
 * This module implements an active reordering algorithm for MPDCCP.
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
 *
 * sysctl allows a configuration as follows:
 * 
 * Enable Active reordering: echo active > proc/sys/net/mpdccp/mpdccp_reordering
 *
 * Once enabled, the following properties are configurable
 *
 * echo <val> > /proc/sys/mpdccp_active_reordering/<property>
 *
 * 1) property = adaptive : Configure active reordering to be adaptive.  
 * 		a) val = 0 : fixed active reordering, timeout is a fixed value (*see 2) : to = const.
 *		b) val = 1 : adaptive active reordering, timeout is an adaptive value derived from 
 *		             fastest and slowest paths : to = max_latency - min_latency
 *      c) val = 2 : equalized adaptive reordering, timeout is an adaptive value derived from 
 *					 slowest and current path : to = max_latency - cur_latency, by that packets  
 *					 from different paths show a different lifetime.
 *
 * 2) property = fixed_timeout : Configure a fixed packet lifetime/timeout used for fixed acitve 
 *								 reordering and as initial value for adaptive algorithms.
 *		a) val > 0 : in ms
 *
 * 3) property = adaptive_timeout_max : Configure an upper bound for adaptive timeout values.
 *		a) val > 0 : in ms 
 *
 * 4) property = timeout_offset : Configure a fixed timeout offset used for adaptive approaches 
 *                                to compensate variances. This will be done adaptively eventually.
 *		a) val > 0 : in ms
 *
 * 5) property = loss_detection : Configure the used loss detection mechanism.
 *		a) val = 0 : no (fast) loss detection
 *		b) val = 1 : fast loss detection by overall sequencing
 *		c) val = 2 : fast loss detection by path sequencing
 *		d) val = 3 : fast loss detection by combining overall and path sequencing
 *
 * 6) property = drop_lost : Configure what to do when receiving lost packets.
 *      a) val = 0 : forward packets to the application
 *      b) val = 1 : drop packets
*
 * 7) property = drop_dup : Configure what to do when receiving duplicated packets.
 *      a) val = 0 : forward packets to the application
 *      b) val = 1 : drop packets
 */


#include <linux/module.h>

#include "../mpdccp.h"
#include "../mpdccp_reordering.h"
#include <linux/vmalloc.h>

/* default values */
#define RBUF_SIZE       2048     // size of fixed size reordering buffer used in active reordering

#define FTO_DEF 		15
#define TO_OFF			5
#define ATO_MAX 		100
#define NOT_RCV_MAX 	250
#define RTT_TYPE        0
#define EXP_TO          50       

/* macros */
// handle buffer
#define __rbuf_entry(cb, seqno)                                                               \
    cb->rbuf.buf[seqno % sysctl_rbuf_size]
#define rbuf_tt_entry(cb, seqno)                                                              \
    cb->rbuf.tt[seqno % sysctl_rbuf_size]
#define rbuf_tt_write(cb)																	  \
    cb->rbuf.tt[atomic_read(&cb->rbuf.tt_w)]; 												  \
    atomic_set(&cb->rbuf.tt_w, (atomic_read(&cb->rbuf.tt_w) % sysctl_rbuf_size))
#define __rbuf_size(cb)                                                                       \
    atomic_read(&cb->rbuf.size)
#define __rbuf_size_inc(cb)                                                                   \
	atomic_inc(&cb->rbuf.size)
#define __rbuf_size_dec(cb)                                                                   \
	atomic_dec(&cb->rbuf.size)
#define __rbuf_next(cb)                                                                       \
    (u64)atomic64_read(&cb->rbuf.next)
#define __rbuf_next_set(cb, seqno)                                                            \
    atomic64_set(&cb->rbuf.next, seqno)
#define __rbuf_last(cb)                                                                       \
    (u64)atomic64_read(&cb->rbuf.last)
#define __rbuf_last_set(cb, seqno)                                                            \
    atomic64_set(&cb->rbuf.last, seqno)
// handle atomic properties
#define __exp(cb)																	          \
    (u64)atomic64_read(&cb->expected)
#define __exp_set(cb, seqno)																  \
    atomic64_set(&cb->expected, seqno)
#define __snd(cb)                                                                             \
    (u64)atomic64_read(&cb->sending)
#define __snd_set(cb, seqno)                                                                  \
    atomic64_set(&cb->sending, seqno)
#define __max_lat(cb)                                                                         \
    (u64)atomic64_read(&cb->_max_lat)
#define __max_lat_set(cb, lat)                                                                \
    atomic64_set(&cb->_max_lat, lat)
#define __min_lat(cb)                                                                         \
    (u64)atomic64_read(&cb->_min_lat)
#define __min_lat_set(cb, lat)                                                                \
    atomic64_set(&cb->_min_lat, lat)
#define __max_sk(cb)                                                                          \
    cb->max_sk
#define __max_sk_set(cb, sk)                                                                  \
    cb->max_sk = sk
#define __min_sk(cb)                                                                          \
    cb->min_sk
#define __min_sk_set(cb, sk)                                                                  \
    cb->min_sk = sk
// other
#define __is2n(n)																			  \
	((n & (n - 1)) == 0)  // check if n = 2^x, x in {0, 1, 2, 3, 4, ...}
	
/* slab cache */
struct kmem_cache *active_cb_cache __read_mostly;

/* lists and locks */
DEFINE_SPINLOCK(active_cb_list_lock);
LIST_HEAD(active_cb_list);

/* sysctl properties */
int sysctl_adaptive 		= 0;					// selection of adaptivness, see description 1)
int sysctl_fto 				= FTO_DEF; 				// fixed timeout [ms]
int sysctl_ato_max 			= ATO_MAX; 				// maximum adaptive timeout
int sysctl_to_off 			= TO_OFF; 				// TimeOut OFFset for adaptive algorithms (to compensate variance) [ms]
int sysctl_loss_detection 	= 0;					// selection of loss detection, see description 5)
int sysctl_not_rcv_max 		= NOT_RCV_MAX;			// token threshold for activity monitoring
int sysctl_rbuf_size 		= RBUF_SIZE;			// buffer size
int sysctl_rtt_type 		= RTT_TYPE;				// selection of rtt type
int sysctl_exp_to           = EXP_TO;               // expiry timeout
int sysctl_drop_lost		= 0;					// drop of lost packets
int sysctl_drop_dup		= 0;					// drop of duplicated packets

/************************************************* 
 *     structures
 *************************************************/
struct mpdccp_rbuf_entry{
	struct sk_buff *skb;
	ktime_t abs_to;                                 // timeout (absolute)
	atomic64_t oall_seqno;
};

/*
 * reordering buffer for active re-
 * ordering (fixed size ring buffer)
 */
struct mpdccp_rbuf {
	// reordering buffer
    struct mpdccp_rbuf_entry *buf;					 // reordering buffer -> array of skb's
    atomic_t size;   								 // current fill level
    atomic64_t next;								 // buffer entry with lowest oall_seqno
    atomic64_t last;								 // buffer entry with highest oall_seqno

    struct mpdccp_cb *mpcb;							 // mpdccp control block -> tunnel level information
    struct active_cb *acb;							 // active control block -> link level information
    struct timer_list exp_timer;						 // expiry timer
};

/* structure declarations */
struct active_cb {
	struct list_head list;

	// base properties
	struct mpdccp_cb *mpcb;							 // mpdccp control block -> tunnel level information
	struct mpdccp_rbuf rbuf;						 // reordering buffer

	// atomic properties 
    atomic64_t expected;                             // expected overall sequence number
    atomic64_t sending;
    atomic64_t _max_lat;                             // latency of slowest subflow
    struct sock *max_sk;                             // socket associated with the slowest subflow
    atomic64_t _min_lat;                             // latency of fastest subflow
    struct sock *min_sk;                             // socket associated with the fastest subflow
    atomic64_t _lmin_seqno;                                                        						
    spinlock_t adaptive_cb_lock;
};


/************************************************* 
 *     functions/function pointer
 *************************************************/
/* function pointer */
u64 (*get_to)(struct active_cb *acb, u64 latency);
void (*detect_loss)(struct active_cb *acb, struct mpdccp_reorder_path_cb *pcb);

/* functions */
// reordering functions
void init_reorder_active_mod(struct mpdccp_cb *mpcb);
void do_reorder_active_mod(struct rcv_buff *rb);
int fast_check(struct active_cb *acb, struct sk_buff *skb, struct mpdccp_cb *mpcb, const u64 oall_seqno);

// buffer functions
void rbuf_init(struct mpdccp_rbuf *rbuf, struct active_cb *acb);
void rbuf_insert(struct active_cb *acb, struct rcv_buff *rb, struct mpdccp_reorder_path_cb *pcb);	
void rbuf_flush(struct active_cb *acb, u64 exp);
void rbuf_find_next(struct active_cb *acb, u64 exp);
void __rbuf_find_next(struct active_cb *acb, u64 exp);

// timer functions
void exp_timer_cb(unsigned long arg);

// reconfigurability functions
u64 get_fixed_to(struct active_cb *acb, u64 latency);
u64 get_adaptive_to(struct active_cb *acb, u64 latency);
u64 get_equalized_adatptive_to(struct active_cb *acb, u64 latency);
char* set_adaptive(void);
void detect_no_loss(struct active_cb *acb, struct mpdccp_reorder_path_cb *pcb);
void detect_fast_loss_oall(struct active_cb *acb, struct mpdccp_reorder_path_cb *pcb);
void detect_fast_loss_path(struct active_cb *acb, struct mpdccp_reorder_path_cb *pcb);
void detect_fast_loss_combined(struct active_cb *acb, struct mpdccp_reorder_path_cb *pcb);
char* set_loss_detection(void);

// active cb management functions
struct active_cb* active_cb_init(struct mpdccp_cb *mpcb);
int allocate_active_cb_cache(void);

// helper 
void forward_inorder(struct active_cb *acb, u64 i);
void forward(struct active_cb *acb, u64 i);

// sysctl functions
static int proc_adaptive(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos);
static int proc_fixed_timeout(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos);
static int proc_adaptive_timeout_max(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos);
static int proc_loss_detection(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos);
static int proc_not_rcv_max(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos);

// module functions
void cleanup_active_mod(void);
static int __init mpdccp_reorder_active_register(void);
static void mpdccp_reorder_active_unregister(void);


/************************************************* 
 *     reordering
 *************************************************/
/**
 * Initialize active reordering module.
 */ 
void init_reorder_active_mod(struct mpdccp_cb *mpcb){
	struct active_cb *acb = NULL;

	acb = active_cb_init(mpcb);
	if(!acb) goto failed;

	mpcb->mpdccp_reorder_cb = (void *)acb;
	spin_lock(&active_cb_list_lock);
		list_add_tail_rcu(&acb->list, &active_cb_list);
		ro_info("RO-INFO: new active cb (0x%p) for MPDCCP connection identified by mpcb (0x%p)", acb, acb->mpcb);
	spin_unlock(&active_cb_list_lock);

	ro_info("RO-INFO: > %s active reordering (new implementation)\n", set_adaptive());
	ro_info("RO-INFO: settings: fixed timeout=%d [ms], buffer size=%d [-],\n", (int)sysctl_fto, sysctl_rbuf_size);
	ro_info("RO-INFO:           %s, initial seqno=%llu, inactivity threshold=%d [-]\n", set_loss_detection(), __exp(acb), sysctl_not_rcv_max);

	goto finished;

failed:
	ro_err("RO-ERROR: NULL acb");

finished:
	return;
}

/**
 * Main roerdering function. This function is invoked 
 * for each packet that arrives. (in interrupt)
 */
void do_reorder_active_mod(struct rcv_buff *rb){
	struct active_cb *acb = NULL;
	struct mpdccp_reorder_path_cb *pcb = NULL;
	struct sock *itr;
	struct my_sock *my_sk = NULL, *my_itr = NULL;
	u64 exp;

    if(!rb) {
        ro_err("RO-ERROR: NULL rb");
        return;
    }

    my_sk = mpdccp_my_sock(rb->sk);
    if(!my_sk) {
        ro_err("RO-ERROR: NULL my_sk");
        goto exit;
    }

    acb = (struct active_cb *)rb->mpdccp_reorder_cb;
    if(!acb){
        ro_err("RO-ERROR: NULL acb");
        goto exit;
    }


    /*
     * ### PATH PROPERTIES:
     * find path cb or create new instance if
     * link was not detected earlier 
     */
    pcb = my_sk->pcb;
    if(!pcb){
        pcb = mpdccp_init_reorder_path_cb(rb->sk);
        my_sk->pcb = pcb;
        pcb->last_path_seqno = DCCP_SKB_CB(rb->skb)->dccpd_seq;
        pcb->last_oall_seqno = rb->oall_seqno;
        ro_dbug1("RO-DEBUG: new pcb 0x%p", pcb);
    }
    /* update path properties */
    pcb->oall_seqno = rb->oall_seqno;
    pcb->path_seqno = DCCP_SKB_CB(rb->skb)->dccpd_seq;

    /* 
     * ### LATENCY ESTIMATION:
     */
    mpdccp_path_est(pcb, rb->latency);

    /* 
     * ### RESET EXPIRY-TIMER:
     */
    mod_timer(&acb->rbuf.exp_timer, jiffies + msecs_to_jiffies(sysctl_exp_to));

    /*
     * ### ACTIVITY MONITORING:
     * detect inactive links
     */
    pcb->not_rcv = 0;                                                               // reset activity monitoring
    if(!pcb->active){
      pcb->active = true;                                                           // sublow is active
      ro_dbug1("RO-DEBUG: new active subflow detected : pcb (0x%p) sk (0x%p)", pcb, pcb->sk);
    }

    spin_lock_bh(&((acb->mpcb)->psubflow_list_lock));
    /* assign tokens to all other sublows but not this */
    list_for_each_entry(my_itr, &((acb->mpcb)->psubflow_list), sk_list) {
        if(!my_itr->pcb) continue;                                                  // skip not initialized links
        if(!my_itr->pcb->active) continue;                                          // skip inactive links
        itr = my_itr->my_sk_sock;
        /* all links but this one */
        if(itr != pcb->sk){                                             
            if(my_itr->pcb->not_rcv >= sysctl_not_rcv_max){
                ro_info("RO-INFO: inactive subflow detected : sk (0x%p)", itr);
                my_itr->pcb->active = false;                                        // set subflow inactive
                /* 
                 * reset max. and min. delay and sk in case 
                 * slow link becomes inactive 
                 */
                if(my_itr->pcb->sk == __max_sk(acb)){
                    __max_lat_set(acb, 0);
                    __max_sk_set(acb, NULL);
                }
                if(my_itr->pcb->sk == __max_sk(acb)){
                    __min_lat_set(acb, U64_MAX);
                    __min_sk_set(acb, NULL);
                }
            }
            else my_itr->pcb->not_rcv++;                                            // assign/increase token 
            ro_dbug3("RO-DEBUG: sk (0x%p) - tokens : %u", my_itr->pcb->sk, my_itr->pcb->not_rcv);
        }       
        /* find max. and min. delay from all active links (which are active) */
        if(my_itr->pcb->active){
            /* update max. delay */
            if(__max_sk(acb) == my_itr->pcb->sk) __max_lat_set(acb, mpdccp_get_lat(my_itr->pcb));
            /* new slowest link */
            else if(__max_lat(acb) < mpdccp_get_lat(my_itr->pcb)){
                __max_lat_set(acb, mpdccp_get_lat(my_itr->pcb));
                __max_sk_set(acb, my_itr->pcb->sk);
                 ro_dbug3("RO-DEBUG: slowest acb: %p pcb: %p sk: %p lat: %u", acb, pcb, my_itr->pcb->sk, mpdccp_get_lat(my_itr->pcb));
            } 

            /* update min. delay */
            if(__min_sk(acb) == my_itr->pcb->sk) __min_lat_set(acb, mpdccp_get_lat(my_itr->pcb));
            /* new fastest link */
            else if(__min_lat(acb) > mpdccp_get_lat(my_itr->pcb)){
                __min_lat_set(acb, mpdccp_get_lat(my_itr->pcb));
                __min_sk_set(acb, my_itr->pcb->sk);
                ro_dbug3("RO-DEBUG: fastest acb: %p pcb: %p sk: %p lat: %u", acb, pcb, my_itr->pcb->sk, mpdccp_get_lat(my_itr->pcb));
            } 
        }
    }
    spin_unlock_bh(&((acb->mpcb)->psubflow_list_lock));

    /* 
     * ### LOSS DETECTION:
     */
    spin_lock_bh(&acb->adaptive_cb_lock);
    detect_loss(acb, pcb);
    pcb->last_oall_seqno = rb->oall_seqno;
    //pcb->last_path_seqno = pcb->path_seqno;
    exp = __exp(acb);
    /*
    * ### REORDERING DECISION:
    * forward expected, drop/forward outdated, buffer others
    */
    if(rb->oall_seqno == exp)
        goto forward;
    else if(rb->oall_seqno < exp) {
        if (sysctl_drop_lost) {
            ro_dbug3("RO-DEBUG: dropping outdated packet seq: %llu pcb %p\n", (u64)rb->oall_seqno, pcb);
  	    kfree_skb (rb->skb);
   	    rb->skb = NULL;
            goto finished;
        } else {
            ro_dbug3("RO-DEBUG: forwarding outdated packet seq: %llu pcb %p\n", (u64)rb->oall_seqno, pcb);
            mpdccp_forward_skb(rb->skb, rb->mpcb);
            goto finished;
        }
    }
    else goto buffer;

/* irreversible out-of-order */
forward:
    mpdccp_forward_skb(rb->skb, rb->mpcb);
    __exp_set(acb, (exp + 1));
    acb->mpcb->glob_lfor_seqno = exp;

    goto finished;
/* in-order or reversible out-of-order */
buffer:
	rbuf_insert(acb, rb, pcb);
finished:
	if (__snd(acb)==0) {
		rbuf_flush(acb, __exp(acb));
	}

    spin_unlock_bh(&acb->adaptive_cb_lock);
exit:
	mpdccp_release_rcv_buff(&rb);
	return;
}

void do_update_pseq(struct my_sock *my_sk, struct sk_buff *skb){
	struct mpdccp_reorder_path_cb *pcb = my_sk->pcb;
	if(pcb && DCCP_SKB_CB(skb)->dccpd_seq > pcb->last_path_seqno)
        pcb->last_path_seqno = DCCP_SKB_CB(skb)->dccpd_seq;
}

/************************************************* 
 *     buffer handling
 *************************************************/

/**
 * Initialize 'rbuf'.
 */
void rbuf_init(struct mpdccp_rbuf *rbuf, struct active_cb *acb){
	unsigned int i = 0;

	if(!rbuf) return;
	if(!acb) return;

	/* reordering buffer */ 
	rbuf->buf = kmalloc(sizeof(struct mpdccp_rbuf_entry) * sysctl_rbuf_size, GFP_ATOMIC);
	atomic_set(&rbuf->size, 0);
	__rbuf_next_set(acb, U64_MAX);
	__rbuf_last_set(acb, 0);

	for(i = 0; i < sysctl_rbuf_size; i++){
		__rbuf_entry(acb, i).skb = NULL;
        __rbuf_entry(acb, i).abs_to = ktime_set(0, 0);
	}

	setup_timer(&rbuf->exp_timer, exp_timer_cb, (unsigned long) rbuf);

	rbuf->acb = acb;
	rbuf->mpcb = acb->mpcb;
}

/**
 * Insert an skb into the buffer according 
 * to its sequence number, set flags.
 */
void rbuf_insert(struct active_cb *acb, struct rcv_buff *rb, struct mpdccp_reorder_path_cb *pcb){
retry:
	if(!__rbuf_entry(acb, rb->oall_seqno).skb){
		__rbuf_entry(acb, rb->oall_seqno).skb = rb->skb;
        	__rbuf_entry(acb, rb->oall_seqno).abs_to = ktime_add_ms(mpdccp_get_now(), get_to(acb, mpdccp_get_lat(pcb))); 
        	ro_dbug3("RO-DEBUG: insert acb: %p pcb: %p to %llu", acb, pcb, get_to(acb, mpdccp_get_lat(pcb)));
		__rbuf_size_inc(acb);
		atomic64_set (&__rbuf_entry(acb, rb->oall_seqno).oall_seqno, rb->oall_seqno);

		/* determine start and end of buffer */
		if(__rbuf_last(acb) < rb->oall_seqno) __rbuf_last_set(acb, rb->oall_seqno);
		if(__rbuf_next(acb) > rb->oall_seqno) __rbuf_next_set(acb, rb->oall_seqno);
	}
	else if (sysctl_drop_dup && rb->oall_seqno == (u64)atomic64_read (&__rbuf_entry(acb, rb->oall_seqno).oall_seqno)) {
		/* drop duplicated packets */
		kfree_skb (rb->skb);
		rb->skb = NULL;
	}
#if 0
	else if (rb->oall_seqno <= (u64)atomic64_read (&__rbuf_entry(acb, rb->oall_seqno).oall_seqno)) {
		ro_warn("RO-WARN: overwriting packets"); 
            	mpdccp_forward_skb(rb->skb, rb->mpcb);
	}
#endif
	else{
		ro_warn("RO-WARN: overwriting packets"); 
		forward(acb, rb->oall_seqno);
		goto retry;
	}
}

/**
 * Forward as many packets as possible inorder. 
 */
void rbuf_flush(struct active_cb *acb, u64 exp){
    int ret;
	u8 cnt = 0;
    u64 next;

	/* rbuf is emtpy */
	if(__rbuf_size(acb) == 0) goto empty; 

	
	//ro_dbug3("RO-DEBUG: flushing buffer (size : %u, exp. : %llu)", __rbuf_size(acb), exp);
	while(__rbuf_entry(acb, exp).skb){
        if (__snd(acb)!=exp){
            __snd_set(acb, exp);
        }
        else {
            printk(KERN_INFO "att sk twice %llu", exp);
            return;
        }
        forward_inorder(acb, exp);
        //ro_dbug3("RO-DEBUG:     flushed packet [%llu]", exp);

		exp++;
		cnt++;
	}

	goto success;

empty:
	ro_dbug3("RO-DEBUG: flushing skipped due to empty buffer");
	goto finished;
success:
	ro_dbug3("RO-DEBUG: flushed %u packets (new size : %u)", cnt, __rbuf_size(acb));

	/* find new next (if packets were forwarded) */
	if(__rbuf_size(acb) > 0) rbuf_find_next(acb, exp);
    else __rbuf_last_set(acb, U64_MAX);  

    /* check for timeout */
    next = __rbuf_next(acb);
    if(next != U64_MAX){
        if(!__rbuf_entry(acb, next).skb) goto finished;
        ret = ktime_compare(__rbuf_entry(acb, next).abs_to, mpdccp_get_now());                     // packet has timedout
        if(ret <= 0) {
            if (__snd(acb)!=next) {
                __snd_set(acb, next);
            } else {
                printk(KERN_INFO "att sk twice %llu", next);
                return;
            }
            ro_dbug2("RO-DEBUG: timeout detected for packet [%llu]", next);
            forward_inorder(acb, next);
        }
    }

finished:
    __snd_set(acb, 0);
	return;
}

/**
 * Find the first availble buffer entry. Set timer accordingly.
 */
void rbuf_find_next(struct active_cb *acb, u64 exp){
    u64 new_low;

    /* find new low */
	__rbuf_find_next(acb, exp);
    new_low = __rbuf_next(acb);

    if(new_low == U64_MAX) return;
}

/**
 * Find the first available buffer entry.
 */
void __rbuf_find_next(struct active_cb *acb, u64 exp){
    u64 i;
//    for(i = exp; i < __rbuf_last(acb); i++){ if(__rbuf_entry(acb, i).skb) return __rbuf_next_set(acb, i); }
    for(i = exp; i < __rbuf_last(acb); i++){ if(__rbuf_entry(acb, i).skb) {__rbuf_next_set(acb, i); return;} }
//    return __rbuf_next_set(acb, U64_MAX);
    __rbuf_next_set(acb, U64_MAX);
}

/************************************************* 
 *     timer handling
 *************************************************/
void exp_timer_cb(unsigned long arg){
    struct mpdccp_rbuf *rbuf = (struct mpdccp_rbuf *) arg;
    struct active_cb *acb = NULL;
    u64 last;
    int i = 0, cnt = 0;

    if(!rbuf) {
        ro_err("RO-ERROR: could not determine container rbuf of t");
        return;
    }

    acb = rbuf->acb;
    spin_lock_bh(&acb->adaptive_cb_lock);
    ro_dbug1("RO-DEBUG: timer (0x%p) elapsed, exp %llu", &rbuf->exp_timer, (u64)__exp(acb));

    /* forward all packets that are buffered */
    last = __rbuf_last(acb);
    //TODO force flush from next to last (does not work somehow)
    //for(next = __rbuf_next(acb); next <  (last == U64_MAX ? (next + sysctl_rbuf_size) : last); next++){ if(__rbuf_entry(acb, next).skb) forward(acb, next); }
    for(i = 0; i < sysctl_rbuf_size; i++){ 
        if(__rbuf_entry(acb, i).skb){
            forward_inorder(acb, i); 
            cnt++;
        } 
    }
    spin_unlock_bh(&acb->adaptive_cb_lock);
    ro_dbug1("RO-DEBUG: %u packets expired", cnt);
}


/************************************************* 
 *     reconfigurability
 *************************************************/

/**
 * Function pointer prototypes to distinguish 
 * 1) fixed
 * 2) adaptive
 * 3) equalize adaptive 
 * reordering.
 */
u64 get_fixed_to(struct active_cb *acb, u64 latency){ return (u64)sysctl_fto; }
u64 get_adaptive_to(struct active_cb *acb, u64 latency){ 
	u64 ato = ((__max_lat(acb) - __min_lat(acb)) + sysctl_to_off);
	return (ato < sysctl_ato_max) ? ato : sysctl_ato_max;
}
u64 get_equalized_adatptive_to(struct active_cb *acb, u64 latency){ 
	u64 eato = (__max_lat(acb) - latency) + sysctl_to_off;
	return (eato < sysctl_ato_max) ? eato : sysctl_ato_max;
}
char* set_adaptive(void){
	switch(sysctl_adaptive){
	case 0:
fixed:
		get_to = get_fixed_to;
		return "FIXED";
	case 1:
		get_to = get_adaptive_to;
		return "ADAPTIVE";
	case 2:
		get_to = get_equalized_adatptive_to;
		return "EQUALIZED ADAPTIVE";
	default:
		goto fixed;
	}
}

/**
 * Function pointer prototypes to distinguish
 * 1) no loss detection
 * 2) fast loss detection by overall sequencing
 * 3) fast loss detection by path sequencing
 * 4) fast loss detection by overall and path sequencing
 * mechanisms.
 */
void detect_no_loss(struct active_cb *acb, struct mpdccp_reorder_path_cb *pcb){ return; }

void detect_fast_loss_oall(struct active_cb *acb, struct mpdccp_reorder_path_cb *pcb)
{
    struct my_sock *my_itr = NULL;
    u64 min = U64_MAX;                          // latest received packet with lowest oaverall sequence number (tunnel-level)
    u64 oall_gap;

    spin_lock_bh(&((acb->mpcb)->psubflow_list_lock));
	list_for_each_entry(my_itr, &((acb->mpcb)->psubflow_list), sk_list) {
        if(!my_itr->pcb) continue;                                                  // skip not initialized links
        if(!my_itr->pcb->active) continue;                                          // skip inactive links
        min = (min > my_itr->pcb->oall_seqno) ? my_itr->pcb->oall_seqno : min;
    }
    spin_unlock_bh(&((acb->mpcb)->psubflow_list_lock));

    oall_gap = (__exp(acb) < min) ? (min - __exp(acb)) : 0;
    if (oall_gap) {
        ro_dbug1("RO-DEBUG: detect_fast_loss_oall lost %llu packets\n", oall_gap);
        __exp_set(acb, __exp(acb) + oall_gap);
    }
}

void detect_fast_loss_path(struct active_cb *acb, struct mpdccp_reorder_path_cb *pcb)
{
    u64 path_gap;

    path_gap = (pcb->path_seqno > pcb->last_path_seqno) ? (pcb->path_seqno - pcb->last_path_seqno - 1) : 0;
    if (path_gap) {
        ro_dbug1("RO-DEBUG: detect_fast_loss_path lost %llu packets on pcb %p\n", path_gap, pcb);
        __exp_set(acb, __exp(acb) + path_gap);
    }
}

void detect_fast_loss_combined(struct active_cb *acb, struct mpdccp_reorder_path_cb *pcb)
{
    u64 oall_gap;
    u64 path_gap;

    oall_gap = (pcb->oall_seqno > pcb->last_oall_seqno) ? (pcb->oall_seqno - pcb->last_oall_seqno - 1) : 0;
    path_gap = (pcb->path_seqno > pcb->last_path_seqno) ? (pcb->path_seqno - pcb->last_path_seqno - 1) : 0;

    if (oall_gap && (oall_gap == path_gap)) {
        ro_dbug1("RO-DEBUG: detect_fast_loss_combined lost %llu packets on pcb %p\n", path_gap, pcb);
        __exp_set(acb, pcb->oall_seqno);
    }
}

char* set_loss_detection(void){
	switch(sysctl_loss_detection){
	case 0:
no_loss:
		detect_loss = detect_no_loss;
		return "NO loss detection";
	case 1:
		detect_loss = detect_fast_loss_oall;
		return "FAST loss detection by OVERALL-SEQUENCING";
	case 2:
		detect_loss = detect_fast_loss_path;
		return "FAST loss detection by PATH-SEQUENCING";
	case 3:
		detect_loss = detect_fast_loss_combined;
		return "FAST loss detection by OVERALL- and PATH-SEQUENCING";
	default:
		goto no_loss;
	}
}

/************************************************* 
 *     active cb management
 *************************************************/

/**
 * Initialize active contro block (acb), one acb 
 * for each MPDCCP connection.
 */
struct active_cb* active_cb_init(struct mpdccp_cb *mpcb){
	struct active_cb *acb = NULL;

	if(!mpcb) goto fail;
	acb = kmem_cache_zalloc(active_cb_cache, GFP_ATOMIC);
	if(!acb) goto fail;

	acb->mpcb = mpcb;
	rbuf_init(&acb->rbuf, acb);

	__exp_set(acb, mpcb->glob_lfor_seqno);	
	spin_lock_init(&acb->adaptive_cb_lock);
	return acb;
fail:
    ro_err("RO-ERROR: NULL mpcb or acb");
	return NULL;
}

/**
 * Create memory pool for active cb.
 */
int allocate_active_cb_cache(void){
	active_cb_cache = kmem_cache_create("active_cb", sizeof(struct active_cb),
                       0, SLAB_TYPESAFE_BY_RCU|SLAB_HWCACHE_ALIGN,
                       NULL);
    if (!active_cb_cache) {
        ro_err("RO-ERROR: Failed to create active_cb slab cache.\n");
        goto out;
    }
    return SUCCESS_RO;
out:   
    return -EAGAIN;
}

/************************************************* 
 *     helper
 *************************************************/
/**
 * Forward skb and reset buffer element, set 
 * expected and last forwarded globally.
 */
void forward_inorder(struct active_cb *acb, u64 i){
    forward(acb, i);
    __exp_set(acb, (i + 1));
    acb->mpcb->glob_lfor_seqno = i;
}

/**
 * Forward skb and reset buffer element.
 */
void forward(struct active_cb *acb, u64 i){
    struct sk_buff *skb_t;
    if(!acb) goto fail0;
    if(!__rbuf_entry(acb, i).skb) goto fail1;

    skb_t = __rbuf_entry(acb, i).skb;
    __rbuf_entry(acb, i).skb = NULL;
    mpdccp_forward_skb(skb_t, acb->mpcb);
    //__rbuf_entry(acb, i).skb = NULL;
    __rbuf_entry(acb, i).abs_to = ktime_set(0, 0);

    __rbuf_size_dec(acb);
    return;

fail0:
    ro_err("RO-ERROR: NULL acb");
    return;
fail1:
    ro_err("RO-ERROR: NULL skb");
    return;
}

/************************************************* 
 *     sysctl
 *************************************************/

/**
 * Configure ADAPTIVE active reordering.
 * 0   = fixed 
 * 1   = adaptive
 * 2   = equalized adaptive
 * > 2 = fixed
 */
static int proc_adaptive(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos){
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
    if (write && ret == 0){
    	switch(sysctl_adaptive){
		case 0: 
fixed:
			get_to = get_fixed_to;
			ro_info("RO-INFO: > FIXED active reordering\n");	
			break;
		case 1:
			get_to = get_adaptive_to;
			ro_info("RO-INFO: > ADAPTIVE active reordering\n");
			break;
		case 2:
			get_to = get_equalized_adatptive_to;
			ro_info("RO-INFO: > EQUALIZED ADAPTIVE active reordering\n");
			break;
		default:
			goto fixed;
    	}
    }
    return 0;
}

/**
 * Set fixed timeout using sysctl.
 */
static int proc_fixed_timeout(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos){
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
    if (write && ret == 0){
    	if(sysctl_fto >= 0){
    		ro_info("RO-INFO: > FTO : %d ms\n", sysctl_fto);
    		return 0;
    	}
    	else{
    		ro_err("RO-ERROR: fixed timeout should be > 0 ms, reset back to default [%d ms]", FTO_DEF);
    		sysctl_fto = FTO_DEF;
    	}
    }
    return 0;
}

/**
 * Set upper bound for adaptive timeouts using sysctl.
 */
static int proc_adaptive_timeout_max(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos){
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
    if (write && ret == 0){
    	if(sysctl_ato_max >= 0){
    		ro_info("RO-INFO: > ATO_MAX : %d ms\n", sysctl_ato_max);
    		return 0;
    	}
    	else{
    		ro_err("RO-ERROR: maximum adaptive timeout should be > 0 ms, reset back to default [%d ms]", ATO_MAX);
    		sysctl_ato_max = ATO_MAX;
    	}
    }
    return 0;
}

/**
 * Set fixed timeout offset.
 */
static int proc_timeout_offset(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos){
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
    if (write && ret == 0){
    	if(sysctl_to_off >= 0){
    		ro_info("RO-INFO: > TO_OFF : %d ms\n", sysctl_to_off);
    		return 0;
    	}
    	else{
    		ro_err("RO-ERROR: adaptive timeout offset should be >= 0 ms, reset back to default [%d ms]", TO_OFF);
    		sysctl_to_off = TO_OFF;
    	}
    }
    return 0;
}

/**
 * Configure LOSS DETECTION mechanisms.
 * 0   = no loss detection 
 * 1   = fast loss detection by overall sequencing
 * 2   = fast loss detection by path sequencing
 * 3   = fast loss detection combining 1 and 2 
 * > 3 = no loss detection 
 */
static int proc_loss_detection(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos){
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
    if (write && ret == 0){
		switch(sysctl_loss_detection){
		case 0:
no_loss:
			detect_loss = detect_no_loss;
			ro_info("RO-INFO: > NO loss detection optimization\n");
			break;
		case 1:
			detect_loss = detect_fast_loss_oall;
			ro_info("RO-INFO: > FAST loss detection by OVERALL-SEQUENCING \n");
			break;
		case 2:
			detect_loss = detect_fast_loss_path;
			ro_info("RO-INFO: > FAST loss detection by PATH-SEQUENCING \n");
			break;
		case 3:
			detect_loss = detect_fast_loss_combined;
			ro_info("RO-INFO: > FAST loss detection by OVERALL- and PATH-SEQUENCING \n");
			break;
		default:
			goto no_loss;
		}
    }
    return 0;
}

/**
 * Set token threshold for activtiy monitoring.
 */
static int proc_not_rcv_max(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos){
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
    if (write && ret == 0){
    	if(sysctl_not_rcv_max >= 0){
    		ro_info("RO-INFO: > NOT_RCV_MAX : %d \n", sysctl_not_rcv_max);
    		return 0;
    	}
    	else{
    		ro_err("RO-ERROR: token threshold should be > 0, reset back to default [%d]", NOT_RCV_MAX);
    		sysctl_not_rcv_max = NOT_RCV_MAX;
    	}
    }
    return 0;
}

//TODO: observed crashing when changing buffer size during operation
/**
 * Set size of the fixed size reordering buffer.
 */
static int proc_rbuf_size(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos){
	int ret;
	struct active_cb *acb = NULL;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
    if (write && ret == 0){
    	if(sysctl_rbuf_size >= 0){
    		if(!__is2n(sysctl_rbuf_size)) ro_warn("RO-WARN: chosen buffer size is not 2^n, this can lead to a performance degradation");

    		spin_lock_bh(&active_cb_list_lock);
				list_for_each_entry_rcu(acb, &active_cb_list, list){
					if(acb->rbuf.buf) kfree(acb->rbuf.buf);
					acb->rbuf.buf = kmalloc(sizeof(struct sk_buff*) * sysctl_rbuf_size, GFP_ATOMIC);

					ro_warn("RO-WARN: reset rbuf for acb (0x%p) to size : %d", acb, sysctl_rbuf_size);
				}	
			spin_unlock_bh(&active_cb_list_lock);

    		ro_info("RO-INFO: > RBUF_SIZE : %d \n", sysctl_rbuf_size);
    		return 0;
    	}
    	else{
    		ro_err("RO-ERROR: buffer size should be > 0, reset back to default [%d]", RBUF_SIZE);
    		sysctl_rbuf_size = RBUF_SIZE;
    	}
    }
    return 0;
}

/**
 * Set rtt-type according to the chosen delay estimation.
 * 0	= mrtt - measured rtt i.e. raw values
 * 1 	= min_rtt
 * 2  	= max_rtt
 * 3    = srtt
 */
static int proc_rtt_type(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos){
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
    if (write && ret == 0) mpdccp_set_rtt_type(sysctl_rtt_type);
    return 0;
}

/**
 * Expiry timeout (in ms).
 */
static int proc_exp_to(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos){
    int ret;

    ret = proc_dointvec(table, write, buffer, lenp, ppos);
    if (write && ret == 0){
        if(sysctl_exp_to >= 0){
            ro_info("RO-INFO: > EXP_TO : %d \n", sysctl_exp_to);
            return 0;
        }
        else{
            ro_err("RO-ERROR: expiry timout should be > 0, reset back to default [%d]", EXP_TO);
            sysctl_exp_to = EXP_TO;
        }
    }
    return 0;
}

/**
 * Configure drop of lost packet behaviour.
 * 0   = lost packet are forwarded
 * >0  = lost packets are dropped
 */
static int proc_drop_lost(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos){
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (write && ret == 0){
		if (sysctl_drop_lost) {
			ro_info("RO-INFO: lost packets are DROPPED\n");
		} else {
			ro_info("RO-INFO: lost packets are FORWARDED\n");
		}
	}
	return 0;
}


/**
 * Configure drop of duplicated packet behaviour.
 * 0   = duplicated packet are forwarded
 * >0  = duplicated packets are dropped
 */
static int proc_drop_dup(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos){
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (write && ret == 0){
		if (sysctl_drop_dup) {
			ro_info("RO-INFO: duplicated packets are DROPPED\n");
		} else {
			ro_info("RO-INFO: duplicated packets are FORWARDED\n");
		}
	}
	return 0;
}

/**
 * ctl table
 */
static struct ctl_table mpdccp_reorder_active_table[] = {
    {
        .procname = "adaptive",
        .data = &sysctl_adaptive,
        .mode = 0644,
        .maxlen = sizeof(int),
        .proc_handler = proc_adaptive,
    },
    {
        .procname = "fixed_timeout",
        .data = &sysctl_fto,
        .mode = 0644,
        .maxlen = sizeof(int),
        .proc_handler = proc_fixed_timeout,
    },
    {
        .procname = "adaptive_timeout_max",
        .data = &sysctl_fto,
        .mode = 0644,
        .maxlen = sizeof(int),
        .proc_handler = proc_adaptive_timeout_max,
    },
    {
        .procname = "timeout_offset",
        .data = &sysctl_to_off,
        .mode = 0644,
        .maxlen = sizeof(int),
        .proc_handler = proc_timeout_offset,
    },
    {
        .procname = "loss_detection",
        .data = &sysctl_loss_detection,
        .mode = 0644,
        .maxlen = sizeof(int),
        .proc_handler = proc_loss_detection,
    },
    {
        .procname = "not_rcv_max",
        .data = &sysctl_not_rcv_max,
        .mode = 0644,
        .maxlen = sizeof(int),
        .proc_handler = proc_not_rcv_max,
    },
    {
        .procname = "__rbuf_size",
        .data = &sysctl_rbuf_size,
        .mode = 0644,
        .maxlen = sizeof(int),
        .proc_handler = proc_rbuf_size,
    },
    {
        .procname = "rtt_type",
        .data = &sysctl_rtt_type,
        .mode = 0644,
        .maxlen = sizeof(int),
        .proc_handler = proc_rtt_type,
    },
    {
        .procname = "expiry_timeout",
        .data = &sysctl_exp_to,
        .mode = 0644,
        .maxlen = sizeof(int),
        .proc_handler = proc_exp_to,
    },
    {
        .procname = "drop_lost",
        .data = &sysctl_drop_lost,
        .mode = 0644,
        .maxlen = sizeof(int),
        .proc_handler = proc_drop_lost,
    },
    {
        .procname = "drop_dup",
        .data = &sysctl_drop_dup,
        .mode = 0644,
        .maxlen = sizeof(int),
        .proc_handler = proc_drop_dup,
    },
    { }
};

static struct ctl_table_header *mpdccp_reorder_active_sysctl;


/************************************************* 
 *     Register/Unregister/Cleanup
 *************************************************/

/**
 * Cleanup allocated memory.
 */
void cleanup_active_mod(void) {
    struct active_cb *acb;
    struct list_head *pos, *temp;
    spin_lock(&active_cb_list_lock);
    list_for_each_safe(pos, temp, &active_cb_list) {
        acb = list_entry(pos, struct active_cb, list);
        list_del(pos);
        del_timer_sync(&acb->rbuf.exp_timer);
        if(acb->rbuf.buf) kfree(acb->rbuf.buf);
        kmem_cache_free(active_cb_cache, acb);
    }
    spin_unlock(&active_cb_list_lock);
    kmem_cache_destroy(active_cb_cache);
}

/**
 * Initialize active reordering operations.
 */
struct mpdccp_reorder_ops mpdccp_reorder_active_mod = {
	.init = init_reorder_active_mod,
	.do_reorder = do_reorder_active_mod,
	.update_pseq = do_update_pseq,
	.name = "active",
	.owner = THIS_MODULE,
};

/**
 * Init: register the passive reordering module.
 */
static int __init mpdccp_reorder_active_register(void){
    if (mpdccp_register_reordering(&mpdccp_reorder_active_mod)) return FAIL_RO;

    /* register sysctl */
    mpdccp_reorder_active_sysctl = register_sysctl("mpdccp_active_reordering", mpdccp_reorder_active_table);
    if (!mpdccp_reorder_active_sysctl) ro_err("RO-ERROR: Failed to register active reordering sysctl.\n"); 

    allocate_active_cb_cache();

    return SUCCESS_RO;
}

/** 
 * Exit: unregister the passive reordering module.
 */
static void mpdccp_reorder_active_unregister(void){ 

    mpdccp_unregister_reordering(&mpdccp_reorder_active_mod);
    unregister_sysctl_table(mpdccp_reorder_active_sysctl);
    cleanup_active_mod();
}

module_init(mpdccp_reorder_active_register);
module_exit(mpdccp_reorder_active_unregister);

MODULE_AUTHOR("Maximilian Schuengel");
MODULE_AUTHOR("Romeo Cane");
MODULE_LICENSE("Proprietary");
MODULE_DESCRIPTION("Multipath DCCP Active Reordering Module");
MODULE_VERSION(MPDCCP_VERSION);
