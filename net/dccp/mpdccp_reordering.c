/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 * 
 * Copyright (C) 2018 by Maximilian Schuengel, Deutsche Telekom AG
 * Copyright (C) 2018 by Markus Amend, Deutsche Telekom AG
 * Copyright (C) 2020 by Nathalie Romo, Deutsche Telekom AG
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

#include <linux/module.h>
#include <linux/hrtimer.h>
#include <linux/time.h>
#include <linux/ktime.h>

#include "ccids/ccid2.h"
#include "mpdccp.h"
#include "mpdccp_reordering.h"


/* debugging */
bool ro_err_state = 1;
EXPORT_SYMBOL(ro_err_state);
bool ro_info_state = 1;
EXPORT_SYMBOL(ro_info_state);
bool ro_warn_state = 1;
EXPORT_SYMBOL(ro_warn_state);
int ro_dbug_state = 0;
EXPORT_SYMBOL(ro_dbug_state); 

module_param(ro_err_state, bool, 0644);
MODULE_PARM_DESC(ro_err_state, "Enable debug messages for reordering, ERROR-Level");
module_param(ro_info_state, bool, 0644);
MODULE_PARM_DESC(ro_info_state, "Enable debug messages for reordering, INFO-Level");
module_param(ro_warn_state, bool, 0644);
MODULE_PARM_DESC(ro_warn_state, "Enable debug messages for reordering, WARNING-Level");
module_param(ro_dbug_state, int, 0644);
MODULE_PARM_DESC(ro_dbug_state, "Enable debug messages for reordering, DEBUG-Level 1, 2 or 3 (3 most detailed)");

static DEFINE_SPINLOCK(mpdccp_reorder_list_lock);
static LIST_HEAD(mpdccp_reorder_list);
static struct mpdccp_reorder_ops	*reorder_default = NULL;
static struct mpdccp_reorder_ops	*reorder_fallback = NULL;

static struct kmem_cache *mpdccp_reorder_path_cb_cache = NULL;
static struct kmem_cache *mpdccp_reorder_rcv_buff_cache = NULL;


static int mpdccp_reset_path_cb(struct mpdccp_reorder_path_cb *pcb);
static void mpdccp_mrtt_estimator(struct mpdccp_reorder_path_cb *pcb, const long mrtt);
static void mpdccp_krtt_estimator(struct mpdccp_reorder_path_cb *pcb, const long mrtt);
static void mpdccp_drtt_estimator(struct mpdccp_reorder_path_cb *pcb, const long mrtt);
static u32 mean(u32 *arr, int size);
static void prepend(u32 *arr, int size, u32 val);
static u32 get_mrtt(struct mpdccp_reorder_path_cb *pcb);
static u32 get_krtt(struct mpdccp_reorder_path_cb *pcb);
static u32 get_drtt(struct mpdccp_reorder_path_cb *pcb);
static int mpdccp_allocate_rcv_buff_cache(void);
static int mpdccp_allocate_path_cb_cache(void);
static void mpdccp_release_path_cb_cache(void);


/************************************************* 
 *     Reordering (generic)
 *************************************************/

int mpdccp_reordering_setup (void)
{
	int	ret;

	ret = mpdccp_allocate_path_cb_cache ();
	if (ret < 0) return ret;
	ret = mpdccp_allocate_rcv_buff_cache ();
	if (ret < 0) return ret;
	ret = mpdccp_reorder_default_register ();
	if (ret < 0) return ret;
	// The following doesn't work - must not be done during module setup!!! - tbd.
	//ret = mpdccp_set_default_reordering(CONFIG_DEFAULT_MPDCCP_REORDER);
	ret = mpdccp_set_default_reordering("default");
	if (ret < 0) {
		mpdccp_pr_error("Failed to set default reordering engine \"%s\".\n",
			CONFIG_DEFAULT_MPDCCP_REORDER);
		return ret;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(mpdccp_reordering_setup);

void mpdccp_reordering_finish (void)
{
	mpdccp_release_path_cb_cache();
	mpdccp_reorder_default_unregister();
}
EXPORT_SYMBOL_GPL(mpdccp_reordering_finish);

/**
 * Initialize reordering, set current reordering operation in control block. 
 */
void mpdccp_init_reordering (struct mpdccp_cb *mpcb)
{
	struct mpdccp_reorder_ops *reorder;

	if (!mpcb) return;
	rcu_read_lock();
	reorder = reorder_default;
	if (try_module_get(reorder->owner)) {
		mpcb->reorder_ops = reorder;
		mpcb->mpdccp_reorder_cb = NULL;
		if (reorder->init)
			reorder->init (mpcb);
		mpdccp_pr_debug("reordering set to %s", reorder->name);
	} else {
		pr_info("cannet init reordering %s", reorder->name);
	}
	rcu_read_unlock();
}

/**
 * Release allocated memory.
 */
void mpdccp_cleanup_reordering(struct mpdccp_cb *mpcb)
{
	/* Release module */
	module_put(mpcb->reorder_ops->owner);
}

/**
 * Register a given reordering engine.
 */
int mpdccp_register_reordering(struct mpdccp_reorder_ops *reorder)
{
	int	ret = SUCCESS_RO;

	if (!reorder) return -EINVAL;
	rcu_read_lock();
	if (mpdccp_reorder_find(reorder->name)) {
		pr_notice("%s already registered\n", reorder->name);
		ret = -EEXIST;
	} else {
		spin_lock(&mpdccp_reorder_list_lock);
		list_add_tail_rcu(&reorder->list, &mpdccp_reorder_list);
		spin_unlock(&mpdccp_reorder_list_lock);
		ro_info("RO-INFO: %s registered\n", reorder->name);
	}

	if (!strcasecmp (reorder->name, "default")) {
		reorder_fallback = reorder;
	}

	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(mpdccp_register_reordering);

/** 
 * Unregister a given reordering engine.
 */
void mpdccp_unregister_reordering (struct mpdccp_reorder_ops *reorder)
{
	struct mpdccp_cb *mpcb = NULL; 

	if (!reorder) return;
	rcu_read_lock ();
	spin_lock(&mpdccp_reorder_list_lock);
	list_del_rcu(&reorder->list);

	if (reorder == reorder_default)
		reorder_default = list_entry_rcu(mpdccp_reorder_list.next, struct mpdccp_reorder_ops, list);
	if (reorder == reorder_fallback)
		reorder_fallback = NULL;
	if (!reorder_default) 
		reorder_default = reorder_fallback;
	/* reset reordering ops back to default */
	mpdccp_for_each_conn(pconnection_list, mpcb) {
		if (mpcb->reorder_ops == reorder) {
			lock_sock (mpcb->meta_sk);
			mpdccp_init_reordering (mpcb);
			release_sock (mpcb->meta_sk);
		}
	}
	spin_unlock(&mpdccp_reorder_list_lock);
	rcu_read_unlock ();
	return;
}
EXPORT_SYMBOL(mpdccp_unregister_reordering);

/**
 * Find reordering engine in 'list_for_each_entry_rcu'.
 */
struct mpdccp_reorder_ops *mpdccp_reorder_find(const char *name)
{
	struct mpdccp_reorder_ops *e;

	if(!name) return NULL;
	list_for_each_entry_rcu(e, &mpdccp_reorder_list, list) {
		if (strcmp(e->name, name) == 0) return e;
	}
	return NULL;
}
EXPORT_SYMBOL(mpdccp_reorder_find);

/**
 * Get the default reordering engine.
 */
void mpdccp_get_default_reordering (char *name)
{
	BUG_ON(list_empty(&mpdccp_reorder_list));
	rcu_read_lock();
	if (reorder_default) {
		strncpy(name, reorder_default->name, MPDCCP_REORDER_NAME_MAX-1);
		name[MPDCCP_REORDER_NAME_MAX-1]=0;
	} else if (reorder_fallback) {
		strncpy(name, reorder_fallback->name, MPDCCP_REORDER_NAME_MAX-1);
		name[MPDCCP_REORDER_NAME_MAX-1]=0;
	} else {
		name[0]=0;
	}
	rcu_read_unlock();
	return;
}

/**
 * Set the default reordering engine.
 */
int mpdccp_set_default_reordering(const char *name)
{
	struct mpdccp_reorder_ops *reorder;
	int ret = -ENOENT;

	spin_lock(&mpdccp_reorder_list_lock);
	reorder = mpdccp_reorder_find(name);
#ifdef CONFIG_MODULES
	if (!reorder && capable(CAP_NET_ADMIN)) {
		spin_unlock(&mpdccp_reorder_list_lock);
		request_module("mpdccp_reorder_%s", name);
		spin_lock(&mpdccp_reorder_list_lock);
		reorder = mpdccp_reorder_find(name);
	}
#endif
	if (reorder) {
		reorder_default = reorder;
		ret = 0;
	} else {
		ro_err("RO-ERROR: %s is not available\n", name); 
	}
	spin_unlock(&mpdccp_reorder_list_lock);
	return ret;
}


/************************************************* 
 *     receive buffer
 *************************************************/
/**
 * Create memory pool for work data blocks.
 */
static int mpdccp_allocate_rcv_buff_cache(void)
{
	mpdccp_reorder_rcv_buff_cache = kmem_cache_create("rcv_buff", sizeof(struct rcv_buff),
                       0, SLAB_TYPESAFE_BY_RCU|SLAB_HWCACHE_ALIGN,
                       NULL);
	if (!mpdccp_reorder_rcv_buff_cache) {
		ro_err("RO-ERROR: Failed to create mpdccp_reorder_rcv_buff slab cache.\n");
		goto out;
	}
	return SUCCESS_RO;
out:   
	return -EAGAIN;
}

/**
 * Release memory allocated for work data.
 */
int mpdccp_release_rcv_buff(struct rcv_buff **rb)
{
	if(rb && *rb){
		//printk(KERN_INFO "buffer released?");
		kmem_cache_free(mpdccp_reorder_rcv_buff_cache, *rb);
		*rb = NULL;
		return SUCCESS_RO;
	}
	else{
		ro_err("RO-ERROR: rb or *rb is NULL");
		return FAIL_RO;
	}
}
EXPORT_SYMBOL(mpdccp_release_rcv_buff);

/**
 * Initialize work data for given parameter.
 */
struct rcv_buff *mpdccp_init_rcv_buff(struct sock *sk, struct sk_buff *skb, struct mpdccp_cb *mpcb)
{
	struct dccp_sock	*dsk = NULL; 
	struct rcv_buff		*rb = NULL;

	rb = kmem_cache_zalloc(mpdccp_reorder_rcv_buff_cache, GFP_ATOMIC);
	if(!rb){
		ro_err("RO-ERROR: Failed to initialize w\n");
		return NULL;
	}
	//INIT_DELAYED_WORK(&rb->work, mpdccp_do_work);  // legacy
	rb->sk = sk;
	rb->skb = skb;
	rb->mpcb = mpcb;
	rb->mpdccp_reorder_cb = mpcb->mpdccp_reorder_cb;

	if(!sk) return rb;
	
	/* 
	 * current sequence number (required
	 * since sequence number is a option, 
	 * hence is extracted from the socket)
	 */
	dsk = dccp_sk(sk);
	rb->oall_seqno = (u64)dsk->dccps_options_received.dccpor_oall_seq;
	//mpdccp_pr_debug("seqno %lu sk %p", (unsigned long)rb->oall_seqno, sk);
	rb->latency = (u32)dsk->dccps_options_received.dccpor_rtt_value;	/* need to divide by two for one way delay*/
	//mpdccp_pr_debug("delay %lu sk %p", (unsigned long)rb->latency, sk);
	return rb;
}
EXPORT_SYMBOL(mpdccp_init_rcv_buff);




/************************************************* 
 *     Path Control Block (Combined 
 *     receive and delay vector)
 *************************************************/


/**
 * Create memory pool for delay control blocks.
 */
static int mpdccp_allocate_path_cb_cache(void)
{
	mpdccp_reorder_path_cb_cache = kmem_cache_create("mpdccp_reorder_path_cb", sizeof(struct mpdccp_reorder_path_cb),
                       0, SLAB_TYPESAFE_BY_RCU|SLAB_HWCACHE_ALIGN,
                       NULL);
	if (!mpdccp_reorder_path_cb_cache) {
		ro_err("RO-ERROR: Failed to create mpdccp_reorder_path_cb slab cache.\n");
		goto out;
	}
	return SUCCESS_RO;
    
out:   
	return -EAGAIN;
}

/**
 * Allocate memory for delay cb from memory pool.
 */
struct mpdccp_reorder_path_cb *mpdccp_init_reorder_path_cb(struct sock *sk)
{
	struct mpdccp_reorder_path_cb *pcb;

	pcb = kmem_cache_zalloc(mpdccp_reorder_path_cb_cache, GFP_ATOMIC);
	if (!pcb) {
		ro_err("RO-ERROR: Failed to initialize pcb.\n");
		return NULL;
	}
	mpdccp_reset_path_cb(pcb);
	pcb->sk = sk;
	pcb->active = true;

	return pcb;
}
EXPORT_SYMBOL(mpdccp_init_reorder_path_cb);

/**
 * Release allocated memory.
 */
void mpdccp_free_reorder_path_cb(struct mpdccp_reorder_path_cb *pcb)
{
	kmem_cache_free(mpdccp_reorder_path_cb_cache, pcb);
}
EXPORT_SYMBOL(mpdccp_free_reorder_path_cb);

/**
 * Destroy memory pool.
 */
static void mpdccp_release_path_cb_cache(void)
{
	kmem_cache_destroy(mpdccp_reorder_path_cb_cache);
}

/**
 * Reset all attributes (exept sk, list) of given 'pcb' of struct 'mpdccp_reorder_path_cb' to 0.
 */
static int mpdccp_reset_path_cb(struct mpdccp_reorder_path_cb *pcb)
{
	int i = 0, ret;
	if(!pcb) goto fail;

	pcb->mrtt = 0; pcb->krtt = 0; pcb->drtt = 0;
	pcb->oall_seqno = 0; pcb->path_seqno = 0; pcb->not_rcv = 0;
	pcb->exp_path_seqno = 0;

	for(i = 0; i < DWINDOW_SIZE; i++){
		pcb->wnd[i] = 0;
		pcb->wnd_raw[i] = 0;
	}
	
	ret = SUCCESS_RO;
	goto finished;

fail:
	ret = FAIL_RO;
finished:
	return ret;
}



/**
 * Perfrom path timing estimations.
 */
int mpdccp_path_est(struct mpdccp_reorder_path_cb* pcb, u32 mrtt)
{
	int ret;
	if(!pcb) goto fail;

	mpdccp_mrtt_estimator(pcb, mrtt);
	mpdccp_krtt_estimator(pcb, mrtt);
	//TODO crashes eventually (only on pyhisical setup I guess)
	mpdccp_drtt_estimator(pcb, mrtt);

	ro_dbug3("RO-DEBUG: mrtt=%llu, krtt=%llu, drtt=%llu [ms]",
			(u64)get_mrtt(pcb), (u64)get_krtt(pcb), (u64)get_drtt(pcb));

	ret = SUCCESS_RO;
	goto finished;

fail:
	ro_err("RO-ERROR: NULL pcb");
	ret = FAIL_RO;
finished:
	return ret;
}
EXPORT_SYMBOL(mpdccp_path_est);




/*
 * latency functions
 */

/**
 * Function pointer that is used to switch 
 * between different delay estimations.
 */
static u32 (*__get_rtt)(struct mpdccp_reorder_path_cb *pcb) = get_mrtt;

/**
 * Function and function pointer used by active (adaptive) 
 * reordering and delay equalization.
 */
u32 mpdccp_get_lat (struct mpdccp_reorder_path_cb *pcb)
{
	return __get_rtt(pcb) / 2;
} 
EXPORT_SYMBOL(mpdccp_get_lat);

/**
 * Set function pointer to corresponding getter funtion.
 */
void mpdccp_set_rtt_type(int type)
{
	switch(type) {
	default:
		ro_warn("RO-WARN: type = %d is invalid, reset to MRTT", type);
		/* fall thru */
	case 0:
		ro_info("RO-INFO: > now using MRTT");
		__get_rtt = get_mrtt;
		break;
	case 1:
		ro_info("RO-INFO: > now using KRTT");
		__get_rtt = get_krtt;
		break;
	case 2:
		__get_rtt = get_drtt;
		ro_info("RO-INFO: > now using DRTT");
		break;
	}
	return;
}
EXPORT_SYMBOL(mpdccp_set_rtt_type);



/**
 * Read different rtt types from path cb.
 */
static u32 get_mrtt(struct mpdccp_reorder_path_cb *pcb)
{
	return pcb ? pcb->mrtt : 1000;
}

static u32 get_krtt(struct mpdccp_reorder_path_cb *pcb)
{
	return pcb ? pcb->krtt : 1000;
}

static u32 get_drtt(struct mpdccp_reorder_path_cb *pcb)
{
	return pcb ? pcb->drtt : 1000;
}


/*
 * Latency Estimator functions
 */

/**
 * MRTT estimator, just calculate varaince.
 */
static void mpdccp_mrtt_estimator(struct mpdccp_reorder_path_cb *pcb, const long mrtt)
{
	if(pcb) pcb->mrtt = mrtt;
	else ro_err("RO-ERROR: NULL pcb"); 
	return;
}

/**
 * Delay prediction using Kalman filter according to paper by Zhang et al., see
 * URL : [https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=6026701] 
 * NOTE : parameters are scaled by 1000 to increase presicion
 */
static void mpdccp_krtt_estimator(struct mpdccp_reorder_path_cb *pcb, const long mrtt)
{
	u32 SF = 100000; 			  // scale factor required for fixed point arithmetics
	u32 Q = 8000, R = 100000; 	  // parameter are interchanged (scaled by 100000) according to Zhang et al. 
	u32 K, kSF = 1000;

	if(!pcb) goto fail;
	/* measurement stage */
	K = (pcb->P_ * kSF) / (pcb->P_ + R); 	// scaling required since K < 1 
	pcb->x = pcb->x_ + (K * ((mrtt * SF) - pcb->x_) / kSF);	
	pcb->P = (pcb->P_ * ((1 * kSF) - K)) / kSF;

	/* time stage */
	pcb->x_ = pcb->x;
	pcb->P_ = pcb->P + Q;

	pcb->krtt = pcb->x_ / SF;
	goto finished;

fail:
	ro_err("RO-ERROR: NULL pcb");
finished:
	return;
}

/**
 * DRTT estimator, directional filter.
 */
static void mpdccp_drtt_estimator(struct mpdccp_reorder_path_cb *pcb, const long mrtt)
{
	u32 SF = 100000;

	if (!pcb) {
		ro_err("RO-ERROR: NULL pcb");
		return;
	}
	if ((pcb->wnd[0] / SF) <= mrtt)
		pcb->drtt = mrtt;
	else
		pcb->drtt = (mean(pcb->wnd, DWINDOW_SIZE) + mean(pcb->wnd_raw, DWINDOW_SIZE)) / (2 * SF);
	
	prepend (pcb->wnd, DWINDOW_SIZE, pcb->drtt * SF);
	prepend (pcb->wnd_raw, DWINDOW_SIZE, mrtt * SF);

	return;
}

/**
 * Calcualte mean of fixed size array, values of 0 are interpreted as empty thus mitigated.
 */
static u32 mean(u32 *arr, int size)
{
	int i = 0, cnt = 0;
	u32 tmp = 0;
	for(i = 0; i < size; i++){
		if(arr[i] > 0){
			tmp += arr[i];
			cnt++;
		}
	} 
	if(cnt)
		return tmp / cnt;
	else
		return 0;
}

/**
 * Prepend element to fixed size array.
 */
static void prepend(u32 *arr, int size, u32 val)
{
	int i = 0;
	for(i = size-1; i > 0; i--) arr[i] = arr[i-1];
	arr[0] = val;
}

/**
 * Get current time as ktime.
 */
ktime_t mpdccp_get_now(void)
{
   //struct timeval now;
   // do_gettimeofday(&now);
   //return timeval_to_ktime(now);
	ktime_t now = ktime_get_real();
	return now;
}
EXPORT_SYMBOL(mpdccp_get_now);
