/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 * Copyright (C) 2017 by Andreas Philipp Matz, Deutsche Telekom AG
 * Copyright (C) 2017 by Markus Amend, Deutsche Telekom AG
 * Copyright (C) 2020 by Nathalie Romo, Deutsche Telekom AG
 * Copyright (C) 2020 by Frank Reker, Deutsche Telekom AG
 * Copyright (C) 2021 by Romeo Cane, Deutsche Telekom AG
 *
 * MPDCCP - DCCP bundling kernel module
 *
 * This module implements a bundling mechanism that aggregates
 * multiple paths using the DCCP protocol.
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

#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/dccp.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/kthread.h>
#include <uapi/linux/net.h>

#include <net/inet_common.h>
#include <net/inet_sock.h>
#include <net/protocol.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <linux/inetdevice.h>
#include <net/mpdccp_link.h>
#include <asm/unaligned.h>
#include <crypto/hash.h>

#include "mpdccp.h"
#include "mpdccp_scheduler.h"
#include "mpdccp_reordering.h"
#include "mpdccp_pm.h"
#include "feat.h"

/*
 * TODO GLOBAL
 * 4)   CLEANUP TODO: Free structures, close sockets etc on module exit to avoid crash
 * 5)   Something like using tcp_read_sock() instead of kernel_recvmsg() would be nice; however, there is 
 *      currently no such function for DCCP. (about 2% performance gain in TCP)
 * 8)   Implement fragmentation (unsuppported by Linux DCCP stack)
 * 9)   Implement service code on both sides (no meaningful service codes are defined by IANA)
 * 12)  Implement data sequence numbers in a new MPDCCP option
 * KNOWN BUGS
 * 1)   For now, this requires CONFIG_NET_L3_MASTER_DEV disabled. When enabled, compute_score() in inet_hashtables.c
 *      will return -1 as exact_dif==true and sk->sk_bound_dev_if != dif (first is 0/not set). Maybe I need to set 
 *      sk->sk_bound_dev somewhere? I dont know if this is going to bite me. 
 *      More info at http://netdevconf.org/1.2/papers/ahern-what-is-l3mdev-paper.pdf
 * 2)   DCCP in the Linux kernel does not support fragmentation and neither does this bundling solution.
 */


#define MPDCCP_SERVER_BACKLOG	1000
#define DUMP_PACKET_CONTENT	0

static struct kmem_cache *mpdccp_cb_cache __read_mostly;


/* A list of all MPDCCP connections (represented as mpcb's) */
struct list_head __rcu pconnection_list;
EXPORT_SYMBOL(pconnection_list);

spinlock_t pconnection_list_lock;
EXPORT_SYMBOL(pconnection_list_lock);

static struct kmem_cache *mpdccp_mysock_cache __read_mostly;

/* Work queue for all reading and writing to/from the socket. */
struct workqueue_struct *mpdccp_wq;
EXPORT_SYMBOL(mpdccp_wq);

/* Crypto contexts for hashing */
struct crypto_shash *tfm_hash;
struct crypto_shash *tfm_hmac;

/*********************************************************
 * Work queue functions
 *********************************************************/

/*
 * Atomically queue work on a connection after the specified delay.
 * Returns 0 if work was queued, or an error code otherwise.
 */
//static int queue_bnd_work_delay(struct sock *sk, unsigned long delay)
//{
//    struct my_sock *my_sk = mpdccp_my_sock(sk);
//
//    if (!queue_delayed_work(mpdccp_wq, &my_sk->work, delay)) {
//        mpdccp_pr_debug("%p - already queued, wq: %p, work: %p, delay: %lu \n", sk, mpdccp_wq, &my_sk->work, delay);
//        return -EBUSY;
//    }
//
//    mpdccp_pr_debug("queue ok %p wq: %p, work: %p delay: %lu\n", sk, mpdccp_wq, &my_sk->work, delay);
//    return 0;
//}

//static int queue_bnd_work(struct sock *sk)
//{
//    return queue_bnd_work_delay(sk, 0);
//}

//static void mpdccp_cancel_bnd_work(struct sock *sk)
//{
//    struct my_sock *my_sk = mpdccp_my_sock(sk);
//
//    if (cancel_delayed_work(&my_sk->work)) {
//        mpdccp_pr_debug(" Work %p cancelled\n", sk);
//    }
//}

void mpdccp_wq_flush(void)
{
    mpdccp_pr_debug("in mpdccp_wq_flush");
    flush_workqueue(mpdccp_wq);
}

static int mpdccp_read_from_subflow (struct sock *sk)
{
    int peeked, sz, ret, off=0;
    struct sk_buff *skb = NULL;
    struct my_sock *my_sk = mpdccp_my_sock(sk);
    struct mpdccp_cb *mpcb = my_sk->mpcb;
    const struct dccp_hdr *dh;

    if(!sk)
        return -EINVAL;

    //skb = __skb_recv_datagram (sk, MSG_DONTWAIT, NULL, &peeked, &off, &ret);
    skb = __skb_recv_datagram(sk, &sk->sk_receive_queue, MSG_DONTWAIT, &off, &ret);
    if (!skb) 
        return 0;

    sz = skb->len;
    dh = dccp_hdr(skb);

    switch(dh->dccph_type) {
        case DCCP_PKT_DATA:
        case DCCP_PKT_DATAACK:
            if (sz > 0) {
                /* Forward skb to reordering engine */
                mpcb->reorder_ops->do_reorder(mpdccp_init_rcv_buff(sk, skb, mpcb));
                mpdccp_pr_debug("Read %d bytes from socket %p.\n", sz, sk);
            } else {
                mpdccp_pr_debug("Read zero-length data from socket %p, discarding\n", sk);
                __kfree_skb(skb);
            }
            break;
        case DCCP_PKT_CLOSE:
        case DCCP_PKT_CLOSEREQ:
            if (!my_sk->closing) {
                my_sk->closing = 1;
                schedule_delayed_work(&my_sk->close_work, 0);
            }
        case DCCP_PKT_RESET:
            __kfree_skb(skb);
            break;
        default:
            mpdccp_pr_debug("unhandled packet type %d from socket %p", dh->dccph_type, sk);
            sz = -1;
    }
    return sz;
}

int mpdccp_forward_skb(struct sk_buff *skb, struct mpdccp_cb *mpcb)
{
	struct sock	*meta_sk;
	int ret;
	mpdccp_pr_debug("forward packet\n");
	if (!skb) return -EINVAL;
	if (!mpcb || !mpcb->meta_sk) {
		dev_kfree_skb_any(skb);
		return -EINVAL;
	}
	meta_sk = mpcb->meta_sk;
	/* we should have a separate setting for rx_qlen, for now use tx_qlen */
	if (dccp_sk(meta_sk)->dccps_tx_qlen &&
			meta_sk->sk_receive_queue.qlen >= dccp_sk(meta_sk)->dccps_tx_qlen) {
		/* drop packet - FIXME: differ between drop oldest and drop newest */
		//mpdccp_pr_debug ("drop packet - queue full\n");
		printk ("mpdccp_forward_skb: drop packet - queue full\n");
		dev_kfree_skb_any(skb);
		return -ENOBUFS;
	}

	if (meta_sk->sk_state != DCCP_OPEN) {
		printk ("mpdccp_forward_skb: drop packet - meta socket not open (state %d)\n", meta_sk->sk_state);
		dev_kfree_skb_any(skb);
		return -EINVAL;
	}

	mpdccp_pr_debug ("enqueue packet\n");
	ret = sock_queue_rcv_skb(meta_sk, skb);
	if (ret < 0) {
		/*
		 * shouldn't happen
		 */
		printk(KERN_ERR "%s: sock_queue_rcv_skb failed! err %d bufsize %d\n",
		       __func__, ret, meta_sk->sk_rcvbuf);
		dev_kfree_skb_any(skb);
	}
#if 0
	__skb_queue_tail(&meta_sk->sk_receive_queue, skb);
	skb_set_owner_r(skb, meta_sk);
	if (meta_sk->sk_data_ready) meta_sk->sk_data_ready(meta_sk);
#endif

	return 0;
}
EXPORT_SYMBOL(mpdccp_forward_skb);


/* *********************************
 * mpcb related functions
 * *********************************/

void mpdccp_cb_get (struct mpdccp_cb *mpcb)
{
	if (!mpcb) return;
	kref_get (&mpcb->kref);
}

static void mpdccp_free_mpcb (struct mpdccp_cb *mpcb)
{
	if (!mpcb) return;
	kmem_cache_free (mpdccp_cb_cache, mpcb);
}

static void mpcb_ref_release (struct kref *ref)
{
        struct mpdccp_cb *mpcb = ref ? container_of (ref, struct mpdccp_cb, kref) : NULL;
	if (!mpcb) return;
        mpdccp_free_mpcb (mpcb);
}

void mpdccp_cb_put (struct mpdccp_cb *mpcb)
{
	if (!mpcb) return;
	kref_put (&mpcb->kref, mpcb_ref_release);
}

struct mpdccp_cb *mpdccp_alloc_mpcb(void)
{
    int i;
    struct mpdccp_cb *mpcb = NULL;

    /* Allocate memory for mpcb */
    mpcb = kmem_cache_zalloc(mpdccp_cb_cache, GFP_ATOMIC);
    if (!mpcb) {
        mpdccp_pr_debug("Failed to initialize mpcb.\n");
        return NULL;
    }

    /* No locking needed, as nobody can access the struct yet */
    INIT_LIST_HEAD(&mpcb->psubflow_list);
    INIT_LIST_HEAD(&mpcb->plisten_list);
    INIT_LIST_HEAD(&mpcb->prequest_list);
    INIT_LIST_HEAD(&mpcb->paddress_list);
    spin_lock_init(&mpcb->psubflow_list_lock);
    spin_lock_init(&mpcb->plisten_list_lock);

    mpcb->to_be_closed = 0;
    mpcb->cnt_subflows      = 0;
    mpcb->cnt_remote_addrs  = 0;
    mpcb->multipath_active  = 1;     //socket option; always active for now
    mpcb->dsn_local  = 0;
    mpcb->dsn_remote = 0;

    /* TODO: move the two settings below to sysctl controls */
    mpcb->mpdccp_suppkeys = MPDCCP_SUPPKEYS;
    mpcb->glob_lfor_seqno = GLOB_SEQNO_INIT;
    mpcb->mp_oall_seqno = GLOB_SEQNO_INIT;
    for (i=0; i < MPDCCP_MAX_KEYS; i++) {
        mpcb->mpdccp_loc_keys[i].type = DCCPK_INVALID;
        mpcb->mpdccp_loc_keys[i].size = 0;
    }
    mpcb->mpdccp_rem_key.type  = DCCPK_INVALID;
    mpcb->mpdccp_rem_key.size  = 0;
    mpcb->cur_key_idx = 0;
    mpcb->master_addr_id = 0;

    kref_init (&mpcb->kref);

    mpdccp_init_path_manager(mpcb);
    mpdccp_init_scheduler(mpcb);
    mpdccp_init_reordering(mpcb);

    spin_lock_bh(&pconnection_list_lock);
    list_add_tail_rcu(&mpcb->connection_list, &pconnection_list);
    mpdccp_pr_debug("Added new entry to pconnection_list @ %p\n", mpcb);
    spin_unlock_bh(&pconnection_list_lock);

    mpdccp_pr_debug("Sucessfully initialized mpcb at %p.\n", mpcb);
    
    return mpcb;
}

int mpdccp_destroy_mpcb(struct mpdccp_cb *mpcb)
{
	struct sock	*sk;
	int		ret;
	struct list_head *pos, *temp;
	struct my_sock *mysk;

	if (!mpcb) return -EINVAL;

	/* Delete the mpcb from the list of MPDCCP connections */
	spin_lock(&pconnection_list_lock);
	list_del_rcu(&mpcb->connection_list);
	INIT_LIST_HEAD(&mpcb->connection_list);
	spin_unlock(&pconnection_list_lock);
	mpcb->to_be_closed = 1;

	if(mpcb->pm_ops->del_addr)
		mpcb->pm_ops->del_addr(mpcb, 0, 0, 1);

	/* close all subflows */
	list_for_each_safe(pos, temp, &((mpcb)->psubflow_list)) {
		mysk = list_entry(pos, struct my_sock, sk_list);
		if (mysk) {
			sk = mysk->my_sk_sock;
			ret = mpdccp_close_subflow(mpcb, sk, 1);
			if (ret < 0) {
				mpdccp_pr_debug ("error closing subflow: %d\n", ret);
				return ret;
			}
		}
	}

	/* close all listening sockets */
	list_for_each_safe(pos, temp, &((mpcb)->plisten_list)) {
		mysk = list_entry(pos, struct my_sock, sk_list);
		if (mysk) {
			sk = mysk->my_sk_sock;	
			ret = mpdccp_close_subflow(mpcb, sk, 1);
			if (ret < 0) {
				mpdccp_pr_debug ("error closing listen socket: %d\n", ret);
				return ret;
			}
		}
	}

	/* close all request sockets */
	list_for_each_safe(pos, temp, &((mpcb)->prequest_list)) {
		mysk = list_entry(pos, struct my_sock, sk_list);
		if (mysk) {
			sk = mysk->my_sk_sock;
			/* Only force close on the sockets in REQUESTING state */
			if (sk->sk_state == DCCP_REQUESTING) {
				ret = mpdccp_close_subflow(mpcb, sk, 1);
				if (ret < 0) {
					mpdccp_pr_debug ("error closing request socket: %d\n", ret);
					return ret;
				}
			}
		}
	}

	mpdccp_cleanup_reordering(mpcb);
	mpdccp_cleanup_scheduler(mpcb);
	mpdccp_cleanup_path_manager(mpcb);

	/* release and eventually free mpcb */   
    mpdccp_link_free_cid(mpcb->mpdccp_loc_cix);
	mpdccp_cb_put (mpcb);
	
	return 0;
}


/******************************************************
 * 'mysock' custom functions
 ******************************************************/
int listen_backlog_rcv (struct sock *sk, struct sk_buff *skb);
void listen_data_ready (struct sock *sk);
void mp_state_change (struct sock *sk);

/* TODO: Differentiate between SUBFLOW and LISTEN socket list!!!
 * Free additional structures and call sk_destruct on the socket*/
int my_sock_pre_destruct (struct sock *sk)
{
    struct my_sock   *my_sk = mpdccp_my_sock(sk);
    struct mpdccp_cb *mpcb = NULL;
    int found = 0;
    int rem_subflows = 0;

    if (!my_sk) return 0;

    /* Delete this subflow from the list of mpcb subflows */
    mpcb = my_sk->mpcb;
    if (mpcb) {
        struct my_sock *pos, *temp;
        spin_lock(&mpcb->psubflow_list_lock);
        list_for_each_entry_safe(pos, temp, &((mpcb)->psubflow_list), sk_list) {
            if (my_sk == pos) {
                sk = my_sk->my_sk_sock;
                list_del_rcu(&my_sk->sk_list);
                INIT_LIST_HEAD(&my_sk->sk_list);
                mpcb->cnt_subflows--;
                rem_subflows = mpcb->cnt_subflows;
                found = 1;
                break;
            }
        }
        /* If not found in mpcb subflows, it might be in the request list */
        if (!found) {
            list_for_each_entry_safe(pos, temp, &((mpcb)->prequest_list), sk_list) {
                if (my_sk == pos) {
                    sk = my_sk->my_sk_sock;
                    list_del_rcu(&my_sk->sk_list);
                    INIT_LIST_HEAD(&my_sk->sk_list);
                    break;
                }
            }
        }
        spin_unlock(&mpcb->psubflow_list_lock);
    }

    /* report socket destruction */
    mpdccp_report_destroy (sk);

    /* release link_info struct */
    if (my_sk->link_info) {
        const char *name = MPDCCP_LINK_NAME (my_sk->link_info);
        mpdccp_pr_debug ("remove subflow %p (%s: %d)\n", sk,
                name ? name : "<copied link>", my_sk->link_info->id);
        mpdccp_link_put (my_sk->link_info);
        my_sk->link_info = NULL;
    }

    sk->sk_user_data = NULL;

    /* Restore old function pointers */
    sk->sk_data_ready       = my_sk->sk_data_ready;
    sk->sk_backlog_rcv      = my_sk->sk_backlog_rcv;
    sk->sk_destruct         = my_sk->sk_destruct;
    sk->sk_state_change     = my_sk->sk_state_change;
    sk->sk_write_space      = my_sk->sk_write_space;

    if (my_sk->pcb)
        mpdccp_free_reorder_path_cb(my_sk->pcb);

    kmem_cache_free(mpdccp_mysock_cache, my_sk);

    mpdccp_pr_debug ("subflow %p removed from mpcb %p (found %d), remaining subflows: %d", sk, mpcb, found, rem_subflows);
    return found;
}

void my_sock_final_destruct (struct sock *sk, struct mpdccp_cb *mpcb, int found)
{
    if (!sk) return;
    if (found && mpcb && (mpcb->meta_sk->sk_state != DCCP_CLOSED) && mpcb->cnt_subflows == 0) {
        struct sock	*msk = mpcb->meta_sk;
        mpdccp_pr_debug ("closing meta %p\n", msk);
        sock_hold (msk);
        dccp_done(msk);
        mpdccp_report_alldown (msk);
        sock_put (msk);
    }
    if (mpcb) mpdccp_cb_put (mpcb);
}

void my_sock_destruct (struct sock *sk)
{
    struct my_sock   *my_sk = mpdccp_my_sock(sk);
    struct mpdccp_cb *mpcb = my_sk ? my_sk->mpcb : NULL;
    int              found=0;

    if (!sk || !my_sk) return;
    found = my_sock_pre_destruct (sk);
    my_sock_final_destruct (sk, mpcb, found);
    if (sk->sk_destruct)
        sk->sk_destruct (sk);
}


static void mpdccp_close_worker(struct work_struct *work)
{
    struct my_sock *my_sk;
    struct sock *sk;
    struct socket_wq *wq;
    my_sk = container_of(work, struct my_sock, close_work.work);
    sk = my_sk->my_sk_sock;

    /* Finish the passive close stuff before final closure */
    if ((sk->sk_state == DCCP_PASSIVE_CLOSE)
        || (sk->sk_state == DCCP_PASSIVE_CLOSEREQ)) {

            if (dccp_sk(sk)->dccps_role == DCCP_ROLE_CLIENT) {
                /* Wipe any ACK retranmission queue */
                inet_csk_clear_xmit_timer(sk, ICSK_TIME_RETRANS);
                if (sk->sk_send_head != NULL) {
                    kfree_skb(sk->sk_send_head);
                    sk->sk_send_head = NULL;
                }
            }
            if(my_sk->mpcb->close_fast)
                dccp_set_state(sk, DCCP_CLOSED);
            else
                dccp_finish_passive_close(sk);
    }

    rcu_read_lock();
    wq = rcu_dereference(sk->sk_wq);
    rcu_read_unlock();

    /* Try again later if the wq is not empty, otherwise dccp_close will invalidate it causing a crash */
    if (skwq_has_sleeper(wq))
        schedule_delayed_work(&mpdccp_my_sock(sk)->close_work, msecs_to_jiffies(200));
    else{
        dccp_sk(sk)->is_fast_close = my_sk->mpcb->close_fast;
        dccp_close(sk, 0);
    }
}

void subflow_write_space(struct sock *sk)
{
    struct my_sock *my_sk = (struct my_sock *)sk->sk_user_data;
    struct mpdccp_cb *mpcb  = my_sk ? my_sk->mpcb : NULL;

    /* Avoid waking any sleeper if the state is not OPEN or CLOSED */
    if (my_sk && ((sk->sk_state == DCCP_OPEN || sk->sk_state == DCCP_CLOSED) || (mpcb && mpcb->fallback_sp)))
        my_sk->sk_write_space(sk);
}

int my_sock_init (struct sock *sk, struct mpdccp_cb *mpcb, int if_idx, enum mpdccp_role role)
{
    struct my_sock *my_sk;
    int ret = 0;
    mpdccp_pr_debug("Enter my_sock_init().\n");

    if (role == MPDCCP_CLIENT) {
        ret = dccp_feat_register_sp(sk, DCCPF_MULTIPATH, 0,
                                    mpdccp_supported_versions,
                                    ARRAY_SIZE(mpdccp_supported_versions));
        if (ret < 0 ) {
            sk->sk_user_data = NULL;
            goto out;
        }
    }

    my_sk = kmem_cache_zalloc(mpdccp_mysock_cache, GFP_ATOMIC);
    if (!my_sk) {
        mpdccp_pr_debug("no mem for my_sk\n");
        ret = -ENOBUFS;
        goto out;
    }

    /* No locking needed, as readers do not yet have access to the structure */
    INIT_LIST_HEAD(&my_sk->sk_list);
    my_sk->my_sk_sock   = sk;
    my_sk->mpcb         = mpcb;
    my_sk->if_idx       = if_idx;
    my_sk->pcb          = NULL;

    /* Init private scheduler data */
    memset(my_sk->sched_priv, 0, MPDCCP_SCHED_SIZE);

    /* Save the original socket callbacks before rewriting */

    mpdccp_pr_debug("role %d my_sk %p", role, my_sk);
    my_sk->sk_data_ready    = sk->sk_data_ready;
    my_sk->sk_backlog_rcv   = sk->sk_backlog_rcv;
    my_sk->sk_destruct      = sk->sk_destruct;

    sk->sk_data_ready       = listen_data_ready;
    sk->sk_backlog_rcv      = listen_backlog_rcv;
    sk->sk_destruct         = my_sock_destruct;
    sk->sk_user_data        = my_sk;

    if (role == MPDCCP_CLIENT) {
        my_sk->sk_state_change  = sk->sk_state_change;
        sk->sk_state_change     = mp_state_change;

        my_sk->sk_write_space   = sk->sk_write_space;
        sk->sk_write_space      = subflow_write_space;
    }

    mpdccp_pr_debug("role %d sk %p kex_done %d", role, sk, mpcb->kex_done);
    if (!mpcb->kex_done) {
        /* Set the kex flag for this socket if no key exchange has been done before */
        dccp_sk(sk)->is_kex_sk = 1;

        if (role == MPDCCP_CLIENT || role == MPDCCP_SERVER) {
            int i;
            u8 supp_keys = MPDCCP_SUPPKEYS;
            /* Generate local keys for each supported type */
            for (i=0; supp_keys && (i < MPDCCP_MAX_KEYS); i++) {
                u32 keytype = ffs(supp_keys) - 1;
                ret = mpdccp_generate_key(&mpcb->mpdccp_loc_keys[i], keytype);
                if (ret) {
                    mpdccp_pr_debug("error generating key type %d\n", keytype);
                    break;
                }
                supp_keys &= ~(1 << keytype);
            }
        }
    } else  {
        if (role == MPDCCP_CLIENT) {
            /* Generate local nonce */
            get_random_bytes(&dccp_sk(sk)->mpdccp_loc_nonce, 4);
            mpdccp_pr_debug("client: generated nonce %x\n", dccp_sk(sk)->mpdccp_loc_nonce);
        }
    }

    // Memory is already reserved in struct my_sk
    mpdccp_pr_debug("Entered my_sock_init\n");

    INIT_DELAYED_WORK(&my_sk->close_work, mpdccp_close_worker);
    /* Make sure refcount for this module is increased */
out:
    return ret;
}
EXPORT_SYMBOL_GPL(my_sock_init);


int
mpdccp_ctrl_maycpylink (struct sock *sk)
{
    struct my_sock 		*my_sk;
    struct mpdccp_link_info	*link, *oldlink;
    int				ret;

    if (!sk) return -EINVAL;
    my_sk = mpdccp_my_sock (sk);
    if (!my_sk) return -EINVAL;	/* no mpdccp socket */
    if (my_sk->link_iscpy) return 0;	/* already copied */
    ret = mpdccp_link_copy (&link, my_sk->link_info);
    if (ret < 0) {
	mpdccp_pr_error ("cannot copy link_info: %d", ret);
	return ret;
    }
    rcu_read_lock ();
    oldlink = xchg ((__force struct mpdccp_link_info **)&my_sk->link_info, link);
    my_sk->link_iscpy = 1;
    strncpy (link->ndev_name, oldlink->ndev_name, IFNAMSIZ+1);
    rcu_read_unlock ();
    mpdccp_link_put (oldlink);
    return 0;
}
EXPORT_SYMBOL (mpdccp_ctrl_maycpylink);

struct mpdccp_link_info*
mpdccp_ctrl_getlink (struct sock *sk)
{
    struct my_sock 		*my_sk;
    struct mpdccp_link_info	*link;

    if (!sk) return NULL;
    my_sk = mpdccp_my_sock (sk);
    if (!my_sk) return NULL;	/* no mpdccp socket */
    rcu_read_lock();
    link = my_sk->link_info;
    mpdccp_link_get (link);
    rcu_read_unlock();
    return link;
}
EXPORT_SYMBOL (mpdccp_ctrl_getlink);

struct mpdccp_link_info*
mpdccp_ctrl_getcpylink (struct sock *sk)
{
    int				ret;
    struct mpdccp_link_info	*link;

    rcu_read_lock();
    ret = mpdccp_ctrl_maycpylink (sk);
    if (ret < 0) {
	rcu_read_unlock();
	return NULL;
    }
    link = mpdccp_ctrl_getlink (sk);
    rcu_read_unlock();
    return link;
}
EXPORT_SYMBOL (mpdccp_ctrl_getcpylink);

int
mpdccp_ctrl_has_cfgchg (struct sock *sk)
{
    struct my_sock 		*my_sk;
    int				ret;

    if (!sk) return 0;
    my_sk = mpdccp_my_sock (sk);
    if (!my_sk) return 0;	/* no mpdccp socket */
    rcu_read_lock();
    ret = (my_sk->link_cnt != mpdccp_link_cnt(my_sk->link_info));
    rcu_read_unlock();
    return ret;
}
EXPORT_SYMBOL (mpdccp_ctrl_has_cfgchg);

void
mpdccp_ctrl_cfgupdate (struct sock *sk)
{
    struct my_sock 		*my_sk;

    if (!sk) return;
    my_sk = mpdccp_my_sock (sk);
    if (!my_sk) return;	/* no mpdccp socket */
    rcu_read_lock();
    my_sk->link_cnt = mpdccp_link_cnt(my_sk->link_info);
    rcu_read_unlock();
}
EXPORT_SYMBOL (mpdccp_ctrl_cfgupdate);

#define LINK_UD_MAGIC	0x33a9c478
struct link_user_data {
	int			magic;
	void			*user_data;
	struct mpdccp_link_info	*link_info;
};



/* ****************************************************************************
 *  add / remove subflows - called by path manager
 * ****************************************************************************/

/* This function adds new sockets to existing connections:
 * - Attempts to establish connections to another endpoint as a client.
 */

int mpdccp_add_client_conn (	struct mpdccp_cb *mpcb,
				struct sockaddr *local_address,
				int locaddr_len,
				int if_idx,
				struct sockaddr *remote_address,
				int remaddr_len)
{
	int			ret = 0;
	int 			flags;
	struct socket   	*sock; /* The newly created socket */
	struct sock     	*sk;
	struct mpdccp_link_info	*link_info = NULL;
	
	if (!mpcb || !local_address || !remote_address) return -EINVAL;
	if (mpcb->role != MPDCCP_CLIENT) return -EINVAL;
	
	/* Create a new socket */
	ret = sock_create_kern(read_pnet(&mpcb->net), PF_INET, SOCK_DCCP, IPPROTO_DCCP, &sock);
	if (ret < 0) {
		mpdccp_pr_debug("Failed to create socket (%d).\n", ret);
		goto out;
	}
	
	sk = sock->sk;

	/* Get the service type from meta socket */
	dccp_sk(sk)->dccps_service = dccp_sk(mpcb->meta_sk)->dccps_service;

	set_mpdccp(sk, mpcb);
	
	ret = my_sock_init (sk, mpcb, if_idx, MPDCCP_CLIENT);
	if (ret < 0) {
		mpdccp_pr_debug("Failed to init mysock (%d).\n", ret);
		sock_release(sock);
		goto out;
	}
	
	/* Bind the socket to one of the DCCP-enabled IP addresses */
	ret = kernel_bind(sock, local_address, locaddr_len);
	if (ret < 0) {
		mpdccp_pr_debug("Failed to bind socket %p (%d).\n", sk, ret);
		sock_release(sock);
		goto out;
	}
	if (local_address->sa_family == AF_INET) {
        int loc_id = 0;
        union inet_addr addr;
		struct sockaddr_in 	*local_v4_address = (struct sockaddr_in*)local_address;
		link_info = mpdccp_link_find_ip4 (&init_net, &local_v4_address->sin_addr, NULL);

        addr.in = local_v4_address->sin_addr;
        if(mpcb->pm_ops->claim_local_addr)
            loc_id = mpcb->pm_ops->claim_local_addr(mpcb, AF_INET, &addr);

        if(loc_id < 1){
            dccp_pr_debug("cant create subflow with unknown address id");
		    sock_release(sock);
		    goto out;
        }
        if(mpcb->master_addr_id == 0){
            mpcb->master_addr_id = loc_id;
            dccp_pr_debug("master_addr_id set %u", mpcb->master_addr_id);
        }
        mpdccp_my_sock(sk)->local_addr_id = loc_id;
	} else if (local_address->sa_family == AF_INET6) {
		struct sockaddr_in6 	*local_v6_address = (struct sockaddr_in6*)local_address;
		link_info = mpdccp_link_find_ip6 (&init_net, &local_v6_address->sin6_addr, NULL);
	}
	if (!link_info) link_info = mpdccp_getfallbacklink (&init_net);
	
	mpdccp_my_sock(sk)->link_info = link_info;
	mpdccp_my_sock(sk)->link_cnt = mpdccp_link_cnt(link_info);
	mpdccp_my_sock(sk)->link_iscpy = 0;

	/* Add socket to the request list */
	spin_lock(&mpcb->psubflow_list_lock);
	list_add_tail_rcu(&mpdccp_my_sock(sk)->sk_list , &mpcb->prequest_list);
	mpdccp_pr_debug("Added new entry to prequest_list @ %p\n", mpdccp_my_sock(sk));
	spin_unlock(&mpcb->psubflow_list_lock);

	/* Only the first (key exchage) socket is blocking */
	flags = dccp_sk(sk)->is_kex_sk ? 0 : O_NONBLOCK;

	ret = kernel_connect(sock, remote_address, remaddr_len, flags);
	if ((ret < 0) && (ret != -EINPROGRESS)) {
#ifdef CONFIG_IP_MPDCCP_DEBUG
		struct sockaddr_in *their_inaddr_ptr = (struct sockaddr_in *)remote_address; 
		mpdccp_pr_debug("Failed to connect from sk %pI4 %p (%d).\n",
			&their_inaddr_ptr->sin_addr, sk, ret);
#endif
		sock_release(sock);
		goto out;
	}

	if (dccp_sk(sk)->is_kex_sk && mpcb->kex_done) {
		struct inet_sock *inet_meta = inet_sk(mpcb->meta_sk);
		struct inet_sock *inet_sub = inet_sk(sk);

		/* MP_KEY sockets can be authorized now. MP_JOIN sockets need to wait one more more ack */
		dccp_sk(sk)->auth_done = 1;

		/* Reset the flag to avoid inserting MP_KEY options in subsenquent ACKs */
		dccp_sk(sk)->is_kex_sk = 0;

		/* Update the state and MSS of meta socket */
		dccp_sk(mpcb->meta_sk)->dccps_mss_cache = dccp_sk(sk)->dccps_mss_cache;
		mpcb->meta_sk->sk_state = DCCP_OPEN;

		/* Update meta socket inet data with info from subflow */
		inet_meta->inet_sport = inet_sub->inet_sport;
		inet_meta->inet_dport = inet_sub->inet_dport;
		inet_meta->inet_saddr = inet_sub->inet_saddr;
		inet_meta->inet_daddr = inet_sub->inet_daddr;
	}

	if (mpcb->fallback_sp) {
		struct inet_sock *inet_meta = inet_sk(mpcb->meta_sk);
		struct inet_sock *inet_sub = inet_sk(sk);

		/* Update the state and MSS of meta socket */
		dccp_sk(mpcb->meta_sk)->dccps_mss_cache = dccp_sk(sk)->dccps_mss_cache;
		mpcb->meta_sk->sk_state = DCCP_OPEN;
		dccp_sk(sk)->is_kex_sk = 0;

		/* Update meta socket inet data with info from subflow */
		inet_meta->inet_sport = inet_sub->inet_sport;
		inet_meta->inet_dport = inet_sub->inet_dport;
		inet_meta->inet_saddr = inet_sub->inet_saddr;
		inet_meta->inet_daddr = inet_sub->inet_daddr;
	}
out:
	return ret;
}
EXPORT_SYMBOL (mpdccp_add_client_conn);

int mpdccp_reconnect_client (  struct sock *sk,
                               int destroy,
                               struct sockaddr *local_address,
                               int locaddr_len,
                               int if_idx)
{
    struct my_sock   *my_sk = mpdccp_my_sock(sk);
    struct mpdccp_cb *mpcb = my_sk ? my_sk->mpcb : NULL;
    int              found, ret;

    if (!sk || !my_sk) return -EINVAL;

    if (mpdccp_my_sock(sk)->delpath_sent){
        found = my_sock_pre_destruct (sk);
        my_sock_final_destruct (sk, mpcb, found);
        unset_mpdccp(sk);
        return 0;
    }

    if (!destroy)
       found = my_sock_pre_destruct (sk);
    mpdccp_pr_debug("try to reconnect sk address %pI4. if %d \n", &sk->__sk_common.skc_rcv_saddr, if_idx);
    ret = mpdccp_add_client_conn(mpcb, local_address, locaddr_len, if_idx,
                                (struct sockaddr*)&mpcb->mpdccp_remote_addr,
                                mpcb->remaddr_len);
    if (ret) {
       mpdccp_pr_debug("reconnecting to sk address %pI4 (if %d) failed: %d\n",
                       &sk->__sk_common.skc_rcv_saddr, if_idx, ret);
       unset_mpdccp(sk);
       if (!destroy)
               my_sock_final_destruct (sk, mpcb, found);
       return ret;
    }
    if (destroy)
       return mpdccp_close_subflow(mpcb, sk, 1);
    return 0;
}
EXPORT_SYMBOL (mpdccp_reconnect_client);


int mpdccp_add_listen_sock (	struct mpdccp_cb *mpcb,
				struct sockaddr *local_address,
				int locaddr_len,
				int if_idx)
{
    int                 retval	= 0;
    struct socket   	*sock; /* The newly created socket */
    struct sock     	*sk;
    struct mpdccp_link_info	*link_info = NULL;

    if (!mpcb || !local_address) return -EINVAL;
    if (mpcb->role != MPDCCP_SERVER) return -EINVAL;

    mpdccp_pr_debug ("Create subflow socket\n");
    /* Create a new socket */
    retval = sock_create(PF_INET, SOCK_DCCP, IPPROTO_DCCP, &sock);
    if (retval < 0) {
        mpdccp_pr_debug("Failed to create socket (%d).\n", retval);
        goto out;
    }
    sock->sk->sk_reuse = SK_FORCE_REUSE;

    sk = sock->sk;
    set_mpdccp(sk, mpcb);

    mpdccp_pr_debug ("init mysock\n");
    retval = my_sock_init (sk, mpcb, if_idx, MPDCCP_SERVER);
    if (retval < 0) {
        mpdccp_pr_debug("Failed to init mysock (%d).\n", retval);
        sock_release(sock);
        goto out;
    }

    mpdccp_pr_debug ("bind address: %pISc\n", local_address);
    /* Bind the socket to one of the DCCP-enabled IP addresses */
    retval = sock->ops->bind(sock, local_address, locaddr_len);
    if (retval < 0) {
        mpdccp_pr_debug("Failed to bind socket %p (%d).\n", sk, retval);
        sock_release(sock);
        goto out;
    }
    if (local_address->sa_family == AF_INET) {
         struct sockaddr_in 	*local_v4_address = (struct sockaddr_in*)local_address;
         link_info = mpdccp_link_find_ip4 (&init_net, &local_v4_address->sin_addr, NULL);
    } else if (local_address->sa_family == AF_INET6) {
         struct sockaddr_in6 	*local_v6_address = (struct sockaddr_in6*)local_address;
         link_info = mpdccp_link_find_ip6 (&init_net, &local_v6_address->sin6_addr, NULL);
    }
    if (!link_info) link_info = mpdccp_getfallbacklink (&init_net);

    mpdccp_my_sock(sk)->link_info = link_info;
    mpdccp_my_sock(sk)->link_cnt = mpdccp_link_cnt(link_info);
    mpdccp_my_sock(sk)->link_iscpy = 0;


    mpdccp_pr_debug ("set subflow to listen state\n");
    retval = sock->ops->listen(sock, MPDCCP_SERVER_BACKLOG);
    if (retval < 0) {
        mpdccp_pr_debug("Failed to listen on socket(%d).\n", retval);
        sock_release(sock);
        goto out;
    }

    spin_lock(&mpcb->plisten_list_lock);
    list_add_tail_rcu(&mpdccp_my_sock(sk)->sk_list , &mpcb->plisten_list);
    mpcb->cnt_listensocks++;
    mpdccp_pr_debug("Added new entry to plisten_list @ %p\n", mpdccp_my_sock(sk));
    spin_unlock(&mpcb->plisten_list_lock);

    mpdccp_pr_debug("server port added successfully. There are %d subflows now.\n",
			mpcb->cnt_subflows);

out:
    return retval;
}
EXPORT_SYMBOL (mpdccp_add_listen_sock);

int mpdccp_close_subflow (struct mpdccp_cb *mpcb, struct sock *sk, int destroy)
{
    if (!mpcb || !sk || !mpdccp_my_sock(sk)) return -EINVAL;
    mpdccp_pr_debug("enter for %p role %s state %d closing %d", sk, dccp_role(sk), sk->sk_state, mpdccp_my_sock(sk)->closing);

    if(mpcb->pm_ops->del_retrans)
        mpcb->pm_ops->del_retrans(sock_net(mpcb->meta_sk), sk);

    if(mpcb->close_fast == 2 && sk->sk_state == DCCP_OPEN){
        dccp_set_state(sk, DCCP_PASSIVE_CLOSE);
    }

    /* This will call dccp_close() in process context (only once per socket) */
    if (!mpdccp_my_sock(sk)->closing) {
        mpdccp_my_sock(sk)->closing = destroy;
        mpdccp_pr_debug("Close socket(%p) %u", sk, destroy);
        schedule_delayed_work(&mpdccp_my_sock(sk)->close_work, 0);
    }
    return 0;
}
EXPORT_SYMBOL (mpdccp_close_subflow);


/*select sk to announce data*/

struct sock *mpdccp_select_ann_sock(struct mpdccp_cb *mpcb, u8 id)
{

    struct sock *sk, *avsk = NULL;
    /*returns the first avilable socket that is not id - can be improved to 
     *the latest used or lowest rtt as in mptcp mptcp_select_ack_sock */

    mpdccp_for_each_sk(mpcb, sk) {
        if (!mpdccp_sk_can_send(sk) || mpdccp_my_sock(sk)->local_addr_id == id)
            continue;
        avsk = sk;
        goto avfound;
    }

avfound:
    return avsk;
}
EXPORT_SYMBOL(mpdccp_select_ann_sock);

/*
 * the real xmit function
 */

int
mpdccp_xmit_to_sk (
	struct sock	*sk,
	struct sk_buff	*skb)
{
	int			len, ret=0, isbh;
	long 			timeo;
	struct mpdccp_cb	*mpcb;
	struct sock		*meta_sk;

	if (!skb || !sk) return -EINVAL;

	len = skb->len;
	if (len > dccp_sk(sk)->dccps_mss_cache) {
		dccp_sk(meta_sk)->dccps_mss_cache = dccp_sk(sk)->dccps_mss_cache;
		return -EMSGSIZE;
	}
	mpcb = get_mpcb (sk);
	meta_sk = mpcb ? mpcb->meta_sk : NULL;

	if (in_softirq()) {
		bh_lock_sock(sk);
		isbh = 1;
	} else {
		lock_sock(sk);
		isbh = 0;
	}

	if (dccp_qpolicy_full(sk)) {
		ret = -EAGAIN;
		goto out_release;
	}

	timeo = sock_sndtimeo(sk, /* noblock */ 1);

	/*
	 * We have to use sk_stream_wait_connect here to set sk_write_pending,
	 * so that the trick in dccp_rcv_request_sent_state_process.
	 */
	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(DCCPF_OPEN | DCCPF_PARTOPEN))
		if ((ret = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_release;

	if (skb->next && meta_sk) dccp_qpolicy_unlink (meta_sk, skb);
	skb_set_owner_w(skb, sk);
	dccp_qpolicy_push(sk, skb);

	if (!timer_pending(&dccp_sk(sk)->dccps_xmit_timer))
		dccp_write_xmit(sk);

	mpdccp_pr_debug("packet with %d bytes sent\n", len);

out_release:
	if(isbh)
		bh_unlock_sock(sk);
	else
		release_sock(sk);
	return ret;
}
EXPORT_SYMBOL_GPL(mpdccp_xmit_to_sk);

/* Process listen state by calling original backlog_rcv callback
 * and accept the connection */
int listen_backlog_rcv (struct sock *sk, struct sk_buff *skb)
{
    int ret = 0;
    struct my_sock *my_sk = mpdccp_my_sock(sk);
    struct mpdccp_cb *mpcb  = my_sk->mpcb;

    mpdccp_pr_debug("Executing backlog_rcv callback. sk %p my_sk %p bklog %p \n", sk, my_sk, my_sk->sk_backlog_rcv);

    if (my_sk->sk_backlog_rcv) {
	mpdccp_pr_debug("There is sk_backlog_rcv");
        ret = my_sk->sk_backlog_rcv (sk, skb);
    }

    if(mpcb && mpcb->reorder_ops->update_pseq)
        mpcb->reorder_ops->update_pseq(my_sk, skb);
#if 0 
    /* If the queue was previously stopped because of a full cwnd,
    * a returning ACK will open the window again, so we should
    * re-enable the queue. */
    if (netif_queue_stopped(mpcb->mpdev->ndev) &&
        mpdccp_cwnd_available(mpcb)) {
        netif_wake_queue(mpcb->mpdev->ndev);
        MPSTATINC (mpcb->mpdev,tx_rearm);
    }
#endif
    
    /* We can safely ignore ret value of my_sk->sk_backlog_rcv, as it can only return 0 anyways
     * (and causes a LOT of pain if it was otherwise). */
    return ret;
}

void listen_data_ready (struct sock *sk)
{
    int ret;

    // Client side setup is not handled by this callback, use original workflow
    if (sk->sk_state == DCCP_REQUESTING) {
        struct my_sock *my_sk = mpdccp_my_sock(sk);
        if (my_sk->sk_data_ready)
            my_sk->sk_data_ready (sk);

        return;
    }

    /* If the socket is not listening, it does not belong to a server. */
    if (sk->sk_state == DCCP_LISTEN) {
        mpdccp_pr_debug("sk %p is in LISTEN state, not handled\n", sk);
         return;

    } 

    if ((sk->sk_state == DCCP_OPEN)
        || (sk->sk_state == DCCP_PARTOPEN)) {
        //mpdccp_pr_debug("sk %p is in OPEN state. Reading...\n", sk);

        ret = mpdccp_read_from_subflow (sk);
        if(ret < 0) {
            mpdccp_pr_debug("Failed to read message from sk %p (%d).\n", sk, ret);
        }
    }

    /* TODO: Work queues temporarily disabled. They led to a lot of 
     * packet loss. */
    // ret = queue_bnd_work(sk);
    // if(ret < 0)
    //     mpdccp_pr_debug("Failed to queue work (%d).\n", ret);

    return;
}

void mp_state_change(struct sock *sk)
{
    struct mpdccp_cb *mpcb;
    struct sock *subsk;
    mpdccp_pr_debug("enter sk %p role %s is_kex %d\n", sk, dccp_role(sk), dccp_sk(sk)->is_kex_sk);

    mpcb = MPDCCP_CB(sk);

    if (sk->sk_state == DCCP_OPEN || (sk->sk_state == DCCP_PARTOPEN && mpcb && mpcb->fallback_sp)) {
        /* Check if the subflow was already added */
        spin_lock(&mpcb->psubflow_list_lock);
        mpdccp_for_each_sk(mpcb, subsk) {
            if (sk == subsk) {
                mpdccp_pr_debug("sk %p already in subflow_list, skipping\n", sk);
                spin_unlock(&mpcb->psubflow_list_lock);
                /* nevertheless report it */
                mpdccp_report_new_subflow(sk);
                goto out;
            }
        }

        /* Move socket from the request to the subflow list */
        list_move_tail(&mpdccp_my_sock(sk)->sk_list, &mpcb->psubflow_list);
        mpdccp_pr_debug("Added new entry sk %p to psubflow_list @ %p\n", sk, mpdccp_my_sock(sk));
        mpcb->cnt_subflows = (mpcb->cnt_subflows) + 1;
        spin_unlock(&mpcb->psubflow_list_lock);

        if (mpcb->sched_ops->init_subflow) {
            rcu_read_lock ();
            mpcb->sched_ops->init_subflow(sk);
            rcu_read_unlock ();
        }

        mpdccp_report_new_subflow(sk);
        mpdccp_pr_debug("client connection established successfully. There are %d subflows now.\n", mpcb->cnt_subflows);
    }

out:
    return;
}

int mpdccp_link_cpy_set_prio(struct sock *sk, int prio)
{
   struct mpdccp_link_info      *link;

   /* copy and get link */
   link = mpdccp_ctrl_getcpylink (sk);
   if (!link) return -EINVAL;
   /* change prio */
   mpdccp_link_change_mpdccp_prio (link, prio);
   mpdccp_link_change_name(link, sk);
   /* release link */
   mpdccp_link_put (link);
   return 0;
}

int mpdccp_get_prio(struct sock *sk)
{
	struct mpdccp_link_info *link;
	int prio;

	link = mpdccp_ctrl_getlink (sk);
	if (!link)
		return -EINVAL;
	prio = link->mpdccp_prio;
	mpdccp_link_put (link);
	return prio;
}

void mpdccp_init_announce_prio(struct sock *sk)
{
    mpdccp_my_sock(sk)->announce_prio = mpdccp_get_prio(sk) + 1;        //adding +1 so we can check also for sending zero
    dccp_send_keepalive(sk);
}

int mpdccp_generate_key(struct mpdccp_key *key, int key_type)
{
	switch (key_type) {
		case DCCPK_PLAIN:
			key->type = key_type;
			key->size = MPDCCP_PLAIN_KEY_SIZE;
			get_random_bytes(&key->value, MPDCCP_PLAIN_KEY_SIZE);
			break;
		case DCCPK_C25519_SHA256:
		case DCCPK_C25519_SHA512:
			/* TODO: add support */
		default:
			key->size = 0;
			key->type = DCCPK_INVALID;
			mpdccp_pr_debug("cannot generate key of type %d", key_type);
			return -1;
	}
	mpdccp_pr_debug("generated key %llx type %d", be64_to_cpu(*((__be64 *)key->value)), key->type);
	return 0;
}
EXPORT_SYMBOL(mpdccp_generate_key);

/* General initialization of MPDCCP */
int mpdccp_ctrl_init(void)
{
    INIT_LIST_HEAD(&pconnection_list);
    spin_lock_init(&pconnection_list_lock);

    mpdccp_mysock_cache = kmem_cache_create("mpdccp_mysock", sizeof(struct my_sock),
                       0, SLAB_TYPESAFE_BY_RCU|SLAB_HWCACHE_ALIGN,
                       NULL);
    if (!mpdccp_mysock_cache) {
        mpdccp_pr_debug("Failed to create mysock slab cache.\n");
        return -ENOMEM;
    }

    mpdccp_cb_cache = kmem_cache_create("mpdccp_cb", sizeof(struct mpdccp_cb),
                       0, SLAB_TYPESAFE_BY_RCU|SLAB_HWCACHE_ALIGN,
                       NULL);
    if (!mpdccp_cb_cache) {
        mpdccp_pr_debug("Failed to create mpcb slab cache.\n");
    	kmem_cache_destroy(mpdccp_mysock_cache);
        return -ENOMEM;
    }

    /*
     * The number of active work items is limited by the number of
     * connections, so leave @max_active at default.
     */
    mpdccp_wq = alloc_workqueue("mpdccp_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    if (!mpdccp_wq) {
        mpdccp_pr_debug("Failed to register sysctl.\n");
    	kmem_cache_destroy(mpdccp_mysock_cache);
    	kmem_cache_destroy(mpdccp_cb_cache);
	return -1;
    }

    /* Allocate crypto contexts */
    tfm_hash = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm_hash)) {
        mpdccp_pr_debug("Failed to alloc tfm_hash, err %ld\n", PTR_ERR(tfm_hash));
        return -1;
    }

    tfm_hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(tfm_hmac)) {
        mpdccp_pr_debug("Failed to alloc tfm_hmac, err %ld\n", PTR_ERR(tfm_hmac));
        crypto_free_shash(tfm_hash);
        return -1;
    }

    return 0;
}

void mpdccp_ctrl_finish(void)
{
    if (mpdccp_wq) {
        mpdccp_wq_flush();
        destroy_workqueue(mpdccp_wq);
        mpdccp_wq = NULL;
    }

    if (tfm_hash)
        crypto_free_shash(tfm_hash);

    if (tfm_hmac)
        crypto_free_shash(tfm_hmac);

    kmem_cache_destroy(mpdccp_mysock_cache);
    kmem_cache_destroy(mpdccp_cb_cache);

#if 0
    /* sk_free (and __sk_free) requires wmem_alloc to be 1.
     * All the rest is set to 0 thanks to __GFP_ZERO above.
     */
    atomic_set(&master_sk->sk_wmem_alloc, 1);
    sk_free(master_sk);
#endif
}

int mpdccp_hmac_sha256(const u8 *key, u8 keylen, const u8 *msg, u8 msglen, u8 *output)
{
        SHASH_DESC_ON_STACK(desc, tfm_hmac);
        u8 buf[32];
        int ret;

        ret = crypto_shash_setkey(tfm_hmac, key, keylen);
        if (ret) {
            mpdccp_pr_debug("Failed crypto_shash_setkey, err %d", ret);
            return -1;
        }

        desc->tfm = tfm_hmac;
        //desc->flags = 0;

        ret = crypto_shash_digest(desc, msg, msglen, buf);
        if (ret) {
            mpdccp_pr_debug("Failed crypto_shash_digest, err %d", ret);
            return -1;
        }
        memcpy(output, buf, MPDCCP_HMAC_SIZE);

        return 0;
}
