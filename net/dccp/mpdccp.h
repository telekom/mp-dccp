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

#ifndef _MPDCCP_H
#define _MPDCCP_H

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

/* Max length for entering an IP
 * TAG-0.7: Replaced by user space tool */
#define MPDCCP_IPV4_MAX             16

/* Bitfield representing the supported key types for handshake */
#define MPDCCP_SUPPKEYS  (DCCPKF_PLAIN)
/* TODO: add support for all key types */
//#define MPDCCP_SUPPKEYS  (DCCPKF_PLAIN | DCCPKF_C25519_SHA256 | DCCPKF_C25519_SHA512)


/* Defines for MPDCCP options.
 * All length values account for payload ONLY. */
#define MPDCCP_LEN_ADD_ADDR4        6
#define MPDCCP_LEN_ADD_ADDR4_PORT   8
#define MPDCCP_LEN_ADD_ADDR6        18
#define MPDCCP_LEN_ADD_ADDR6_PORT   20
#define MPDCCP_LEN_DEL_ADDR         2

/* Define general reordering parameter */
#define GLOB_SEQNO_INIT             1        // global sequence number of first packet that is sent, TODO superseed with dynamic approach in connection setup


/* Debug output, enabled via sysctl */
#if 0
/* Debug that translates socket states to human-readable format.
 * Unused for now, but this is just to beautiful to delete */
static const char *mpdccp_state_name(const int state)
{
    static const char *const dccp_state_names[] = {
    [DCCP_OPEN]     = "OPEN",
    [DCCP_REQUESTING]   = "REQUESTING",
    [DCCP_PARTOPEN]     = "PARTOPEN",
    [DCCP_LISTEN]       = "LISTEN",
    [DCCP_RESPOND]      = "RESPOND",
    [DCCP_CLOSING]      = "CLOSING",
    [DCCP_ACTIVE_CLOSEREQ]  = "CLOSEREQ",
    [DCCP_PASSIVE_CLOSE]    = "PASSIVE_CLOSE",
    [DCCP_PASSIVE_CLOSEREQ] = "PASSIVE_CLOSEREQ",
    [DCCP_TIME_WAIT]    = "TIME_WAIT",
    [DCCP_CLOSED]       = "CLOSED",
    };

    if (state >= DCCP_MAX_STATES)
        return "INVALID STATE!";
    else
        return dccp_state_names[state];
}
#endif
extern int mpdccp_enabled;
extern bool mpdccp_debug;
extern bool mpdccp_accept_prio;
#ifdef CONFIG_IP_MPDCCP_DEBUG
#define MPDCCP_PRINTK(enable, fmt, args...)   do { if (enable)                  \
                            printk_ratelimited(fmt, ##args);                    \
                        } while(0)
#define MPDCCP_PR_DEBUG(enable, fmt, a...)    DCCP_PRINTK(enable, KERN_DEBUG    \
                          "%s: " fmt, __func__, ##a)
// depends on mpdccp_debug, fixed KERN_DEBUG prio, prints func
#define mpdccp_pr_debug(format, a...)   MPDCCP_PR_DEBUG(mpdccp_debug, format, ##a)
// depends on mpdccp_debug, variable prio
#define mpdccp_pr_debug_cat(format, a...)   MPDCCP_PRINTK(mpdccp_debug, format, ##a)
// depends on mpdccp_debug, fixed KERN_DEBUG prio,
#define mpdccp_debug(fmt, a...)         mpdccp_pr_debug_cat(KERN_DEBUG fmt, ##a)
#define mpdccp_sockinfo(sk)             do { mpdccp_pr_debug("Socket info: %s(%p) Prio %d State %s\n",  \
                                            dccp_role(sk), sk, mpdccp_my_sock(sk)->priority,            \
                                            mpdccp_state_name(sk->sk_state));                           \
                                        } while(0)
#define mpdccp_pr_info(format, a...) MPDCCP_PRINTK(mpdccp_debug, KERN_INFO format, ##a)
#else
#define MPDCCP_PRINTK(enable, fmt, args...) 
#define MPDCCP_PR_DEBUG(enable, fmt, a...)
#define mpdccp_pr_debug(format, a...)
#define mpdccp_pr_debug_cat(format, a...)
#define mpdccp_debug(format, a...)
#define mpdccp_pr_info(format, a...)
#endif
#define mpdccp_pr_error(format, a...) do { printk (KERN_ERR format, ##a); } while (0)


/* List traversal macros allowing for multiple readers and a single 
 * writer to operate concurrently. These must be called with the rcu_read_lock held */
#define mpdccp_my_sock(sk)                                                                              \
        ((struct my_sock *)(sk)->sk_user_data)

static inline void
set_mpdccp(struct sock *sk, struct mpdccp_cb *mpcb) {
	dccp_sk(sk)->mpdccp = (struct mpdccp_meta_cb) {
                                .magic = MPDCCP_MAGIC,
                                .mpcb = mpcb,
                                .is_meta = 0 };

}

static inline void
unset_mpdccp(struct sock *sk) {
	dccp_sk(sk)->mpdccp = (struct mpdccp_meta_cb) {
                                .magic = 0 };
}

/* Iterate over all connections */
#define mpdccp_for_each_conn(list, mpcb)                                                                \
    list_for_each_entry_rcu(mpcb, &list, connection_list)


#define chk_id(x,y) (x != y) ? x : 0

/**
 * mpdccp_list_first_or_null_rcu - get the first element from a list
 * @ptr:        the list head to take the element from.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_head within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 *
 * This primitive may safely run concurrently with the _rcu list-mutation
 * primitives such as list_add_rcu() as long as it's guarded by rcu_read_lock().
 */
#define mpdccp_list_first_or_null_rcu(ptr, type, member) \
({ \
    struct list_head *__ptr = (ptr); \
    struct list_head *__next = READ_ONCE(__ptr->next); \
    likely(__ptr != __next) ? list_entry_rcu(__next, type, member)->my_sk_sock : NULL; \
})

/**
 * mpdccp_list_next_or_null_rcu - get the first element from a list
 * @head:   the head for the list.
 * @ptr:        the list head to take the next element from.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_head within the struct.
 *
 * Note that if the ptr is at the end of the list, NULL is returned.
 *
 * This primitive may safely run concurrently with the _rcu list-mutation
 * primitives such as list_add_rcu() as long as it's guarded by rcu_read_lock().
 */
#define mpdccp_list_next_or_null_rcu(head, ptr, type, member) \
({ \
    struct list_head *__head = (head); \
    struct list_head *__ptr = (ptr); \
    struct list_head *__next = READ_ONCE(__ptr->next); \
    likely(__next != __head) ? list_entry_rcu(__next, type, \
                          member)->my_sk_sock : NULL; \
})

/* Iterate over all subflows of a connection */
#define mpdccp_for_each_sk(mpcb, sk)                                                                          \
    for ((sk) = mpdccp_list_first_or_null_rcu(&(mpcb)->psubflow_list, struct my_sock, sk_list);               \
    sk && &mpdccp_my_sock((sk))->sk_list != &((mpcb)->psubflow_list);                                         \
    (sk) = mpdccp_list_next_or_null_rcu(&(mpcb)->psubflow_list, &mpdccp_my_sock((sk))->sk_list, struct my_sock, sk_list)) \

/* Iterate over all listening sockets (server side only) */
#define mpdccp_for_each_listen_sk(mpcb, sk)                                                                   \
    for ((sk) = mpdccp_list_first_or_null_rcu(&(mpcb)->plisten_list, struct my_sock, sk_list);                \
    sk && &mpdccp_my_sock((sk))->sk_list != &((mpcb)->plisten_list);                                          \
    (sk) = mpdccp_list_next_or_null_rcu(&(mpcb)->plisten_list, &mpdccp_my_sock((sk))->sk_list, struct my_sock, sk_list)) \

/* Iterate over all request sockets (client side only) */
#define mpdccp_for_each_request_sk(mpcb, sk)                                                                   \
    for ((sk) = mpdccp_list_first_or_null_rcu(&(mpcb)->prequest_list, struct my_sock, sk_list);                \
    sk && &mpdccp_my_sock((sk))->sk_list != &((mpcb)->prequest_list);                                          \
    (sk) = mpdccp_list_next_or_null_rcu(&(mpcb)->prequest_list, &mpdccp_my_sock((sk))->sk_list, struct my_sock, sk_list)) \

enum mpdccp_role {
    MPDCCP_CLIENT,
    MPDCCP_SERVER,
    MPDCCP_SERVER_SUBFLOW,  /* A server-side subflow socket */
    MPDCCP_MAX_FUNC
};


/* A list of all existing connections */
extern struct list_head __rcu   pconnection_list;
extern spinlock_t               pconnection_list_lock;
/* The MPDCCP work queue */
extern struct workqueue_struct *mpdccp_wq;
/* Target connection information */
struct mpdccp_sched_ops;
struct mpdccp_reorder_ops;
struct mpdccp_reorder_path_cb;
struct mpdccp_pm_ops;

/* This struct holds connection-level (i.e., bundling) information. */
struct mpdccp_cb {
	/* List of MPDCCP end-to-end connections */
	struct list_head        connection_list;
	/* Pointer to list of per-connection subflows */
	struct list_head __rcu  psubflow_list;
	spinlock_t              psubflow_list_lock;
	/* Pointer to list of listening sockets (server side) */
	struct list_head __rcu  plisten_list;
	spinlock_t              plisten_list_lock;
	/* Pointer to list of request sockets (client side) */
	struct list_head __rcu  prequest_list;
	/* Pointer to list of addresses */
	struct list_head __rcu  paddress_list;
	/* kref for freeing */
	struct kref             kref;
	int			to_be_closed;
	
	int     multipath_active;
	
	/* Local and remote connection-level Data Sequence Number (DSN). 
	 * MUST be handled with 48-bit functions. */
	__u64   dsn_local;                      // TAG-0.9: Currently unused
	__u64   dsn_remote;                     // TAG-0.9: Currently unused
	
	/* meta socket */
	struct sock		*meta_sk;
	
	/* Path manager related data */
	struct mpdccp_pm_ops    *pm_ops;
	enum   mpdccp_role      role;               // Is this a client or a server?
	struct sockaddr_storage mpdccp_local_addr;	// Client only: the target address to connect to
	int                     localaddr_len;	// length of mpdccp_remote_addr;
	int			    has_localaddr;
	struct sockaddr_storage mpdccp_remote_addr; // Client only: the target address to connect to
	int                     remaddr_len;	// length of mpdccp_remote_addr;
	u16			    server_port;	// Server only 
	int			    backlog;

	int			up_reported;
	u8 			master_addr_id;
	int  		cnt_remote_addrs;

	/* Scheduler related data */
	struct mpdccp_sched_ops *sched_ops;
	int			    has_own_sched;
	struct sk_buff          *next_skb;      // for schedulers sending the skb on >1 flow
	int    cnt_subflows;                    // Total number of flows we can use
	int    cnt_listensocks;
	bool 	do_incr_oallseq;
	
	/* Reordering related data */
	struct mpdccp_reorder_ops *reorder_ops; 
	void *mpdccp_reorder_cb;                // pointer to cb structure specific to current reordering 
	int			      has_own_reorder;
	u64 glob_lfor_seqno;                    // global sequence number of last forwarded packet
	u64 mp_oall_seqno;

	/* Authentication data */
	struct mpdccp_key 	mpdccp_loc_keys[MPDCCP_MAX_KEYS];
	struct mpdccp_key 	mpdccp_rem_key;
	u8			dkeyA[MPDCCP_MAX_KEY_SIZE * 2];
	u8			dkeyB[MPDCCP_MAX_KEY_SIZE * 2];
	int			dkeylen;
	u32			mpdccp_loc_cix;
	u32			mpdccp_rem_cix;
	int			kex_done;
	u8			mpdccp_suppkeys;
	int			cur_key_idx;
	int			fallback_sp;

	int			close_fast;
	/* First subflow socket */
	struct sock*		master_sk;

	/* Namespace info */
	possible_net_t		net;
};

/* This struct holds subflow-level information. */
struct my_sock 
{
	/* List of per-connection subflows OR listening sockets (server side only) */
	struct list_head        sk_list;
	
	/* A pointer back to the sock this belongs to */
	struct sock             *my_sk_sock;
	struct mpdccp_cb        *mpcb;
	
	/* send|recv work. TODO: not sure if i need dynamic memory here to re-queue that work. */
	struct delayed_work     close_work;
	struct mpdccp_link_info	*link_info;
	int			link_cnt;
	int			link_iscpy;
	int			up_reported;
	
	/* Address ID related data */
	u8 local_addr_id;
	u8 remote_addr_id;
	
	/* Path manager related data */
	int     if_idx; /* Interface ID, used for event handling */

/* following data is used for sending options*/

	/* send mp_prio option with next packet:*/
	u8  announce_prio;
	bool prio_rcvrd;
	/* prio was changed with this sequence number */
	u64 last_prio_seq;

	u8 delpath_id;
	bool delpath_sent;

	/* addpath[0] is used for the length of the option */
	u8 addpath[MPDCCP_ADDADDR_SIZE];
	u8 addpath_hmac[MPDCCP_HMAC_SIZE];

	u64 last_addpath_seq;

	/* temporary memory for received options that require sending a confirm as response  */
	u8 cnf_cache[MPDCCP_CONFIRM_SIZE];
	u8 cnf_cache_len;

	/* temporary memory for resending unconfirmed options, biggest possible option is MP_ADDADDR */
	u8 reins_cache[MPDCCP_ADDADDR_SIZE];

	/* Scheduler related data */
	/* Limit in Bytes. Dont forget to adjust when increasing the
	 * size of any scheduler's priv data struct*/
	#define MPDCCP_SCHED_SIZE 64
	__u8 sched_priv[MPDCCP_SCHED_SIZE] __aligned(8);
	
	/* Used to store the original, unmodified callbacks from 
	 * struct sock. Additional function pointers available in struct sock:
	 * void            (*sk_write_space)(struct sock *sk);
	 * void            (*sk_error_report)(struct sock *sk);
	 */
	void            (*sk_write_space)(struct sock *sk);
	void            (*sk_state_change)(struct sock *sk);
	void            (*sk_data_ready)(struct sock *sk);
	int             (*sk_backlog_rcv)(struct sock *sk, 
	                    struct sk_buff *skb);
	void            (*sk_destruct)(struct sock *sk);
	
	/* Reordering related data */
	struct mpdccp_reorder_path_cb *pcb;

	/* Close in progress flag */
	int	closing;
	int saw_mp_close;
};


/* 
 * protocol functions
 */

int mpdccp_init_funcs (void);
int mpdccp_deinit_funcs (void);

int mpdccp_report_new_subflow (struct sock*);
int mpdccp_report_destroy (struct sock*);
int mpdccp_report_alldown (struct sock*);


int mpdccp_add_client_conn (struct mpdccp_cb *, struct sockaddr *local, int llen, int if_idx, struct sockaddr *rem, int rlen);
int mpdccp_reconnect_client (struct sock*, int destroy, struct sockaddr*, int addrlen, int ifidx);
int mpdccp_add_listen_sock (struct mpdccp_cb *, struct sockaddr *local, int llen, int if_idx);
int mpdccp_close_subflow (struct mpdccp_cb*, struct sock*, int destroy);
struct sock *mpdccp_select_ann_sock(struct mpdccp_cb *mpcb, u8 id);

struct mpdccp_cb *mpdccp_alloc_mpcb(void);

int mpdccp_destroy_mpcb(struct mpdccp_cb *mpcb);

struct mpdccp_link_info;
int mpdccp_ctrl_maycpylink (struct sock *sk);
struct mpdccp_link_info* mpdccp_ctrl_getlink (struct sock *sk);
struct mpdccp_link_info* mpdccp_ctrl_getcpylink (struct sock *sk);
int mpdccp_ctrl_has_cfgchg (struct sock *sk);
void mpdccp_ctrl_cfgupdate (struct sock *sk);

int mpdccp_forward_skb(struct sk_buff *skb, struct mpdccp_cb *mpcb);

/*
 * Generic MPDCCP functions
 */

/* Generic MPDCCP data structure management functions */
int my_sock_init (struct sock *sk, struct mpdccp_cb *mpcb, int if_idx, enum mpdccp_role role);
void my_sock_destruct (struct sock *sk);
/* the real xmit */
int mpdccp_xmit_to_sk (struct sock *sk, struct sk_buff *skb);

void mpdccp_init_announce_prio(struct sock *sk);
int mpdccp_get_prio(struct sock *sk);
int mpdccp_link_cpy_set_prio(struct sock *sk, int prio);

/* Functions for authentication */
int mpdccp_hash_key(const u8 *in, u8 inlen, u32 *token);
int mpdccp_hmac_sha256(const u8 *key, u8 keylen, const u8 *msg, u8 msglen, u8 *output);
int mpdccp_generate_key(struct mpdccp_key *key, int key_type);

static inline struct mpdccp_cb *get_mpcb(const struct sock *sk)
{
	return MPDCCP_CB(sk);
}

static inline struct sock *mpdccp_getmeta (const struct sock *sk)
{
	struct mpdccp_cb *mpcb = MPDCCP_CB(sk);
	return mpcb ? mpcb->meta_sk : NULL;
}

// Inverse function to dccp_sk()
static inline struct sock *dccp_sk_inv(const struct dccp_sock *dp)
{
	return (struct sock *)dp;
}

static inline u8 get_id(struct sock *sk)
{
    return chk_id(mpdccp_my_sock(sk)->local_addr_id, mpdccp_my_sock(sk)->mpcb->master_addr_id);
}

static inline void mpdccp_set_accept_prio(int val) { mpdccp_accept_prio = val; }

#endif /* _MPDCCP_H */

