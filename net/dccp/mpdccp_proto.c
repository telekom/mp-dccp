/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 * 
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
#include "feat.h"
#include "mpdccp.h"
#include "mpdccp_scheduler.h"
#include "mpdccp_reordering.h"
#include "mpdccp_pm.h"

static int do_mpdccp_write_xmit (struct sock*, struct sk_buff*);

static
int
_mpdccp_mk_meta_sk (
	struct sock	*sk)
{
	struct dccp_sock		*dp = dccp_sk(sk);

	if (!sk) return -EINVAL;
	if (mpdccp_is_meta (sk)) return 0;
	dp->mpdccp = (struct mpdccp_meta_cb) {
			.magic = MPDCCP_MAGIC,
			.is_meta = 1 };
	dp->mpdccp.mpcb = mpdccp_alloc_mpcb ();
	if (!dp->mpdccp.mpcb) return -ENOBUFS;
	dp->mpdccp.mpcb->meta_sk = sk;
	mpdccp_pr_debug ("meta socket created\n");

	return 0;
}

static
int
_mpdccp_activate (
	struct sock	*sk,
	int		on)
{
	if (!sk) return -EINVAL;
	mpdccp_pr_debug("activate mpdccp on socket\n");

	if (on) {
		dccp_sk(sk)->mpdccp = (struct mpdccp_meta_cb) {
								.magic = MPDCCP_MAGIC,
								.mpcb = NULL,
								.is_meta = 0};
	} else {
		dccp_sk(sk)->mpdccp = (struct mpdccp_meta_cb) {
								.magic = 0,
								.mpcb = NULL,
								.is_meta = 0};
	}
	dccp_sk(sk)->multipath_active = on;
	return 0;
}

static
int
_mpdccp_isactive (
	const struct sock	*sk)
{
	return dccp_sk(sk)->multipath_active;
}


static
int
_mpdccp_xmit_skb (
	struct sock	*sk,
	struct sk_buff	*skb)
{
	int	ret;
	long	timeo;

	if (!sk || !skb) return -EINVAL;
	if (!mpdccp_is_meta (sk)) return -EINVAL;
	rcu_read_lock();
	bh_lock_sock(sk);
	if (dccp_qpolicy_full(sk)) {
		bh_unlock_sock(sk);
		rcu_read_unlock();
		return -EAGAIN;
	}

	/* Wait for a connection to finish. */
	timeo = sock_sndtimeo(sk, 1);
	if ((1 << sk->sk_state) & ~(DCCPF_OPEN | DCCPF_PARTOPEN)) {
		if ((ret = sk_stream_wait_connect(sk, &timeo)) != 0) {
			bh_unlock_sock(sk);
			rcu_read_unlock();
			return -EAGAIN;
		}
	}

	skb_set_owner_w(skb, sk);
	dccp_qpolicy_push(sk, skb);
	if (!timer_pending(&dccp_sk(sk)->dccps_xmit_timer)) {
		mpdccp_write_xmit(sk);
	}
	bh_unlock_sock(sk);
	rcu_read_unlock ();
	return 0;
}

static
int
_mpdccp_write_xmit (
	struct sock	*meta_sk)
{
	struct sk_buff		*skb;
	int			ret2=0, ret;

	if (!mpdccp_is_meta(meta_sk)) return -EINVAL;
	while ((skb = dccp_qpolicy_top(meta_sk))) {
		ret = do_mpdccp_write_xmit (meta_sk, skb);
		if (ret == -EAGAIN) {
			sk_reset_timer(meta_sk, &dccp_sk(meta_sk)->dccps_xmit_timer,
				       jiffies + 1);
			return ret;
		} else if (ret < 0) {
			dccp_qpolicy_drop (meta_sk, skb);
			//mpdccp_pr_debug ("packet drop due to error in xmit: %d", ret);
			printk ("packet drop due to error in xmit: %d", ret);
			ret2 = ret;
		}
	}
	return ret2;
}

static
int
do_mpdccp_write_xmit (
	struct sock	*meta_sk,
	struct sk_buff	*skb)
{
	struct mpdccp_cb	*mpcb;
	struct sock		*sk;

	if (!skb) return -EINVAL;
	mpcb = MPDCCP_CB(meta_sk);
	if (!mpcb) return -EINVAL;

	sk = mpcb->sched_ops->get_subflow(mpcb);
	if (!sk) {
		return -EAGAIN;
	}
	return mpdccp_xmit_to_sk (sk, skb);
}

static int do_mpdccp_setsockopt(struct sock *sk, int level, int optname,
		char __user *optval, unsigned int optlen)
{
	int				err = 0;
	struct sock			*subsk;
	struct mpdccp_cb		*mpcb;
	struct mpdccp_sched_ops		*sched;
	char				*val;
	struct mpdccp_reorder_ops	*reorder;

        rcu_read_lock();
	lock_sock(sk);
	mpcb = MPDCCP_CB(sk);
	if (level == SOL_DCCP) {
		/* handle multipath socket options */
		switch (optname) {
		case DCCP_SOCKOPT_MP_REORDER:
			val = memdup_user(optval, optlen);
			if (IS_ERR(val)) {
				err = PTR_ERR(val);
				goto out_release;
			}
			reorder = mpdccp_reorder_find(val);
			kfree (val);
			if(!reorder){
				err = -ENOENT;
				mpdccp_pr_debug("Reordering engine not found.\n");
				goto out_release;
			}
			mpcb->reorder_ops = reorder;
			mpcb->mpdccp_reorder_cb = NULL;
			mpcb->has_own_reorder = 1;
			mpcb->reorder_ops->init(mpcb);
			goto out_release;
		case DCCP_SOCKOPT_MP_SCHEDULER:
			val = memdup_user(optval, optlen);
			if (IS_ERR(val)) {
				err = PTR_ERR(val);
				goto out_release;
			}
			sched = mpdccp_sched_find(val);
			kfree (val);
			if (!sched){
				err = -ENOENT;
				mpdccp_pr_debug("Scheduler not found.\n");
				goto out_release;
			}
			mpcb->sched_ops = sched;
			mpcb->has_own_sched = 1;
			if (sched->init_conn)
				sched->init_conn(mpcb);
			goto out_release;
		}
	}
	/* pass to all subflows */
	mpcb = MPDCCP_CB (sk);
	mpdccp_for_each_sk (mpcb, subsk) {
		err = dccp_setsockopt (subsk, level, optname, optval, optlen);
		if (err) goto out_release;
	}
out_release:
	release_sock (sk);
	rcu_read_unlock();
	return err;
}


int mpdccp_setsockopt(struct sock *sk, int level, int optname,
		    char __user *optval, unsigned int optlen)
{
	int	ret;

	if (level != SOL_DCCP) {
		ret = inet_csk(sk)->icsk_af_ops->setsockopt(sk, level,
							     optname, optval,
							     optlen);
		if (ret) return ret;
	}
	return do_mpdccp_setsockopt(sk, level, optname, optval, optlen);
}
EXPORT_SYMBOL(mpdccp_setsockopt);


static int do_mpdccp_getsockopt(struct sock *sk, int level, int optname,
		    char __user *optval, int __user *optlen)
{
	int			len, err=0;
	struct mpdccp_cb	*mpcb;
	struct sock		*subsk;
	char			*val;

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < (int)sizeof(int))
		return -EINVAL;

	mpcb = MPDCCP_CB (sk);
	if (!mpcb) return -EINVAL;
	switch (optname) {
	case DCCP_SOCKOPT_MP_REORDER:
		val = mpcb->reorder_ops->name;
		len = strlen (val);
		if (put_user(len+1, optlen) ||
				copy_to_user(optval, val, len+1)) {
			return -EFAULT;
		}
		break;
	case DCCP_SOCKOPT_MP_SCHEDULER:
		val = mpcb->sched_ops->name;
		len = strlen (val);
		if (put_user(len+1, optlen) ||
				copy_to_user(optval, val, len+1)) {
			return -EFAULT;
		}
		break;
	default:
    		mpdccp_for_each_sk (mpcb, subsk) {
			err = dccp_getsockopt (subsk, level, optname, optval, optlen);
			/* just get the first subflow */
			break;
		}
	}
	return err;
}

int mpdccp_getsockopt(struct sock *sk, int level, int optname,
		    char __user *optval, int __user *optlen)
{
	if (level != SOL_DCCP)
		return inet_csk(sk)->icsk_af_ops->getsockopt(sk, level,
							     optname, optval,
							     optlen);
	return do_mpdccp_getsockopt(sk, level, optname, optval, optlen);
}
EXPORT_SYMBOL(mpdccp_getsockopt);


static
int
_mpdccp_connect (
	struct sock		*meta_sk, 
	const struct sockaddr	*addr,
	int			addrlen)
{
	char			pm_name[MPDCCP_PM_NAME_MAX];
	struct mpdccp_pm_ops	*pm;
	struct mpdccp_cb	*mpcb;
	int			ret;

	ret = _mpdccp_mk_meta_sk(meta_sk);
	if (ret < 0) {
		mpdccp_pr_debug ("error creating meta\n");
		return ret;
	}

	if (!mpdccp_is_meta(meta_sk)) return -EINVAL;
	mpcb = MPDCCP_CB(meta_sk);
	if (!mpcb) return -EINVAL;

	mpcb->role = MPDCCP_CLIENT;

	/* Save the meta socket namespace info */
	write_pnet(&mpcb->net, sock_net(meta_sk));

	mpcb->glob_lfor_seqno = GLOB_SEQNO_INIT;
	mpcb->mp_oall_seqno = GLOB_SEQNO_INIT;
	
	mpdccp_get_default_path_manager(pm_name);
	pm = mpdccp_pm_find(pm_name);
	if(!pm){
		mpdccp_pr_debug("Path manager not found.");
		return -ENOENT;
	}
	ret = pm->add_init_client_conn (mpcb, (struct sockaddr*)addr, addrlen);
	if (ret < 0) {
		mpdccp_pr_debug("Failed to set up MPDCCP Client mpcb: %d\n", ret);
		return ret;
	}
	
	return 0;
}



static
int
_mpdccp_destroy_sock (
	struct sock	*sk)
{
	struct mpdccp_meta_sk	*meta_sk;
	struct mpdccp_cb	*mpcb;

	if (!mpdccp_is_meta(sk)) return -EINVAL;
	meta_sk = sk->sk_user_data;
	sk->sk_user_data = 0;
	mpcb = MPDCCP_CB(sk);
	if (mpcb) mpdccp_destroy_mpcb (mpcb);
	if (meta_sk) kfree (meta_sk);
	unset_mpdccp(sk);
	return 0;
}


int
mpdccp_report_destroy (
	struct sock	*sk)
{
	return mpdccp_report_subflow (sk, MPDCCP_SUBFLOW_DESTROY);
}
EXPORT_SYMBOL(mpdccp_report_destroy);


int
mpdccp_report_new_subflow (
	struct sock	*sk)
{
	return mpdccp_report_subflow (sk, MPDCCP_SUBFLOW_CREATE);
}
EXPORT_SYMBOL(mpdccp_report_new_subflow);


int
mpdccp_report_subflow (
	struct sock	*sk,
	int		action)
{
	struct sock		*meta_sk;
	struct mpdccp_cb	*mpcb;
	struct my_sock		*my_sk;
	struct mpdccp_link_info	*link;

	if (!sk) return -EINVAL;
	if (mpdccp_is_meta(sk)) return 0;
	mpcb = get_mpcb (sk);
	if (!mpcb) return -EINVAL;
	meta_sk = mpcb->meta_sk;
	if (!meta_sk) return -EINVAL;
	my_sk = mpdccp_my_sock(sk);
	if (!my_sk) return -EINVAL;
	rcu_read_lock();
	link = my_sk->link_info;
	mpdccp_link_get (link);
	rcu_read_unlock();
	if (mpcb->report_subflow) {
		mpcb->report_subflow (action, meta_sk, sk, link, mpcb->role);
	}
	rcu_read_lock();
	mpdccp_link_put (link);
	rcu_read_unlock();
	return 0;
}
EXPORT_SYMBOL(mpdccp_report_subflow);


static
int
_mpdccp_set_subflow_report (
	struct sock	*sk,
	void 		(*report_subflow) (int, struct sock*, struct sock*, struct mpdccp_link_info*, int))
{
	struct mpdccp_cb	*mpcb;

	if (!mpdccp_is_meta(sk)) return -EINVAL;
	mpcb = MPDCCP_CB(sk);
	if (!mpcb) return -EINVAL;
	mpcb->report_subflow = report_subflow;
	return 0;
}

/* From mptcp_hmac_sha1@mptcp_ctrl.c */
void mpdccp_hmac_sha1(const u8 *key_1, const u8 *key_2, u32 *hash_out, int arg_num, ...)
{
	u32 workspace[SHA_WORKSPACE_WORDS];
	u8 input[128]; /* 2 512-bit blocks */
	int i;
	int index;
	int length;
	u8 *msg;
	va_list list;

	memset(workspace, 0, sizeof(workspace));

	/* Generate key xored with ipad */
	memset(input, 0x36, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	va_start(list, arg_num);
	index = 64;
	for (i = 0; i < arg_num; i++) {
		length = va_arg(list, int);
		msg = va_arg(list, u8 *);
		BUG_ON(index + length > 125); /* Message is too long */
		memcpy(&input[index], msg, length);
		index += length;
	}
	va_end(list);

	input[index] = 0x80; /* Padding: First bit after message = 1 */
	memset(&input[index + 1], 0, (126 - index));

	/* Padding: Length of the message = 512 + message length (bits) */
	input[126] = 0x02;
	input[127] = ((index - 64) * 8); /* Message length (bits) */

	sha_init(hash_out);
	sha_transform(hash_out, input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, &input[64], workspace);
	memset(workspace, 0, sizeof(workspace));

	for (i = 0; i < 5; i++)
		hash_out[i] = cpu_to_be32(hash_out[i]);

	/* Prepare second part of hmac */
	memset(input, 0x5C, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	memcpy(&input[64], hash_out, 20);
	input[84] = 0x80;
	memset(&input[85], 0, 41);

	/* Padding: Length of the message = 512 + 160 bits */
	input[126] = 0x02;
	input[127] = 0xA0;

	sha_init(hash_out);
	sha_transform(hash_out, input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, &input[64], workspace);

	for (i = 0; i < 5; i++)
		hash_out[i] = cpu_to_be32(hash_out[i]);
}

static int mpdccp_generate_key(struct mpdccp_key *key, int key_type)
{
	__u64 temp;
	int ret;
	switch (key_type) {
		case DCCPK_PLAIN:
			key->type = key_type;
			key->size = MPDCCP_PLAIN_KEY_SIZE;
			get_random_bytes(&temp, MPDCCP_PLAIN_KEY_SIZE);
			memcpy(key->value, &temp, MPDCCP_PLAIN_KEY_SIZE);
			ret = 0;
			break;
		case DCCPK_C25519_SHA256:
		case DCCPK_C25519_SHA512:
			/* TODO: add support */
			key->size = 0;
			ret = -1;
			break;
		default:
			mpdccp_pr_debug("cannot generate key of type %d", key_type);
			key->size = 0;
			ret = -1;
	}
	mpdccp_pr_debug("generated key %llx type %d", be64_to_cpu(*((__be64 *)key->value)), key->type);
	return ret;
}

static int _mpdccp_conn_request(struct sock *sk, struct dccp_request_sock *dreq)
{
	struct dccp_sock *dp = dccp_sk(sk);
	struct dccp_options_received *opt_recv = &dp->dccps_options_received;

	u8 msg[8];
	mpdccp_pr_debug("enter for sk %p saw_mpkey %d dmeta %p", sk, opt_recv->saw_mpkey, dreq->meta_sk);

	if (opt_recv->saw_mpkey) {
		/* MP_KEY was in the options: we are in the key exchange phase */
		int key_type;
		dreq->meta_sk = NULL;

		if (opt_recv->dccpor_mp_vers != MPDCCP_VERSION_NUM) {
			mpdccp_pr_debug("version mismatch srv: %d cli: %d", MPDCCP_VERSION_NUM, opt_recv->dccpor_mp_vers);
			return -1;
		}

		/* TODO: replace with proper crypto select algo */
		key_type = ffs(opt_recv->dccpor_mp_suppkeys & MPDCCP_SUPPKEYS) - 1;
		if (key_type < 0) {
			mpdccp_pr_debug("no key support type match srv: %x cli: %x", MPDCCP_SUPPKEYS, opt_recv->dccpor_mp_suppkeys);
			return -1;
		}

		/* Generate local key for handshake */
		/* TODO: check for collisions in existing MPCBs */
		if (mpdccp_generate_key(&dreq->mpdccp_loc_key, key_type)) {
			mpdccp_pr_debug("error generating key of type %d", key_type);
			return -1;
		}
	} else {
		/* No MP_KEY: this is a join */
		struct sock *meta_sk = NULL;
		struct mpdccp_cb *mpcb;

		if ((opt_recv->dccpor_mp_token == 0) || (opt_recv->dccpor_mp_nonce == 0)) {
			mpdccp_pr_debug("invalid token or nonce received");
			return -1;
		}
		dreq->mpdccp_rem_nonce = opt_recv->dccpor_mp_nonce;
		dreq->mpdccp_rem_token = opt_recv->dccpor_mp_token;

		/* Lookup the token in existing MPCBs */
		mpdccp_for_each_conn(pconnection_list, mpcb) {
			if (mpcb->mpdccp_loc_token == dreq->mpdccp_rem_token) {
				meta_sk = mpcb->meta_sk;
				mpdccp_pr_debug("found token in mpcb %p\n", mpcb);
				break;
			}
		}

		if (meta_sk == NULL) {
			mpdccp_pr_debug("no token found for join");
			return -1;
		}

		mpcb = MPDCCP_CB(meta_sk);

		/* Hold a reference to the meta socket (will be released in req destructor) */
		sock_hold(meta_sk);
		dreq->meta_sk = meta_sk;

		/* Generate local nonce */
		get_random_bytes(&dreq->mpdccp_loc_nonce, 4);
		mpdccp_pr_debug("generated nonce %x", dreq->mpdccp_loc_nonce);

		/* Calculate HMAC */
		put_unaligned_be32(mpcb->mpdccp_loc_token, &msg[0]);
		put_unaligned_be32(dreq->mpdccp_rem_nonce, &msg[4]);
		mpdccp_hmac_sha1((u8 *)mpcb->mpdccp_loc_key.value,
						 (u8 *)mpcb->mpdccp_rem_key.value,
						 (u32 *)dreq->mpdccp_loc_hmac, 1,
						 8, msg);

		mpdccp_pr_debug("calculated HMAC %llx", be64_to_cpu(*((u64 *)dreq->mpdccp_loc_hmac)));
	}
	return 0;
}
static int _mpdccp_rcv_request_sent_state_process(struct sock *sk, const struct sk_buff *skb)
{
	struct mpdccp_cb *mpcb;
	struct dccp_sock *dp = dccp_sk(sk);
	struct dccp_options_received *opt_recv = &dp->dccps_options_received;

	mpdccp_pr_debug("enter for sk %p is_meta %d", sk, mpdccp_is_meta(sk));

	if (dccp_sk(sk)->is_kex_sk) {
		/* We are in key exchange phase: process data from MP_KEY option */
		int key_type;
		mpcb = MPDCCP_CB(sk);

		/* Check if key type proposed is supported */
		key_type = ffs(opt_recv->dccpor_mp_suppkeys & MPDCCP_SUPPKEYS) - 1;
		if (key_type < 0) {
			mpdccp_pr_debug("no key type match srv: %x cli: %x", opt_recv->dccpor_mp_suppkeys, MPDCCP_SUPPKEYS);
			return -1;
		}

		/* Store remote key */
		if (opt_recv->dccpor_mp_keys[0].type != key_type) {
			mpdccp_pr_debug("rx key not the expected type rx: %d exp: %d", opt_recv->dccpor_mp_keys[0].type, key_type);
			return -1;
		}
		if ((opt_recv->dccpor_mp_keys[0].size == 0) || (opt_recv->dccpor_mp_keys[0].size > MPDCCP_MAX_KEY_SIZE)) {
			mpdccp_pr_debug("rx key(s) have invalid length %d", opt_recv->dccpor_mp_keys[0].size);
			return -1;
		}

		mpcb->mpdccp_rem_key.type = opt_recv->dccpor_mp_keys[0].type;
		mpcb->mpdccp_rem_key.size = opt_recv->dccpor_mp_keys[0].size;
		memcpy(mpcb->mpdccp_rem_key.value, opt_recv->dccpor_mp_keys[0].value, mpcb->mpdccp_rem_key.size);

		/* Generate local key for handshake */
		/* TODO: check for collisions in existing MPCBs */
		if (mpdccp_generate_key(&mpcb->mpdccp_loc_key, key_type)) {
			mpdccp_pr_debug("error generating key of type %d", key_type);
			return -1;
		}

		/* On client side the key exchange is done */
		mpcb->kex_done = 1;
	} else {
		/* We are in authentication phase: process data from MP_JOIN option */
		u8 hash_mac[MPDCCP_HMAC_SIZE];
		u8 msg[8];

		mpcb = MPDCCP_CB(sk);
		if ((opt_recv->dccpor_mp_token == 0) || (opt_recv->dccpor_mp_nonce == 0)) {
			mpdccp_pr_debug("invalid token or nonce received");
			return -1;
		}
		dccp_sk(sk)->mpdccp_rem_nonce = opt_recv->dccpor_mp_nonce;
		mpcb->mpdccp_rem_token = opt_recv->dccpor_mp_token;

		/* Validate HMAC from srv */
		memcpy(dccp_sk(sk)->mpdccp_rem_hmac, opt_recv->dccpor_mp_hmac, MPDCCP_HMAC_SIZE);
		put_unaligned_be32(mpcb->mpdccp_rem_token, &msg[0]);
		put_unaligned_be32(dccp_sk(sk)->mpdccp_loc_nonce, &msg[4]);
		mpdccp_hmac_sha1((u8 *)mpcb->mpdccp_rem_key.value,
						 (u8 *)mpcb->mpdccp_loc_key.value,
						 (u32 *)hash_mac, 1,
						 8, msg);
		mpdccp_pr_debug("calculated HMAC(B) %llx", be64_to_cpu(*((u64 *)hash_mac)));

		if (memcmp(dccp_sk(sk)->mpdccp_rem_hmac, hash_mac, MPDCCP_HMAC_SIZE)) {
			mpdccp_pr_debug("HMAC validation failed! rx: %llx exp: %llx",
							be64_to_cpu(*(u64 *)dccp_sk(sk)->mpdccp_rem_hmac),
							be64_to_cpu(*((u64 *)hash_mac)));
			return -1;
		}
		mpdccp_pr_debug("HMAC validation OK");

		/* Now calculate the HMAC from the received JOIN */
		put_unaligned_be32(mpcb->mpdccp_rem_token, &msg[0]);
		put_unaligned_be32(dccp_sk(sk)->mpdccp_rem_nonce, &msg[4]);
		mpdccp_hmac_sha1((u8 *)mpcb->mpdccp_loc_key.value,
						 (u8 *)mpcb->mpdccp_rem_key.value,
						 (u32 *)dccp_sk(sk)->mpdccp_loc_hmac, 1,
						 8, msg);
		mpdccp_pr_debug("calculated HMAC(A) %llx", be64_to_cpu(*((u64 *)dccp_sk(sk)->mpdccp_loc_hmac)));
	}
	return 0;
}

static int _mpdccp_rcv_established(struct sock *sk)
{
	/* Check if the socket has been authenticated */
	if(!dccp_sk(sk)->auth_done) {
		mpdccp_pr_debug("sk %p NOT authenticated \n", sk);
		return -1;
	}
	return 0;
}

static int _mpdccp_rcv_respond_partopen_state_process(struct sock *sk, int type)
{
	struct mpdccp_cb *mpcb = MPDCCP_CB(sk);
	mpdccp_pr_debug("enter for sk %p role %s is_meta %d is_kex %d type %d", sk, dccp_role(sk), mpdccp_is_meta(sk), dccp_sk(sk)->is_kex_sk, type);

	if (type == DCCP_PKT_ACK || type == DCCP_PKT_DATAACK ) {
		if (dccp_sk(sk)->is_kex_sk && !mpcb->kex_done) {
			mpdccp_pr_debug("key exchange done for mpcb %p\n", mpcb); 
			mpcb->kex_done = 1;
			/* No longer need to include the MP_KEY in the options */
			dccp_sk(sk)->is_kex_sk = 0;
		}

		/* Authentication complete, send an additional ACK if required */
		dccp_sk(sk)->auth_done = 1;
		if (dccp_sk(sk)->need_hmac_ack) {
			mpdccp_pr_debug("send ACK");
			dccp_send_ack(sk);
			dccp_sk(sk)->need_hmac_ack = 0;
		}
	}

	/* Open the meta socket if necessary */
	if ((sk->sk_state == DCCP_OPEN) && (mpcb->meta_sk->sk_state == DCCP_RESPOND)) {
		mpdccp_pr_debug("opening meta %p\n", mpcb->meta_sk);
		mpcb->meta_sk->sk_state = DCCP_OPEN;
	}

	return 0;
}


static int
create_subflow(
	struct sock *sk,
	struct sock *meta_sk,
	struct sk_buff *skb,
	struct request_sock *req,
	int clone)
{
	int ret;
	struct sock *newsk;
	struct mpdccp_cb *mpcb = MPDCCP_CB(meta_sk);
	struct mpdccp_link_info *link_info = NULL;
	struct dccp_request_sock *dreq = dccp_rsk(req);

	mpdccp_pr_debug("enter sk %p meta %p req %p clone %d\n", sk, meta_sk, req, clone);
	if (clone) {
		bool own;
		/* Use the dccp request flow to create a clone of the meta socket */
		newsk = dccp_v4_request_recv_sock(sk, skb, req, NULL, inet_reqsk(meta_sk), &own);
		if (!newsk) {
			mpdccp_pr_debug("error calling dccp_v4_request_recv_sock sk %p meta %p\n", sk, meta_sk);
			goto err;
		}
		/* Activate the features on the new socket as in the request */
		if (dccp_feat_activate_values(newsk, &dreq->dreq_featneg_mp)) {
			mpdccp_pr_debug("error calling dccp_feat_activate_values for sk %p\n", newsk);
			inet_csk_prepare_forced_close(newsk);
			dccp_done(newsk);
			goto err;
		}
		mpdccp_pr_debug("cloned socket sk %p meta %p newsk %p\n", sk, meta_sk, newsk);
	} else {
		/* For a join we don't need to clone the socket */
		newsk = sk;
		mpdccp_pr_debug("not cloned socket sk %p meta %p newsk %p\n", sk, meta_sk, newsk);
	}

	if (dreq->link_info) {
		link_info = dreq->link_info;
		mpdccp_link_get(link_info);
	} else {
		link_info = mpdccp_getfallbacklink(&init_net);
	}

	set_mpdccp(newsk, mpcb);

	mpdccp_pr_debug("mysock new: %p\n", mpdccp_my_sock(newsk));

	ret = my_sock_init(newsk, mpcb, sk->sk_bound_dev_if, MPDCCP_SERVER_SUBFLOW);
	if (ret < 0) {
		mpdccp_pr_debug("my_sock_init for sk %p failed with exit code %d.\n", newsk, ret);
		if (clone) {
			inet_csk_prepare_forced_close(newsk);
			dccp_done(newsk);
		}
		goto err;
	}

	mpcb->cnt_subflows = (mpcb->cnt_subflows) + 1;

	mpdccp_my_sock(newsk)->link_info = link_info;
	mpdccp_my_sock(newsk)->link_cnt = mpdccp_link_cnt(link_info);
	mpdccp_my_sock(newsk)->link_iscpy = 0;

	spin_lock(&mpcb->psubflow_list_lock);
	list_add_tail_rcu(&mpdccp_my_sock(newsk)->sk_list, &mpcb->psubflow_list);
	mpdccp_pr_debug("Added new entry to psubflow_list @ %p\n", mpdccp_my_sock(newsk));
	spin_unlock(&mpcb->psubflow_list_lock);

	if (mpcb->sched_ops->init_subflow)
		mpcb->sched_ops->init_subflow(newsk);

	mpdccp_pr_debug("Connection accepted. There are %d subflows now newsk. %p\n",
					mpcb->cnt_subflows, newsk);

	if (clone) {
		bh_unlock_sock(meta_sk);
	}
	mpcb->master_sk = newsk;
	return 0;
err:
	return -ENOBUFS;
}

static int
_mpdccp_create_master(
	struct sock *sk,
	struct sock *child,
	struct request_sock *req,
	struct sk_buff *skb)
{
	int ret;
	struct sock *meta_sk;
	struct mpdccp_cb *mpcb;
	struct sockaddr_in sin;
	struct inet_sock *inet = inet_sk(child);
	struct dccp_request_sock *dreq = dccp_rsk(req);

	mpdccp_pr_debug("enter for sk %p child %p dreq %p\n", sk, child, dreq);

	/* Allocate mpcb and meta socket data */
	ret = _mpdccp_mk_meta_sk(child);
	if (ret < 0) {
		mpdccp_pr_debug("error creating meta for sk %p\n", child);
		goto err_meta;
	}

	/* Populate mpcb */
	meta_sk = child;
	mpcb = MPDCCP_CB(meta_sk);
	sin.sin_family = AF_INET;
	sin.sin_port = inet->inet_sport;
	sin.sin_addr.s_addr = inet->inet_saddr;
	memcpy(&mpcb->mpdccp_local_addr, &sin, sizeof(struct sockaddr_in));
	mpcb->localaddr_len = sizeof(struct sockaddr_in);
	mpcb->has_localaddr = 1;
	mpcb->mpdccp_loc_token = dreq->mpdccp_loc_token;
	mpcb->mpdccp_rem_token = dreq->mpdccp_rem_token;
	mpcb->mpdccp_loc_key = dreq->mpdccp_loc_key;
	mpcb->mpdccp_rem_key = dreq->mpdccp_rem_key;
	mpcb->role = MPDCCP_SERVER;

	/* Create subflow and meta sockets */
	ret = create_subflow(sk, meta_sk, skb, req, 1);
	if (ret < 0) {
		mpdccp_pr_debug("error creating subflow %d\n", ret);
		goto err_sub;
	}

	return 0;
err_sub:
	mpdccp_destroy_mpcb(mpcb);
err_meta:
	return ret;
}


/* We get here on the server side at final stage of the handshake to validate the client request */
static int _mpdccp_check_req(struct sock *sk, struct sock *newsk, struct request_sock *req, struct sk_buff *skb, struct sock **master_sk)
{
	struct mpdccp_cb *mpcb;
	struct dccp_sock *dp = dccp_sk(newsk);
	struct dccp_options_received *opt_recv = &dp->dccps_options_received;
	struct dccp_request_sock *dreq = dccp_rsk(req);
	int ret;

	mpdccp_pr_debug("enter sk %p newsk %p dmeta %p", sk, newsk, dreq->meta_sk);

	if (!dreq->meta_sk && !mpdccp_is_meta(newsk)) {
		/* This is a new session, need to create MPCB and meta */
		u32 token;

		/* Validate the data from the options */
		if (opt_recv->dccpor_mp_keys[0].type != dreq->mpdccp_loc_key.type) {
			mpdccp_pr_debug("received key not the expected type rx: %d exp: %d",
								opt_recv->dccpor_mp_keys[0].type, dreq->mpdccp_loc_key.type);
			return -1;
		}
		if ((opt_recv->dccpor_mp_keys[0].size == 0) || (opt_recv->dccpor_mp_keys[0].size > MPDCCP_MAX_KEY_SIZE)) {
			mpdccp_pr_debug("received key has invalid length");
			return -1;
		}

		/* Get the client key */
		dreq->mpdccp_rem_key.type = opt_recv->dccpor_mp_keys[0].type;
		dreq->mpdccp_rem_key.size = opt_recv->dccpor_mp_keys[0].size;
		memcpy(dreq->mpdccp_rem_key.value, opt_recv->dccpor_mp_keys[0].value,
			   dreq->mpdccp_rem_key.size);

		mpdccp_pr_debug("key exchange done, creating meta socket");

		/* Calculate the path tokens */
		dccp_sk(newsk)->is_kex_sk = 0;

		mpdccp_key_sha1(*(u64 *)dreq->mpdccp_loc_key.value,
						*(u64 *)dreq->mpdccp_rem_key.value, &token);
		dreq->mpdccp_loc_token = token;
		mpdccp_pr_debug("token(B) %x", token);
		mpdccp_key_sha1(*(u64 *)dreq->mpdccp_rem_key.value,
						*(u64 *)dreq->mpdccp_loc_key.value, &token);
		dreq->mpdccp_rem_token = token;
		mpdccp_pr_debug("token(A) %x", token);

		/* Now create the MPCB, meta & c */
		ret = mpdccp_create_master(sk, newsk, req, skb);
		if (ret) {
			mpdccp_pr_debug("error mpdccp_create_master %d", ret);
			return -1;
		}
		*master_sk = MPDCCP_CB(newsk)->master_sk;

		/* Finally complete the request handling */
		inet_csk_complete_hashdance(sk, newsk, req, true);
	} else {
		/* This is a new subflow socket */
		u8 hash_mac[20];
		u8 msg[8];

		struct sock *meta_sk = dreq->meta_sk;
		if (!meta_sk) {
			mpdccp_pr_debug("%s meta_sk is null\n",__func__);
			return -1;
		}

		/* Validate the HMAC from the client */
		mpcb = MPDCCP_CB(meta_sk);
		if (!mpcb) {
			mpdccp_pr_debug("%s mpcb is null\n",__func__);
			return -1;
		}
		memcpy(dreq->mpdccp_rem_hmac, opt_recv->dccpor_mp_hmac, MPDCCP_HMAC_SIZE);
		put_unaligned_be32(mpcb->mpdccp_loc_token, &msg[0]);
		put_unaligned_be32(dreq->mpdccp_loc_nonce, &msg[4]);
		mpdccp_hmac_sha1((u8 *)mpcb->mpdccp_rem_key.value,
						 (u8 *)mpcb->mpdccp_loc_key.value, (u32 *)hash_mac, 1, 8,
						 msg);
		if (memcmp(dreq->mpdccp_rem_hmac, hash_mac, MPDCCP_HMAC_SIZE)) {
					mpdccp_pr_debug("HMAC validation failed! rx: %llx exp: %llx\n",
									be64_to_cpu(*(u64 *)dreq->mpdccp_rem_hmac),
									be64_to_cpu(*((u64 *)hash_mac)));
			return -1;
		}
		mpdccp_pr_debug("HMAC validation OK");

		/* Now add the subflow to the mpcb */
		ret = create_subflow(newsk, meta_sk, skb, req, 0);//_mpdccp_listen(newsk, 1);
		if (ret) {
			mpdccp_pr_debug("error mpdccp_create_master_sub %d", ret);
			return -1;
		}
		*master_sk = mpcb->master_sk;

		/* Drop the request since this is not following the accept() flow */
		inet_csk_reqsk_queue_drop(sk, req);

		/* Set the flag to send an ack later */
		dccp_sk(newsk)->need_hmac_ack = 1;
	}
	return 0;
}

static int _mpdccp_close_meta(struct sock *meta_sk)
{
	struct mpdccp_cb	*mpcb = MPDCCP_CB(meta_sk);
	struct sock	*sk;
	int ret = 0;
	struct list_head *pos, *temp;
	struct my_sock *mysk;

	mpdccp_pr_debug ("enter for sk %p\n", meta_sk);
	/* close all subflows */
	list_for_each_safe(pos, temp, &((mpcb)->psubflow_list)) {
		mysk = list_entry(pos, struct my_sock, sk_list);
		if (mysk) {
			sk = mysk->my_sk_sock;
			mpdccp_pr_debug ("closing subflow %p\n", sk);
			ret = mpdccp_close_subflow(mpcb, sk, 1);
			if (ret < 0) {
				mpdccp_pr_debug ("error closing subflow: %d\n", ret);
				break;
			}
		}
	}
	return ret;
}

int
mpdccp_init_funcs (void)
{
	mpdccp_pr_debug ("initailize mpdccp functions\n");
	if (mpdccp_funcs.magic == MPDCCP_MAGIC) return 0;
	mpdccp_funcs = (struct mpdccp_funcs) {
		.magic = MPDCCP_MAGIC,
		.destroy_sock = _mpdccp_destroy_sock,
		.mk_meta_sk = _mpdccp_mk_meta_sk,
		.connect = _mpdccp_connect,
		.write_xmit = _mpdccp_write_xmit,
		.xmit_skb = _mpdccp_xmit_skb,
		.set_subflow_report = _mpdccp_set_subflow_report,
		.activate = _mpdccp_activate,
		.isactive = _mpdccp_isactive,
		.conn_request = _mpdccp_conn_request,
		.rcv_request_sent_state_process = _mpdccp_rcv_request_sent_state_process,
		.rcv_respond_partopen_state_process = _mpdccp_rcv_respond_partopen_state_process,
		.rcv_established = _mpdccp_rcv_established,
		.check_req = _mpdccp_check_req,
		.create_master = _mpdccp_create_master,
		.close_meta = _mpdccp_close_meta,
	};
	mpdccp_pr_debug ("mpdccp functions initialized (.magic=%x)\n",
				mpdccp_funcs.magic);
	return 0;
}

int
mpdccp_deinit_funcs (void)
{
	mpdccp_pr_debug ("de-initialize mpdccp functions\n");
	mpdccp_funcs = (struct mpdccp_funcs) { .magic = 0, };
	return 0;
}

