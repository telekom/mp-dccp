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
#include <linux/string.h>
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
int mpdccp_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen);
int mpdccp_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen);


static
int
_mpdccp_mk_meta_sk (
	struct sock	*sk)
{
	struct dccp_sock		*dp = dccp_sk(sk);

	if (!sk) return -EINVAL;
	if (mpdccp_is_meta (sk)) return 0;
	try_module_get (THIS_MODULE);
	dp->mpdccp = (struct mpdccp_meta_cb) {
			.magic = MPDCCP_MAGIC,
			.is_meta = 1 };
	dp->mpdccp.mpcb = mpdccp_alloc_mpcb ();
	if (!dp->mpdccp.mpcb) {
		module_put (THIS_MODULE);
		return -ENOBUFS;
	}
	sk->sk_prot->setsockopt = mpdccp_setsockopt;
	sk->sk_prot->getsockopt = mpdccp_getsockopt;
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

	if (!mpdccp_enabled) {
		mpdccp_pr_debug ("mpdccp_enabled: %u, interrupting socket creation", mpdccp_enabled);
		return -EINVAL;
	}

	if (on) {
		mpdccp_pr_debug("activate mpdccp on socket %p\n", sk);
		dccp_sk(sk)->mpdccp = (struct mpdccp_meta_cb) {
								.magic = MPDCCP_MAGIC,
								.mpcb = NULL,
								.is_meta = 0};
	} else {
		mpdccp_pr_debug("deactivate mpdccp on socket %p\n", sk);
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
	lock_sock(sk);
	if (dccp_qpolicy_full(sk)) {
		release_sock(sk);
		return -EAGAIN;
	}

	/* Wait for a connection to finish. */
	timeo = sock_sndtimeo(sk, 1);
	if ((1 << sk->sk_state) & ~(DCCPF_OPEN | DCCPF_PARTOPEN)) {
		if ((ret = sk_stream_wait_connect(sk, &timeo)) != 0) {
			release_sock(sk);
			return -EAGAIN;
		}
	}

	skb_set_owner_w(skb, sk);
	dccp_qpolicy_push(sk, skb);
	//if (!timer_pending(&dccp_sk(sk)->dccps_xmit_timer)) {
		mpdccp_write_xmit(sk);
	//}
	release_sock(sk);
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
	int			ret;

	if (!skb) return -EINVAL;
	mpcb = MPDCCP_CB(meta_sk);
	if (!mpcb) return -EINVAL;

	rcu_read_lock ();
	sk = mpcb->sched_ops->get_subflow(mpcb);
	DCCP_SKB_CB(skb)->dccpd_mpseq = mpcb->mp_oall_seqno;
	rcu_read_unlock();
	if (!sk) {
		return -EAGAIN;
	}
	ret = mpdccp_xmit_to_sk (sk, skb);
	rcu_read_lock ();
	if (!strcasecmp (mpcb->sched_ops->name, "redundant")){
		dccp_inc_seqno(&mpcb->mp_oall_seqno);
	}
	rcu_read_unlock();
	return ret;
}

static int do_mpdccp_setsockopt(struct sock *sk, int level, int optname,
		sockptr_t optval, unsigned int optlen)
{
	int				err = 0;
	struct sock			*subsk;
	struct mpdccp_cb		*mpcb;
	struct mpdccp_sched_ops		*sched;
	char				*val;
	u8					*intval;
	struct mpdccp_reorder_ops	*reorder;

	lock_sock(sk);
	mpcb = MPDCCP_CB(sk);
	mpdccp_pr_debug ("setsockopt: %d\n", optname );
	if (level == SOL_DCCP) {
		/* handle multipath socket options */
		switch (optname) {
		case DCCP_SOCKOPT_MP_REORDER:
			val = memdup_sockptr(optval, optlen);
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
			val = memdup_sockptr(optval, optlen);
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
		case DCCP_SOCKOPT_MP_FAST_CLOSE:
			intval = memdup_sockptr(optval, optlen);
			if (IS_ERR(intval)) {
				err = PTR_ERR(intval);
				goto out_release;
			}
			mpcb->close_fast = *intval;
			mpdccp_pr_debug("Toggle fast close %u\n", mpcb->close_fast);
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
	return err;
}


int mpdccp_setsockopt(struct sock *sk, int level, int optname,
		   sockptr_t optval, unsigned int optlen)
{
	int	ret;
	if(!is_mpdccp(sk) || (is_mpdccp(sk) && !mpdccp_is_meta(sk))){
		ret = dccp_setsockopt (sk, level, optname, optval, optlen);
		return ret;
	}

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
	mpcb->mpdccp_loc_cix = mpdccp_link_generate_cid();
	
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
	struct mpdccp_cb	*mpcb;

	if (!mpdccp_is_meta(sk)) return -EINVAL;
	mpcb = MPDCCP_CB(sk);
	if (mpcb) mpdccp_destroy_mpcb (mpcb);
	unset_mpdccp(sk);
	module_put (THIS_MODULE);
	return 0;
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

		if ((opt_recv->dccpor_mp_keys[0].size == 0) || (opt_recv->dccpor_mp_keys[0].size > MPDCCP_MAX_KEY_SIZE)) {
			mpdccp_pr_debug("received key has invalid length");
			return -1;
		}
		/* Get the client key */
		dreq->mpdccp_rem_key.type = opt_recv->dccpor_mp_keys[0].type;
		dreq->mpdccp_rem_key.size = opt_recv->dccpor_mp_keys[0].size;
		memcpy(dreq->mpdccp_rem_key.value, opt_recv->dccpor_mp_keys[0].value,
			   dreq->mpdccp_rem_key.size);

		dreq->mpdccp_loc_cix = mpdccp_link_generate_cid();
		dreq->mpdccp_rem_cix = opt_recv->dccpor_mp_cix;
	} else if (opt_recv->saw_mpjoin) {
		/* No MP_KEY: this is a join */
		struct sock *meta_sk = NULL;
		struct mpdccp_cb *mpcb;
		int ret;

		if ((opt_recv->dccpor_mp_cix == 0) || (opt_recv->dccpor_mp_nonce == 0)) {
			mpdccp_pr_debug("invalid CID or nonce received");
			return -1;
		}
		dreq->mpdccp_rem_nonce = opt_recv->dccpor_mp_nonce;

		/* Lookup the token in existing MPCBs */
		mpdccp_for_each_conn(pconnection_list, mpcb) {
			if (mpcb->mpdccp_loc_cix == opt_recv->dccpor_mp_cix) {
				meta_sk = mpcb->meta_sk;
				mpdccp_pr_debug("found CID in mpcb %p\n", mpcb);
				break;
			}
		}

		if (meta_sk == NULL) {
			mpdccp_pr_debug("no CID found for join");
			return -1;
		}

		mpcb = MPDCCP_CB(meta_sk);

		/* Hold a reference to the meta socket (will be released in req destructor) */
		sock_hold(meta_sk);
		dreq->meta_sk = meta_sk;

		/* Check the MP version is the same as the first subflow */
		if (dccp_sk(meta_sk)->multipath_ver != dreq->multipath_ver) {
			mpdccp_pr_debug("MP version mismatch in JOIN expected: %d got:%d", dccp_sk(meta_sk)->multipath_ver, dreq->multipath_ver);
			return -1;
		}

		/* Generate local nonce */
		get_random_bytes(&dreq->mpdccp_loc_nonce, 4);
		mpdccp_pr_debug("generated nonce %x", dreq->mpdccp_loc_nonce);

		/* Calculate HMAC */
		put_unaligned_be32(mpcb->mpdccp_loc_cix, &msg[0]);
		put_unaligned_be32(dreq->mpdccp_rem_nonce, &msg[4]);
		ret = mpdccp_hmac_sha256(mpcb->dkeyB, mpcb->dkeylen, msg, 8, dreq->mpdccp_loc_hmac);
		if (ret) {
			mpdccp_pr_debug("error calculating HMAC, err %d", ret);
			return -1;
		}
		mpdccp_pr_debug("calculated HMAC %llx", be64_to_cpu(*((u64 *)dreq->mpdccp_loc_hmac)));
	} else {
		mpdccp_pr_debug("no MP_KEY or MP_JOIN in DCCP REQUEST");
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
		int i;
		mpcb = MPDCCP_CB(sk);
		/* Fallback to single path if mp cannot be established */
		if (!opt_recv->saw_mpkey || (dccp_sk(sk)->multipath_ver == MPDCCP_VERS_UNDEFINED)) {
			mpdccp_pr_debug("no MP_KEY in response, fallback to single DCCP");
			if (mpcb) {
				mpdccp_pr_debug("no MP_KEY in response or invalid MP version, fallback to single path DCCP\n");
				mpcb->fallback_sp = 1;
				return 0;
			} else {
				mpdccp_pr_debug("invalid MPCB\n");
				return -1;
			}
		}

		if ((opt_recv->dccpor_mp_keys[0].size == 0) || (opt_recv->dccpor_mp_keys[0].size > MPDCCP_MAX_KEY_SIZE)) {
			mpdccp_pr_debug("rx key(s) have invalid length %d", opt_recv->dccpor_mp_keys[0].size);
			return -1;
		}

		/* Pick the local key with the same type as the remote */
		for (i=0; i < MPDCCP_MAX_KEYS; i++) {
			if (mpcb->mpdccp_loc_keys[i].type == opt_recv->dccpor_mp_keys[0].type) {
				mpcb->cur_key_idx = i;
				mpdccp_pr_debug("found local matching key idx %i type %d\n", i, mpcb->mpdccp_loc_keys[i].type);
				break;
			}
		}
		if (i == MPDCCP_MAX_KEYS) {
			mpdccp_pr_debug("no key type match srv: %x cli: %x", opt_recv->dccpor_mp_suppkeys, MPDCCP_SUPPKEYS);
			return -1;
		}

		/* Store the remote key */
		mpcb->mpdccp_rem_key.type = opt_recv->dccpor_mp_keys[0].type;
		mpcb->mpdccp_rem_key.size = opt_recv->dccpor_mp_keys[0].size;
		memcpy(mpcb->mpdccp_rem_key.value, opt_recv->dccpor_mp_keys[0].value, mpcb->mpdccp_rem_key.size);

		mpcb->mpdccp_rem_cix = opt_recv->dccpor_mp_cix;
		/* Created derived key(s) */
		if (mpcb->mpdccp_loc_keys[i].type == DCCPK_PLAIN) {
			memcpy(&mpcb->dkeyA[0], mpcb->mpdccp_loc_keys[i].value, MPDCCP_PLAIN_KEY_SIZE);
			memcpy(&mpcb->dkeyA[MPDCCP_PLAIN_KEY_SIZE], mpcb->mpdccp_rem_key.value, MPDCCP_PLAIN_KEY_SIZE);
			memcpy(&mpcb->dkeyB[0], mpcb->mpdccp_rem_key.value, MPDCCP_PLAIN_KEY_SIZE);
			memcpy(&mpcb->dkeyB[MPDCCP_PLAIN_KEY_SIZE], mpcb->mpdccp_loc_keys[i].value, MPDCCP_PLAIN_KEY_SIZE);
			mpcb->dkeylen = MPDCCP_PLAIN_KEY_SIZE * 2;
		} else {
			/* TODO */
			mpdccp_pr_debug("unsupported key type %d", mpcb->mpdccp_loc_keys[i].type);
			return -1;
		}

		/* On client side the key exchange is done */
		mpcb->kex_done = 1;
	} else {
		/* We are in authentication phase: process data from MP_JOIN option */
		u8 hash_mac[MPDCCP_HMAC_SIZE];
		u8 msg[8];
		int ret;

		mpcb = MPDCCP_CB(sk);

		if (!opt_recv->saw_mpjoin || mpcb->fallback_sp || (dccp_sk(sk)->multipath_ver == MPDCCP_VERS_UNDEFINED)) {
			mpdccp_pr_debug("no MP_JOIN in response, invalid MP version or using single path DCCP fallback\n");
			return -1;
		}

		if ((opt_recv->dccpor_mp_cix == 0) || (opt_recv->dccpor_mp_nonce == 0)) {
			mpdccp_pr_debug("invalid CID or nonce received");
			return -1;
		}
		dccp_sk(sk)->mpdccp_rem_nonce = opt_recv->dccpor_mp_nonce;

		if (opt_recv->dccpor_mp_cix != mpcb->mpdccp_loc_cix){
			mpdccp_pr_debug("error unknown CID");
			return -1;
		}

		/* Validate HMAC from srv */
		memcpy(dccp_sk(sk)->mpdccp_rem_hmac, opt_recv->dccpor_mp_hmac, MPDCCP_HMAC_SIZE);
		put_unaligned_be32(mpcb->mpdccp_rem_cix, &msg[0]);
		put_unaligned_be32(dccp_sk(sk)->mpdccp_loc_nonce, &msg[4]);
		ret = mpdccp_hmac_sha256(mpcb->dkeyB, mpcb->dkeylen, msg, 8, hash_mac);
		if (ret) {
			mpdccp_pr_debug("error calculating HMAC, err %d", ret);
			return -1;
		}
		mpdccp_pr_debug("calculated HMAC(B) %llx", be64_to_cpu(*((u64 *)hash_mac)));

		if (memcmp(dccp_sk(sk)->mpdccp_rem_hmac, hash_mac, MPDCCP_HMAC_SIZE)) {
			mpdccp_pr_debug("HMAC validation failed! rx: %llx exp: %llx",
							be64_to_cpu(*(u64 *)dccp_sk(sk)->mpdccp_rem_hmac),
							be64_to_cpu(*((u64 *)hash_mac)));
			return -1;
		}
		mpdccp_pr_debug("HMAC validation OK");

		/* Now calculate the HMAC from the received JOIN */
		put_unaligned_be32(mpcb->mpdccp_rem_cix, &msg[0]);
		put_unaligned_be32(dccp_sk(sk)->mpdccp_rem_nonce, &msg[4]);
		ret = mpdccp_hmac_sha256(mpcb->dkeyA, mpcb->dkeylen, msg, 8, dccp_sk(sk)->mpdccp_loc_hmac);
		if (ret) {
			mpdccp_pr_debug("error calculating HMAC, err %d", ret);
			return -1;
		}
		mpdccp_pr_debug("calculated HMAC(A) %llx", be64_to_cpu(*((u64 *)dccp_sk(sk)->mpdccp_loc_hmac)));
	}
	return 0;
}

static int _mpdccp_rcv_established(struct sock *sk)
{
	struct mpdccp_cb *mpcb = MPDCCP_CB(sk);

	/* Check if the socket has been authenticated */
	if(dccp_sk(sk)->auth_done || (mpcb && mpcb->fallback_sp)) {
			return 0;
	}
	mpdccp_pr_debug("sk %p NOT authenticated \n", sk);
	return -1;
}

static int _mpdccp_rcv_respond_partopen_state_process(struct sock *sk, int type)
{
	struct mpdccp_cb *mpcb = MPDCCP_CB(sk);
	mpdccp_pr_debug("enter for sk %p role %s is_meta %d is_kex %d type %d", sk, dccp_role(sk), mpdccp_is_meta(sk), dccp_sk(sk)->is_kex_sk, type);

	if (mpcb && !mpcb->fallback_sp && (type == DCCP_PKT_ACK || type == DCCP_PKT_DATAACK)) {
		if (dccp_sk(sk)->is_kex_sk && !mpcb->kex_done) {
			int key_idx = mpcb->cur_key_idx;
			mpdccp_pr_debug("key exchange done for mpcb %p\n", mpcb); 
			mpcb->kex_done = 1;

			/* Created derived key(s) */
			if (mpcb->mpdccp_loc_keys[key_idx].type == DCCPK_PLAIN) {
				memcpy(&mpcb->dkeyA[0], mpcb->mpdccp_rem_key.value, MPDCCP_PLAIN_KEY_SIZE);
				memcpy(&mpcb->dkeyA[MPDCCP_PLAIN_KEY_SIZE], mpcb->mpdccp_loc_keys[key_idx].value, MPDCCP_PLAIN_KEY_SIZE);
				memcpy(&mpcb->dkeyB[0], mpcb->mpdccp_loc_keys[key_idx].value, MPDCCP_PLAIN_KEY_SIZE);
				memcpy(&mpcb->dkeyB[MPDCCP_PLAIN_KEY_SIZE], mpcb->mpdccp_rem_key.value, MPDCCP_PLAIN_KEY_SIZE);
				mpcb->dkeylen = MPDCCP_PLAIN_KEY_SIZE * 2;
			} else {
				/* TODO */
				mpdccp_pr_debug("unsupported key type %d", mpcb->mpdccp_loc_keys[key_idx].type);
				return -1;
			}
			/* No longer need to include the MP_KEY in the options */
			dccp_sk(sk)->is_kex_sk = 0;
		}

		if (dccp_sk(sk)->dccps_role == DCCP_ROLE_CLIENT) {
			/* Stop the ACK retry timer */
			inet_csk_clear_xmit_timer(sk, ICSK_TIME_RETRANS);
			WARN_ON(sk->sk_send_head == NULL);
			kfree_skb(sk->sk_send_head);
			sk->sk_send_head = NULL;

			if(mpdccp_get_prio(sk) != 3)				// dont announce if prio = 3 (default value)
				mpdccp_init_announce_prio(sk);			// announce prio values for all subflows after creation
		}

		/* Authentication complete, send an additional ACK if required */
		dccp_sk(sk)->auth_done = 1;
		if (dccp_sk(sk)->dccps_role == DCCP_ROLE_SERVER) {
			struct mpdccp_link_info *link = mpdccp_ctrl_getlink (sk);

			mpdccp_pr_debug("send ACK");
			dccp_send_ack(sk);

			/* we have a virtual link (created by a script or mpdccplink add_link) */
			if(link && !link->is_devlink && link->mpdccp_prio != 3)
				mpdccp_init_announce_prio(sk);			// (server) announce prio only for non dev links
			else if(link && link->is_devlink)
				mpdccp_link_cpy_set_prio(sk, 3);
			
			mpdccp_link_put (link);
		}
	}

	/* Open the meta socket if necessary */
	if ((sk->sk_state == DCCP_OPEN) && (mpcb && mpcb->meta_sk->sk_state == DCCP_RESPOND)) {
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
	int clone,
	u8 loc_addr_id,
	u8 rem_addr_id)
{
	int ret;
	struct sock *newsk;
	struct mpdccp_cb *mpcb = MPDCCP_CB(meta_sk);
	struct mpdccp_link_info *link_info = NULL;
	struct dccp_request_sock *dreq = dccp_rsk(req);

	mpdccp_pr_debug("enter sk %p meta %p req %p clone %d loc_id %u rem_id %u\n", sk, meta_sk, req, clone, loc_addr_id, rem_addr_id);
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

	mpdccp_my_sock(newsk)->link_info = link_info;
	mpdccp_my_sock(newsk)->link_cnt = mpdccp_link_cnt(link_info);
	mpdccp_my_sock(newsk)->link_iscpy = 0;
    mpdccp_my_sock(newsk)->local_addr_id = loc_addr_id;
    mpdccp_my_sock(newsk)->remote_addr_id = rem_addr_id;

	spin_lock(&mpcb->psubflow_list_lock);
	list_add_tail_rcu(&mpdccp_my_sock(newsk)->sk_list, &mpcb->psubflow_list);
	mpdccp_pr_debug("Added new entry to psubflow_list @ %p\n", mpdccp_my_sock(newsk));
	mpcb->cnt_subflows = (mpcb->cnt_subflows) + 1;
	spin_unlock(&mpcb->psubflow_list_lock);

	if (mpcb->sched_ops->init_subflow) {
		rcu_read_lock ();
		mpcb->sched_ops->init_subflow(newsk);
		rcu_read_unlock ();
	}

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
	union inet_addr addr;

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
	mpcb->mpdccp_loc_keys[0] = dreq->mpdccp_loc_key;
	mpcb->mpdccp_loc_cix = dreq->mpdccp_loc_cix;
	mpcb->mpdccp_rem_cix = dreq->mpdccp_rem_cix;
	mpcb->cur_key_idx = 0;
	mpcb->mpdccp_rem_key = dreq->mpdccp_rem_key;
	mpcb->role = MPDCCP_SERVER;
	mpcb->master_addr_id = 0;

	//prevent cid entry deletion triggered by freeing dreq  
	dreq->mpdccp_loc_cix = 0;

	addr.ip = inet->inet_saddr;
	if(mpcb->pm_ops->claim_local_addr)
		mpcb->master_addr_id = mpcb->pm_ops->claim_local_addr(mpcb, AF_INET, &addr);

	mpdccp_pr_debug("master subflow id: %u\n", mpcb->master_addr_id);

	addr.ip = inet->inet_daddr;
	if(mpcb->pm_ops->add_addr)
		mpcb->pm_ops->add_addr(mpcb, AF_INET, 0, &addr, inet->inet_dport, true);

	/* Create subflow and meta sockets */
	ret = create_subflow(sk, meta_sk, skb, req, 1, mpcb->master_addr_id, 0);
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

	if (dreq && !dreq->meta_sk && !mpdccp_is_meta(newsk)) {
		/* This is a new session, need to create MPCB and meta */
		int dkeylen;
		u8 dkeyA[MPDCCP_MAX_KEY_SIZE * 2];
		u8 dkeyB[MPDCCP_MAX_KEY_SIZE * 2];

		/* Fallback to single path if mp cannot be established */
		if (dreq->multipath_ver == MPDCCP_VERS_UNDEFINED) {
			mpdccp_pr_debug("failed MP negotiation with client, fallback to single path DCCP\n");
			mpdccp_activate (newsk, 0);
			*master_sk = inet_csk_complete_hashdance(sk, newsk, req, true);
			return 0;
		}

		dccp_sk(newsk)->multipath_ver = dreq->multipath_ver;


		mpdccp_pr_debug("key exchange done, creating meta socket");
		dccp_sk(newsk)->is_kex_sk = 0;

		/* Created derived key(s) */
		if (dreq->mpdccp_loc_key.type == DCCPK_PLAIN) {
			memcpy(&dkeyA[0], dreq->mpdccp_rem_key.value, MPDCCP_PLAIN_KEY_SIZE);
			memcpy(&dkeyA[MPDCCP_PLAIN_KEY_SIZE], dreq->mpdccp_loc_key.value, MPDCCP_PLAIN_KEY_SIZE);
			memcpy(&dkeyB[0], dreq->mpdccp_loc_key.value, MPDCCP_PLAIN_KEY_SIZE);
			memcpy(&dkeyB[MPDCCP_PLAIN_KEY_SIZE], dreq->mpdccp_rem_key.value, MPDCCP_PLAIN_KEY_SIZE);
			dkeylen = MPDCCP_PLAIN_KEY_SIZE * 2;
		} else {
			/* TODO */
			mpdccp_pr_debug("unsupported key type %d", dreq->mpdccp_loc_key.type);
			return -1;
		}


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
		int loc_id = 0, rem_id = 0;
		union inet_addr addr;

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
		put_unaligned_be32(mpcb->mpdccp_loc_cix, &msg[0]);
		put_unaligned_be32(dreq->mpdccp_loc_nonce, &msg[4]);
		ret = mpdccp_hmac_sha256(mpcb->dkeyA, mpcb->dkeylen, msg, 8, hash_mac);
		if (ret) {
			mpdccp_pr_debug("error calculating HMAC, err %d", ret);
			return -1;
		}

		if (memcmp(dreq->mpdccp_rem_hmac, hash_mac, MPDCCP_HMAC_SIZE)) {
					mpdccp_pr_debug("HMAC validation failed! rx: %llx exp: %llx\n",
									be64_to_cpu(*(u64 *)dreq->mpdccp_rem_hmac),
									be64_to_cpu(*((u64 *)hash_mac)));
			return -1;
		}
		mpdccp_pr_debug("HMAC validation OK");

		if(mpcb->pm_ops->get_id_from_ip){
			addr.ip = ip_hdr(skb)->daddr;
			loc_id = mpcb->pm_ops->get_id_from_ip(mpcb, &addr, AF_INET, false);
			addr.ip = ip_hdr(skb)->saddr;
			rem_id = mpcb->pm_ops->get_id_from_ip(mpcb, &addr, AF_INET, true);

			if(loc_id < 0 || rem_id < 0){
				mpdccp_pr_debug("cant create subflow with unknown address id");
				return -1;
			}
		}
		/* Now add the subflow to the mpcb */

		ret = create_subflow(newsk, meta_sk, skb, req, 0, (u8)loc_id, (u8)rem_id);
		if (ret) {
			mpdccp_pr_debug("error mpdccp_create_master_sub %d", ret);
			return -1;
		}
		*master_sk = mpcb->master_sk;

		/* Drop the request since this is not following the accept() flow */
		inet_csk_reqsk_queue_drop(sk, req);
		reqsk_queue_removed(&inet_csk(sk)->icsk_accept_queue, req);
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

	if (!mpcb) return -EINVAL;
	if(mpcb->to_be_closed) return 0;

	mpcb->to_be_closed = 1;
	mpdccp_pr_debug ("enter for sk %p\n", meta_sk);
	/* close all subflows */
	list_for_each_safe(pos, temp, &((mpcb)->psubflow_list)) {
		mysk = list_entry(pos, struct my_sock, sk_list);
		if (mysk) {
			sk = mysk->my_sk_sock;
			mpdccp_pr_debug ("closing subflow %p\n", sk);
			ret = mpdccp_close_subflow(mpcb, sk, mpcb->close_fast+1);
			if (ret < 0) {
				mpdccp_pr_debug ("error closing subflow: %d\n", ret);
				break;
			}
		}
	}

	meta_sk->sk_prot->setsockopt = dccp_setsockopt;
	meta_sk->sk_prot->getsockopt = dccp_getsockopt;

	if(mpcb->pm_ops->del_addr)
		mpcb->pm_ops->del_addr(mpcb, 0, 0, true);

	return ret;
}

static int _mpdccp_try(struct sock *sk)
{
	if(!is_mpdccp(sk) && mpdccp_enabled == 1){
		mpdccp_pr_debug ("mpdcc_enabled: 1, upgrading to mpdccp (%p)", sk);
		_mpdccp_activate(sk,1);
		return 1;
	}
	return 0;
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
		.activate = _mpdccp_activate,
		.isactive = _mpdccp_isactive,
		.conn_request = _mpdccp_conn_request,
		.rcv_request_sent_state_process = _mpdccp_rcv_request_sent_state_process,
		.rcv_respond_partopen_state_process = _mpdccp_rcv_respond_partopen_state_process,
		.rcv_established = _mpdccp_rcv_established,
		.check_req = _mpdccp_check_req,
		.create_master = _mpdccp_create_master,
		.close_meta = _mpdccp_close_meta,
		.try_mpdccp = _mpdccp_try,
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

