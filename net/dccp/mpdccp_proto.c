/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 * 
 * Copyright (C) 2020 by Frank Reker, Deutsche Telekom AG
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
	if (is_mpdccp (sk)) return 0;
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
	int		ret;

	if (!sk) return -EINVAL;
	mpdccp_pr_debug("activate mpdccp on socket\n");
	if (!is_mpdccp (sk)) {
		ret = _mpdccp_mk_meta_sk (sk);
		if (ret < 0) return ret;
	}
	MPDCCP_CB(sk)->multipath_active = on;
	return 0;
}

static
int
_mpdccp_isactive (
	struct sock	*sk)
{
	if (!is_mpdccp (sk)) return 0;
	return MPDCCP_CB(sk)->multipath_active;
}


static
int
_mpdccp_xmit_skb (
	struct sock	*sk,
	struct sk_buff	*skb)
{
	if (!sk || !skb) return -EINVAL;
	if (!mpdccp_is_meta (sk)) return -EINVAL;
	rcu_read_lock();
	bh_lock_sock(sk);
	if (dccp_qpolicy_full(sk)) {
		bh_unlock_sock(sk);
		rcu_read_unlock();
		return -EAGAIN;
	}

	skb_set_owner_w(skb, sk);
	dccp_qpolicy_push(sk, skb);
	if (!timer_pending(&dccp_sk(sk)->dccps_xmit_timer)) {
		mpdccp_write_xmit(sk);
	}
	bh_unlock_sock(sk);
	rcu_read_lock ();
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

	if (!mpdccp_is_meta(meta_sk)) return -EINVAL;
	mpcb = MPDCCP_CB(meta_sk);
	if (!mpcb) return -EINVAL;

	mpcb->role = MPDCCP_CLIENT;
	if (mpcb->sched_ops->init_conn)
		mpcb->sched_ops->init_conn (mpcb);
	if (mpcb->reorder_ops->init)
		mpcb->reorder_ops->init (mpcb);
	mpcb->glob_lfor_seqno = GLOB_SEQNO_INIT;
	
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
	meta_sk->sk_state = TCP_ESTABLISHED;
	
	return 0;
}


static
int
_mpdccp_bind (
	struct sock		*meta_sk, 
	const struct sockaddr	*addr,
	int			addrlen)
{
	struct mpdccp_cb	*mpcb;

	if (!mpdccp_is_meta(meta_sk)) return -EINVAL;
	mpcb = MPDCCP_CB(meta_sk);
	if (!mpcb) return -EINVAL;

	mpdccp_pr_debug ("set local address\n");
	memcpy(&mpcb->mpdccp_local_addr, addr, addrlen);
	mpcb->localaddr_len = addrlen;
	mpcb->has_localaddr = 1;
	return 0;
}

static
int
_mpdccp_listen (
	struct sock		*meta_sk, 
	int			backlog)
{
	char			pm_name[MPDCCP_PM_NAME_MAX];
	struct mpdccp_pm_ops	*pm;
	struct mpdccp_cb	*mpcb;
	int			ret;

	if (!mpdccp_is_meta(meta_sk)) return -EINVAL;
	mpcb = MPDCCP_CB(meta_sk);
	if (!mpcb) return -EINVAL;

	mpdccp_pr_debug ("mpdccp_listen: basic init (sched,reorder)\n");
	mpcb->role = MPDCCP_SERVER;
	if (mpcb->sched_ops->init_conn)
		mpcb->sched_ops->init_conn (mpcb);
	if (mpcb->reorder_ops->init)
		mpcb->reorder_ops->init (mpcb);
	mpcb->glob_lfor_seqno = GLOB_SEQNO_INIT;
	
	mpdccp_get_default_path_manager(pm_name);
	pm = mpdccp_pm_find(pm_name);
	if(!pm){
		mpdccp_pr_debug("mpdccp_listen: Path manager not found.");
		return -ENOENT;
	}
	mpdccp_pr_debug("mpdccp_pr_debug: start pathmanager\n");
	ret = pm->add_init_server_conn (mpcb, backlog);
	if (ret < 0) {
		mpdccp_pr_debug("mpdccp_listen: Failed to set up MPDCCP Server mpcb: %d\n", ret);
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


int
mpdccp_init_funcs (void)
{
	mpdccp_pr_debug ("initailize mpdccp functions\n");
	if (mpdccp_funcs.magic == MPDCCP_MAGIC) return 0;
	mpdccp_funcs = (struct mpdccp_funcs) {
		.magic = MPDCCP_MAGIC,
		.destroy_sock = _mpdccp_destroy_sock,
		.mk_meta_sk = _mpdccp_mk_meta_sk,
		.listen = _mpdccp_listen,
		.connect = _mpdccp_connect,
		.bind = _mpdccp_bind,
		.write_xmit = _mpdccp_write_xmit,
		.xmit_skb = _mpdccp_xmit_skb,
		.set_subflow_report = _mpdccp_set_subflow_report,
		.activate = _mpdccp_activate,
		.isactive = _mpdccp_isactive,
	};
	mpdccp_pr_debug ("mpdccp functions initialized (.magic=%x, .listen=%p)\n",
				mpdccp_funcs.magic, mpdccp_funcs.listen);
	return 0;
}

