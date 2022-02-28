/*
 * MPDCCP - DCCP bundling kernel module
 *
 * This module implements a bundling mechanism that aggregates
 * multiple paths using the DCCP protocol.
 * 
 * Copyright (C) 2022 by Frank Reker <frank@reker.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */


#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/notifier.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <linux/rtnetlink.h>
#include <generated/autoconf.h>
#include <net/mpdccp.h>
#include <net/mpdccp_link.h>
#include <net/mpdccp_link_info.h>
#include "mpdccp.h"

static RAW_NOTIFIER_HEAD(mpdccp_subflow_chain);


int
register_mpdccp_subflow_notifier (
	struct notifier_block	*nb)
{
	int	ret;

	rtnl_lock();
	ret = raw_notifier_chain_register(&mpdccp_subflow_chain, nb);
	rtnl_unlock();
	return ret;
}
EXPORT_SYMBOL(register_mpdccp_subflow_notifier);


int
unregister_mpdccp_subflow_notifier (
	struct notifier_block	*nb)
{
	int	ret;

	rtnl_lock();
	ret = raw_notifier_chain_unregister(&mpdccp_subflow_chain, nb);
	rtnl_unlock();
	return ret;
}
EXPORT_SYMBOL(unregister_mpdccp_subflow_notifier);

int
call_mpdccp_subflow_notifiers (
	unsigned long		action,
	struct sock		*sk)
{
	int				ret;
	struct sock			*meta_sk = NULL;
	struct mpdccp_cb		*mpcb = NULL;
	struct my_sock			*my_sk = NULL;
	struct mpdccp_link_info		*link = NULL;
	struct mpdccp_subflow_notifier	info;

	if (!sk) return -EINVAL;
	mpcb = get_mpcb (sk);
	if (!mpcb) return -EINVAL;
	switch (action) {
	case MPDCCP_EV_ALL_SUBFLOW_DOWN:
		if (!mpdccp_is_meta(sk)) return 0;
		if (!mpcb->up_reported) return 0;
		meta_sk = sk;
		sk = NULL;
		link = NULL;
		break;
	case MPDCCP_EV_SUBFLOW_CREATE:
	case MPDCCP_EV_SUBFLOW_DESTROY:
		if (mpdccp_is_meta(sk)) return 0;
		meta_sk = mpcb->meta_sk;
		if (!meta_sk) return -EINVAL;
		my_sk = mpdccp_my_sock(sk);
		if (!my_sk) return -EINVAL;
		if (action == MPDCCP_EV_SUBFLOW_CREATE) {
			my_sk->up_reported = 1;
			mpcb->up_reported = 1;
		} else {
			if (!my_sk->up_reported) return 0;
		}
		rcu_read_lock();
		link = my_sk->link_info;
		mpdccp_link_get (link);
		rcu_read_unlock();
		break;
	}
	sock_hold (meta_sk);

	info = (struct mpdccp_subflow_notifier) {
		.link = link,
		.sk = meta_sk,
		.subsk = sk,
		.role = mpcb->role,
	};

	ret = raw_notifier_call_chain(&mpdccp_subflow_chain, action, &info);
	if (link) {
		rcu_read_lock();
		mpdccp_link_put (link);
		rcu_read_unlock();
	}
	sock_put (meta_sk);
	return ret;
}
EXPORT_SYMBOL(call_mpdccp_subflow_notifiers);

int
mpdccp_report_alldown (
	struct sock	*sk)
{
	return call_mpdccp_subflow_notifiers (MPDCCP_EV_ALL_SUBFLOW_DOWN, sk);
}
EXPORT_SYMBOL(mpdccp_report_alldown);

int
mpdccp_report_destroy (
	struct sock	*sk)
{
	return call_mpdccp_subflow_notifiers (MPDCCP_EV_SUBFLOW_DESTROY, sk);
}
EXPORT_SYMBOL(mpdccp_report_destroy);


int
mpdccp_report_new_subflow (
	struct sock	*sk)
{
	return call_mpdccp_subflow_notifiers (MPDCCP_EV_SUBFLOW_CREATE, sk);
}
EXPORT_SYMBOL(mpdccp_report_new_subflow);




