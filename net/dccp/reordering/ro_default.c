/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 * 
 * Copyright (C) 2018 by Maximilian Schuengel, Deutsche Telekom AG
 * Copyright (C) 2018 by Markus Amend, Deutsche Telekom AG
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

#include "../mpdccp.h"
#include "../mpdccp_reordering.h"


/************************************************* 
 *    Default Reordering
 *************************************************/

/**
 * Initialize default reordering module.
 */ 
static void init_reorder_default (struct mpdccp_cb *mpcb)
{
	mpcb->mpdccp_reorder_cb = NULL;
	ro_info("RO-INFO: default reordering module active [default module]\n"); 
}

/**
 * Queue work item.
 */
static void do_reorder_default(struct rcv_buff *rb)
{
	int	ret;

	//mpdccp_pr_debug ("do_reorder_default: called\n");
	if (!rb) {
		ro_err("RO-ERROR: w is NULL\n"); 
		return;
	}
	ret = mpdccp_forward_skb(rb->skb, rb->mpcb);
	if (ret < 0)
		printk ("do_reorder_default: error in forward: %d\n", ret);
	rb->mpcb->glob_lfor_seqno = (u64)rb->oall_seqno;
	mpdccp_release_rcv_buff(&rb);
	return; 
}

void do_update_pseq(struct my_sock *my_sk, struct sk_buff *skb){}

/**
 * Initialize active reordering operations.
 */
struct mpdccp_reorder_ops mpdccp_reorder_default = {
	.init		= init_reorder_default,
	.do_reorder	= do_reorder_default,
	.update_pseq = do_update_pseq,
	.name		= "default",
	.owner		= THIS_MODULE,
};


int mpdccp_reorder_default_register(void)
{
	if (mpdccp_register_reordering(&mpdccp_reorder_default))
		return FAIL_RO; 
	return SUCCESS_RO;
}

/** 
 * Exit: unregister the default reordering module.
 */
void mpdccp_reorder_default_unregister (void)
{
	mpdccp_unregister_reordering(&mpdccp_reorder_default);
}

