/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 * Copyright (C) 2017 by Andreas Philipp Matz, Deutsche Telekom AG
 * Copyright (C) 2017 by Markus Amend, Deutsche Telekom AG
 * Copyright (C) 2020-2021 by Frank Reker, Deutsche Telekom AG
 *
 * MPDCCP - DCCP bundling kernel module
 *
 * This module implements a bundling mechanism that aggregates
 * multiple paths using the DCCP protocol.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
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

/* Sysctl variables */
struct  ctl_table_header *mpdccp_sysctl;
/* Controls whether the client sends SRTT or MRTT */
int sysctl_mpdccp_delay_config __read_mostly    = 0;
int sysctl_mpdccp_accept_prio __read_mostly    = 0;


static int proc_mpdccp_path_manager(struct ctl_table *ctl, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos)
{
	int			ret;
	struct mpdccp_pm_ops	*pm;
	struct mpdccp_cb	*mpcb;
	char			val[MPDCCP_PM_NAME_MAX];
	
	struct ctl_table tbl = {
		.data = val,
		.maxlen = MPDCCP_PM_NAME_MAX,
	};
	
	mpdccp_get_default_path_manager(val);
	
	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0){
	    
		ret = mpdccp_set_default_path_manager(val);
		if(ret < 0){
			mpdccp_pr_debug("Path manager not found (%d).\n", ret);
			return ret;
		}
		
		rcu_read_lock();
		//Find pm struct corresponding to pm name
		pm = mpdccp_pm_find(val);
		if(!pm) {
			rcu_read_unlock();
			mpdccp_pr_debug("Path manager not found.\n");
			return ret;
		}
		
		//Assign pm to all existing connections
		mpdccp_for_each_conn(pconnection_list, mpcb) {
			mpcb->pm_ops = pm;
		}
		
		rcu_read_unlock();
	}
	
	return ret;
}

static int proc_mpdccp_scheduler(struct ctl_table *ctl, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos)
{
	int			ret;
	struct mpdccp_sched_ops	*sched;
	struct mpdccp_cb	*mpcb;
	char			val[MPDCCP_SCHED_NAME_MAX];
	
	struct ctl_table tbl = {
		.data = val,
		.maxlen = MPDCCP_SCHED_NAME_MAX,
	};
	
	mpdccp_get_default_scheduler(val);
	
	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0){
	    
		ret = mpdccp_set_default_scheduler(val);
		if(ret < 0){
			mpdccp_pr_debug("Scheduler not found (%d).\n", ret);
			return ret;
		}
		
		rcu_read_lock();
		//Find sched struct corresponding to sched name
		sched = mpdccp_sched_find(val);
		if(!sched){
			rcu_read_unlock();
			mpdccp_pr_debug("Scheduler not found.\n");
			return ret;
		}

        //Assign sched to all existing connections
	mpdccp_for_each_conn(pconnection_list, mpcb) {
		if (!mpcb->has_own_sched) {
			lock_sock(mpcb->meta_sk);
			mpdccp_init_scheduler (mpcb);
			release_sock(mpcb->meta_sk);
		}
	}

        rcu_read_unlock();
    }

    return ret;
}

static int proc_mpdccp_reordering(struct ctl_table *ctl, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos)
{
	int ret;
	struct mpdccp_reorder_ops *reorder;
	struct mpdccp_cb *mpcb;
	char val[MPDCCP_REORDER_NAME_MAX];
	
	struct ctl_table tbl = {
		.data = val,
		.maxlen = MPDCCP_REORDER_NAME_MAX,
	};
	
	mpdccp_get_default_reordering(val);
	
	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0){
	    
		ret = mpdccp_set_default_reordering(val);
		if(ret < 0){
			mpdccp_pr_debug("Reordering engine not found (%d)\n", ret);
			return ret;
		}
		
		rcu_read_lock();
		
		//Find reorder struct corresponding to reorder name
		reorder = mpdccp_reorder_find(val);
		if(!reorder){
			mpdccp_pr_debug("Reordering engine not found.\n");
			return ret;
		}
		
		//Assign reorder to all existing connections
		mpdccp_for_each_conn(pconnection_list, mpcb) {
			if (!mpcb->has_own_reorder) {
				rcu_read_unlock();
				lock_sock (mpcb->meta_sk);
				mpdccp_init_reordering (mpcb);
				release_sock (mpcb->meta_sk);
				rcu_read_lock();
			}
		}
		rcu_read_unlock();
	}
	return ret;
}

static int proc_mpdccp_delay_config(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos)
{   
	int ret;
	mpdccp_pr_debug("/proc triggered reordering delay config\n");
	ret = proc_dointvec(table, write, buffer, lenp, ppos);  
	
	if(ret == 0){
		switch(sysctl_mpdccp_delay_config){
		case MPDCCP_REORDERING_DELAY_MRTT:
			mpdccp_pr_debug("Switched to MRTT\n");
			set_mrtt_as_delayn();
			break;
		case MPDCCP_REORDERING_DELAY_MIN_RTT:
			mpdccp_pr_debug("Switched to Min RTT\n");
			set_min_rtt_as_delayn();
			break;
		case MPDCCP_REORDERING_DELAY_MAX_RTT:
			mpdccp_pr_debug("Switched to Max RTT\n");
			set_max_rtt_as_delayn();
			break;
		case MPDCCP_REORDERING_DELAY_SRTT:
			mpdccp_pr_debug("Switched to SRTT\n");
			set_srtt_as_delayn();
			break;
		default:
			mpdccp_pr_debug("Parameter %d unknown, switched to SRTT\n", sysctl_mpdccp_delay_config);
			set_srtt_as_delayn();
			break;
		}
	} else {
		set_srtt_as_delayn();
	}
	return ret;
}

static int proc_mpdccp_accept_prio(struct ctl_table *table, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos)
{
	int ret = proc_dointvec(table, write, buffer, lenp, ppos);

	if(ret == 0)
		mpdccp_set_accept_prio(sysctl_mpdccp_accept_prio);
	return ret;
}

struct ctl_table mpdccp_table[] = {
	{
		.procname = "mpdccp_enabled",
		.data = &mpdccp_enabled,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "mpdccp_path_manager",
		.maxlen = MPDCCP_PM_NAME_MAX,
		.mode = 0644,
		.proc_handler = proc_mpdccp_path_manager,
	},
	{
		.procname = "mpdccp_scheduler",
		.maxlen = MPDCCP_SCHED_NAME_MAX,
		.mode = 0644,
		.proc_handler = proc_mpdccp_scheduler,
	},
	{
		.procname = "mpdccp_reordering",
		.maxlen = MPDCCP_REORDER_NAME_MAX,
		.mode = 0644,
		.proc_handler = proc_mpdccp_reordering,
	},
	{
		.procname = "mpdccp_rtt_config",
		.data = &sysctl_mpdccp_delay_config,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_mpdccp_delay_config,
	},
	{
		.procname = "mpdccp_accept_prio",
		.data = &sysctl_mpdccp_accept_prio,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_mpdccp_accept_prio,
	},
	{
		.procname = "mpdccp_debug",
		.data = &mpdccp_debug,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec,
	},
	{ }
};


int mpdccp_sysctl_init (void)
{
	/* Initialize /proc interface for controlling the solution*/
	mpdccp_sysctl = register_net_sysctl(&init_net, "net/mpdccp", mpdccp_table);
	if (!mpdccp_sysctl) {
		mpdccp_pr_debug("Failed to register sysctl.\n");
		return -1;
	}
	return 0;
}

void mpdccp_sysctl_finish(void)
{
	unregister_net_sysctl_table(mpdccp_sysctl);
}




