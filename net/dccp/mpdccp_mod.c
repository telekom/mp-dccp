/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 * Copyright (C) 2017 by Andreas Philipp Matz, Deutsche Telekom AG
 * Copyright (C) 2017 by Markus Amend, Deutsche Telekom AG
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
#include <net/mpdccp.h>

#include "mpdccp.h"
#include "mpdccp_scheduler.h"
#include "mpdccp_reordering.h"
#include "mpdccp_pm.h"


int mpdccp_enabled = 1;
module_param(mpdccp_enabled, int, 0644);
MODULE_PARM_DESC(mpdccp_enabled, "Enable MPDCCP");
EXPORT_SYMBOL(mpdccp_enabled);

bool mpdccp_debug;
module_param(mpdccp_debug, bool, 0644);
MODULE_PARM_DESC(mpdccp_debug, "Enable debug messages");
EXPORT_SYMBOL(mpdccp_debug);

bool mpdccp_accept_prio;
module_param(mpdccp_accept_prio, bool, 0644);
MODULE_PARM_DESC(mpdccp_accept_prio, "Accept priority from incoming mp_prio options");
EXPORT_SYMBOL(mpdccp_accept_prio);

int mpdccp_sysctl_init (void);
int mpdccp_ctrl_init (void);
void mpdccp_sysctl_finish(void);
void mpdccp_ctrl_finish(void);


/* General initialization of MPDCCP */
static int __init mpdccp_register(void)
{
	int ret = 0;
	
	mpdccp_pr_debug ("register MPDCCP\n");
	ret = mpdccp_init_funcs ();
	if (ret) {
		mpdccp_pr_error ("Failed to initialize protocol functions.\n");
		goto err_ctrl_init;
	}
	
	ret = mpdccp_ctrl_init ();
	if (ret) {
		mpdccp_pr_error("Failed to initialize ctrl structures.\n");
		goto err_ctrl_init;
	}

	ret = mpdccp_pm_setup ();
	if (ret) {
		mpdccp_pr_error("Failed to setup path manager\n");
		goto err_set_pm;
	}	

	/* Initialize scheduler */
	ret = mpdccp_scheduler_setup ();
	if (ret < 0) 
		goto err_scheduler;

	ret = mpdccp_reordering_setup ();
	if (ret < 0)
		goto err_register_reorder;


	/* Initialize /proc interface for controlling the solution*/
	ret = mpdccp_sysctl_init ();
	if (ret) {
		mpdccp_pr_error ("Failed to register sysctl.\n");
		goto err_register_sysctl;
	}
	
	pr_info("MPDCCP: %s release %s", MPDCCP_RELEASE_TYPE, MPDCCP_VERSION);

out:
	return ret;

err_register_sysctl:
err_register_reorder:
	mpdccp_reordering_finish();
err_set_pm:
	mpdccp_pm_finish();
err_scheduler:
	mpdccp_ctrl_finish();
err_ctrl_init:
	mpdccp_pr_error ("Failed to initialize MPDCCP\n");
goto out;
}

static void mpdccp_unregister(void)
{
	/* TODO: Tear down connections */
	
	mpdccp_sysctl_finish();
	mpdccp_pm_finish();
	mpdccp_reordering_finish();
	mpdccp_ctrl_finish();
	mpdccp_deinit_funcs ();
}

module_init(mpdccp_register);
module_exit(mpdccp_unregister);

MODULE_AUTHOR("Andreas Ph. Matz");
MODULE_AUTHOR("Frank Reker");
MODULE_AUTHOR("Romeo Cane");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Multipath DCCP");
MODULE_VERSION(MPDCCP_VERSION);
