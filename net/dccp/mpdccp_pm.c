/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 * Copyright (C) 2018 by Andreas Philipp Matz, Deutsche Telekom AG
 * Copyright (C) 2018 by Markus Amend, Deutsche Telekom AG
 * Copyright (C) 2020 by Frank Reker, Deutsche Telekom AG
 *
 * MPDCCP - Path manager architecture
 *
 * A flexible architecture to load arbitrary path managers. 
 *
 * The code in this file is partly derived from the MPTCP project's 
 * mptcp_pm.c and mptcp_fullmesh.c. Derived code is Copyright (C) 
 * the original authors Christoph Paasch et al.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <linux/module.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <net/addrconf.h>
#include <net/net_namespace.h>
#include <net/netns/mpdccp.h>

#include "ccids/ccid2.h"
#include "dccp.h"
#include <net/mpdccp_link.h>
#include <net/mpdccp.h>
#include "mpdccp.h"
#include "mpdccp_pm.h"


static DEFINE_SPINLOCK(mpdccp_pm_list_lock);
static LIST_HEAD(mpdccp_pm_list);

int mpdccp_pm_setup (void)
{
	int	ret;

	ret = mpdccp_pm_default_register();
	if (ret) {
		mpdccp_pr_error("Failed to register default path manager.\n");
		return ret;
	}
	ret = mpdccp_set_default_path_manager(CONFIG_DEFAULT_MPDCCP_PM);
	if (ret) {
		mpdccp_pr_error("Failed to set default path manager \"%s\".\n", CONFIG_DEFAULT_MPDCCP_PM);
		return ret;
	}
	
	return 0;
}
EXPORT_SYMBOL(mpdccp_pm_setup);

void mpdccp_pm_finish (void)
{
	mpdccp_pm_default_unregister();
}
EXPORT_SYMBOL(mpdccp_pm_finish);


/* Dynamic interface management */


struct mpdccp_pm_ops *mpdccp_pm_find(const char *name)
{
	struct mpdccp_pm_ops *e;

	list_for_each_entry_rcu(e, &mpdccp_pm_list, list) {
		if (strcmp(e->name, name) == 0)
			return e;
	}

	return NULL;
}
EXPORT_SYMBOL(mpdccp_pm_find);

int mpdccp_register_path_manager(struct mpdccp_pm_ops *pm)
{
	int ret = 0;

	/* TODO: Add the path manager to the global list of pm net name spaces 
	PROBLEM: HOW DO WE GET THE NET HERE IN ORDER TO WRITE IT? */
	spin_lock(&mpdccp_pm_list_lock);
	if (mpdccp_pm_find(pm->name)) {
		pr_notice("%s path manager already registered\n", pm->name);
		ret = -EEXIST;
	} else {
		list_add_tail_rcu(&pm->list, &mpdccp_pm_list);
		pr_info("%s path manager registered\n", pm->name);
	}
	spin_unlock(&mpdccp_pm_list_lock);

	return ret;
}
EXPORT_SYMBOL(mpdccp_register_path_manager);

void mpdccp_unregister_path_manager(struct mpdccp_pm_ops *pm)
{
	spin_lock(&mpdccp_pm_list_lock);
	list_del_rcu(&pm->list);
	spin_unlock(&mpdccp_pm_list_lock);

	/* Wait for outstanding readers to complete before the
	 * module gets removed entirely.
	 *
	 * A try_module_get() should fail by now as our module is
	 * in "going" state since no refs are held anymore and
	 * module_exit() handler being called.
	 */
	synchronize_rcu();
}
EXPORT_SYMBOL(mpdccp_unregister_path_manager);

/* Get/set the active path manager */
void mpdccp_get_default_path_manager(char *name)
{
	struct mpdccp_pm_ops *pm;

	BUG_ON(list_empty(&mpdccp_pm_list));

	rcu_read_lock();
	pm = list_entry(mpdccp_pm_list.next, struct mpdccp_pm_ops, list);
	strncpy(name, pm->name, MPDCCP_PM_NAME_MAX);
	rcu_read_unlock();
}
EXPORT_SYMBOL(mpdccp_get_default_path_manager);

int mpdccp_set_default_path_manager(const char *name)
{
	struct mpdccp_pm_ops *pm;
	int ret = -ENOENT;

	spin_lock(&mpdccp_pm_list_lock);
	pm = mpdccp_pm_find(name);
#ifdef CONFIG_MODULES
	if (!pm && capable(CAP_NET_ADMIN)) {
		spin_unlock(&mpdccp_pm_list_lock);

		request_module("mpdccp_%s", name);
		spin_lock(&mpdccp_pm_list_lock);
		pm = mpdccp_pm_find(name);
	}
#endif

	if (pm) {
		list_move(&pm->list, &mpdccp_pm_list);
		ret = 0;
	} else {
		pr_info("%s is not available\n", name);
	}
	spin_unlock(&mpdccp_pm_list_lock);

	return ret;
}
EXPORT_SYMBOL(mpdccp_set_default_path_manager);

/* Manage refcounts on socket close. */
void mpdccp_cleanup_path_manager(struct mpdccp_cb *mpcb)
{
	if (!mpcb->pm_ops) return;
	module_put(mpcb->pm_ops->owner);
}
EXPORT_SYMBOL(mpdccp_cleanup_path_manager);

void mpdccp_init_path_manager(struct mpdccp_cb *mpcb)
{
	struct mpdccp_pm_ops *pm;

	rcu_read_lock();

	list_for_each_entry_rcu(pm, &mpdccp_pm_list, list) {
		if (try_module_get(pm->owner)) {
			mpcb->pm_ops = pm;
			break;
		}
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL(mpdccp_init_path_manager);





