/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 * Copyright (C) 2020 by Frank Reker, Deutsche Telekom AG
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

#include <linux/bitops.h>
#include <linux/capability.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <linux/rtnetlink.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/inetdevice.h>
#include <net/if_inet6.h>
#include <generated/autoconf.h>
#include <linux/list.h>
#include <net/netns/generic.h>
#include <linux/interrupt.h>
#include <asm/processor.h>
#include <asm/uaccess.h>

#include <net/mpdccp_link.h>
#include "mpdccp_link_sysfs.h"

static void mpdccp_link_free (struct mpdccp_link_info*);
static void mlk_free (struct mpdccp_link_info*);
static struct mpdccp_link_info *mlk_alloc (void);
static void mpdccp_link_release_nolock (struct mpdccp_link_info*);

#define mpdccp_pr_debug(format, a...) do { printk (KERN_DEBUG format, ##a); } while (0)
#define mpdccp_pr_info(format, a...) do { printk (KERN_INFO format, ##a); } while (0)
#define mpdccp_pr_error(format, a...) do { printk (KERN_ERR format, ##a); } while (0)

/* ***********************
 * find / get functions
 * ***********************/

static LIST_HEAD(link_list);
int mpdccp_link_net_id = -1;

#if 0

static DEFINE_MUTEX(mpdccp_link_mutex);
#define mlk_lock		mutex_lock (&mpdccp_link_mutex)
#define mlk_unlock	mutex_unlock (&mpdccp_link_mutex)
#define mlk_init

#else

static spinlock_t		mlk_mutex;
static unsigned long	mlk_lf = 0;

static
inline
void
mlk_doinit(void)
{
	spin_lock_init (&mlk_mutex);
}

static
inline
void
mlk_dolock(void)
{
	unsigned long	lf=0;

	if (in_interrupt()) {
		spin_lock_irqsave (&mlk_mutex, lf);
		mlk_lf = lf;
	} else {
		spin_lock (&mlk_mutex);
	}
}

static
inline
void
mlk_dounlock(void)
{
	unsigned long	lf;

	if (in_interrupt()) {
		lf = mlk_lf;
		spin_unlock_irqrestore (&mlk_mutex, lf);
	} else {
		spin_unlock (&mlk_mutex);
	}
}

#define mlk_init mlk_doinit()
#define mlk_lock mlk_dolock()
#define mlk_unlock mlk_dounlock()

#endif



struct mpdccp_link_info*
mpdccp_link_find_by_name (
	struct net	*net,
	const char	*name)
{
	struct mpdccp_link_info	*link;

	mlk_lock;
	list_for_each_entry (link, &link_list, link_list) {
		if (MPDCCP_LINK_TO_NET(link) != net) continue;
		if (!strcmp (link->name, name)) goto found;
	}
	link=NULL;
found:
	//mpdccp_link_get (link);
	mlk_unlock;
	return link;
}
EXPORT_SYMBOL(mpdccp_link_find_by_name);

int mpdccp_link_change_name (struct mpdccp_link_info *link, struct sock *sk) {
	char newname[64];

	snprintf(newname, 64, "%s_%pI4:%u", link->ndev_name,
				&sk->__sk_common.skc_daddr, sk->__sk_common.skc_dport);
	strcpy(link->ndev_name, "mp_prio");
	return mpdccp_link_sysfs_changename(link, newname);
}
EXPORT_SYMBOL(mpdccp_link_change_name);

struct mpdccp_link_info*
mpdccp_link_find_by_dev (
	struct net_device	*dev)
{
	struct mpdccp_link_info	*link;

	if (!dev) return NULL;
	mlk_lock;
	list_for_each_entry (link, &link_list, link_list) {
		if (MPDCCP_LINK_TO_DEV(link) == dev) goto found;
	}
	link = NULL;
found:
	//mpdccp_link_get (link);
	mlk_unlock;
	return link;
}
EXPORT_SYMBOL(mpdccp_link_find_by_dev);

struct mpdccp_link_info*
mpdccp_link_find_by_skb (
	struct net				*net,
	const struct sk_buff	*skb)
{
	struct mpdccp_link_info	*link;
	struct net_device			*ndev;
	
	if (!skb) return NULL;
	if (skb->mark) {
		link = mpdccp_link_find_mark (net, skb->mark);
		if (link) {
			ndev = dev_get_by_index (net, skb->skb_iif);
			mpdccp_pr_debug ("mpdccp_link_find_by_skb(): has found link (%s) by mark "
							"(%x/%x) - skb->iif = %s\n", MPDCCP_LINK_NAME(link),
							link->mpdccp_match_mark, link->mpdccp_match_mask,
							(ndev?ndev->name:"<none>"));
			
			return link;
		}
	}
#if 0		/* this is unsafe - do always use skb_iif instead */
	if (skb->dev) {
		rcu_read_lock();
		ndev = skb->dev;
		if (ndev) dev_hold (ndev);
		rcu_read_unlock();
	} else {
#endif
		ndev = dev_get_by_index (net, skb->skb_iif);
#if 0
	}
#endif
	if (ndev) {
		link = mpdccp_link_find_by_dev (ndev);
		if (!link) {
			mpdccp_pr_debug ("mpdccp_link_find_by_skb(): cannot find by device (%s)\n",
							ndev->name);
		} else {
			mpdccp_pr_debug ("%s(): found link (%s) by device (%s)\n", __func__,
							MPDCCP_LINK_NAME(link), ndev->name);
		}
		mpdccp_link_get (link);
		dev_put (ndev);
		if (link) return link;
	} else {
		mpdccp_pr_debug ("mpdccp_link_find_by_skb(): skb has no input device\n");
	}
	/* yet, we don't match for ip's in skb, use the sk in 
		calling function to get ip's
	 */
	return NULL;
}
EXPORT_SYMBOL(mpdccp_link_find_by_skb);

struct mpdccp_link_info*
mpdccp_link_find_mark (
	struct net	*net,
	u32			mark)
{
	struct mpdccp_link_info	*link;

	if (!mark) return NULL;
	mlk_lock;
	list_for_each_entry (link, &link_list, link_list) {
		if (MPDCCP_LINK_TO_NET(link) != net) continue;
		if (!link->mpdccp_match_mark) continue;
		if ((link->mpdccp_match_mark & link->mpdccp_match_mask) == 
				(mark & link->mpdccp_match_mask)) goto found;
	}
	link=NULL;
found:
	mpdccp_link_get (link);
	mlk_unlock;
	return link;
}
EXPORT_SYMBOL(mpdccp_link_find_mark);


struct mpdccp_link_info*
mpdccp_link_find_ip4 (
	struct net		*net,
	struct in_addr	*saddr,
	struct in_addr	*daddr)
{	
	struct in_ifaddr			*ia;
	struct mpdccp_link_info	*link;

	mlk_lock;
	list_for_each_entry (link, &link_list, link_list) {
		if (!MPDCCP_LINK_ISDEV_VALID(link)) continue;
		if (MPDCCP_LINK_TO_NET(link) != net) continue;
		for (ia = link->ndev->ip_ptr->ifa_list; ia; ia = ia->ifa_next) {
			if (saddr && ia->ifa_local == saddr->s_addr) goto found;
			/* does this make sense??? */
			if (saddr && ia->ifa_address == saddr->s_addr) goto found;
			/* works for PtP-devices only */
			if (daddr && ia->ifa_address == daddr->s_addr) goto found;
		}
	}
	link=NULL;
found:
	mpdccp_link_get (link);
	mlk_unlock;
	return link;
}
EXPORT_SYMBOL(mpdccp_link_find_ip4);


#if IS_ENABLED(CONFIG_IPV6)
#define ipv6cmp(a,b) (memcmp ((a).s6_addr, (b).s6_addr, 16))
#define ipv6eq(a,b) (!ipv6cmp(a,b))
const static u8	v4pref[] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
#define ipv6isv4(a) (!memcmp ((a),v4pref,12))
struct mpdccp_link_info*
mpdccp_link_find_ip6 (
	struct net			*net,
	struct in6_addr	*saddr,
	struct in6_addr	*daddr)
{
	struct inet6_ifaddr		*ifa;
	struct mpdccp_link_info	*link;

	if (saddr && daddr && ipv6isv4(saddr->s6_addr) && ipv6isv4(daddr->s6_addr)) {
		return mpdccp_link_find_ip4 (net, (struct in_addr*)&(saddr->s6_addr[12]), 
													(struct in_addr*)&(daddr->s6_addr[12]));
	} else if (saddr && !daddr && ipv6isv4(saddr->s6_addr)) {
		return mpdccp_link_find_ip4 (net, (struct in_addr*)&(saddr->s6_addr[12]),
													NULL);
	}
	mlk_lock;
	list_for_each_entry (link, &link_list, link_list) {
		if (!MPDCCP_LINK_ISDEV_VALID(link)) continue;
		if (MPDCCP_LINK_TO_NET(link) != net) continue;
		list_for_each_entry(ifa, &(link->ndev->ip6_ptr->addr_list), if_list) {
			if (saddr && ipv6eq (*saddr, ifa->addr)) goto found;
			if (daddr && ipv6eq (*daddr, ifa->peer_addr)) goto found;
		}
	}
	link=NULL;
found:
	mpdccp_link_get (link);
	mlk_unlock;
	return link;
}
EXPORT_SYMBOL(mpdccp_link_find_ip6);
#endif /* IS_ENABLED(CONFIG_IPV6) */




struct mpdccp_link_info*
mpdccp_getfallbacklink (struct net	*net)
{
	struct mpdccp_link_net_data	*linkdata;

	if (!net) net = &init_net;
	if (mpdccp_link_net_id < 0) return NULL;
	linkdata = net_generic (net, mpdccp_link_net_id);
	mpdccp_link_get (linkdata->fallback);
	return linkdata->fallback;
}
EXPORT_SYMBOL(mpdccp_getfallbacklink);

static
int
link_get_next_counter (
	struct net	*net)
{
	struct mpdccp_link_net_data	*linkdata;

	if (!net || mpdccp_link_net_id < 0) return 0;
	linkdata = net_generic (net, mpdccp_link_net_id);
	return atomic_fetch_add (1, &linkdata->counter);
}






/* ***************************
 * link change functions
 * ***************************/

/**
 *	mpdccp_link_change_mpdccp_prio - change prio for mpdccp connections
 *	@dev: device
 *	@mpdccp_prio: prio to set
 *
 *	Change settings of mpdccp priority.
 */
int mpdccp_link_change_mpdccp_prio(struct mpdccp_link_info *link, u32 mpdccp_prio)
{
	if (!link) return 0;
	if (link->mpdccp_prio == mpdccp_prio) return 0;
	link->mpdccp_prio = mpdccp_prio;
	link->config_cnt ++;
	call_mpdccp_link_notifiers(MPDCCP_LINK_CHANGE_PRIO, link);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_prio);

/**
 *	mpdccp_link_change_mpdccp_maxbuf - change maxbuf for mpdccp subflows
 *	@dev: device
 *	@mpdccp_maxbuf: maxbuf to set
 *
 *	Change settings of the max. buffer size of mpdccp subflows.
 */
int mpdccp_link_change_mpdccp_maxbuf(struct mpdccp_link_info *link, u64 mpdccp_maxbuf)
{
	if (link->mpdccp_maxbuf == mpdccp_maxbuf) return 0;
	link->mpdccp_maxbuf = mpdccp_maxbuf;
	link->config_cnt ++;
	call_mpdccp_link_notifiers(MPDCCP_LINK_CHANGE_MAXBUF, link);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_maxbuf);

/**
 *	mpdccp_link_change_mpdccp_T_delay - change T_delay for mpdccp subflows
 *	@dev: device
 *	@mpdccp_T_delay: T_delay to set
 *
 *	Change settings of the delay on peek start.
 */
int mpdccp_link_change_mpdccp_T_delay(struct mpdccp_link_info *link, u32 mpdccp_T_delay)
{
	if (link->mpdccp_T_delay == mpdccp_T_delay) return 0;
	link->mpdccp_T_delay = mpdccp_T_delay;
	link->mpdccp_T_delay_j = mpdccp_T_delay * HZ / 1000;
	link->config_cnt ++;
	call_mpdccp_link_notifiers(MPDCCP_LINK_CHANGE_DELAY, link);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_T_delay);

/**
 *	mpdccp_link_change_mpdccp_T_start_delay - change T_start_delay for mpdccp subflows
 *	@dev: device
 *	@mpdccp_T_start_delay: T_delay to set
 *
 *	Change settings of the delay on stream start.
 */
int mpdccp_link_change_mpdccp_T_start_delay(struct mpdccp_link_info *link, u32 mpdccp_T_delay)
{
	if (link->mpdccp_T_start_delay == mpdccp_T_delay) return 0;
	link->mpdccp_T_start_delay = mpdccp_T_delay;
	link->mpdccp_T_start_delay_j = mpdccp_T_delay * HZ / 1000;
	link->config_cnt ++;
	call_mpdccp_link_notifiers(MPDCCP_LINK_CHANGE_DELAY, link);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_T_start_delay);

/**
 *	mpdccp_link_change_mpdccp_T_lpu - change T_lpu for mpdccp subflows
 *	@dev: device
 *	@mpdccp_T_lpu: T_lpu to set
 *
 *	Change settings of the last path usage (interval between two peeks)
 */
int mpdccp_link_change_mpdccp_T_lpu(struct mpdccp_link_info *link, u32 mpdccp_T_lpu)
{
	if (link->mpdccp_T_lpu == mpdccp_T_lpu) return 0;
	link->mpdccp_T_lpu = mpdccp_T_lpu;
	link->mpdccp_T_lpu_j = mpdccp_T_lpu * HZ / 1000;
	link->config_cnt ++;
	call_mpdccp_link_notifiers(MPDCCP_LINK_CHANGE_LPU, link);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_T_lpu);

/**
 *	mpdccp_link_change_mpdccp_T_lpu_min - change T_lpu_min for mpdccp subflows
 *	@dev: device
 *	@mpdccp_T_lpu: T_lpu to set
 *
 *	Change settings of the last path usage (interval between two peeks)
 */
int mpdccp_link_change_mpdccp_T_lpu_min(struct mpdccp_link_info *link, u32 mpdccp_T_lpu)
{
	if (link->mpdccp_T_lpu_min == mpdccp_T_lpu) return 0;
	link->mpdccp_T_lpu_min = mpdccp_T_lpu;
	link->mpdccp_T_lpu_min_j = mpdccp_T_lpu * HZ / 1000;
	link->config_cnt ++;
	call_mpdccp_link_notifiers(MPDCCP_LINK_CHANGE_LPU, link);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_T_lpu_min);

/**
 *	mpdccp_link_change_mpdccp_lpu_cnt - change lpu_cnt for mpdccp subflows
 *	@dev: device
 *	@mpdccp_lpu_cnt: lpu_cnt to set
 *
 *	Change settings of the last path usage (interval between two peeks)
 */
int mpdccp_link_change_mpdccp_lpu_cnt(struct mpdccp_link_info *link, u32 mpdccp_lpu_cnt)
{
	if (link->mpdccp_lpu_cnt == mpdccp_lpu_cnt) return 0;
	link->mpdccp_lpu_cnt = mpdccp_lpu_cnt;
	link->config_cnt ++;
	call_mpdccp_link_notifiers(MPDCCP_LINK_CHANGE_LPU, link);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_lpu_cnt);

/**
 *	mpdccp_link_change_mpdccp_ignthrottle - ignores throttling if set
 *	@dev: device
 *	@mpdccp_ignthrottle: bool to set
 *
 *	Change settings of mpdccp ignthrottle
 */
int mpdccp_link_change_mpdccp_ignthrottle(struct mpdccp_link_info *link, unsigned int mpdccp_ignthrottle)
{
	if (link->mpdccp_ignthrottle == mpdccp_ignthrottle) return 0;
	link->mpdccp_ignthrottle = mpdccp_ignthrottle;
	link->config_cnt ++;
	call_mpdccp_link_notifiers(MPDCCP_LINK_CHANGE_THROTTLE, link);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_ignthrottle);

/**
 *	mpdccp_link_change_mpdccp_match_mark - change fw mark against to which match incomming connection
 *	@dev: device
 *	@mpdccp_match_mark: fw mark to match
 *
 *	Change fw mark against to which match incomming connection
 */
int mpdccp_link_change_mpdccp_match_mark(struct mpdccp_link_info *link, u32 mpdccp_match_mark)
{
	if (link->mpdccp_match_mark == mpdccp_match_mark) return 0;
	link->mpdccp_match_mark = mpdccp_match_mark;
	link->config_cnt ++;
	call_mpdccp_link_notifiers(MPDCCP_LINK_CHANGE_MARK, link);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_match_mark);

/**
 *	mpdccp_link_change_mpdccp_match_mask - change fw mask against to which match incomming connection
 *	@dev: device
 *	@mpdccp_match_mask: fw mask used for matching
 *
 *	Change fw mask against to which match incomming connection
 */
int mpdccp_link_change_mpdccp_match_mask(struct mpdccp_link_info *link, u32 mpdccp_match_mask)
{
	if (link->mpdccp_match_mask == mpdccp_match_mask) return 0;
	link->mpdccp_match_mask = mpdccp_match_mask;
	link->config_cnt ++;
	call_mpdccp_link_notifiers(MPDCCP_LINK_CHANGE_MARK, link);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_match_mask);

/**
 *	mpdccp_link_change_mpdccp_send_mark - fw mark set in outgoing traffic
 *	@dev: device
 *	@mpdccp_send_mark: fw mark set in outgoing traffic
 *
 *	fw mark set in outgoing traffic
 */
int mpdccp_link_change_mpdccp_send_mark(struct mpdccp_link_info *link, u32 mpdccp_send_mark)
{
	if (link->mpdccp_send_mark == mpdccp_send_mark) return 0;
	link->mpdccp_send_mark = mpdccp_send_mark;
	link->config_cnt ++;
	call_mpdccp_link_notifiers(MPDCCP_LINK_CHANGE_MARK, link);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_send_mark);

/**
 *	mpdccp_link_change_mpdccp_cgstalg - changes the congestion algorithmn for subflow
 *	@dev: device
 *	@buf: the new value
 *	@len: strlen of buf
 *
 *	Change settings of the congestion algorithmn used for mpdccp subflows over
 *	this device.
 */
int mpdccp_link_change_mpdccp_cgstalg(struct mpdccp_link_info *link, const char *buf, size_t len)
{
	if (buf && len == 0) len = strlen (buf);
	if (!buf || (len == 0) || (len == 7 && !strncasecmp (buf, "default", 7))) {
		link->mpdccp_cgstalg[0] = 0;
	} else if (len >= sizeof (link->mpdccp_cgstalg)) {
		mpdccp_pr_debug ("mpdccp_link_change_mpdccp_cgstalg(): cgstalg name >>%.*s<< too long (>%d)\n",
					(int)len, buf, (int)sizeof (link->mpdccp_cgstalg)-1);
		return -E2BIG;
	} else {
		if (!strncasecmp (link->mpdccp_cgstalg, buf, len)) {
			return 0;
		}
		strncpy (link->mpdccp_cgstalg, buf, len);
		link->mpdccp_cgstalg[len]=0;
	}
	link->config_cnt ++;
	call_mpdccp_link_notifiers(MPDCCP_LINK_CHANGE_CGSTCTRL, link);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_cgstalg);

/**
 *	mpdccp_link_change_mpdccp_path_type - path type (lte, wifi, ...)
 *	@dev: device
 *	@mpdccp_path_type: path type (lte, wifi, ...)
 *
 *	fw mark set in outgoing traffic
 */
int mpdccp_link_change_mpdccp_path_type(struct mpdccp_link_info *link, u32 mpdccp_path_type)
{
	if (link->mpdccp_path_type == mpdccp_path_type) return 0;
	link->mpdccp_path_type = mpdccp_path_type;
	link->config_cnt ++;
	call_mpdccp_link_notifiers(MPDCCP_LINK_CHANGE_PATHTYPE, link);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_path_type);

/**
 *	mpdccp_link_change_mpdccp_match_pathtype - path type (lte, wifi, ...)
 *	@dev: device
 *	@mpdccp_match_pathtype: path type (lte, wifi, ...)
 *
 *	fw mark set in outgoing traffic
 */
int mpdccp_link_change_mpdccp_match_pathtype(struct mpdccp_link_info *link, u32 mpdccp_match_pathtype)
{
	if (link->mpdccp_match_pathtype == mpdccp_match_pathtype) return 0;
	link->mpdccp_match_pathtype = mpdccp_match_pathtype;
	link->config_cnt ++;
	call_mpdccp_link_notifiers(MPDCCP_LINK_CHANGE_MATCH_PATHTYPE, link);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_match_pathtype);

/**
 *	mpdccp_link_change_mpdccp_resetstat 
 *	@dev: device
 *	@mpdccp_newbuf: bool to set
 *
 *	reset mpdccp statistics for device
 */
int mpdccp_link_change_mpdccp_resetstat(struct mpdccp_link_info *link)
{
#ifdef CONFIG_MPDCCP_STATS
	link->mpdccp_noavail_hard = 0;
	link->mpdccp_noavail_hard_state = 0;
	link->mpdccp_noavail_hard_pre = 0;
	link->mpdccp_noavail_hard_pf = 0;
	link->mpdccp_noavail_hard_loss = 0;
	link->mpdccp_noavail_nocwnd = 0;
	link->mpdccp_noavail_nospace_maxbuf = 0;
	link->mpdccp_noavail_nospace = 0;
	link->mpdccp_noavail_zerownd = 0;
	link->mpdccp_noavail_nobuf = 0;
	link->mpdccp_noavail_delay = 0;
	link->mpdccp_noavail_start_delay = 0;
	link->mpdccp_noavail_dontreinject = 0;
	link->mpdccp_selected_delayed = 0;
	link->mpdccp_selected_onlypath = 0;
	link->mpdccp_selected_shutdown = 0;
	link->mpdccp_selected_backup = 0;
	link->mpdccp_selected_good = 0;
	link->mpdccp_selected_best = 0;
	link->mpdccp_selected_fallback = 0;
	link->mpdccp_selected = 0;
#endif
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_change_mpdccp_resetstat);




/* ***********************
 * add / del functions
 * ***********************/

static void link_ref_release (struct kref *ref)
{	
	struct mpdccp_link_info	*link = container_of (ref, struct mpdccp_link_info, kref);
	mpdccp_link_free (link);
}

int
mpdccp_link_add (
	struct mpdccp_link_info	**link_info,
	struct net					*net,
	struct net_device			*ndev,
	const char					*name)
{
	struct mpdccp_link_info	*link = NULL;
	int							ret;

	if (name && !*name) {
		mpdccp_pr_error ("mpdccp_link_add(): invalid empty link name\n");
		return -EINVAL;
	}
	if (name && strlen (name) >= sizeof (link->name)) {
		mpdccp_pr_error ("mpdccp_link_add(): name >>%s<< too long (max %d)\n", name, 
					(int)sizeof (link->name)-1);
		return -ERANGE;
	}
	if (!net && !ndev) return -EINVAL;
	if (!net) net = read_pnet(&(ndev->nd_net));
	if (!net) net = &init_net;
	if (name && mpdccp_link_find_by_name (net, name)) {
		mpdccp_pr_error ("mpdccp_link_add(): link with name >>%s<< already exists\n", name);
		return -EEXIST;
	}
	if (ndev) {
		mpdccp_pr_info ("mpdccp_link:: create new device link (dev=%s)\n", ndev->name);
	} else if (name) {
		mpdccp_pr_info ("mpdccp_link:: create new named link (%s)\n", name);
	} else {
		mpdccp_pr_info ("mpdccp_link:: create new unnamed link\n");
	}
	link = mlk_alloc ();
	if (!link) return -ENOMEM;
	*link = (struct mpdccp_link_info) { .ndev = ndev, .net = net };
	if (name) strcpy (link->name, name);
	if (ndev) {
		link->is_devlink = 1;
		strcpy (link->ndev_name, MPDCCP_LINK_TO_DEV(link)->name);
	}
	if (!ndev && !name) {
		link->is_released = 1;
	}
	link->id = link_get_next_counter (net);
	link->mpdccp_prio = 3;
	ret = mpdccp_link_sysfs_add (link);
	if (ret < 0) {
		mpdccp_pr_error ("mpdccp_link_add(): error adding sysfs entry\n");
		mlk_free (link);
		return ret;
	}
	kref_init (&link->kref);
	mlk_lock;
	list_add (&link->link_list, &link_list);
	link->is_linked = 1;
	mlk_unlock;
	if (link_info) *link_info = link;
	mpdccp_pr_info ("mpdccp_link_add: link %d successfully created", link->id);
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_add);

int
mpdccp_link_copy (
	struct mpdccp_link_info	**new_link,
	struct mpdccp_link_info	*old_link)
{
	int	ret;

	if (!new_link || !old_link) return -EINVAL;
	ret = mpdccp_link_add (new_link, old_link->net, NULL, NULL);
	if (ret < 0) {
		mpdccp_pr_error ("mpdccp_link_copy(): error creating new link: %d", ret);
		return ret;
	}
	/* copy old configuration */
	memcpy (&(*new_link)->start_config, &old_link->start_config,
				&old_link->end_config - &old_link->start_config);
	(*new_link)->config_cnt = old_link->config_cnt+1;
	return 0;
}
EXPORT_SYMBOL(mpdccp_link_copy);

void
mpdccp_link_get (
	struct mpdccp_link_info	*link)
{
	if (!link) return;
	kref_get (&link->kref);
#if 0
	//mpdccp_pr_debug ("mpdccp_link:: ref counter (%s) incremented to %d\n",
	//	MPDCCP_LINK_NAME(link), MPDCCP_LINK_REFCOUNT(link));
	printk ("mpdccp_link:: ref counter (%s) incremented to %d\n",
		MPDCCP_LINK_NAME(link), MPDCCP_LINK_REFCOUNT(link));
#endif
#ifdef CONFIG_MPDCCP_STATS
	link->allref++;
#endif
}
EXPORT_SYMBOL(mpdccp_link_get);

void
mpdccp_link_put (
	struct mpdccp_link_info	*link)
{
	if (!link) return;
#if 0
	//mpdccp_pr_debug ("mpdccp_link:: ref counter (%s) decremented from %d\n",
	//	MPDCCP_LINK_NAME(link), MPDCCP_LINK_REFCOUNT(link));
	printk ("mpdccp_link:: ref counter (%s) decremented from %d\n",
		MPDCCP_LINK_NAME(link), MPDCCP_LINK_REFCOUNT(link));
#endif
	kref_put (&link->kref, link_ref_release);
}
EXPORT_SYMBOL(mpdccp_link_put);

static
struct mpdccp_link_info *
mlk_alloc ()
{
	/* we should use a kind of caching */
	return (struct mpdccp_link_info*) kmalloc (sizeof (struct mpdccp_link_info), GFP_KERNEL);
}
	
static
void
mlk_free (
	struct mpdccp_link_info	*link)
{
	if (!link) return;
	kfree (link);
}

static
void
mpdccp_link_free (
	struct mpdccp_link_info	*link)
{
	if (!link) return;
	//mlk_lock;
	if (!link->is_released) {
		mpdccp_pr_info ("mpdccp_link:: link not released yet (%s) ref cnt: %d",
				MPDCCP_LINK_NAME(link), MPDCCP_LINK_REFCOUNT(link));
		
		if(strcmp(link->ndev_name, "mp_prio")) {
			mpdccp_link_get (link);
			return;
		}
		mpdccp_link_release_nolock(link);
	}
	if (MPDCCP_LINK_ISDEV(link)) {
		mpdccp_pr_info ("mpdccp_link:: device link freed (dev=%s)\n", link->ndev_name);
	} else {
		mpdccp_pr_info ("mpdccp_link:: named link %s freed\n", link->name);
	}
	mlk_free (link);
	//mlk_unlock;
}	


void
mpdccp_link_release (
	struct mpdccp_link_info	*link)
{
	mpdccp_pr_info ("mpdccp_link:: named link %s released\n", link->name);
	if (!link) return;
	mlk_lock;
	mpdccp_link_release_nolock (link);
	mlk_unlock;
}

static
void
mpdccp_link_release_nolock (
	struct mpdccp_link_info	*link)
{
	if (!link) return;
	if (link->is_linked) {
		list_del (&link->link_list);
		link->is_linked = 0;
	}
	if (MPDCCP_LINK_ISDEV(link)) {
		mpdccp_pr_info ("mpdccp_link:: device link released (dev=%s)\n", link->ndev_name);
	} else {
		mpdccp_pr_info ("mpdccp_link:: named link %s released\n", link->name);
	}
	mpdccp_link_sysfs_del (link);
	link->ndev = NULL;
	link->is_released = 1;
	mpdccp_link_put (link);
}


/* **************************
 * react on device notifiers 
 * **************************/

static int link_ndev_event (struct notifier_block *, unsigned long, void*);

static struct notifier_block mpdccp_link_netdev_notifier = {
	.notifier_call = link_ndev_event,
};


static
int
link_ndev_event (nblk, event, ptr)
	struct notifier_block	*nblk;
	unsigned long		event;
	void			*ptr;
{
	struct net_device	*ndev;

	ndev = netdev_notifier_info_to_dev (ptr);
	if (!ndev) return NOTIFY_DONE;
	dev_hold (ndev);
	
	switch (event) {
	case NETDEV_REGISTER:
		mpdccp_link_add (NULL, NULL, ndev, NULL);
		break;
	case NETDEV_UNREGISTER:
		mpdccp_link_release (MPDCCP_LINK_FROM_DEV(ndev));
		break;
	case NETDEV_CHANGENAME:
		mpdccp_link_sysfs_changedevname (MPDCCP_LINK_FROM_DEV(ndev));
		break;
	}
	dev_put (ndev);
	return NOTIFY_DONE;
}




/* ************************
 * notifier functions
 * ************************/

static RAW_NOTIFIER_HEAD(mpdccp_link_chain);


int
register_mpdccp_link_notifier (
	struct notifier_block	*nb)
{
	int	ret;

	rtnl_lock();
	ret = raw_notifier_chain_register(&mpdccp_link_chain, nb);
	rtnl_unlock();
	return ret;
}
EXPORT_SYMBOL(register_mpdccp_link_notifier);


int
unregister_mpdccp_link_notifier (
	struct notifier_block	*nb)
{
	int	ret;

	rtnl_lock();
	ret = raw_notifier_chain_unregister(&mpdccp_link_chain, nb);
	rtnl_unlock();
	return ret;
}
EXPORT_SYMBOL(unregister_mpdccp_link_notifier);

int
call_mpdccp_link_notifiers (
	unsigned long				val,
	struct mpdccp_link_info	*link)
{
	int	ret;

	struct mpdccp_link_notifier_info info = { .link_info = link, };
	if (!link) return 0;
	//mlk_lock;
	if (MPDCCP_LINK_ISDEV(link)) {
		if (!MPDCCP_LINK_ISDEV_VALID (link)) {
			//mlk_unlock;
			return 0;
		}
		info.ndev = MPDCCP_LINK_TO_DEV (link);
	}
	ret = raw_notifier_call_chain(&mpdccp_link_chain, val, &info);
	//mlk_unlock;
	return ret;
}
EXPORT_SYMBOL(call_mpdccp_link_notifiers);

/*
* Connection ID implementation. 
* Here uniqueness is guaranteed by keeping track of all assigned CIDs in memory.
* When a new CID is generated, we loop the list to make sure it's unique.
* There are other, more performant ways to do this.
*/

struct mpdccp_link_cidb {
	/* List of local MPDCCP connection IDs */
	struct list_head list;
	u32 cid;
};

struct list_head __rcu cid_list;
spinlock_t cid_list_lock;

u32 mpdccp_link_generate_cid()
{
    bool unique = false;
    struct mpdccp_link_cidb *mcid, *ptr;
    mcid = kmalloc(sizeof(struct mpdccp_link_cidb), GFP_ATOMIC);
    if (!mcid)
        return 0;

    spin_lock_bh(&cid_list_lock);
    while (!unique || !mcid->cid) {
        mcid->cid = get_random_u32();
        unique = true;

        list_for_each_entry(ptr, &cid_list, list) {
            if (ptr->cid == mcid->cid) {
                unique = false;
                break;
            }
        }
    }
    
    list_add_tail_rcu(&mcid->list, &cid_list);
    spin_unlock_bh(&cid_list_lock);
	mpdccp_pr_debug("generated new CID: %u", mcid->cid);
    return mcid->cid;
}
EXPORT_SYMBOL(mpdccp_link_generate_cid);

void mpdccp_link_free_cid(u32 cid){
    struct mpdccp_link_cidb *ptr;
	if(!cid) return;
    spin_lock_bh(&cid_list_lock);
    list_for_each_entry(ptr, &cid_list, list) {
        if (ptr->cid == cid) {
            list_del_rcu(&ptr->list);
            INIT_LIST_HEAD(&ptr->list);
            kfree(ptr);
            break;
        }
    }
    spin_unlock_bh(&cid_list_lock);
	mpdccp_pr_debug("freed CID: %u", cid);
}
EXPORT_SYMBOL(mpdccp_link_free_cid);

static
int
link_net_init (
	struct net	*net)
{
	struct mpdccp_link_net_data	*linkdata;
	int									ret;

	if (!net || mpdccp_link_net_id < 0) return 0;
	mpdccp_pr_info ("mpdccp_link:: new network namespace created\n");
	linkdata = net_generic (net, mpdccp_link_net_id);
	*linkdata = (struct mpdccp_link_net_data) { .net = net };
	atomic_set (&linkdata->counter, 0);
	mpdccp_link_sysfs_netinit (linkdata);
	ret = mpdccp_link_add (&linkdata->fallback, net, NULL, "fallback");
	if (ret < 0) {
		printk ("mpdccp_link::net_init: error creating fallback link: %d\n", ret);
	}
	return 0;
}

static
void
link_del_by_net (
	struct net	*net)
{
	struct mpdccp_link_info	*link, *tmp;

	mlk_lock;
	list_for_each_entry_safe (link, tmp, &link_list, link_list) {
		if (!MPDCCP_LINK_TO_NET(link)) continue;
		if (MPDCCP_LINK_TO_NET(link) != net) continue;
		/* only non devices */
		if (MPDCCP_LINK_ISDEV(link)) continue;
		/* delete it manually to avoid dead lock */
	   list_del (&link->link_list);
		link->is_linked = 0;
		mpdccp_link_release_nolock (link);
	}
	mlk_unlock;
}

static
void
link_net_invalid (
	struct net	*net)
{
	struct mpdccp_link_info	*link, *tmp;

	mlk_lock;
	list_for_each_entry_safe (link, tmp, &link_list, link_list) {
		if (!MPDCCP_LINK_TO_NET(link)) continue;
		if (MPDCCP_LINK_TO_NET(link) != net) continue;
		link->net = NULL;
	}
	mlk_unlock;
}


static
void
link_net_exit (
	struct net	*net)
{
	struct mpdccp_link_net_data	*linkdata;

	if (!net || mpdccp_link_net_id < 0) return;
	mpdccp_pr_info ("mpdccp_link:: network namespace will be destroyed\n");
	link_del_by_net (net);
	link_net_invalid (net);
	linkdata = net_generic (net, mpdccp_link_net_id);
	mpdccp_link_sysfs_netexit (linkdata);
	*linkdata = (struct mpdccp_link_net_data) { .fallback = NULL };
}


static struct pernet_operations link_net_ops = {
	.id = &mpdccp_link_net_id,
	.init = link_net_init,
	.exit = link_net_exit,
	.size = sizeof (struct mpdccp_link_net_data),
};



static
int
__init
mpdccp_link_module_init (void)
{
	int	ret;
	mpdccp_pr_info ("mpdccp_link_module_init()\n");
	mlk_init;
	ret = mpdccp_link_sysfs_init ();
	if (ret < 0) {
		mpdccp_pr_error ("mpdccp_link: error in mpdccp_link_sysfs_init(): %d\n", ret);
		return ret;
	}
	ret = register_pernet_subsys (&link_net_ops);
	if (ret < 0) {
		mpdccp_pr_error ("mpdccp_link: error registering pernet subsystem: %d\n", ret);
		return ret;
	}
	printk ("mpdccp_link_net_id = %d\n", mpdccp_link_net_id);
	ret = register_netdevice_notifier (&mpdccp_link_netdev_notifier);
	if (ret < 0) {
		mpdccp_pr_error ("mpdccp_link: error in register_netdevice_notifier(): %d\n", ret);
		return ret;
	}

    INIT_LIST_HEAD(&cid_list);
    spin_lock_init(&cid_list_lock);

	mpdccp_pr_info ("mpdccp_link_module_init() - done\n");
	return 0;
}

static
void
__exit
mpdccp_link_module_exit (void)
{
	unregister_netdevice_notifier (&mpdccp_link_netdev_notifier);
	unregister_pernet_subsys (&link_net_ops);
	mpdccp_link_sysfs_exit ();
}




module_init (mpdccp_link_module_init);
module_exit (mpdccp_link_module_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frank Reker <frank@reker.net>");
MODULE_VERSION("3");
MODULE_DESCRIPTION("Link Information for Scheduling");





/*
 * Overrides for XEmacs and vim so that we get a uniform tabbing style.
 * XEmacs/vim will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-indent-level: 3
 * c-basic-offset: 3
 * tab-width: 3
 * End:
 * vim:tw=0:ts=3:wm=0:
 */
