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

#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <net/mpdccp_link.h>
#include <linux/rtnetlink.h>
#include <net/netns/generic.h>
#include <linux/sched/signal.h>
#include "mpdccp_link_sysfs.h"


static const char fmt_hex[] = "%#x\n";
static const char fmt_dec[] = "%d\n";
static const char fmt_ulong[] = "%lu\n";
static const char fmt_int[] = "%d\n";
static const char fmt_uint[] = "%u\n";
static const char fmt_u32[] = "%u\n";
static const char fmt_u64[] = "%llu\n";
static const char fmt_str[] = "%s\n";

#define mpdccp_pr_debug(format, a...) do { printk (KERN_DEBUG format, ##a); } while (0)
#define mpdccp_pr_info(format, a...) do { printk (KERN_INFO format, ##a); } while (0)
#define mpdccp_pr_error(format, a...) do { printk (KERN_ERR format, ##a); } while (0)

static void null_kobj_release(struct kobject *kobj)
{
	/* realy nothing to be done, because refcounter is not used */
}

static
ssize_t
link_sys_store (
	struct kobject				*kobj,
	struct kobj_attribute	*attr,
	const char					*buf,
	size_t						len,
	int							(*set)(struct mpdccp_link_info *, const char *, size_t))
{
	struct net					*net;
	struct mpdccp_link_info	*link;
	int							ret = 0;

	link = container_of (kobj, struct mpdccp_link_info, kobj);
	net = MPDCCP_LINK_TO_NET (link);
	if (!net) return -EINVAL;

	if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
		return -EPERM;

	if (!rtnl_trylock())
		return restart_syscall();

	ret = (*set)(link, buf, len);

	rtnl_unlock();
	return (ret==0) ? len : ret;
}


#define SHOW_ATTR(name,fmt) \
	static \
	ssize_t \
	link_sys_show_attr_##name ( \
		struct kobject				*kobj, \
		struct kobj_attribute	*attr, \
		char							*buf) \
	{ \
		struct mpdccp_link_info	*link; \
		link = container_of (kobj, struct mpdccp_link_info, kobj); \
		return sprintf (buf, fmt, link->name); \
	}

#define STORE_ATTR(name,setfunc) \
	static \
	ssize_t \
	link_sys_store_attr_##name ( \
		struct kobject				*kobj, \
		struct kobj_attribute	*attr, \
		const char					*buf, \
		size_t						count) \
	{ \
		return link_sys_store (kobj, attr, buf, count, setfunc); \
	}

#define STORE_ATTR_SCAN(name,fmt,typ,setfunc) \
	static \
	int \
	link_sys_store_scan_attr_##name ( \
		struct mpdccp_link_info	*link, \
		const char					*buf, \
		size_t						count) \
	{ \
		typ	val; \
		sscanf (buf, fmt, &val); \
		return setfunc (link, val); \
	} \
	STORE_ATTR(name,link_sys_store_scan_attr_##name);
	


#define MKATTR_RO(name) \
	static struct kobj_attribute name##_attribute = \
			__ATTR(name, 0444, link_sys_show_attr_##name, NULL);

#define MKATTR_RW(name) \
	static struct kobj_attribute name##_attribute = \
			__ATTR(name, 0644, link_sys_show_attr_##name, link_sys_store_attr_##name);

#define MKATTR_WO(name) \
	static struct kobj_attribute name##_attribute = \
			__ATTR(name, 0200, NULL, link_sys_store_attr_##name);


#define MLATTR_RO(name,fmt) \
	SHOW_ATTR(name,fmt)\
	MKATTR_RO(name)
#define MLATTR_RW(name,fmt,typ) \
	SHOW_ATTR(name,fmt)\
	STORE_ATTR_SCAN(name,fmt,typ,mpdccp_link_change_##name)\
	MKATTR_RW(name)

MLATTR_RO(id,fmt_int)
MLATTR_RO(config_cnt,fmt_u64)
#ifdef CONFIG_MPDCCP_STATS
MLATTR_RO(allref,fmt_u64)
#endif
MLATTR_RW(mpdccp_prio,fmt_u32,u32)
MLATTR_RW(mpdccp_maxbuf,fmt_u64,u64)
MLATTR_RW(mpdccp_T_delay,fmt_u32,u32)
MLATTR_RW(mpdccp_T_start_delay,fmt_u32,u32)
MLATTR_RW(mpdccp_T_lpu,fmt_u32,u32)
MLATTR_RW(mpdccp_T_lpu_min,fmt_u32,u32)
MLATTR_RW(mpdccp_lpu_cnt,fmt_u32,u32)
MLATTR_RW(mpdccp_ignthrottle,fmt_uint,unsigned int)
MLATTR_RW(mpdccp_match_mark,fmt_u32,u32)
MLATTR_RW(mpdccp_match_mask,fmt_u32,u32)
MLATTR_RW(mpdccp_send_mark,fmt_u32,u32)
MLATTR_RW(mpdccp_path_type,fmt_u32,u32)
MLATTR_RW(mpdccp_match_pathtype,fmt_u32,u32)
MLATTR_RO(mpdccp_rx_packets,fmt_u64)
MLATTR_RO(mpdccp_rx_bytes,fmt_u64)
MLATTR_RO(mpdccp_tx_packets,fmt_u64)
MLATTR_RO(mpdccp_tx_bytes,fmt_u64)


static
int
link_sys_store_scan_attr_mpdccp_cgstalg (
	struct mpdccp_link_info	*link,
	const char					*buf,
	size_t						len)
{
	/* ignore trailing newline */
	if (len >  0 && buf[len - 1] == '\n')
		--len;
	return mpdccp_link_change_mpdccp_cgstalg(link, buf, len);
}
STORE_ATTR(mpdccp_cgstalg,link_sys_store_scan_attr_mpdccp_cgstalg);

static
ssize_t
link_sys_show_attr_mpdccp_cgstalg (
	struct kobject				*kobj,
	struct kobj_attribute	*attr,
	char							*buf)
{
	struct mpdccp_link_info	*link;
	ssize_t						ret;

	link = container_of (kobj, struct mpdccp_link_info, kobj);
	if (!rtnl_trylock())
		return restart_syscall();
	if (*link->mpdccp_cgstalg) {
		ret = sprintf(buf, "%s\n", link->mpdccp_cgstalg);
	} else {
		ret = sprintf(buf, "default\n");
	}
	rtnl_unlock();
	return ret;
}
MKATTR_RW(mpdccp_cgstalg)

static
ssize_t
link_sys_show_attr_refcount (
	struct kobject				*kobj,
	struct kobj_attribute	*attr,
	char							*buf)
{
	struct mpdccp_link_info	*link;
	link = container_of (kobj, struct mpdccp_link_info, kobj);
	return sprintf (buf, "%u\n", (unsigned)MPDCCP_LINK_REFCOUNT(link));
}
MKATTR_RO(refcount)

static
ssize_t
link_sys_show_attr_link_name (
	struct kobject				*kobj,
	struct kobj_attribute	*attr,
	char							*buf)
{
	struct mpdccp_link_info	*link;
	link = container_of (kobj, struct mpdccp_link_info, kobj);
	return sprintf (buf, "%s\n", MPDCCP_LINK_NAME(link));
}
MKATTR_RO(link_name)

static
ssize_t
link_sys_show_attr_is_dev_link (
	struct kobject				*kobj,
	struct kobj_attribute	*attr,
	char							*buf)
{
	struct mpdccp_link_info	*link;
	link = container_of (kobj, struct mpdccp_link_info, kobj);
	return sprintf (buf, "%d\n", MPDCCP_LINK_ISDEV(link) ? 1 : 0);
}
MKATTR_RO(is_dev_link)

static struct attribute *mpdccp_link_sys_attrs[] = {
	&id_attribute.attr,
	&config_cnt_attribute.attr,
	&refcount_attribute.attr,
#ifdef CONFIG_MPDCCP_STATS
	&allref_attribute.attr,
#endif
	&link_name_attribute.attr,
	&is_dev_link_attribute.attr,
	&mpdccp_prio_attribute.attr,
	&mpdccp_maxbuf_attribute.attr,
	&mpdccp_T_delay_attribute.attr,
	&mpdccp_T_start_delay_attribute.attr,
	&mpdccp_T_lpu_attribute.attr,
	&mpdccp_T_lpu_min_attribute.attr,
	&mpdccp_lpu_cnt_attribute.attr,
	&mpdccp_ignthrottle_attribute.attr,
	&mpdccp_match_mark_attribute.attr,
	&mpdccp_match_mask_attribute.attr,
	&mpdccp_send_mark_attribute.attr,
	&mpdccp_cgstalg_attribute.attr,
	&mpdccp_path_type_attribute.attr,
	&mpdccp_match_pathtype_attribute.attr,
	&mpdccp_rx_packets_attribute.attr,
	&mpdccp_rx_bytes_attribute.attr,
	&mpdccp_tx_packets_attribute.attr,
	&mpdccp_tx_bytes_attribute.attr,
	NULL,
};

/* extra attributes */
static
int
link_sys_store_scan_attr_name (
	struct mpdccp_link_info	*link,
	const char					*buf,
	size_t						count)
{
	char		name[sizeof(link->name)];
	int		ret;
	size_t	len = count;

	if (len >  0 && buf[len - 1] == '\n') --len;
	if (len > sizeof (name)-1) return -EINVAL;
	strncpy (name, buf, len);
	name[len]=0;
	mpdccp_pr_debug ("mpdccp_link_sysfs_changename(): %s -> %s(%d)\n", link->name, name, (int)len);
	ret = mpdccp_link_sysfs_changename (link, name);
	if (ret < 0) return ret;
	return count;
}
STORE_ATTR(name,link_sys_store_scan_attr_name);
SHOW_ATTR(name,fmt_str);
MKATTR_RW(name);
MLATTR_RO(ndev_name, fmt_str);
static struct attribute *mpdccp_link_sys_name_attrs[] = {
	&name_attribute.attr,
	NULL,
};
static struct attribute *mpdccp_link_sys_devname_attrs[] = {
	&ndev_name_attribute.attr,
	NULL,
};
static struct attribute_group mpdccp_link_sys_name_attr_group = {
	.attrs = mpdccp_link_sys_name_attrs,
};
static struct attribute_group mpdccp_link_sys_devname_attr_group = {
	.attrs = mpdccp_link_sys_devname_attrs,
};



#ifdef CONFIG_MPDCCP_STATS
MLATTR_RO(mpdccp_noavail_hard, fmt_u64)
MLATTR_RO(mpdccp_noavail_hard_state, fmt_u64)
MLATTR_RO(mpdccp_noavail_hard_pre, fmt_u64)
MLATTR_RO(mpdccp_noavail_hard_pf, fmt_u64)
MLATTR_RO(mpdccp_noavail_hard_loss, fmt_u64)
MLATTR_RO(mpdccp_noavail_nocwnd, fmt_u64)
MLATTR_RO(mpdccp_noavail_nospace_maxbuf, fmt_u64)
MLATTR_RO(mpdccp_noavail_nospace, fmt_u64)
MLATTR_RO(mpdccp_noavail_zerownd, fmt_u64)
MLATTR_RO(mpdccp_noavail_nobuf, fmt_u64)
MLATTR_RO(mpdccp_noavail_delay, fmt_u64)
MLATTR_RO(mpdccp_noavail_start_delay, fmt_u64)
MLATTR_RO(mpdccp_noavail_dontreinject, fmt_u64)
MLATTR_RO(mpdccp_selected_delayed, fmt_u64)
MLATTR_RO(mpdccp_selected_onlypath, fmt_u64)
MLATTR_RO(mpdccp_selected_shutdown, fmt_u64)
MLATTR_RO(mpdccp_selected_backup, fmt_u64)
MLATTR_RO(mpdccp_selected_good, fmt_u64)
MLATTR_RO(mpdccp_selected_best, fmt_u64)
MLATTR_RO(mpdccp_selected_fallback, fmt_u64)
MLATTR_RO(mpdccp_selected, fmt_u64)


static
ssize_t
link_sys_store_attr_mpdccp_resetstat (
	struct kobject				*kobj,
	struct kobj_attribute	*attr,
	const char					*buf,
	size_t						count)
{
	struct mpdccp_link_info	*link = container_of (kobj, struct mpdccp_link_info, kobj);
	unsigned int				ret;
	sscanf (buf, "%u", &ret);
	if (ret != 0) {
		mpdccp_link_change_mpdccp_resetstat (link);
	}
	return count;
}
MKATTR_WO(mpdccp_resetstat)

static struct attribute *mpdccp_link_stat_sys_attrs[] = {
	&mpdccp_resetstat_attribute.attr,
	&mpdccp_noavail_hard_attribute.attr,
	&mpdccp_noavail_hard_state_attribute.attr,
	&mpdccp_noavail_hard_pre_attribute.attr,
	&mpdccp_noavail_hard_pf_attribute.attr,
	&mpdccp_noavail_hard_loss_attribute.attr,
	&mpdccp_noavail_nocwnd_attribute.attr,
	&mpdccp_noavail_nospace_maxbuf_attribute.attr,
	&mpdccp_noavail_nospace_attribute.attr,
	&mpdccp_noavail_zerownd_attribute.attr,
	&mpdccp_noavail_nobuf_attribute.attr,
	&mpdccp_noavail_delay_attribute.attr,
	&mpdccp_noavail_start_delay_attribute.attr,
	&mpdccp_noavail_dontreinject_attribute.attr,
	&mpdccp_selected_delayed_attribute.attr,
	&mpdccp_selected_onlypath_attribute.attr,
	&mpdccp_selected_shutdown_attribute.attr,
	&mpdccp_selected_backup_attribute.attr,
	&mpdccp_selected_good_attribute.attr,
	&mpdccp_selected_best_attribute.attr,
	&mpdccp_selected_fallback_attribute.attr,
	&mpdccp_selected_attribute.attr,
	NULL,
};

static struct attribute_group mpdccp_link_stat_sys_attr_group = {
	.name = "statistics",
	.attrs = mpdccp_link_stat_sys_attrs,
};

#endif	/* CONFIG_MPDCCP_STATS */


static
const
void *
link_namespace (
	struct kobject	*kobj)
{
	struct mpdccp_link_info	*link = container_of (kobj, struct mpdccp_link_info, kobj);
	return MPDCCP_LINK_TO_NET (link);
}




static struct kobject *mpdccp_link_sys_base_kobj = NULL;

#if 0
static void link_kobj_release(struct kobject *kobj)
{
	struct mpdccp_link_info	*link = container_of (kobj, struct mpdccp_link_info, kobj);
	mpdccp_link_release (link);
}
#endif

static struct kobj_type link_kobj_ktype = {
	//.release   = link_kobj_release,
	.release   = null_kobj_release,	/* ref counter is not used, so it is ok */
	.sysfs_ops = &kobj_sysfs_ops,
	.namespace = link_namespace,
	.default_attrs = mpdccp_link_sys_attrs,
};


int
mpdccp_link_sysfs_add (
	struct mpdccp_link_info	*link)
{
	struct kobject					*devkobj;
	int								ret;
	struct mpdccp_link_net_data	*ld = NULL;

	if (!link) return -EINVAL;
	ret = kobject_init_and_add (&link->kobj, &link_kobj_ktype, mpdccp_link_sys_base_kobj, "%d", link->id);
	if (ret < 0) {
		mpdccp_pr_error ("error in kobject_add(): %d\n", ret);
		return ret;
	}
	if (MPDCCP_LINK_ISDEV(link)) {
		sysfs_create_group(&link->kobj, &mpdccp_link_sys_devname_attr_group);	/* ignore error */
	} else {
		sysfs_create_group(&link->kobj, &mpdccp_link_sys_name_attr_group);	/* ignore error */
	}
#ifdef CONFIG_MPDCCP_STATS
	ret = sysfs_create_group(&link->kobj, &mpdccp_link_stat_sys_attr_group);
	if (ret < 0) {
		mpdccp_pr_error ("error in kobject_add() for stat: %d\n", ret);
		kobject_put (&link->kobj);
		return ret;
	}
#endif
	if (mpdccp_link_net_id >= 0 && MPDCCP_LINK_TO_NET(link)) {
		ld = net_generic (MPDCCP_LINK_TO_NET(link), mpdccp_link_net_id);
	}

	if (*link->name && ld) {
		sysfs_create_link_nowarn (&ld->name, &link->kobj, link->name);
	}
	if (MPDCCP_LINK_ISDEV(link)) {
		/* create symlinks */
		//strcpy (link->ndev_name, MPDCCP_LINK_TO_DEV(link)->name);
		if (ld) sysfs_create_link (&ld->dev, &link->kobj, link->ndev_name);
		devkobj = &MPDCCP_LINK_TO_DEV(link)->dev.kobj;
		sysfs_create_link (&link->kobj, devkobj, "dev");
		sysfs_create_link (devkobj, &link->kobj, "mpdccp_link");
	}
	link->sysfs_to_del = 1;
	return 0;
}

int
mpdccp_link_sysfs_changename (
	struct mpdccp_link_info	*link,
	const char					*name)
{
	struct mpdccp_link_net_data	*ld = NULL;

	if (!link) return -EINVAL;
	if (!name || strlen (name) > sizeof (link->name)-1) return -EINVAL;
	if (mpdccp_link_net_id >= 0 && MPDCCP_LINK_TO_NET(link)) {
		ld = net_generic (MPDCCP_LINK_TO_NET(link), mpdccp_link_net_id);
	}

	/* we have to change symbolic link */
	if (ld && *link->name) sysfs_remove_link (&ld->name, link->name);
	strcpy (link->name, name);
	if (ld && *link->name) sysfs_create_link (&ld->name, &link->kobj, link->name);
	return 0;
}

int
mpdccp_link_sysfs_changedevname (
	struct mpdccp_link_info	*link)
{
	struct mpdccp_link_net_data	*ld = NULL;
	if (!link) return -EINVAL;
	if (mpdccp_link_net_id >= 0 && MPDCCP_LINK_TO_NET(link)) {
		ld = net_generic (MPDCCP_LINK_TO_NET(link), mpdccp_link_net_id);
	}

	/* we have to change symbolic link */
	if (ld) sysfs_remove_link (&ld->dev, link->ndev_name);
	strcpy (link->ndev_name, MPDCCP_LINK_TO_DEV(link)->name);
	if (ld) sysfs_create_link (&ld->dev, &link->kobj, link->ndev_name);
	return 0;
}

void
mpdccp_link_sysfs_del (
	struct mpdccp_link_info	*link)
{
	struct kobject					*devkobj;
	struct mpdccp_link_net_data	*ld = NULL;

	if (!link) return;
	if (!link->sysfs_to_del) return;
	if (mpdccp_link_net_id >= 0 && MPDCCP_LINK_TO_NET(link)) {
		ld = net_generic (MPDCCP_LINK_TO_NET(link), mpdccp_link_net_id);
	}
	if (!ld) return;
	if (MPDCCP_LINK_ISDEV(link)) {
		sysfs_remove_link (&ld->dev, link->ndev_name);
		if (MPDCCP_LINK_TO_DEV(link)) {
			devkobj = &MPDCCP_LINK_TO_DEV(link)->dev.kobj;
			sysfs_remove_link (devkobj, "mpdccp_link");
		}
	} else if (*link->name) {
		sysfs_remove_link (&ld->name, link->name);
	}
	link->sysfs_to_del = 0;

	kobject_put (&link->kobj);
}


/*
 * create dev and name directories on a ns base
 */

static
const
void *
linkdev_namespace (
	struct kobject	*kobj)
{
	struct mpdccp_link_net_data	*ld = container_of (kobj, struct mpdccp_link_net_data, dev);
	return ld->net;
}
static
const
void *
linkname_namespace (
	struct kobject	*kobj)
{
	struct mpdccp_link_net_data	*ld = container_of (kobj, struct mpdccp_link_net_data, name);
	return ld->net;
}

static struct kobj_type linkdev_kobj_ktype = {
	.release   = null_kobj_release,	/* ref counter is not used, so it is ok */
	.sysfs_ops = &kobj_sysfs_ops,
	.namespace = linkdev_namespace,
};
static struct kobj_type linkname_kobj_ktype = {
	.release   = null_kobj_release,	/* ref counter is not used, so it is ok */
	.sysfs_ops = &kobj_sysfs_ops,
	.namespace = linkname_namespace,
};

int
mpdccp_link_sysfs_netinit (
	struct mpdccp_link_net_data	*ld)
{
	int	ret, ret2=0;

	if (!ld) return -EINVAL;
  	ret = kobject_init_and_add (&ld->dev, &linkdev_kobj_ktype, mpdccp_link_sys_base_kobj, "dev");
	if (ret < 0) {
		printk ("mpdccp_link::netinit: error creatind \"dev\" dir: %d\n", ret);
		ret2 = ret;
	}
  	ret = kobject_init_and_add (&ld->name, &linkname_kobj_ktype, mpdccp_link_sys_base_kobj, "name");
	if (ret < 0) {
		//kobject_put (&ld->dev);
		printk ("mpdccp_link::netinit: error creatind \"name\" dir: %d\n", ret);
		ret2 = ret;
	}
	return ret2;
}

void
mpdccp_link_sysfs_netexit (
	struct mpdccp_link_net_data	*ld)
{
	if (!ld) return;
	kobject_put (&ld->dev);
	kobject_put (&ld->name);
}


/*
 * create base dir
 */

static
ssize_t
link_sys_store_attr_add_link (
	struct kobject				*kobj,
	struct kobj_attribute	*attr,
	const char					*buf,
	size_t						count)
{
	struct net	*net = current->nsproxy->net_ns;
	int			ret;
	size_t		len = count;
	char			name[IFNAMSIZ];

	if (len >  0 && buf[len - 1] == '\n') --len;
	if (!len || len >= sizeof (name)) return -EINVAL;
	strncpy (name, buf, len);
	name[len]=0;
	ret = mpdccp_link_add (NULL, net, NULL, name);
	if (ret < 0) return ret;
	return count;
}

static
ssize_t
link_sys_store_attr_del_link (
	struct kobject				*kobj,
	struct kobj_attribute	*attr,
	const char					*buf,
	size_t						count)
{
	struct net					*net = current->nsproxy->net_ns;
	struct mpdccp_link_info	*link;
	char							name[sizeof(link->name)];
	size_t						len = count;

	if (len >  0 && buf[len - 1] == '\n') --len;
	if (!len || len >= sizeof (name)) return -EINVAL;
	strncpy (name, buf, len);
	name[len]=0;
	link = mpdccp_link_find_by_name (net, name);
	if (!link) return -ENOENT;
	if (link == mpdccp_getfallbacklink (net)) return -EPERM;
	//mpdccp_link_sysfs_del (link);
	mpdccp_link_release (link);
	return count;
}
MKATTR_WO(add_link)
MKATTR_WO(del_link)
static struct attribute *mpdccp_link_base_sys_attrs[] = {
	&add_link_attribute.attr,
	&del_link_attribute.attr,
	NULL
};
static struct attribute_group mpdccp_link_sys_base_attr_group = {
	.attrs = mpdccp_link_base_sys_attrs,
};


static
const
struct kobj_ns_type_operations *
link_ns_op (
	struct kobject	*kobj)
{
	return &net_ns_type_operations;
}

static struct kobj_type linkbase_kobj_ktype = {
	.release   = null_kobj_release,	/* ref counter is not used, so it is ok */
	.sysfs_ops = &kobj_sysfs_ops,
	.child_ns_type = link_ns_op,
	//.default_attrs = mpdccp_link_base_sys_attrs,
};


int
mpdccp_link_sysfs_init (void)
{
	struct kobject	*parent;
	int				ret;
	
	if (mpdccp_link_sys_base_kobj) return 0;
#ifdef MODULE
	parent = &THIS_MODULE->mkobj.kobj;
#else
	parent = kset_find_obj (module_kset, KBUILD_MODNAME);
#endif
	mpdccp_link_sys_base_kobj = kzalloc (sizeof (struct kobject), GFP_KERNEL);
   if (!mpdccp_link_sys_base_kobj) return -ENOMEM;
   ret = kobject_init_and_add (mpdccp_link_sys_base_kobj, &linkbase_kobj_ktype, parent, "links");
   if (ret < 0) {
      kobject_put (mpdccp_link_sys_base_kobj);
      mpdccp_link_sys_base_kobj = NULL;
      return ret;
   }
	/* I don't like to put it on top level, better in links, but 
	 * does not work due to namespace tagging
	 */
	ret = sysfs_create_group (parent, &mpdccp_link_sys_base_attr_group);
   if (ret < 0) {
      kobject_put (mpdccp_link_sys_base_kobj);
      mpdccp_link_sys_base_kobj = NULL;
      return ret;
   }
	return 0;
}

void
mpdccp_link_sysfs_exit (void)
{
	if (mpdccp_link_sys_base_kobj) {
		kobject_put (mpdccp_link_sys_base_kobj);
		mpdccp_link_sys_base_kobj = NULL;
	}
}










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
