#ifndef _LINUX_MPDCCP_LINK_INFO_H
#define _LINUX_MPDCCP_LINK_INFO_H

#include <generated/autoconf.h>
#include <net/net_namespace.h>
#include <linux/types.h>
#include <linux/kobject.h>
#include <linux/netdevice.h>


struct mpdccp_link_info {

	struct list_head	link_list;
//	char			name[IFNAMSIZ+1];
	char			name[64];
	int			id;
	u32			is_linked:1,
				is_devlink:1,
				is_released:1,
				sysfs_to_del:1;
	struct net_device	*ndev;
	struct net		*net;
	char			ndev_name[IFNAMSIZ+1];
#ifdef CONFIG_SYSFS
	struct kobject		kobj;
#endif
	struct kref		kref;
/* public: read-only - write thru mpdccp_link_change_... functions */

	int	start_config;
	u64	config_cnt;		/* config counter */
	u32	mpdccp_prio;		/* prio for mpdccp connections */
	u64	mpdccp_maxbuf;		/* max. buf for mpdccp subflows */
	u32	mpdccp_ignthrottle;	/* ignore throttling */
	char	mpdccp_cgstalg[64];	/* congestion algorithmn for subpath */
	u32	mpdccp_match_mark;	/* fwmark to match incomming requests */
	u32	mpdccp_match_mask;	/* fwmask to match incomming requests */
	u32	mpdccp_send_mark;	/* mark outgoing packets */
	u32	mpdccp_T_delay;		/* delay before peak start in ms */
	u32	mpdccp_T_delay_j;	/* delay before peak start in jiffies */
	u32	mpdccp_T_start_delay;	/* delay at stream start in ms */
	u32	mpdccp_T_start_delay_j;	/* delay at stream start in jiffies */
	u32	mpdccp_T_lpu;		/* threshhold for last path usage in ms */
	u32	mpdccp_T_lpu_j;		/* threshhold for last path usage in jiffies */
	u32	mpdccp_T_lpu_min;	/* threshhold for last path usage in ms */
	u32	mpdccp_T_lpu_min_j;	/* threshhold for last path usage in jiffies */
	u32	mpdccp_lpu_cnt;		/* max packets that can be sent between lpu_min and lpu */
	u32	mpdccp_path_type;	/* path type (lte, wifi, ...) */
	u32	mpdccp_match_pathtype;	/* match path type (e.g. match if path is lte */
	int	end_config;

	u64	mpdccp_rx_packets;	/* number packets received */
	u64	mpdccp_rx_bytes;	/* number bytes received */
	u64	mpdccp_tx_packets;	/* number packets send */
	u64	mpdccp_tx_bytes;	/* number bytes send */

#ifdef CONFIG_MPDCCP_STATS
	/* mpdccp statistics */
	int	start_stats;
	u64	mpdccp_noavail_hard;
	u64	mpdccp_noavail_hard_state;
	u64	mpdccp_noavail_hard_pre;
	u64	mpdccp_noavail_hard_pf;
	u64	mpdccp_noavail_hard_loss;
	u64	mpdccp_noavail_nocwnd;
	u64	mpdccp_noavail_nospace_maxbuf;
	u64	mpdccp_noavail_nospace;
	u64	mpdccp_noavail_zerownd;
	u64	mpdccp_noavail_nobuf;
	u64	mpdccp_noavail_delay;
	u64	mpdccp_noavail_start_delay;
	u64	mpdccp_noavail_dontreinject;
	u64	mpdccp_selected_delayed;
	u64	mpdccp_selected_onlypath;
	u64	mpdccp_selected_shutdown;
	u64	mpdccp_selected_backup;
	u64	mpdccp_selected_good;
	u64	mpdccp_selected_best;
	u64	mpdccp_selected_fallback;
	u64	mpdccp_selected;
	u64	allref;
	int	end_stats;
#endif
};

#define mpdccp_link_cnt(link) ((link)?((link)->config_cnt):0)



#endif	/* _LINUX_MPDCCP_LINK_INFO_H */
