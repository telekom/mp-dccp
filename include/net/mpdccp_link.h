#ifndef _LINUX_MPDCCP_LINK_H
#define _LINUX_MPDCCP_LINK_H

#include <generated/autoconf.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <net/net_namespace.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include <net/mpdccp_link_info.h>

#define MPDCCP_LINK_VER	3
#define MPDCCP_HAS_DELAY	2
#define MPDCCP_HAS_EXT_LPU

#if 0
#  define MPDCCP_LINK_TO_NET(link) ((link)->ndev ? read_pnet(&((link)->ndev->nd_net)) : \
		(((link)->net ? (link)->net : &init_net)))
#else
#  define MPDCCP_LINK_TO_NET(link) ((link)->net)
#endif

struct mpdccp_link_info *mpdccp_link_find_by_dev(struct net_device*);
#define MPDCCP_LINK_ISDEV(link) ((link)->is_devlink)
#define MPDCCP_LINK_ISDEV_VALID(link) (MPDCCP_LINK_ISDEV(link) && ((link)->ndev))
#define MPDCCP_LINK_FROM_DEV(ndev) mpdccp_link_find_by_dev(ndev)
#define MPDCCP_LINK_TO_DEV(link) ((link)->ndev)
#define MPDCCP_LINK_NAME(link) (((link)->ndev)?((link)->ndev_name):((link)->name))
#ifdef CONFIG_SYSFS
//#define MPDCCP_LINK_REFCOUNT(link) (atomic_read (&(link)->kobj.kref.refcount.refs))
#define MPDCCP_LINK_REFCOUNT(link) (atomic_read (&(link)->kref.refcount.refs))
#else
#define MPDCCP_LINK_REFCOUNT(link) (atomic_read (&(link)->kref.refcount.refs))
#endif


int mpdccp_link_copy (struct mpdccp_link_info **new_link, struct mpdccp_link_info *old_link);
int mpdccp_link_add (struct mpdccp_link_info**, struct net*, struct net_device*, const char *name);
void mpdccp_link_get (struct mpdccp_link_info*);
void mpdccp_link_put (struct mpdccp_link_info*);


struct mpdccp_link_notifier_info {
	struct mpdccp_link_info	*link_info;
	struct net_device	*ndev;
};


int register_mpdccp_link_notifier (struct notifier_block*);
int unregister_mpdccp_link_notifier (struct notifier_block*);
int call_mpdccp_link_notifiers (unsigned long, struct mpdccp_link_info*);

#define MPDCCP_LINK_CHANGE_PRIO				1
#define MPDCCP_LINK_CHANGE_MAXBUF			2
#define MPDCCP_LINK_CHANGE_DELAY				3
#define MPDCCP_LINK_CHANGE_LPU				4
#define MPDCCP_LINK_CHANGE_THROTTLE			5
#define MPDCCP_LINK_CHANGE_MARK				6
#define MPDCCP_LINK_CHANGE_CGSTCTRL			7
#define MPDCCP_LINK_CHANGE_PATHTYPE			8
#define MPDCCP_LINK_CHANGE_MATCH_PATHTYPE	9

/*
 * change functions, prototypes and dev_change_ inline wrappers
 */


#define MPDCCP_DEV_CHANGE(func,typ) \
	int mpdccp_link_change_##func(struct mpdccp_link_info*, typ); \
	static inline int dev_change_##func(struct net_device *dev, typ val) \
	{ \
		return mpdccp_link_change_##func (MPDCCP_LINK_FROM_DEV(dev), (val)); \
	}
MPDCCP_DEV_CHANGE(mpdccp_prio,u32)
MPDCCP_DEV_CHANGE(mpdccp_maxbuf,u64)
MPDCCP_DEV_CHANGE(mpdccp_T_delay,u32)
MPDCCP_DEV_CHANGE(mpdccp_T_start_delay,u32)
MPDCCP_DEV_CHANGE(mpdccp_T_lpu,u32)
MPDCCP_DEV_CHANGE(mpdccp_T_lpu_min,u32)
MPDCCP_DEV_CHANGE(mpdccp_lpu_cnt,u32)
MPDCCP_DEV_CHANGE(mpdccp_ignthrottle,unsigned int)
MPDCCP_DEV_CHANGE(mpdccp_match_mark,u32)
MPDCCP_DEV_CHANGE(mpdccp_match_mask,u32)
MPDCCP_DEV_CHANGE(mpdccp_send_mark,u32)
MPDCCP_DEV_CHANGE(mpdccp_path_type,u32)
MPDCCP_DEV_CHANGE(mpdccp_match_pathtype,u32)
int mpdccp_link_change_name (struct mpdccp_link_info *link, struct sock *sk);
int mpdccp_link_change_mpdccp_cgstalg(struct mpdccp_link_info *, const char *, size_t );
static inline int dev_change_mpdccp_cgstalg(struct net_device *dev, const char *buf, size_t len)
{
	return mpdccp_link_change_mpdccp_cgstalg (MPDCCP_LINK_FROM_DEV(dev), buf, len);
}
int mpdccp_link_change_mpdccp_resetstat(struct mpdccp_link_info *);
static inline int dev_change_mpdccp_resetstat(struct net_device *dev)
{
	return mpdccp_link_change_mpdccp_resetstat(MPDCCP_LINK_FROM_DEV(dev));
}

/* Connection ID functions  */
u32 mpdccp_link_generate_cid(void);
void mpdccp_link_free_cid(u32 cid);
/* 
 * find functions
 */

struct mpdccp_link_info* mpdccp_link_find_by_name (struct net *net, const char *name);
struct mpdccp_link_info* mpdccp_link_find_mark (struct net *net, u32 mark);
struct mpdccp_link_info* mpdccp_link_find_ip4 (struct net *net, struct in_addr *saddr, struct in_addr *daddr);
#if IS_ENABLED(CONFIG_IPV6)
struct mpdccp_link_info* mpdccp_link_find_ip6 (struct net *net, struct in6_addr *saddr, struct in6_addr *daddr);
#endif /* IS_ENABLED(CONFIG_IPV6) */
struct mpdccp_link_info *mpdccp_link_find_by_skb (struct net*, const struct sk_buff*);

struct mpdccp_link_info *mpdccp_getfallbacklink(struct net *net);


extern int mpdccp_link_net_id;
struct mpdccp_link_net_data {
	atomic_t		counter;
	struct mpdccp_link_info	*fallback;
	struct net		*net;
#ifdef CONFIG_SYSFS
	struct kobject		dev;
	struct kobject		name;
#endif
};



#endif	/* _LINUX_MPDCCP_LINK_H */
