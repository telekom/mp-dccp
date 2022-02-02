/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 * Copyright (C) 2018 by Andreas Philipp Matz, Deutsche Telekom AG
 * Copyright (C) 2018 by Markus Amend, Deutsche Telekom AG
 * Copyright (C) 2020 by Nathalie Romo, Deutsche Telekom AG
 * Copyright (C) 2020 by Frank Reker, Deutsche Telekom AG
 *
 * MPDCCP - Path manager default
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

#include "../ccids/ccid2.h"
#include "../dccp.h"
#include <net/mpdccp_link.h>
#include <net/mpdccp.h>
#include "../mpdccp.h"
#include "../mpdccp_pm.h"

static struct kmem_cache *mpdccp_pm_addr_cache __read_mostly;
static struct mpdccp_pm_ops mpdccp_pm_default;


enum {
	MPDCCP_EVENT_ADD = 1,
	MPDCCP_EVENT_DEL,
	MPDCCP_EVENT_MOD,
};

struct mpdccp_local_addr_event {
	struct list_head list;
	unsigned short	family;
	u8	code;
	int	if_idx;
	union inet_addr addr;
};

/* Holds a single local interface address */
struct mpdccp_local_addr {
	struct list_head address_list;

	/* Address family, IPv4/v6 address, Interface ID */
	sa_family_t family;
	union inet_addr addr;
	int if_idx;

//	u8 next_v4_index;
//	u8 next_v6_index;

	struct rcu_head rcu;
};

static struct mpdccp_pm_ns *fm_get_ns(const struct net *net)
{
	/* TAG-0.8: Migrate to list implementation */
	return (struct mpdccp_pm_ns *)net->mpdccp.path_managers[MPDCCP_PM_FULLMESH];
}



/***********************************
* Path manager work queue
************************************/


/* The following two functions mpdccp_add_addr and mpdccp_del_addr
 * add or delete an address to/from both the global address list and all
 * existing connections. We assume that every operation produces a 
 * consistent state upon completion, i.e. if an address is not
 * in the list, it is not used in any connection. */
static void mpdccp_announce_remove_path(int addr_id, struct mpdccp_cb *mpcb)
{
	struct sock *sk = mpdccp_select_ann_sock(mpcb);
	if (sk){
		mpcb->delpath = addr_id;
		mpdccp_pr_debug("Sending delete path\n");
#if IS_ENABLED(CONFIG_DCCP_KEEPALIVE)
		dccp_send_keepalive(sk);
#endif
	}
}


static int mpdccp_add_addr(struct mpdccp_pm_ns *pm_ns,
			      			struct mpdccp_local_addr_event *event)
{
	struct mpdccp_local_addr *local_addr;
	struct mpdccp_cb *mpcb;

	struct sockaddr 			*local;
	struct sockaddr_in 			local_v4_address;
	struct sockaddr_in6 		local_v6_address;

	sa_family_t family 			= event->family;
	union inet_addr *addr 		= &event->addr;
    int if_idx 					= event->if_idx;
	int locaddr_len;

	struct list_head *plocal_addr_list = &pm_ns->plocal_addr_list;

	//rcu_read_lock_bh();
	spin_lock(&pm_ns->plocal_lock);

	/* Add the address to the list of known addresses so that
	 * new connections can use it. If the address is known, it does not
	 * need to be added, as all existing connections already use it. */
	list_for_each_entry_rcu(local_addr, plocal_addr_list, address_list) {
		if (family == local_addr->family &&
		   (!if_idx || if_idx == local_addr->if_idx))
		{
			if ((family == AF_INET  && 
				local_addr->addr.in.s_addr == addr->in.s_addr) ||
				(family == AF_INET6 && 
				ipv6_addr_equal(&local_addr->addr.in6, &addr->in6)))
			{
				spin_unlock(&pm_ns->plocal_lock);
				//rcu_read_unlock_bh();

				return false;
			}
		}
	}

	/* Address is unused, create a new address entry. */
    local_addr = kmem_cache_zalloc(mpdccp_pm_addr_cache, GFP_ATOMIC);
    if (!local_addr) {
    	spin_unlock(&pm_ns->plocal_lock);
		rcu_read_unlock_bh();

        mpdccp_pr_debug("Failed to allocate memory for new local address.\n");
        
        return false;
    }

    local_addr->family = family;
	local_addr->if_idx = if_idx;

	if (family == AF_INET) {
	    local_addr->addr.in.s_addr = addr->in.s_addr;

		mpdccp_pr_debug("Updated IP %pI4 on ifidx %u\n",
			    &addr->in.s_addr, if_idx);
	} else {
		local_addr->addr.in6 = addr->in6;

		mpdccp_pr_debug("%s updated IP %pI6 on ifidx %u\n",
				__func__, &addr->in6, if_idx);
	}
	
	list_add_tail_rcu(&local_addr->address_list, plocal_addr_list);

	/* TODO: Is this needed? It might have been a MOD-event. */
	//event->code = MPDCCP_EVENT_ADD;

	/* Set target IPv4/v6 address correctly */
	if (family == AF_INET) {
		local_v4_address.sin_family			= AF_INET;
		local_v4_address.sin_addr.s_addr 	= addr->in.s_addr;
	} else {
		local_v6_address.sin6_family		= AF_INET6;
		local_v6_address.sin6_addr 			= addr->in6;
	}

	/* Iterate over all connections and create new connections via this address */
	mpdccp_for_each_conn(pconnection_list, mpcb) {
		if (family == AF_INET) {
			if(mpcb->role == MPDCCP_CLIENT)
				local_v4_address.sin_port		= 0;
			else
				local_v4_address.sin_port		= htons (mpcb->server_port);

			local = (struct sockaddr *) &local_v4_address;
			locaddr_len = sizeof (struct sockaddr_in);
		} else {
			if(mpcb->role == MPDCCP_CLIENT)
				local_v6_address.sin6_port		= 0;
			else
				local_v6_address.sin6_port		= htons (mpcb->server_port);

			local = (struct sockaddr *) &local_v6_address;
			locaddr_len = sizeof (struct sockaddr_in6);
		}

		switch (mpcb->role) {
		case MPDCCP_CLIENT:
			/* Do not add more subflows if the client in in SP mode */
			if (!(mpcb->fallback_sp && (mpcb->cnt_subflows > 0)))
				mpdccp_add_client_conn(mpcb, local, locaddr_len, if_idx,
						(struct sockaddr*)&mpcb->mpdccp_remote_addr,
						mpcb->remaddr_len);
			break;
		case MPDCCP_SERVER:
			/* do nothing */
			break;
		default:
			break;
		}
	}
	spin_unlock(&pm_ns->plocal_lock);
	//rcu_read_unlock_bh();

	return true;
}

static bool mpdccp_del_addr(struct mpdccp_pm_ns *pm_ns,
			      struct mpdccp_local_addr_event *event)
{

	struct sock *sk;
	struct mpdccp_cb *mpcb;
	struct 	mpdccp_local_addr *local_addr;

	sa_family_t family 			= event->family;
	union inet_addr *addr 		= &event->addr;
    int if_idx 					= event->if_idx;
    int addr_id;
	bool found 					= false;

	struct list_head *plocal_addr_list = &pm_ns->plocal_addr_list;

	//TODO reordering
	pr_info("RO: mpdccp_del_addr triggered...");

	//rcu_read_lock_bh();
	spin_lock(&pm_ns->plocal_lock);

	/* Delete the address from the list of known addresses so that
	 * new connections stop using it. */
	list_for_each_entry_rcu(local_addr, plocal_addr_list, address_list) {
		/* Search for an entry with matching address family and iface ID */
		if (family == local_addr->family &&
		   (!if_idx || if_idx == local_addr->if_idx))
		{
			/* Check for a matching IPv4/v6 address */
			if ((family == AF_INET  && 
				local_addr->addr.in.s_addr == addr->in.s_addr) ||
				(family == AF_INET6 && 
				ipv6_addr_equal(&local_addr->addr.in6, &addr->in6)))
			{
				found = true;
				list_del_rcu(&local_addr->address_list);
				kfree_rcu(local_addr, rcu);
			}
		}
	}

	/* Address is unknown, so it is not used in any connection. */
	if(!found) 
	{
		spin_unlock(&pm_ns->plocal_lock);
		//rcu_read_unlock_bh();
		return false;
	}

	/* Iterate over all connections and remove any socket that still
	 * uses this address */
	mpdccp_for_each_conn(pconnection_list, mpcb) {
		mpdccp_for_each_sk(mpcb, sk) {

			/* Not yet sure if this applies to MPDCCP, too */
			// if (sock_net(sk) != net)
			// 	continue;

			/* If the PM has changed, we are not responsible for this mpcb */
			if (mpcb->pm_ops != &mpdccp_pm_default)
				break;

			/* Does the event family and interface ID match the socket? */
			if (family == sk->__sk_common.skc_family &&
			   (!if_idx || mpdccp_my_sock(sk)->if_idx  == if_idx))
			{
				/* Does the IP address in the event match the socket */
				if ((family == AF_INET  && 
					sk->__sk_common.skc_rcv_saddr == addr->in.s_addr) ||
					(family == AF_INET6 && 
					ipv6_addr_equal(&sk->__sk_common.skc_v6_rcv_saddr, &addr->in6)))
				{
					if(family == AF_INET)
						mpdccp_pr_debug("Deleting subflow socket %p with address %pI4.\n", sk, &sk->__sk_common.skc_rcv_saddr);
					else
						mpdccp_pr_debug("Deleting subflow socket %p with address %pI6.\n", sk, &sk->__sk_common.skc_v6_rcv_saddr);
					//mpdccp_my_sock(sk)->mpcb->delpath = mpdccp_my_sock(sk)->link_info->id;
					addr_id = mpdccp_my_sock(sk)->link_info->id;
					mpdccp_close_subflow (mpcb, sk, 0);
					mpdccp_announce_remove_path(addr_id, mpcb);

				}
			}
		}

		mpdccp_for_each_listen_sk(mpcb, sk) {
			/* Not yet sure if this applies to MPDCCP, too */
			// if (sock_net(sk) != net)
			// 	continue;

			/* If the PM has changed, we are not responsible for this mpcb */
			if (mpcb->pm_ops != &mpdccp_pm_default)
				break;

			/* Does the event family and interface ID match the socket? */
			if (family == sk->__sk_common.skc_family &&
			   (!if_idx || mpdccp_my_sock(sk)->if_idx  == if_idx))
			{
				/* Does the IP address in the event match the socket */
				if ((family == AF_INET  && 
					sk->__sk_common.skc_rcv_saddr == addr->in.s_addr) ||
					(family == AF_INET6 && 
					ipv6_addr_equal(&sk->__sk_common.skc_v6_rcv_saddr, &addr->in6)))
				{
					if(family == AF_INET)
						mpdccp_pr_debug("Deleting listening socket %p with address %pI4.\n", sk, &sk->__sk_common.skc_rcv_saddr);
					else
						mpdccp_pr_debug("Deleting listening socket %p with address %pI6.\n", sk, &sk->__sk_common.skc_v6_rcv_saddr);

					mpdccp_close_subflow (mpcb, sk, 0);
				}
			}
		}
	}
	spin_unlock(&pm_ns->plocal_lock);
	//rcu_read_unlock_bh();

	return true;
}

static void mpdccp_local_address_worker(struct work_struct *work)
{
	const struct delayed_work *delayed_work = container_of(work,
							 struct delayed_work,
							 work);
	struct mpdccp_pm_ns *pm_ns = container_of(delayed_work,
						 struct mpdccp_pm_ns,
						 address_worker);
	struct mpdccp_local_addr_event *event = NULL;

next_event:
	kfree(event);

	/* First, let's dequeue an event from our event-list */
	/* TODO: is _bh REALLY the right thing to do here? */
	//rcu_read_lock_bh();
	event = list_first_entry_or_null(&pm_ns->events,
					 struct mpdccp_local_addr_event, list);
	if (!event) {
		/* No more events to work on */
		//rcu_read_unlock_bh();
		return;
	}

	list_del(&event->list);
	//mpdccp_local = rcu_dereference_bh(pm_ns->local);

	if (event->code == MPDCCP_EVENT_DEL) {
		if( !mpdccp_del_addr(pm_ns, event) ) {
			mpdccp_pr_debug("Delete address failed: Address not found.\n");
		}
			
	} else {
		/* TODO: Filter link local and TUN devices */
		if( !mpdccp_add_addr(pm_ns, event) ) {
			mpdccp_pr_debug("Add address failed: Address already in use.\n");
		}
	}
	//rcu_read_unlock_bh();

	goto next_event;
}



/***********************************
* IPv4/v6 address event handling
************************************/

static struct mpdccp_local_addr_event *lookup_similar_event(const struct net *net,
						     const struct mpdccp_local_addr_event *event)
{
	struct mpdccp_local_addr_event *eventq;
	struct mpdccp_pm_ns *pm_ns = fm_get_ns(net);

	list_for_each_entry(eventq, &pm_ns->events, list) {
		if (eventq->family != event->family)
			continue;
		if (eventq->if_idx != event->if_idx)
			continue;
		if (event->family == AF_INET) {
			if (eventq->addr.in.s_addr == event->addr.in.s_addr)
				return eventq;
		} else {
			if (ipv6_addr_equal(&eventq->addr.in6, &event->addr.in6))
				return eventq;
		}
	}
	return NULL;
}

/* We already hold the net-namespace MPDCCP-lock */
static void add_pm_event(struct net *net, const struct mpdccp_local_addr_event *event)
{
	struct mpdccp_local_addr_event *eventq = lookup_similar_event(net, event);
	struct mpdccp_pm_ns *pm_ns = fm_get_ns(net);

	if (eventq) {
		switch (event->code) {
		case MPDCCP_EVENT_DEL:
			mpdccp_pr_debug("%s del old_code %u\n", __func__, eventq->code);
			list_del(&eventq->list);
			kfree(eventq);
			break;
		case MPDCCP_EVENT_ADD:
			mpdccp_pr_debug("%s add old_code %u\n", __func__, eventq->code);
			eventq->code = MPDCCP_EVENT_ADD;
			return;
		case MPDCCP_EVENT_MOD:
			mpdccp_pr_debug("%s mod old_code %u\n", __func__, eventq->code);
			eventq->code = MPDCCP_EVENT_MOD;
			return;
		}
	}

	/* OK, we have to add the new address to the wait queue */
	eventq = kmemdup(event, sizeof(struct mpdccp_local_addr_event), GFP_ATOMIC);
	if (!eventq)
		return;

	list_add_tail(&eventq->list, &pm_ns->events);

	/* Create work-queue */
	if (!delayed_work_pending(&pm_ns->address_worker))
		queue_delayed_work(mpdccp_wq, &pm_ns->address_worker,
				   msecs_to_jiffies(500));
}

static void addr4_event_handler(const struct in_ifaddr *ifa, unsigned long event,
				struct net *net)
{
	const struct net_device *netdev = ifa->ifa_dev->dev;
	struct mpdccp_pm_ns *pm_ns = fm_get_ns(net);
	struct mpdccp_local_addr_event mpevent;

	/* Do not create events for link-local interfaces and TUN devices */
	if ( ifa->ifa_scope > RT_SCOPE_LINK 	||
		 netdev->flags & IFF_POINTOPOINT	||
	     ipv4_is_loopback(ifa->ifa_local) )
		return;

	spin_lock_bh(&pm_ns->plocal_lock);

	mpevent.family = AF_INET;
	mpevent.addr.in.s_addr = ifa->ifa_local;
	mpevent.if_idx  = netdev->ifindex;

	if (event == NETDEV_DOWN || !netif_running(netdev) || netdev->operstate == IF_OPER_DOWN ||
	    !(netdev->flags & IFF_MPDCCPON)|| !(netdev->flags & IFF_UP))
		mpevent.code = MPDCCP_EVENT_DEL;
	else if (event == NETDEV_UP)
		mpevent.code = MPDCCP_EVENT_ADD;
	else if (event == NETDEV_CHANGE)
		mpevent.code = MPDCCP_EVENT_MOD;

	mpdccp_pr_debug("event %lu, running %d flags %u oper %x", event, netif_running(netdev), netdev->flags, netdev->operstate);
    mpdccp_pr_debug("%s created event for %pI4, code %u idx %u\n", __func__,
		    &ifa->ifa_local, mpevent.code, mpevent.if_idx);
	add_pm_event(net, &mpevent);

	spin_unlock_bh(&pm_ns->plocal_lock);
	return;
}

static int mpdccp_pm_inetaddr_event(struct notifier_block *this,
				   unsigned long event, void *ptr)
{
	const struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net *net = dev_net(ifa->ifa_dev->dev);

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	addr4_event_handler(ifa, event, net);

	return NOTIFY_DONE;
}

static struct notifier_block mpdccp_pm_inetaddr_notifier = {
		.notifier_call = mpdccp_pm_inetaddr_event,
};

static int mpdccp_pm_dccp_event(struct notifier_block *this,
				   unsigned long event, void *ptr)
{
	const struct sock *sk_closed = (struct sock *)ptr;

	struct sock *sk;
	struct mpdccp_cb *mpcb;
	struct sockaddr 			*local;
	struct sockaddr_in 			local_v4_address;
	struct sockaddr_in6 		local_v6_address;
	int	locaddr_len;
	int	if_idx;

	if (!sk_closed) return NOTIFY_DONE;

	if(sk_closed->__sk_common.skc_family == AF_INET){
			local_v4_address.sin_family		= AF_INET;
			local_v4_address.sin_addr.s_addr = sk_closed->__sk_common.skc_rcv_saddr;
			local_v4_address.sin_port		= 0;
			local = (struct sockaddr *) &local_v4_address;
			locaddr_len = sizeof (struct sockaddr_in);
		} else {
			local_v6_address.sin6_family		= AF_INET6;
			local_v6_address.sin6_addr 		= sk_closed->__sk_common.skc_v6_rcv_saddr;
			local_v6_address.sin6_port		= 0;
			local = (struct sockaddr *) &local_v6_address;
			locaddr_len = sizeof (struct sockaddr_in6);
		}

	if_idx = sk_closed->__sk_common.skc_bound_dev_if;
	if (event == DCCP_EVENT_CLOSE){
		mpdccp_for_each_conn(pconnection_list, mpcb) {
			mpdccp_for_each_sk(mpcb, sk) {
				/* Handle close events for both the subflow and meta sockets */
				if (mpcb->meta_sk == sk_closed) {
					mpdccp_close_subflow(mpcb, sk, 0);
					mpdccp_pr_debug("close dccp sk %p", sk_closed);
				}
				else if(sk == sk_closed) {
					mpdccp_close_subflow(mpcb, sk, 0);
					mpdccp_pr_debug("close dccp sk %p", sk_closed);
					//attempt reconnect
					if (mpcb->meta_sk->sk_state == DCCP_OPEN && mpcb->role == MPDCCP_CLIENT){
						mpdccp_pr_debug("try to reconnect sk address %pI4. if %d \n", &sk->__sk_common.skc_rcv_saddr, if_idx);
							mpdccp_add_client_conn(mpcb, local, locaddr_len, if_idx, 
							(struct sockaddr*)&mpcb->mpdccp_remote_addr,
							mpcb->remaddr_len);
					}

					break;
				}
			}
		}
	}
	return NOTIFY_DONE;
}

static struct notifier_block mpdccp_pm_dccp_notifier = {
		.notifier_call = mpdccp_pm_dccp_event,
};

#if IS_ENABLED(CONFIG_IPV6)

/* IPV6-related address/interface watchers */
struct mpdccp_dad_data {
	struct timer_list timer;
	struct inet6_ifaddr *ifa;
};

static void dad_callback(unsigned long arg);
static int inet6_addr_event(struct notifier_block *this,
				     unsigned long event, void *ptr);

static bool ipv6_dad_finished(const struct inet6_ifaddr *ifa)
{
	return !(ifa->flags & IFA_F_TENTATIVE) ||
	       ifa->state > INET6_IFADDR_STATE_DAD;
}

static void dad_init_timer(struct mpdccp_dad_data *data,
				 struct inet6_ifaddr *ifa)
{
	data->ifa = ifa;
	data->timer.data = (unsigned long)data;
	data->timer.function = dad_callback;
	if (ifa->idev->cnf.rtr_solicit_delay)
		data->timer.expires = jiffies + ifa->idev->cnf.rtr_solicit_delay;
	else
		data->timer.expires = jiffies + (HZ/10);
}

static void dad_callback(unsigned long arg)
{
	struct mpdccp_dad_data *data = (struct mpdccp_dad_data *)arg;

	/* DAD failed or IP brought down? */
	if (data->ifa->state == INET6_IFADDR_STATE_ERRDAD ||
	    data->ifa->state == INET6_IFADDR_STATE_DEAD)
		goto exit;

	if (!ipv6_dad_finished(data->ifa)) {
		dad_init_timer(data, data->ifa);
		add_timer(&data->timer);
		return;
	}

	inet6_addr_event(NULL, NETDEV_UP, data->ifa);

exit:
	in6_ifa_put(data->ifa);
	kfree(data);
}

static inline void dad_setup_timer(struct inet6_ifaddr *ifa)
{
	struct mpdccp_dad_data *data;

	data = kmalloc(sizeof(*data), GFP_ATOMIC);

	if (!data)
		return;

	init_timer(&data->timer);
	dad_init_timer(data, ifa);
	add_timer(&data->timer);
	in6_ifa_hold(ifa);
}

static void addr6_event_handler(const struct inet6_ifaddr *ifa, unsigned long event,
				struct net *net)
{
	const struct net_device *netdev = ifa->idev->dev;
	int addr_type = ipv6_addr_type(&ifa->addr);
	struct mpdccp_pm_ns *pm_ns = fm_get_ns(net);
	struct mpdccp_local_addr_event mpevent;

	if ( ifa->scope > RT_SCOPE_LINK 		||
		 netdev->flags & IFF_POINTOPOINT	||
	     addr_type == IPV6_ADDR_ANY 		||
	    (addr_type & IPV6_ADDR_LOOPBACK) 	||
	    (addr_type & IPV6_ADDR_LINKLOCAL))
		return;

	spin_lock_bh(&pm_ns->plocal_lock);

	mpevent.family = AF_INET6;
	mpevent.addr.in6 = ifa->addr;
	mpevent.if_idx = netdev->ifindex;

	if (event == NETDEV_DOWN || !netif_running(netdev) ||
	    !(netdev->flags & IFF_MPDCCPON)|| !(netdev->flags & IFF_UP))
		mpevent.code = MPDCCP_EVENT_DEL;
	else if (event == NETDEV_UP)
		mpevent.code = MPDCCP_EVENT_ADD;
	else if (event == NETDEV_CHANGE)
		mpevent.code = MPDCCP_EVENT_MOD;

	mpdccp_pr_debug("%s created event for %pI6, code %u idx %u\n", __func__,
		    &ifa->addr, mpevent.code, mpevent.if_idx);
	add_pm_event(net, &mpevent);

	spin_unlock_bh(&pm_ns->plocal_lock);
	return;
}

/* React on IPv6-addr add/rem-events */
static int mpdccp_pm_inet6addr_event(struct notifier_block *this, unsigned long event,
			    void *ptr)
{
	struct inet6_ifaddr *ifa6 = (struct inet6_ifaddr *)ptr;
	struct net *net = dev_net(ifa6->idev->dev);

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	if (!ipv6_dad_finished(ifa6))
		dad_setup_timer(ifa6);
	else
		addr6_event_handler(ifa6, event, net);

	return NOTIFY_DONE;
}

static struct notifier_block mpdccp_pm_inet6addr_notifier = {
		.notifier_call = mpdccp_pm_inet6addr_event,
};
#endif

static int mpdccp_init_net(struct net *net)
{
	struct mpdccp_pm_ns *pm_ns;

	pm_ns = kzalloc(sizeof(*pm_ns), GFP_KERNEL);
	if (!pm_ns)
		return -ENOBUFS;

	INIT_LIST_HEAD(&pm_ns->plocal_addr_list);
	spin_lock_init(&pm_ns->plocal_lock);
	INIT_LIST_HEAD(&pm_ns->events);
	INIT_DELAYED_WORK(&pm_ns->address_worker, mpdccp_local_address_worker);
	pm_ns->net = net;
	net->mpdccp.path_managers[MPDCCP_PM_FULLMESH] = pm_ns;

	return 0;
}

/* Wipe the local address list */
static void dccp_free_local_addr_list(struct mpdccp_pm_ns *pm_ns)
{
	struct mpdccp_local_addr *addr;
	struct list_head *pos, *temp;
	list_for_each_safe(pos, temp, &pm_ns->plocal_addr_list) {
		addr = list_entry(pos, struct mpdccp_local_addr, address_list);
		list_del(pos);
		kfree(addr);
	}
}

static void mpdccp_exit_net(struct net *net)
{
	struct mpdccp_pm_ns *pm_ns;

	pm_ns = net->mpdccp.path_managers[MPDCCP_PM_FULLMESH];
	/* Stop the worker */
	cancel_delayed_work_sync(&pm_ns->address_worker);

	/* Clean and free the list */
	dccp_free_local_addr_list(pm_ns);
	kfree(pm_ns);

/* This is statistics stuff that is not yet supported. */
#if 0
    remove_proc_entry("snmp", net->mpdccp.proc_net_mpdccp);
    remove_proc_entry("mpdccp", net->mpdccp.proc_net_mpdccp);
    remove_proc_subtree("mpdccp_net", net->proc_net);
    free_percpu(net->mpdccp.mpdccp_statistics);
#endif
}

static struct pernet_operations mpdccp_pm_net_ops = {
    .init = mpdccp_init_net,
    .exit = mpdccp_exit_net,
};

/* React on IPv6-addr add/rem-events */
static int inet6_addr_event(struct notifier_block *this, unsigned long event,
			    void *ptr)
{
	struct inet6_ifaddr *ifa6 = (struct inet6_ifaddr *)ptr;
	struct net *net = dev_net(ifa6->idev->dev);

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	if (!ipv6_dad_finished(ifa6))
		dad_setup_timer(ifa6);
	else
		addr6_event_handler(ifa6, event, net);

	return NOTIFY_DONE;
}

/* React on ifup/down-events */
static int netdev_event(struct notifier_block *this, unsigned long event,
			void *ptr)
{
	const struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct in_device *in_dev;
#if IS_ENABLED(CONFIG_IPV6)
	struct inet6_dev *in6_dev;
#endif

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	//rcu_read_lock();
	in_dev = __in_dev_get_rtnl(dev);

	if (in_dev) {
		for_ifa(in_dev) {
			mpdccp_pm_inetaddr_event(NULL, event, ifa);
		} endfor_ifa(in_dev);
	}

#if IS_ENABLED(CONFIG_IPV6)
	in6_dev = __in6_dev_get(dev);

	if (in6_dev) {
		struct inet6_ifaddr *ifa6;
		list_for_each_entry(ifa6, &in6_dev->addr_list, if_list)
			inet6_addr_event(NULL, event, ifa6);
	}
#endif

	//rcu_read_unlock();
	return NOTIFY_DONE;
}

static struct notifier_block mpdccp_pm_netdev_notifier = {
		.notifier_call = netdev_event,
};

/* General initialization of MPDCCP */
static int mpdccp_pm_init(void)
{
    int ret = 0;

    mpdccp_pm_addr_cache = kmem_cache_create("mpdccp_pm_addr", sizeof(struct mpdccp_local_addr),
                       0, SLAB_TYPESAFE_BY_RCU|SLAB_HWCACHE_ALIGN,
                       NULL);
    if (!mpdccp_pm_addr_cache) {
        mpdccp_pr_debug("Failed to create mpcb pm address slab cache.\n");
        ret = -1;
        goto out;
    }

    ret = register_pernet_subsys(&mpdccp_pm_net_ops);
    if (ret) {
        mpdccp_pr_debug("Failed to register pernet subsystem.\n");
        goto err_reg_pernet_subsys;
    }

    ret = register_inetaddr_notifier(&mpdccp_pm_inetaddr_notifier);
    if (ret) {
        mpdccp_pr_debug("Failed to register inet address notifier.\n");
        goto err_reg_inetaddr;
    }

#if IS_ENABLED(CONFIG_IPV6)
    ret = register_inet6addr_notifier(&mpdccp_pm_inet6addr_notifier);
    if (ret) {
        mpdccp_pr_debug("Failed to register inet6 address notifier.\n");
        goto err_reg_inet6addr;
    }
#endif

    ret = register_netdevice_notifier(&mpdccp_pm_netdev_notifier);
    if (ret) {
        mpdccp_pr_debug("Failed to register netdevice notifier.\n");
        goto err_reg_netdev;
    }

    ret = register_dccp_notifier(&mpdccp_pm_dccp_notifier);
    if (ret) {
        mpdccp_pr_debug("Failed to register dccp notifier.\n");
        goto err_reg_dccp;
    }

out:
    return ret;

    //unregister_netdevice_notifier(&mpdccp_pm_netdev_notifier);
err_reg_dccp: // later change position
	unregister_dccp_notifier(&mpdccp_pm_dccp_notifier);
goto out;

err_reg_netdev:
#if IS_ENABLED(CONFIG_IPV6)
    unregister_inet6addr_notifier(&mpdccp_pm_inet6addr_notifier);
err_reg_inet6addr:
#endif
    unregister_inetaddr_notifier(&mpdccp_pm_inetaddr_notifier);
err_reg_inetaddr:
    unregister_pernet_subsys(&mpdccp_pm_net_ops);
err_reg_pernet_subsys:
	kmem_cache_destroy(mpdccp_pm_addr_cache);
goto out;
}

static void mpdccp_pm_exit(void)
{
    unregister_dccp_notifier(&mpdccp_pm_dccp_notifier);

    /* TODO: Tear down connections */
    unregister_netdevice_notifier(&mpdccp_pm_netdev_notifier);
#if IS_ENABLED(CONFIG_IPV6)
    unregister_inet6addr_notifier(&mpdccp_pm_inet6addr_notifier);
#endif
    unregister_inetaddr_notifier(&mpdccp_pm_inetaddr_notifier);
    unregister_pernet_subsys(&mpdccp_pm_net_ops);

    /* TODO: we need to free all mpcb's (slab cache) on exit. */
    kmem_cache_destroy(mpdccp_pm_addr_cache);
#if 0
    /* sk_free (and __sk_free) requires wmem_alloc to be 1.
     * All the rest is set to 0 thanks to __GFP_ZERO above.
     */
    atomic_set(&master_sk->sk_wmem_alloc, 1);
    sk_free(master_sk);
#endif
}

static
int
add_init_client_conn (
	struct mpdccp_cb		*mpcb,
	struct sockaddr			*remote_address,
	int				socklen)
{
	struct mpdccp_local_addr 	*local;
	struct sockaddr 		*local_address;
	struct sockaddr_in 		local_v4_address;
	struct sockaddr_in6 		local_v6_address;
	int				locaddr_len;
	int				ret=0, num=0;
	struct mpdccp_pm_ns		*pm_ns;
	int local_if_idx;
	
	if (!mpcb || !remote_address) return -EINVAL;
	if (mpcb->role != MPDCCP_CLIENT) return -EPERM;
	
	//pm_ns = fm_get_ns (current->nsproxy->net_ns);
	pm_ns = fm_get_ns (read_pnet (&mpcb->net));
	
	memcpy(&mpcb->mpdccp_remote_addr, remote_address, socklen);
	mpcb->remaddr_len = socklen;
	
	/* Create subflows on all local interfaces */
	//rcu_read_lock_bh();
	list_for_each_entry_rcu(local, &pm_ns->plocal_addr_list, address_list) {
		/* Set target IPv4/v6 address correctly */
		if (local->family == AF_INET) {
			local_v4_address.sin_family		= AF_INET;
			local_v4_address.sin_addr.s_addr 	= local->addr.in.s_addr;
			local_v4_address.sin_port		= 0;
			local_address = (struct sockaddr *) &local_v4_address;
			locaddr_len = sizeof (struct sockaddr_in);
		} else {
			local_v6_address.sin6_family		= AF_INET6;
			local_v6_address.sin6_addr 		= local->addr.in6;
			local_v6_address.sin6_port		= 0;
			local_address = (struct sockaddr *) &local_v6_address;
			locaddr_len = sizeof (struct sockaddr_in6);
		}
		local_if_idx = local->if_idx;
		/* unlock since mpdccp_add_client_conn() can sleep (data from the list entry are now copied locally) */
		//rcu_read_unlock_bh();
		ret = mpdccp_add_client_conn (	mpcb, local_address, locaddr_len,
						local_if_idx, remote_address, socklen);
		if ((ret < 0) && (ret != -EINPROGRESS) ) {
			mpdccp_pr_debug ("error in mpdccp_add_client_conn() for "
					"subflow %d: %d\n", num, ret);
		} else {
			num++;
			if (mpcb && mpcb->fallback_sp) {
				mpdccp_pr_debug ("fallback to single path DCCP, don't create more subflows\n");
				goto out;
			}
		}
		/* lock again to continue scanning the list */
		//rcu_read_lock_bh();
	}
	//rcu_read_unlock_bh();

out:
	if (num == 0) {
		mpdccp_pr_debug ("no connection could be established\n");
		return ret == 0 ? -ENOTCONN : ret;
	}

	mpdccp_pr_debug("%d client connections added successfully. There are "
			"%d subflows now.\n", num, mpcb->cnt_subflows);

	return num;
}

static
int
add_init_server_conn (
    struct mpdccp_cb		*mpcb,
    int				backlog)
{
    struct mpdccp_local_addr 	*local;
    struct sockaddr 		*local_address;
    struct sockaddr_in 		local_v4_address;
    struct sockaddr_in6 	local_v6_address;
    int				locaddr_len;
    int				ret;
    struct mpdccp_pm_ns		*pm_ns;
    int				server_port = 0;


    if (!mpcb) return -EINVAL;
    if (mpcb->role != MPDCCP_SERVER) return -EPERM;
    if (!mpcb->has_localaddr) return -EINVAL;

    /* get server port from local addr - to be changed - use full local address instead!! */
    local_address = (struct sockaddr*) &mpcb->mpdccp_local_addr;
    if (local_address->sa_family == AF_INET) {
	server_port = ((struct sockaddr_in*)local_address)->sin_port;
    } else if (local_address->sa_family == AF_INET6) {
	server_port = ((struct sockaddr_in6*)local_address)->sin6_port;
    }
    if (server_port == 0) return -EINVAL;

    //pm_ns = fm_get_ns (current->nsproxy->net_ns);
    pm_ns = fm_get_ns (read_pnet (&mpcb->net));

    mpcb->server_port = server_port;
    mpcb->backlog = backlog;

    /* Create subflows on all local interfaces */
    //rcu_read_lock_bh();
    list_for_each_entry_rcu(local, &pm_ns->plocal_addr_list, address_list) {
    
	/* Set target IPv4/v6 address correctly */
	if (local->family == AF_INET) {
	    local_v4_address.sin_family		= AF_INET;
	    local_v4_address.sin_addr.s_addr 	= local->addr.in.s_addr;
	    local_v4_address.sin_port		= server_port;
	    local_address = (struct sockaddr *) &local_v4_address;
	    locaddr_len = sizeof (struct sockaddr_in);
	} else {
	    local_v6_address.sin6_family	= AF_INET6;
	    local_v6_address.sin6_addr 		= local->addr.in6;
	    local_v6_address.sin6_port		= server_port;
	    local_address = (struct sockaddr *) &local_v6_address;
	    locaddr_len = sizeof (struct sockaddr_in6);
	}
	mpdccp_pr_debug("add listen socket: %pISc:%u\n", local_address, htons((unsigned)server_port));
	ret = mpdccp_add_listen_sock (	mpcb, local_address, locaddr_len,
					local->if_idx);
	if (ret < 0) {
	    mpdccp_pr_debug ("error in mpdccp_add_listen_sock(): %d\n", ret);
    	    //rcu_read_unlock_bh();
	    return ret;
	}
    }
    //rcu_read_unlock_bh();

    mpdccp_pr_debug("all server sockets added successfully. There are %d "
			"listening sockets now.\n", mpcb->cnt_subflows);

    return 0;
}

static struct mpdccp_pm_ops mpdccp_pm_default = {
	.add_init_server_conn	= add_init_server_conn,
	.add_init_client_conn	= add_init_client_conn,
	.name 			= "default",
	.owner 			= THIS_MODULE,
};


int mpdccp_pm_default_register(void)
{
	int	ret;

	ret = mpdccp_register_path_manager(&mpdccp_pm_default);
	if (ret < 0) {
		mpdccp_pr_error("Failed to register deault path manager\n");
		return ret;
	}
	/* Register notifier chains for dynamic interface management */
	ret = mpdccp_pm_init();
	if (ret) {
		mpdccp_pr_error("Failed to init default path manager.\n");
		return ret;
	}
	return 0;
}

void mpdccp_pm_default_unregister (void)
{
	mpdccp_pm_exit();
	mpdccp_unregister_path_manager(&mpdccp_pm_default);
}

