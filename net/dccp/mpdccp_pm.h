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

#ifndef _MPDCCP_PM_H
#define _MPDCCP_PM_H

#include <net/net_namespace.h>
#include <linux/netpoll.h>
#include <linux/rculist.h>
#include <linux/ktime.h>
#include "dccp.h"
#include "mpdccp.h"
#include "mpdccp_version.h"

/* Maximum lengths for module names */
#define MPDCCP_PM_NAME_MAX          16

#define pm_jiffies32	((u32)jiffies)
/*
 * Namespace related functionality
 */

/* Path manager namespace */
struct mpdccp_pm_ns {
	/* TODO: List of path manager name spaces */
	void			*next_pm;
	
	/* List of local network interfaces */
	struct list_head	plocal_addr_list;
	spinlock_t		plocal_lock;
	
	struct list_head	retransmit;
	struct delayed_work	retransmit_worker;

	struct list_head	events;
	struct delayed_work	address_worker;

	u64 loc4_bits;

	struct net		*net;
};

/* mpdccp_pm_ops - MPDCCP path manager operations. 
 * (*new_session)   Create a new connection to a specific target host
 * (*init)          Initialize path manager and per-subflow data for all connections
 * name[]           The name of this algorithm
 * *owner           Useful for memleak detection
 */
struct mpdccp_pm_ops {
	struct list_head	list;
	
	int			(*add_init_server_conn) (struct mpdccp_cb*, int);
	int			(*add_init_client_conn) (struct mpdccp_cb*, struct sockaddr*, int);
	int			(*claim_local_addr)     (struct mpdccp_cb*, sa_family_t, union inet_addr*);
	void		(*del_addr)       		(struct mpdccp_cb*, u8, bool, bool);
	void		(*add_addr)             (struct mpdccp_cb*, sa_family_t, u8, union inet_addr*, u16, bool);
	int			(*get_id_from_ip)       (struct mpdccp_cb*, union inet_addr*, sa_family_t, bool);
	int 		(*get_hmac)				(struct mpdccp_cb*, u8, sa_family_t, union inet_addr*, u16, bool, u8*);
	void		(*rcv_removeaddr_opt)   (struct mpdccp_cb*, u8);
	void 		(*rcv_prio_opt)			(struct sock*, u8, u64);

	int 		(*rcv_confirm_opt)		(struct mpdccp_cb*, u8*, u8);
	void 		(*store_confirm_opt)	(struct sock*, u8*, u8, u8, u8);
	void		(*del_retrans)			(struct net*, struct sock*);

	char			name[MPDCCP_PM_NAME_MAX];
	struct module		*owner;
};



/*
 * Path management functions
 */

/* Generic path management functions */
int mpdccp_pm_setup (void);
void mpdccp_pm_finish (void);

int mpdccp_register_path_manager(struct mpdccp_pm_ops *pm);
void mpdccp_unregister_path_manager(struct mpdccp_pm_ops *pm);
void mpdccp_init_path_manager(struct mpdccp_cb *mpcb);
void mpdccp_cleanup_path_manager(struct mpdccp_cb *mpcb);
void mpdccp_get_default_path_manager(char *name);
int mpdccp_set_default_path_manager(const char *name);
struct mpdccp_pm_ops *mpdccp_pm_find(const char *name);



int mpdccp_pm_default_register(void);
void mpdccp_pm_default_unregister (void);

#endif /* _MPDCCP_PM_H */

