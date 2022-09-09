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

#ifndef _LINUX_MPDCCP_LINK_SYSFS_H
#define _LINUX_MPDCCP_LINK_SYSFS_H

#include <net/mpdccp_link.h>

void mpdccp_link_release (struct mpdccp_link_info*);

#ifdef CONFIG_SYSFS
int mpdccp_link_sysfs_add (struct mpdccp_link_info *link);
void mpdccp_link_sysfs_del (struct mpdccp_link_info *link);
int mpdccp_link_sysfs_changedevname (struct mpdccp_link_info *link);
int mpdccp_link_sysfs_changename (struct mpdccp_link_info*, const char *);
int mpdccp_link_sysfs_netinit (struct mpdccp_link_net_data*);
void mpdccp_link_sysfs_netexit (struct mpdccp_link_net_data*);
int mpdccp_link_sysfs_init (void);
void mpdccp_link_sysfs_exit (void);
#else
static inline int mpdccp_link_sysfs_add (struct mpdccp_link_info *link) { return 0; };
static inline void mpdccp_link_sysfs_del (struct mpdccp_link_info *link) {};
static inline int mpdccp_link_sysfs_changedevname (struct mpdccp_link_info *link) { return 0; };
static inline int mpdccp_link_sysfs_changename (struct mpdccp_link_info link, const char *name) { return 0; };
static inline int mpdccp_link_sysfs_netinit (struct mpdccp_link_net_data *ld) { return 0; };
static inline void mpdccp_link_sysfs_netexit (struct mpdccp_link_net_data *ld) {};
static inline int mpdccp_link_sysfs_init (void) { return 0; };
static inline void mpdccp_link_sysfs_exit (void) {};
#endif



#endif	/* _LINUX_MPDCCP_LINK_SYSFS_H */
