/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 * 
 * Copyright (C) 2020 by Frank Reker, Deutsche Telekom AG
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

#ifndef _MPDCCP_META_SK_H
#define _MPDCCP_META_SK_H



#define MPDCCP_META_SK_MAGIC	0xc34fb2e1


struct mpdccp_cb;

struct mpdccp_meta_sk {
	u32			magic;
	struct mpdccp_cb	*mpcb;
};

#define mpdccp_is_meta(sk) \
	((sk) && ((sk)->sk_user_data) && \
		(((struct mpdccp_meta_sk*)((sk)->sk_user_data))->magic \
			== MPDCCP_META_SK_MAGIC))

#define MPDCCP_CB(sk) \
	mpdccp_is_meta(sk) ? ((struct mpdccp_meta_sk*)(sk)->sk_user_data)->mpcb : NULL;










#endif	/* _MPDCCP_META_SK_H */

