/*
 * MPDCCP - DCCP bundling kernel module
 *
 * This module implements a bundling mechanism that aggregates
 * multiple paths using the DCCP protocol.
 * 
 * Copyright (C) 2020 by Frank Reker <frank@reker.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef MPDCCP_META_H
#define MPDCCP_META_H



#define MPDCCP_MAGIC	0xab386ff5
struct mpdccp_cb;

struct mpdccp_meta_cb {
	u32			magic;
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	int			is_meta;
	struct mpdccp_cb	*mpcb;
#endif
};





#endif	/* MPDCCP_META_H */
