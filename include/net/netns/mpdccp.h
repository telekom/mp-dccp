/*
 * MPDCCP - MPDCCP namespace
 *
 * The namespace holds global information about interfaces and path
 * managers.
 *
 * The code in this file is directly derived from the mptcp project's 
 * include/net/netns/mptcp.h. All Copyright (C) the original authors
 * Christoph Paasch et al.
 *
 * MPDCCP adjustments are Copyright (C) 2018 
 * by Andreas Philipp Matz <info@andreasmatz.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef __NETNS_MPDCCP_H__
#define __NETNS_MPDCCP_H__

#include <linux/compiler.h>

enum {
	MPDCCP_PM_FULLMESH = 0,
	MPDCCP_PM_MAX
};

struct netns_mpdccp {
	/* TAG-0.8: Migrate to list implementation */
	void *path_managers[MPDCCP_PM_MAX];
};

#endif /* __NETNS_MPDCCP_H__ */
