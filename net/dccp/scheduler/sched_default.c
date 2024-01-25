/*  SPDX-License-Identifier: GNU General Public License v2 only (GPL-2.0-only)
 *
 * Copyright (C) 2021 by Frank Reker, Deutsche Telekom AG
 *
 * MPDCCP - Default scheduler kernel module
 *
 * It returns the first available sk
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
#include <linux/rculist.h>

#include <net/mpdccp_link.h>
#include <net/mpdccp_link_info.h>
#include "../mpdccp.h"
#include "../mpdccp_scheduler.h"


struct sock *sched_default (struct mpdccp_cb *mpcb)
{
    struct sock	*sk;

    rcu_read_lock();
    mpdccp_for_each_sk(mpcb, sk) {
        if(!mpdccp_sk_can_send(sk) || !mpdccp_packet_fits_in_cwnd(sk)) continue;
        rcu_read_unlock();
        return sk;
    }

    rcu_read_unlock();
    return NULL;
}


struct mpdccp_sched_ops sched_default_ops = {
	.get_subflow	= sched_default,
	.name		= "default",
	.owner		= THIS_MODULE,
};


int mpdccp_sched_default_register (void)
{
	if (mpdccp_register_scheduler(&sched_default_ops))
		return -1;
	return 0;
}

void mpdccp_sched_default_unregister (void)
{
    mpdccp_unregister_scheduler(&sched_default_ops);
}

