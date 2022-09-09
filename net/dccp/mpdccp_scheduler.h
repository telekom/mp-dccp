/*
 * MPDCCP - DCCP bundling kernel module
 *
 * This module implements a bundling mechanism that aggregates
 * multiple paths using the DCCP protocol.
 * 
 * Copyright (C) 2017 by Andreas Philipp Matz <info@andreasmatz.de>
 * Copyright (C) 2020-2021 by Frank Reker <frank@reker.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _MPDCCP_SCHEDULER_H
#define _MPDCCP_SCHEDULER_H


#define MPDCCP_SCHED_NAME_MAX       16


struct mpdccp_cb;
struct sock;


/* mpdccp_sched_ops - MPDCCP scheduler operations. 
 * (*get_subflow)   The scheduling function itself
 * (*init)          Initialize scheduler and per-subflow data for all connections
 * (*init_conn)     Initialize scheduler and per-subflow data for a specific connection
 * name[]           The name of this algorithm
 * *owner           Useful for memleak detection
 */
struct mpdccp_sched_ops {
    struct list_head list;

    struct sock *       (*get_subflow)(struct mpdccp_cb *mpcb);
    void                (*init_conn) (struct mpdccp_cb *mpcb);
    void                (*init_subflow) (struct sock *sk);

    char                name[MPDCCP_SCHED_NAME_MAX];
    struct module       *owner;
};



/* 
 * Generic scheduling functions 
 */

/* Check if a flow is fully established, i.e. the handshake is complete. */
bool mpdccp_sk_can_send(struct sock *sk);

bool mpdccp_packet_fits_in_cwnd(struct sock *sk);

/* This function returns a pointer that is part of a RCU protected
 * structure. It must be called with the rcu_read_lock() held. */
struct sock *mpdccp_return_single_flow(struct mpdccp_cb *mpcb);


/* 
 * Scheduler management functions
 */

int mpdccp_scheduler_setup(void);

int mpdccp_register_scheduler(struct mpdccp_sched_ops *sched);
void mpdccp_unregister_scheduler(struct mpdccp_sched_ops *sched);
void mpdccp_init_scheduler(struct mpdccp_cb *mpcb);
void mpdccp_cleanup_scheduler(struct mpdccp_cb *mpcb);
void mpdccp_get_default_scheduler(char *name);
int mpdccp_set_default_scheduler(const char *name);
struct mpdccp_sched_ops *mpdccp_sched_find(const char *name);


/*
 * Special default scheduler
 */
int mpdccp_sched_default_register (void);
void mpdccp_sched_default_unregister (void);



#endif /* _MPDCCP_SCHEDULER_H */

