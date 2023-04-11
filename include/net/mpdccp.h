/*
 * MPDCCP - DCCP bundling kernel module
 *
 * This module implements a bundling mechanism that aggregates
 * multiple paths using the DCCP protocol.
 * 
 * Copyright (C) 2020 by Frank Reker <frank@reker.net>
 * Copyright (C) 2021 by Romeo Cane <rmcane@tiscali.it>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef MPDCCP_UI_H
#define MPDCCP_UI_H


#define MPDCCP_EV_SUBFLOW_CREATE	1
#define MPDCCP_EV_SUBFLOW_DESTROY	2
#define MPDCCP_EV_ALL_SUBFLOW_DOWN	3

/* the following two are for backward compatibilitiy */
#define MPDCCP_SUBFLOW_CREATE	MPDCCP_EV_SUBFLOW_CREATE
#define MPDCCP_SUBFLOW_DESTROY	MPDCCP_EV_SUBFLOW_DESTROY

#include <linux/dccp.h>
#include <net/mpdccp_meta.h>

/* List of supported version(s) (in ascending order of preference) */
static u8 mpdccp_supported_versions[] __attribute__((unused)) = {
	MPDCCP_VERS_0 << 4
};

struct sockaddr;
struct sk_buff;
#if IS_ENABLED(CONFIG_IP_MPDCCP)
struct mpdccp_link_info;
#else
struct mpdccp_link_info { int dummy; };
#endif

#if IS_ENABLED(CONFIG_IP_MPDCCP)
struct mpdccp_funcs {
	u32	magic;
	/* call back functions */
	int (*destroy_sock) (struct sock*);
	int (*mk_meta_sk) (struct sock*);
	int (*connect) (struct sock*, const struct sockaddr*, int addrlen);
	int (*write_xmit) (struct sock*);
	int (*xmit_skb) (struct sock*, struct sk_buff*);
	int (*activate) (struct sock*, int);
	int (*isactive) (const struct sock*);
	int (*try_mpdccp) (struct sock*);
	int (*conn_request) (struct sock *sk, struct dccp_request_sock *dreq);
	int (*rcv_request_sent_state_process) (struct sock *sk, const struct sk_buff *skb);
	int (*rcv_respond_partopen_state_process) (struct sock *sk, int type);
	int (*rcv_established) (struct sock *sk);
	int (*check_req) (struct sock *sk, struct sock *new, struct request_sock *req, struct sk_buff *skb, struct sock **master_sk);
	int (*create_master) (struct sock *sk, struct sock *newsk, struct request_sock *req, struct sk_buff *skb);
	int (*close_meta) (struct sock *sk);
};
extern struct mpdccp_funcs	mpdccp_funcs;
#endif

#if IS_ENABLED(CONFIG_IP_MPDCCP)
# define MPDCCP_HAS_FUNC(func)  ((mpdccp_funcs.magic == MPDCCP_MAGIC) && \
				 mpdccp_funcs.func)
#else
# define MPDCCP_HAS_FUNC(func)  (0)
#endif


static inline int is_mpdccp (const struct sock *sk)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	return sk ? dccp_sk(sk)->mpdccp.magic == MPDCCP_MAGIC : 0;
#else
	return 0;
#endif
}


static inline int mpdccp_is_meta (const struct sock *sk)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	return is_mpdccp (sk) ? dccp_sk(sk)->mpdccp.is_meta : 0;
#else
	return 0;
#endif
}

static inline bool mpdccp_is_validkey(struct mpdccp_key *key)
{
	return (key && (((key->type == DCCPK_PLAIN) && (key->size == MPDCCP_PLAIN_KEY_SIZE))
			|| ((key->type == DCCPK_C25519_SHA256) && (key->size == MPDCCP_C25519_KEY_SIZE))
			|| ((key->type == DCCPK_C25519_SHA512) && (key->size == MPDCCP_C25519_KEY_SIZE))));
}

#if IS_ENABLED(CONFIG_IP_MPDCCP)
#define MPDCCP_CB(sk) (is_mpdccp(sk) ? dccp_sk(sk)->mpdccp.mpcb : NULL)
#else
#define MPDCCP_CB(sk) (NULL)
#endif

#if IS_ENABLED(CONFIG_IP_MPDCCP)
# define MPDCCP_CHECK_SK(sk) do { \
	   if (!is_mpdccp(sk)) { \
		   printk ("%s: socket is not an mpdccp socket\n", __func__); \
		   return -ENOTSUPP; \
	   } \
	} while (0)
# define MPDCCP_CHECK_FUNC(func) do { \
	   if (!MPDCCP_HAS_FUNC(func)) { \
		   printk ("%s: mpdccp_funcs not initialized: .magic=%x, .%s=%p\n", \
						__func__, mpdccp_funcs.magic, #func, mpdccp_funcs.func); \
		   return -ENOTSUPP; \
	   } \
	} while (0)
# define MPDCCP_CHECK_SKFUNC(sk,func) do { \
		MPDCCP_CHECK_SK(sk); \
		MPDCCP_CHECK_FUNC(func); \
	} while (0)
#else
# define MPDCCP_CHECK_SK(sk) do { } while (0)
# define MPDCCP_CHECK_FUNC(func) do { } while (0)
# define MPDCCP_CHECK_SKFUNC(sk,func) do { } while (0)
#endif


static inline int mpdccp_destroy_sock (struct sock *sk)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_SKFUNC(sk,destroy_sock);
	return mpdccp_funcs.destroy_sock (sk);
#else
	return 0;
#endif
}

static inline int mpdccp_mk_meta_sk (struct sock *sk)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_FUNC(mk_meta_sk);
	return mpdccp_funcs.mk_meta_sk (sk);
#else
	return 0;
#endif
}


static inline int mpdccp_connect (struct sock *sk, const struct sockaddr *addr, int addrlen)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_SKFUNC (sk,connect);
	return mpdccp_funcs.connect (sk, addr, addrlen);
#else
	return 0;
#endif
}

static inline int mpdccp_write_xmit (struct sock *sk)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_SKFUNC(sk,write_xmit);
	return mpdccp_funcs.write_xmit (sk);
#else
	return 0;
#endif
}

static inline int mpdccp_xmit_skb (struct sock *sk, struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_SKFUNC(sk,xmit_skb);
	return mpdccp_funcs.xmit_skb (sk, skb);
#else
	return 0;
#endif
}


#define MPDCCP_SUBFLOW_NOTIFIER
struct mpdccp_subflow_notifier {
	struct mpdccp_link_info	*link;
	struct sock		*sk;
	struct sock		*subsk;
	int			role;
};
#if IS_ENABLED(CONFIG_IP_MPDCCP)
int register_mpdccp_subflow_notifier (struct notifier_block *nb);
int unregister_mpdccp_subflow_notifier (struct notifier_block *nb);
#else
static inline int register_mpdccp_subflow_notifier (struct notifier_block *nb)
{
	return 0;
}
static inline int unregister_mpdccp_subflow_notifier (struct notifier_block *nb)
{
	return 0;
}
#endif

static inline int try_mpdccp (struct sock *sk)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_FUNC(try_mpdccp);
	return mpdccp_funcs.try_mpdccp (sk);
#else
	return 0;
#endif
}

static inline int mpdccp_activate (struct sock *sk, int on)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_FUNC(activate);
	return mpdccp_funcs.activate (sk, on);
#else
	return 0;
#endif
}

static inline int mpdccp_isactive (const struct sock *sk)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_FUNC(isactive);
	return mpdccp_funcs.isactive (sk);
#else
	return 0;
#endif
}


static inline int mpdccp_conn_request (struct sock *sk, struct dccp_request_sock *dreq)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_SKFUNC(sk, conn_request);
	return mpdccp_funcs.conn_request (sk, dreq);
#else
	return 0;
#endif
}

static inline int mpdccp_rcv_request_sent_state_process (struct sock *sk, const struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_SKFUNC(sk, rcv_request_sent_state_process);
	return mpdccp_funcs.rcv_request_sent_state_process (sk, skb);
#else
	return 0;
#endif
}

static inline int mpdccp_rcv_respond_partopen_state_process (struct sock *sk, int type)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_SKFUNC(sk, rcv_respond_partopen_state_process);
	return mpdccp_funcs.rcv_respond_partopen_state_process (sk, type);
#else
	return 0;
#endif
}

static inline int mpdccp_rcv_established (struct sock *sk)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_SKFUNC(sk, rcv_established);
	return mpdccp_funcs.rcv_established (sk);
#else
	return 0;
#endif
}

static inline int mpdccp_check_req (struct sock *sk, struct sock *newsk, struct request_sock *req, struct sk_buff *skb, struct sock **master_sk)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_SKFUNC(sk, check_req);
	return mpdccp_funcs.check_req (sk, newsk, req, skb, master_sk);
#else
	return 0;
#endif
}

static inline int mpdccp_create_master (struct sock *sk, struct sock *newsk, struct request_sock *req, struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_SKFUNC (sk,create_master);
	return mpdccp_funcs.create_master (sk, newsk, req, skb);
#else
	return 0;
#endif
}

static inline int mpdccp_close_meta (struct sock *sk)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_SKFUNC(sk, close_meta);
	return mpdccp_funcs.close_meta (sk);
#else
	return 0;
#endif
}

#endif	/* MPDCCP_UI_H */
