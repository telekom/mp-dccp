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

#ifndef MPDCCP_UI_H
#define MPDCCP_UI_H


#define MPDCCP_SUBFLOW_CREATE	1
#define MPDCCP_SUBFLOW_DESTROY	2

#include <linux/dccp.h>
#include <net/mpdccp_meta.h>


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
	int (*listen) (struct sock*, int backlog);
	int (*connect) (struct sock*, const struct sockaddr*, int addrlen);
	int (*bind) (struct sock*, const struct sockaddr*, int addrlen);
	int (*write_xmit) (struct sock*);
	int (*xmit_skb) (struct sock*, struct sk_buff*);
	int (*set_subflow_report) (struct sock*, void (*)(int, struct sock*, struct sock*, struct mpdccp_link_info*, int));
	int (*activate) (struct sock*, int);
	int (*isactive) (struct sock*);
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

static inline int mpdccp_listen (struct sock *sk, int backlog)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_SKFUNC (sk,listen);
	return mpdccp_funcs.listen (sk, backlog);
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

static inline int mpdccp_bind (struct sock *sk, const struct sockaddr *addr, int addrlen)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_SKFUNC(sk,bind);
	return mpdccp_funcs.bind (sk, addr, addrlen);
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

static inline int mpdccp_set_subflow_report (struct sock *sk, void (*callback)(int, struct sock*, struct sock*, struct mpdccp_link_info*, int))
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_SKFUNC(sk,set_subflow_report);
	return mpdccp_funcs.set_subflow_report (sk, callback);
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

static inline int mpdccp_isactive (struct sock *sk)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	MPDCCP_CHECK_FUNC(isactive);
	return mpdccp_funcs.isactive (sk);
#else
	return 0;
#endif
}







#endif	/* MPDCCP_UI_H */
