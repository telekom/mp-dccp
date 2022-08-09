/*
 *  net/dccp/options.c
 *
 *  An implementation of the DCCP protocol
 *  Copyright (c) 2005 Aristeu Sergio Rozanski Filho <aris@cathedrallabs.org>
 *  Copyright (c) 2005 Arnaldo Carvalho de Melo <acme@ghostprotocols.net>
 *  Copyright (c) 2005 Ian McDonald <ian.mcdonald@jandi.co.nz>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#include <linux/dccp.h>
#include <linux/module.h>
#include <linux/types.h>
#include <asm/unaligned.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>

// TODO: cleanup
#include "ccids/ccid2.h"

#include "ackvec.h"
#include "ccid.h"
#include "dccp.h"
#include "feat.h"
#if IS_ENABLED(CONFIG_IP_MPDCCP)
#  include "mpdccp.h"
#  include "mpdccp_pm.h"
#  include <net/mpdccp.h>
#endif

u64 dccp_decode_value_var(const u8 *bf, const u8 len)
{
	u64 value = 0;

	if (len >= DCCP_OPTVAL_MAXLEN)
		value += ((u64)*bf++) << 40;
	if (len > 4)
		value += ((u64)*bf++) << 32;
	if (len > 3)
		value += ((u64)*bf++) << 24;
	if (len > 2)
		value += ((u64)*bf++) << 16;
	if (len > 1)
		value += ((u64)*bf++) << 8;
	if (len > 0)
		value += *bf;

	return value;
}


void mpdccp_do_hmac_chk(struct sock *sk, struct dccp_options_received *opt_recv){
	struct mpdccp_cb *mpcb = get_mpcb(sk);
	u8 chk_hmac[MPDCCP_HMAC_SIZE];
	int ret;

	if (opt_recv->dccpor_addaddr[0] && mpcb->pm_ops->add_remote_addr){
		u8 len = opt_recv->dccpor_addaddr_len;
		u8 id = opt_recv->dccpor_addaddr[3];
		union inet_addr addr;
		sa_family_t family = AF_INET;
		u16 port = 0;

		if(len == 8 || len == 10){					// ipv4
			addr.ip = get_unaligned_be32(&opt_recv->dccpor_addaddr[4]);
			if(len == 10){
				port = get_unaligned_be16(&opt_recv->dccpor_addaddr[8]);
			}
			dccp_pr_debug("rx opt: DCCPO_MP_ADDADDR = rem_id: %u, ip4 %pI4:%u", id, &addr.ip, port);
		} else if(len == 20 || len == 22){			//ipv6
			family = AF_INET6;
			memcpy(addr.ip6, &opt_recv->dccpor_addaddr[4], 16);
			if(len == 22){
				port = get_unaligned_be16(&opt_recv->dccpor_addaddr[20]);
			}
			dccp_pr_debug("rx opt: DCCPO_MP_ADDADDR = rem_id: %u, ip6 %pI6:%u", id, &addr.ip6, port);
		}

		ret = mpcb->pm_ops->pm_hmac(mpcb, id, family, &addr, port, 0, chk_hmac);

		if(!ret){
			dccp_pr_debug("HMAC compare rx: %llx exp: %llx", be64_to_cpu(*(u64 *)opt_recv->dccpor_mp_hmac),
					be64_to_cpu(*((u64 *)chk_hmac)));
			if(memcmp(opt_recv->dccpor_mp_hmac, chk_hmac, MPDCCP_HMAC_SIZE)){
				dccp_pr_debug("HMAC CHECK FAILED!");
				return;
			}
			mpcb->pm_ops->add_remote_addr(mpcb, family, id, &addr, port);

		}
	}
	
	else if(opt_recv->dccpor_removeaddr[0] && mpcb->pm_ops->rm_remote_addr){
		u8 id = opt_recv->dccpor_removeaddr[3];
		dccp_pr_debug("%s rx opt: DCCPO_MP_REMOVEADDR id: %u", dccp_role(sk), id);

		ret = mpcb->pm_ops->pm_hmac(mpcb, id, 0, 0, 0, 0, chk_hmac);

		if(!ret){
			dccp_pr_debug("HMAC compare rx: %llx exp: %llx", be64_to_cpu(*(u64 *)opt_recv->dccpor_mp_hmac),
					be64_to_cpu(*((u64 *)chk_hmac)));
			if(memcmp(opt_recv->dccpor_mp_hmac, chk_hmac, MPDCCP_HMAC_SIZE)){
				dccp_pr_debug("HMAC CHECK FAILED!");
				return;
			}
			mpcb->pm_ops->rm_remote_addr(id);

		}
	}
}

/**
 * dccp_parse_options  -  Parse DCCP options present in @skb
 * @sk: client|server|listening dccp socket (when @dreq != NULL)
 * @dreq: request socket to use during connection setup, or NULL
 */
int dccp_parse_options(struct sock *sk, struct dccp_request_sock *dreq,
		       struct sk_buff *skb)
{
	struct dccp_sock *dp = dccp_sk(sk);
	const struct dccp_hdr *dh = dccp_hdr(skb);
	const u8 pkt_type = DCCP_SKB_CB(skb)->dccpd_type;
	unsigned char *options = (unsigned char *)dh + dccp_hdr_len(skb);
	unsigned char *opt_ptr = options;
	const unsigned char *opt_end = (unsigned char *)dh +
					(dh->dccph_doff * 4);
	struct dccp_options_received *opt_recv = &dp->dccps_options_received;
	unsigned char opt, len;
	unsigned char *uninitialized_var(value);
	u32 elapsed_time;
	__be32 opt_val;
	int rc;
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	u8 mp_opt = 0;
#endif
	int mandatory = 0;
	memset(opt_recv, 0, sizeof(*opt_recv));

	opt = len = 0;
	while (opt_ptr != opt_end) {
		opt   = *opt_ptr++;
		len   = 0;
		value = NULL;

		/* Check if this isn't a single byte option */
		if (opt > DCCPO_MAX_RESERVED) {
			if (opt_ptr == opt_end){
				goto out_nonsensical_length;
			}

			len = *opt_ptr++;
			if (len < 2){
				goto out_nonsensical_length;
			}
			/*
			 * Remove the type and len fields, leaving
			 * just the value size
			 */
			len	-= 2;
			value	= opt_ptr;
			opt_ptr += len;

			if (opt_ptr > opt_end){
				goto out_nonsensical_length;
			}
		}

		/*
		 * CCID-specific options are ignored during connection setup, as
		 * negotiation may still be in progress (see RFC 4340, 10.3).
		 * The same applies to Ack Vectors, as these depend on the CCID.
		 */
		if (dreq != NULL && (opt >= DCCPO_MIN_RX_CCID_SPECIFIC ||
		    opt == DCCPO_ACK_VECTOR_0 || opt == DCCPO_ACK_VECTOR_1))
			goto ignore_option;

		switch (opt) {
		case DCCPO_PADDING:
			break;
		case DCCPO_MANDATORY:
			if (mandatory)
				goto out_invalid_option;
			if (pkt_type != DCCP_PKT_DATA)
				mandatory = 1;
			break;
		case DCCPO_NDP_COUNT:
			if (len > 6)
				goto out_invalid_option;

			opt_recv->dccpor_ndp = dccp_decode_value_var(value, len);
			dccp_pr_debug("%s opt: NDP count=%llu\n", dccp_role(sk),
				      (unsigned long long)opt_recv->dccpor_ndp);
			break;
		case DCCPO_CHANGE_L ... DCCPO_CONFIRM_R:
			if (pkt_type == DCCP_PKT_DATA)      /* RFC 4340, 6 */
				break;
			if (len == 0)
				goto out_invalid_option;
			rc = dccp_feat_parse_options(sk, dreq, mandatory, opt,
						    *value, value + 1, len - 1);
			if (rc)
				goto out_featneg_failed;
			break;
		case DCCPO_TIMESTAMP:
			if (len != 4)
				goto out_invalid_option;
			/*
			 * RFC 4340 13.1: "The precise time corresponding to
			 * Timestamp Value zero is not specified". We use
			 * zero to indicate absence of a meaningful timestamp.
			 */
			opt_val = get_unaligned((__be32 *)value);
			if (unlikely(opt_val == 0)) {
				DCCP_WARN("Timestamp with zero value\n");
				break;
			}

			if (dreq != NULL) {
				dreq->dreq_timestamp_echo = ntohl(opt_val);
				dreq->dreq_timestamp_time = dccp_timestamp();
			} else {
				opt_recv->dccpor_timestamp =
					dp->dccps_timestamp_echo = ntohl(opt_val);
				dp->dccps_timestamp_time = dccp_timestamp();
			}
			dccp_pr_debug("%s rx opt: TIMESTAMP=%u, ackno=%llu\n",
				      dccp_role(sk), ntohl(opt_val),
				      (unsigned long long)
				      DCCP_SKB_CB(skb)->dccpd_ack_seq);
			/* schedule an Ack in case this sender is quiescent */
			inet_csk_schedule_ack(sk);
			break;
		case DCCPO_TIMESTAMP_ECHO:
			if (len != 4 && len != 6 && len != 8)
				goto out_invalid_option;

			opt_val = get_unaligned((__be32 *)value);
			opt_recv->dccpor_timestamp_echo = ntohl(opt_val);

			dccp_pr_debug("%s rx opt: TIMESTAMP_ECHO=%u, len=%d, "
				      "ackno=%llu", dccp_role(sk),
				      opt_recv->dccpor_timestamp_echo,
				      len + 2,
				      (unsigned long long)
				      DCCP_SKB_CB(skb)->dccpd_ack_seq);

			value += 4;

			if (len == 4) {		/* no elapsed time included */
				dccp_pr_debug_cat("\n");
				break;
			}

			if (len == 6) {		/* 2-byte elapsed time */
				__be16 opt_val2 = get_unaligned((__be16 *)value);
				elapsed_time = ntohs(opt_val2);
			} else {		/* 4-byte elapsed time */
				opt_val = get_unaligned((__be32 *)value);
				elapsed_time = ntohl(opt_val);
			}

			dccp_pr_debug_cat(", ELAPSED_TIME=%u\n", elapsed_time);

			/* Give precedence to the biggest ELAPSED_TIME */
			if (elapsed_time > opt_recv->dccpor_elapsed_time)
				opt_recv->dccpor_elapsed_time = elapsed_time;
			break;
		case DCCPO_ELAPSED_TIME:
			if (dccp_packet_without_ack(skb))   /* RFC 4340, 13.2 */
				break;

			if (len == 2) {
				__be16 opt_val2 = get_unaligned((__be16 *)value);
				elapsed_time = ntohs(opt_val2);
			} else if (len == 4) {
				opt_val = get_unaligned((__be32 *)value);
				elapsed_time = ntohl(opt_val);
			} else {
				goto out_invalid_option;
			}

			if (elapsed_time > opt_recv->dccpor_elapsed_time)
				opt_recv->dccpor_elapsed_time = elapsed_time;

			dccp_pr_debug("%s rx opt: ELAPSED_TIME=%d\n",
				      dccp_role(sk), elapsed_time);
			break;
#if IS_ENABLED(CONFIG_IP_MPDCCP)
		case DCCPO_MULTIPATH:
			if (len == 0)
				goto out_invalid_option;
			mp_opt = *value++;
			len--;
			switch(mp_opt) {

			case DCCPO_MP_CONFIRM:
			case DCCPO_MP_JOIN:
			case DCCPO_MP_FAST_CLOSE:
			case DCCPO_MP_KEY:
				if (len < 2) {
					goto out_invalid_option;
				}
				opt_recv->saw_mpkey = 1;
				if (pkt_type == DCCP_PKT_REQUEST) {
					int i;
					/* Request: collect key types */
					for (i = 0; len && (i < MPDCCP_MAX_KEYS); i++) {
						int key_len;
						u8 key_type = *value++;
						switch (key_type) {
							case DCCPK_PLAIN:
								key_len = MPDCCP_PLAIN_KEY_SIZE;
								break;
							/* fall through */
							case DCCPK_C25519_SHA256:
							case DCCPK_C25519_SHA512:
								key_len = MPDCCP_C25519_KEY_SIZE;
								break;
							default:
								dccp_pr_debug("%s rx opt: received unsupported key type %d", dccp_role(sk), key_type);
								goto out_invalid_option;
						}
						len--;
						if (len < key_len) {
							dccp_pr_debug("%s rx opt: invalid key length %d", dccp_role(sk), len);
							goto out_invalid_option;
						}

						dccp_pr_debug("%s rx opt: DCCPO_MP_KEY(%d) = %llx, type %d, len %d, sk %p dreq %p remlen %d",
								dccp_role(sk), i, be64_to_cpu(*(u64*)value), key_type, key_len, sk, dreq, len);
						memcpy(opt_recv->dccpor_mp_keys[i].value, value, key_len);
						opt_recv->dccpor_mp_keys[i].size = key_len;
						opt_recv->dccpor_mp_keys[i].type = key_type;
						opt_recv->dccpor_mp_suppkeys |= (1 << key_type);
						len -= key_len;
						value += key_len;
					}
				} else if ((pkt_type == DCCP_PKT_ACK) || (pkt_type == DCCP_PKT_RESPONSE)) {
					int i;
					/* Response/Ack: collect key data */
					for (i = 0; len && (i < MPDCCP_MAX_KEYS); i++) {
						int key_len;
						u8 key_type = *value++;
						switch (key_type) {
							case DCCPK_PLAIN:
								key_len = MPDCCP_PLAIN_KEY_SIZE;
								break;
							/* fall through */
							case DCCPK_C25519_SHA256:
							case DCCPK_C25519_SHA512:
								key_len = MPDCCP_C25519_KEY_SIZE;
								break;
							default:
								dccp_pr_debug("%s rx opt: received unsupported key type %d", dccp_role(sk), key_type);
								goto out_invalid_option;
						}
						len--;
						if (len < key_len) {
							dccp_pr_debug("%s rx opt: invalid key length %d", dccp_role(sk), len);
							goto out_invalid_option;
						}

						dccp_pr_debug("%s rx opt: DCCPO_MP_KEY(%d) = %llx, type %d, len %d, sk %p dreq %p remlen %d",
								dccp_role(sk), i, be64_to_cpu(*(u64*)value), key_type, key_len, sk, dreq, len);
						memcpy(opt_recv->dccpor_mp_keys[i].value, value, key_len);
						opt_recv->dccpor_mp_keys[i].size = key_len;
						opt_recv->dccpor_mp_keys[i].type = key_type;
						opt_recv->dccpor_mp_suppkeys |= (1 << key_type);
						len -= key_len;
						value += key_len;
					}
					/* Send ack if the authentication was completed before */
					if ((pkt_type == DCCP_PKT_ACK) && dccp_sk(sk)->auth_done) {
						dccp_send_ack(sk);
					}
				}
				break;

			case DCCPO_MP_SEQ:
				//TODO reordering, use 48 bit > 8 -> 6
				if(len != 6){ //if not 48 bit
					goto out_invalid_option;
				}
				opt_recv->dccpor_oall_seq = dccp_decode_value_var(value, len);
				dccp_pr_debug("%s rx opt: MP_SEQ = %llu", dccp_role(sk), (u64)opt_recv->dccpor_oall_seq);
				break;

			case DCCPO_MP_HMAC:
				if (len != MPDCCP_HMAC_SIZE) {
					goto out_invalid_option;
				}
				dccp_pr_debug("%s rx opt: DCCPO_MP_HMAC = %llx, sk %p dreq %p", dccp_role(sk),
						be64_to_cpu(*(u64 *)value), sk, dreq);

				memcpy(opt_recv->dccpor_mp_hmac, value, MPDCCP_HMAC_SIZE);
				/* Send ack if the authentication was completed before */
				if ((pkt_type == DCCP_PKT_ACK) && dccp_sk(sk)->auth_done)
					dccp_send_ack(sk);

				if(is_mpdccp(sk))
					mpdccp_do_hmac_chk(sk, opt_recv);
				break;

			case DCCPO_MP_RTT:
			case DCCPO_MP_ADDADDR:
				if(len == 5 || len == 7 || len == 17 || len == 19){
					opt_recv->dccpor_addaddr_len = len+3;
					memcpy(&opt_recv->dccpor_addaddr[0], value-3, opt_recv->dccpor_addaddr_len);
				} else
					goto out_invalid_option;
				break;

			case DCCPO_MP_REMOVEADDR:
				if(len == 1){
					memcpy(&opt_recv->dccpor_removeaddr[0], value-3, len+3);
				} else
					goto out_invalid_option;
				break;

			case DCCPO_MP_PRIO:
			case DCCPO_MP_CLOSE:

			default:
				DCCP_CRIT("DCCP(%p): mp option %d(len=%d) not "
					  "implemented, ignoring", sk, mp_opt, len);
				break;
			}

#endif
		case DCCPO_MIN_RX_CCID_SPECIFIC ... DCCPO_MAX_RX_CCID_SPECIFIC:
			if (ccid_hc_rx_parse_options(dp->dccps_hc_rx_ccid, sk,
						     pkt_type, opt, value, len))
				goto out_invalid_option;
			break;
		case DCCPO_ACK_VECTOR_0:
		case DCCPO_ACK_VECTOR_1:
			if (dccp_packet_without_ack(skb))   /* RFC 4340, 11.4 */
				break;
			/*
			 * Ack vectors are processed by the TX CCID if it is
			 * interested. The RX CCID need not parse Ack Vectors,
			 * since it is only interested in clearing old state.
			 * Fall through.
			 */
		case DCCPO_MIN_TX_CCID_SPECIFIC ... DCCPO_MAX_TX_CCID_SPECIFIC:
			if (ccid_hc_tx_parse_options(dp->dccps_hc_tx_ccid, sk,
						     pkt_type, opt, value, len))
				goto out_invalid_option;
			break;
		default:
			DCCP_CRIT("DCCP(%p): option %d(len=%d) not "
				  "implemented, ignoring", sk, opt, len);
			break;
		}
ignore_option:
		if (opt != DCCPO_MANDATORY)
			mandatory = 0;
	}

	/* mandatory was the last byte in option list -> reset connection */
	if (mandatory)
		goto out_invalid_option;

out_nonsensical_length:
	/* RFC 4340, 5.8: ignore option and all remaining option space */
	return 0;

out_invalid_option:
	DCCP_INC_STATS(DCCP_MIB_INVALIDOPT);
	rc = DCCP_RESET_CODE_OPTION_ERROR;
out_featneg_failed:
	DCCP_WARN("DCCP(%p): Option %d (len=%d) error=%u\n", sk, opt, len, rc);
	DCCP_SKB_CB(skb)->dccpd_reset_code = rc;
	DCCP_SKB_CB(skb)->dccpd_reset_data[0] = opt;
	DCCP_SKB_CB(skb)->dccpd_reset_data[1] = len > 0 ? value[0] : 0;
	DCCP_SKB_CB(skb)->dccpd_reset_data[2] = len > 1 ? value[1] : 0;
	return -1;
}

EXPORT_SYMBOL_GPL(dccp_parse_options);

void dccp_encode_value_var(const u64 value, u8 *to, const u8 len)
{
	if (len >= DCCP_OPTVAL_MAXLEN)
		*to++ = (value & 0xFF0000000000ull) >> 40;
	if (len > 4)
		*to++ = (value & 0xFF00000000ull) >> 32;
	if (len > 3)
		*to++ = (value & 0xFF000000) >> 24;
	if (len > 2)
		*to++ = (value & 0xFF0000) >> 16;
	if (len > 1)
		*to++ = (value & 0xFF00) >> 8;
	if (len > 0)
		*to++ = (value & 0xFF);
}

static inline u8 dccp_ndp_len(const u64 ndp)
{
	if (likely(ndp <= 0xFF))
		return 1;
	return likely(ndp <= USHRT_MAX) ? 2 : (ndp <= UINT_MAX ? 4 : 6);
}

int dccp_insert_option(struct sk_buff *skb, const unsigned char option,
		       const void *value, const unsigned char len)
{
	unsigned char *to;

	if (DCCP_SKB_CB(skb)->dccpd_opt_len + len + 2 > DCCP_MAX_OPT_LEN)
		return -1;

	DCCP_SKB_CB(skb)->dccpd_opt_len += len + 2;

	to    = skb_push(skb, len + 2);
	*to++ = option;
	*to++ = len + 2;

	memcpy(to, value, len);
	return 0;
}

EXPORT_SYMBOL_GPL(dccp_insert_option);

static int dccp_insert_option_ndp(struct sock *sk, struct sk_buff *skb)
{
	struct dccp_sock *dp = dccp_sk(sk);
	u64 ndp = dp->dccps_ndp_count;

	if (dccp_non_data_packet(skb))
		++dp->dccps_ndp_count;
	else
		dp->dccps_ndp_count = 0;

	if (ndp > 0) {
		unsigned char *ptr;
		const int ndp_len = dccp_ndp_len(ndp);
		const int len = ndp_len + 2;

		if (DCCP_SKB_CB(skb)->dccpd_opt_len + len > DCCP_MAX_OPT_LEN)
			return -1;

		DCCP_SKB_CB(skb)->dccpd_opt_len += len;

		ptr = skb_push(skb, len);
		*ptr++ = DCCPO_NDP_COUNT;
		*ptr++ = len;
		dccp_encode_value_var(ndp, ptr, ndp_len);
	}

	return 0;
}

static inline int dccp_elapsed_time_len(const u32 elapsed_time)
{
	return elapsed_time == 0 ? 0 : elapsed_time <= 0xFFFF ? 2 : 4;
}

static int dccp_insert_option_timestamp(struct sk_buff *skb)
{
	__be32 now = htonl(dccp_timestamp());
	/* yes this will overflow but that is the point as we want a
	 * 10 usec 32 bit timer which mean it wraps every 11.9 hours */

	return dccp_insert_option(skb, DCCPO_TIMESTAMP, &now, sizeof(now));
}

static int dccp_insert_option_timestamp_echo(struct dccp_sock *dp,
					     struct dccp_request_sock *dreq,
					     struct sk_buff *skb)
{
	__be32 tstamp_echo;
	unsigned char *to;
	u32 elapsed_time, elapsed_time_len, len;

	if (dreq != NULL) {
		elapsed_time = dccp_timestamp() - dreq->dreq_timestamp_time;
		tstamp_echo  = htonl(dreq->dreq_timestamp_echo);
		dreq->dreq_timestamp_echo = 0;
	} else {
		elapsed_time = dccp_timestamp() - dp->dccps_timestamp_time;
		tstamp_echo  = htonl(dp->dccps_timestamp_echo);
		dp->dccps_timestamp_echo = 0;
	}

	elapsed_time_len = dccp_elapsed_time_len(elapsed_time);
	len = 6 + elapsed_time_len;

	if (DCCP_SKB_CB(skb)->dccpd_opt_len + len > DCCP_MAX_OPT_LEN)
		return -1;

	DCCP_SKB_CB(skb)->dccpd_opt_len += len;

	to    = skb_push(skb, len);
	*to++ = DCCPO_TIMESTAMP_ECHO;
	*to++ = len;

	memcpy(to, &tstamp_echo, 4);
	to += 4;

	if (elapsed_time_len == 2) {
		const __be16 var16 = htons((u16)elapsed_time);
		memcpy(to, &var16, 2);
	} else if (elapsed_time_len == 4) {
		const __be32 var32 = htonl(elapsed_time);
		memcpy(to, &var32, 4);
	}

	return 0;
}

static int dccp_insert_option_ackvec(struct sock *sk, struct sk_buff *skb)
{
	struct dccp_sock *dp = dccp_sk(sk);
	struct dccp_ackvec *av = dp->dccps_hc_rx_ackvec;
	struct dccp_skb_cb *dcb = DCCP_SKB_CB(skb);
	const u16 buflen = dccp_ackvec_buflen(av);
	/* Figure out how many options do we need to represent the ackvec */
	const u8 nr_opts = DIV_ROUND_UP(buflen, DCCP_SINGLE_OPT_MAXLEN);
	u16 len = buflen + 2 * nr_opts;
	u8 i, nonce = 0;
	const unsigned char *tail, *from;
	unsigned char *to;

	if (dcb->dccpd_opt_len + len > DCCP_MAX_OPT_LEN) {
		DCCP_WARN("Lacking space for %u bytes on %s packet\n", len,
			  dccp_packet_name(dcb->dccpd_type));
		return -1;
	}
	/*
	 * Since Ack Vectors are variable-length, we can not always predict
	 * their size. To catch exception cases where the space is running out
	 * on the skb, a separate Sync is scheduled to carry the Ack Vector.
	 */
	if (len > DCCPAV_MIN_OPTLEN &&
	    len + dcb->dccpd_opt_len + skb->len > dp->dccps_mss_cache) {
		DCCP_WARN("No space left for Ack Vector (%u) on skb (%u+%u), "
			  "MPS=%u ==> reduce payload size?\n", len, skb->len,
			  dcb->dccpd_opt_len, dp->dccps_mss_cache);
		dp->dccps_sync_scheduled = 1;
		return 0;
	}
	dcb->dccpd_opt_len += len;

	to   = skb_push(skb, len);
	len  = buflen;
	from = av->av_buf + av->av_buf_head;
	tail = av->av_buf + DCCPAV_MAX_ACKVEC_LEN;

	for (i = 0; i < nr_opts; ++i) {
		int copylen = len;

		if (len > DCCP_SINGLE_OPT_MAXLEN)
			copylen = DCCP_SINGLE_OPT_MAXLEN;

		/*
		 * RFC 4340, 12.2: Encode the Nonce Echo for this Ack Vector via
		 * its type; ack_nonce is the sum of all individual buf_nonce's.
		 */
		nonce ^= av->av_buf_nonce[i];

		*to++ = DCCPO_ACK_VECTOR_0 + av->av_buf_nonce[i];
		*to++ = copylen + 2;

		/* Check if buf_head wraps */
		if (from + copylen > tail) {
			const u16 tailsize = tail - from;

			memcpy(to, from, tailsize);
			to	+= tailsize;
			len	-= tailsize;
			copylen	-= tailsize;
			from	= av->av_buf;
		}

		memcpy(to, from, copylen);
		from += copylen;
		to   += copylen;
		len  -= copylen;
	}
	/*
	 * Each sent Ack Vector is recorded in the list, as per A.2 of RFC 4340.
	 */
	if (dccp_ackvec_update_records(av, dcb->dccpd_seq, nonce))
		return -ENOBUFS;
	return 0;
}

/**
 * dccp_insert_option_mandatory  -  Mandatory option (5.8.2)
 * Note that since we are using skb_push, this function needs to be called
 * _after_ inserting the option it is supposed to influence (stack order).
 */
int dccp_insert_option_mandatory(struct sk_buff *skb)
{
	if (DCCP_SKB_CB(skb)->dccpd_opt_len >= DCCP_MAX_OPT_LEN)
		return -1;

	DCCP_SKB_CB(skb)->dccpd_opt_len++;
	*(u8 *)skb_push(skb, 1) = DCCPO_MANDATORY;
	return 0;
}

/**
 * dccp_insert_fn_opt  -  Insert single Feature-Negotiation option into @skb
 * @type: %DCCPO_CHANGE_L, %DCCPO_CHANGE_R, %DCCPO_CONFIRM_L, %DCCPO_CONFIRM_R
 * @feat: one out of %dccp_feature_numbers
 * @val: NN value or SP array (preferred element first) to copy
 * @len: true length of @val in bytes (excluding first element repetition)
 * @repeat_first: whether to copy the first element of @val twice
 *
 * The last argument is used to construct Confirm options, where the preferred
 * value and the preference list appear separately (RFC 4340, 6.3.1). Preference
 * lists are kept such that the preferred entry is always first, so we only need
 * to copy twice, and avoid the overhead of cloning into a bigger array.
 */
int dccp_insert_fn_opt(struct sk_buff *skb, u8 type, u8 feat,
		       u8 *val, u8 len, bool repeat_first)
{
	u8 tot_len, *to;

	/* take the `Feature' field and possible repetition into account */
	if (len > (DCCP_SINGLE_OPT_MAXLEN - 2)) {
		DCCP_WARN("length %u for feature %u too large\n", len, feat);
		return -1;
	}

	if (unlikely(val == NULL || len == 0))
		len = repeat_first = false;
	tot_len = 3 + repeat_first + len;

	if (DCCP_SKB_CB(skb)->dccpd_opt_len + tot_len > DCCP_MAX_OPT_LEN) {
		DCCP_WARN("packet too small for feature %d option!\n", feat);
		return -1;
	}
	DCCP_SKB_CB(skb)->dccpd_opt_len += tot_len;

	to    = skb_push(skb, tot_len);
	*to++ = type;
	*to++ = tot_len;
	*to++ = feat;

	if (repeat_first)
		*to++ = *val;
	if (len)
		memcpy(to, val, len);
	return 0;
}

/* The length of all options needs to be a multiple of 4 (5.8) */
static void dccp_insert_option_padding(struct sk_buff *skb)
{
	int padding = DCCP_SKB_CB(skb)->dccpd_opt_len % 4;

	if (padding != 0) {
		padding = 4 - padding;
		memset(skb_push(skb, padding), 0, padding);
		DCCP_SKB_CB(skb)->dccpd_opt_len += padding;
	}
}

#if IS_ENABLED(CONFIG_IP_MPDCCP)
static int dccp_insert_option_multipath(struct sk_buff *skb, const unsigned char mp_option,
		       const void *value, const unsigned char len)
{
	unsigned char *to;

	if (DCCP_SKB_CB(skb)->dccpd_opt_len + len + 3 > DCCP_MAX_OPT_LEN)
		return -1;

	DCCP_SKB_CB(skb)->dccpd_opt_len += len + 3;

	to    = skb_push(skb, len + 3);
	*to++ = DCCPO_MULTIPATH;
	*to++ = len + 3;
	*to++ = mp_option;

	memcpy(to, value, len);
	return 0;
}

/*static int dccp_insert_option_mp_confirm(struct sk_buff *skb)
{
	return 0;
}

static int dccp_insert_option_mp_join(struct sk_buff *skb)
{
	return 0;
}

static int dccp_insert_option_mp_fast_close(struct sk_buff *skb)
{
	return 0;
}*/

static int dccp_insert_option_mp_key(struct sk_buff *skb, struct mpdccp_cb *mpcb, struct dccp_request_sock *dreq)
{
	u8 buf[MPDCCP_MAX_KEYS*(MPDCCP_MAX_KEY_SIZE + 1)];
	int ret, i;
	int optlen = 0;

	switch (DCCP_SKB_CB(skb)->dccpd_type) {
		case DCCP_PKT_REQUEST:
			for (i=0; i < MPDCCP_MAX_KEYS; i++) {
				struct mpdccp_key *key = &mpcb->mpdccp_loc_keys[i];
				if (mpcb && mpdccp_is_validkey(key)) {
					buf[optlen] = key->type;
					memcpy(&buf[optlen + 1], key->value, key->size);
					optlen += key->size + 1;
				}
			}
			break;
		case DCCP_PKT_RESPONSE:
			if (dreq && mpdccp_is_validkey(&dreq->mpdccp_loc_key)) {
				struct mpdccp_key *key = &dreq->mpdccp_loc_key;
				buf[0] = key->type;
				memcpy(&buf[1], key->value, key->size);
				optlen = key->size + 1;
			} else {
				DCCP_WARN("MP_KEY: invalid input key for DCCP_PKT_RESPONSE\n");
				ret = -1;
			}
			break;
		case DCCP_PKT_ACK:
			if (mpcb && (mpcb->cur_key_idx < MPDCCP_MAX_KEYS)) {
				struct mpdccp_key *key1, *key2;
				key1 = &mpcb->mpdccp_loc_keys[mpcb->cur_key_idx];
				key2 = &mpcb->mpdccp_rem_key;
				if (mpdccp_is_validkey(key1) && mpdccp_is_validkey(key2)) {
					buf[0] = key1->type;
					memcpy(&buf[1], key1->value, key1->size);
					buf[key1->size + 1] = key2->type;
					memcpy(&buf[key1->size + 2], key2->value, key2->size);
					optlen = key1->size + key2->size + 2;
				} else {
					DCCP_WARN("MP_KEY: invalid input key(s) for DCCP_PKT_ACK\n");
					ret = -1;
				}
			} else {
				DCCP_WARN("MP_KEY: invalid mpcb for DCCP_PKT_ACK\n");
				ret = -1;
			}
			break;
		default:
			DCCP_WARN("MP_KEY: unsupported packet type %d\n", DCCP_SKB_CB(skb)->dccpd_type);
			ret = -1;
			break;
	}
	if (optlen) {
		ret = dccp_insert_option_multipath(skb, DCCPO_MP_KEY, &buf, optlen);
	}
	return ret;
}

/* Insert overall sequence number option */
static int dccp_insert_option_mp_seq(struct sk_buff *skb, u64 *mp_oall_seq)
{
	__be64 be_oall_seq;
	be_oall_seq = cpu_to_be64((*mp_oall_seq << 16)); // convert to big endian // << 16
	dccp_inc_seqno(mp_oall_seq); // increment overall sequence number
	return dccp_insert_option_multipath(skb, DCCPO_MP_SEQ, &be_oall_seq, 6);
}

static int dccp_insert_option_mp_hmac(struct sk_buff *skb, u8 *hmac)
{
	return dccp_insert_option_multipath(skb, DCCPO_MP_HMAC, hmac, MPDCCP_HMAC_SIZE);
}

/*static int dccp_insert_option_mp_rtt(struct sk_buff *skb)
{
}*/

static int dccp_insert_option_mp_addaddr(struct sk_buff *skb, struct mpdccp_cb *mpcb)
{
	u8 buf[MPDCCP_ADDADDR_SIZE];
	int len = 0;

	buf[len] = mpcb->addpath_id;
	len++;
	if(mpcb->addpath_family == AF_INET){
		put_unaligned_be32(mpcb->addpath_addr.ip, &buf[len]);
		len += 4;
	} else if(mpcb->addpath_family == AF_INET6){
		memcpy(&buf[len], mpcb->addpath_addr.ip6, 16);
		len += 16;
	}

	if(mpcb->addpath_port){
		put_unaligned_be16(mpcb->addpath_port, &buf[len]);
		len += 2;
	}
	return dccp_insert_option_multipath(skb, DCCPO_MP_ADDADDR, &buf, len);
}

static int dccp_insert_option_mp_removeaddr(struct sk_buff *skb, u8 id)
{
	return dccp_insert_option_multipath(skb, DCCPO_MP_REMOVEADDR, &id, 1);
}
/*
static int dccp_insert_option_mp_prio(struct sk_buff *skb)
{
	return 0;
}

static int dccp_insert_option_mp_close(struct sk_buff *skb)
{
	return 0;
}*/

#endif


int dccp_insert_options(struct sock *sk, struct sk_buff *skb)
{
	struct dccp_sock *dp = dccp_sk(sk);
	struct ccid2_hc_tx_sock *hc = NULL;
	hc = ccid2_hc_tx_sk(sk);

	DCCP_SKB_CB(skb)->dccpd_opt_len = 0;
	if (dp->dccps_send_ndp_count && dccp_insert_option_ndp(sk, skb))
		return -1;
	if (DCCP_SKB_CB(skb)->dccpd_type != DCCP_PKT_DATA) {

		/* Feature Negotiation */
		if (dccp_feat_insert_opts(dp, NULL, skb))
			return -1;

		if (DCCP_SKB_CB(skb)->dccpd_type == DCCP_PKT_REQUEST) {
			/*
			 * Obtain RTT sample from Request/Response exchange.
			 * This is currently used for TFRC initialisation.
			 */
			if (dccp_insert_option_timestamp(skb))
				return -1;

		} else if (dccp_ackvec_pending(sk) &&
			   dccp_insert_option_ackvec(sk, skb)) {
				return -1;
		}
	}

	if (dp->dccps_hc_rx_insert_options) {
		if (ccid_hc_rx_insert_options(dp->dccps_hc_rx_ccid, sk, skb))
			return -1;
		dp->dccps_hc_rx_insert_options = 0;
	}

	if (dp->dccps_timestamp_echo != 0 &&
	    dccp_insert_option_timestamp_echo(dp, NULL, skb))
		return -1;

#if IS_ENABLED(CONFIG_IP_MPDCCP)
	/* Role dependent option required status. MPDCCP Server does not have 
	 * to add delay values since MPDCCP Client knows delays due to its 
	 * congestion control */
	if (is_mpdccp(sk)) {
		struct mpdccp_cb *mpcb = get_mpcb(sk);
		u8 mp_addr_id = get_id(sk);

		/* Skip if fallback to sp DCCP */
		if (mpcb && mpcb->fallback_sp)
			goto out;

		/* Insert delay value (sub-flow specific) as DCCP option */
		switch(DCCP_SKB_CB(skb)->dccpd_type){
			case DCCP_PKT_DATA:
			case DCCP_PKT_DATAACK:
			case DCCP_PKT_DATA:
				dccp_insert_option_mp_seq(skb, &mpdccp_my_sock(sk)->mpcb->mp_oall_seqno);
				if(mpcb){
					if(mpcb->delpath_id && mpcb->pm_ops){
						u8 del_id = chk_id(mpcb->delpath_id, mpcb->master_addr_id);
						/* dont send over path that is about to be removed */
						if(del_id != mp_addr_id){
							u8 delpath_hmac[MPDCCP_HMAC_SIZE];
							mpcb->pm_ops->pm_hmac(mpcb, del_id, 0, 0, 0, 1, delpath_hmac);
							dccp_pr_debug("(%s) REQ insert opt MP_HMAC %llx", dccp_role(sk), be64_to_cpu(*((u64 *)delpath_hmac)));
							dccp_insert_option_mp_hmac(skb, delpath_hmac);

							dccp_pr_debug("(%s) REQ insert opt MP_REMOVEADDR, id: %u", dccp_role(sk), del_id);
							dccp_insert_option_mp_removeaddr(skb, del_id);
							mpcb->delpath_id = 0;
						}
					}

					if(mpcb->addpath_id && mpcb->pm_ops){
						u8 addpath_hmac[MPDCCP_HMAC_SIZE];
						mpcb->pm_ops->pm_hmac(mpcb, mpcb->addpath_id, AF_INET, &mpcb->addpath_addr, mpcb->addpath_port, 1, addpath_hmac);
						dccp_pr_debug("(%s) REQ insert opt MP_HMAC %llx", dccp_role(sk), be64_to_cpu(*((u64 *)addpath_hmac)));
						dccp_insert_option_mp_hmac(skb, addpath_hmac);

						dccp_pr_debug("(%s) REQ insert opt MP_ADDADDR, id: %u, ip: %pI4", dccp_role(sk), mpcb->addpath_id, &mpcb->addpath_addr.ip);
						dccp_insert_option_mp_addaddr(skb, mpcb);
						mpcb->addpath_id = 0;
						mpcb->addpath_port = 0;
					}

				}
				break;
			case DCCP_PKT_REQUEST:
				if (dccp_sk(sk)->is_kex_sk) {
					dccp_pr_debug("(%s) REQ insert opt MP_KEY (supp)", dccp_role(sk));
					/* Insert supported keys */
					dccp_insert_option_mp_key(skb, mpcb, NULL);
				} else {
					/* Insert token and nonce */
					dccp_pr_debug("(%s) REQ insert opt MP_JOIN tk:%x nc:%x",
									dccp_role(sk),
									mpcb->mpdccp_rem_token,
									dccp_sk(sk)->mpdccp_loc_nonce);
					dccp_insert_option_mp_join(skb, mpcb->mpdccp_rem_token, dccp_sk(sk)->mpdccp_loc_nonce);
				}
				break;
			case DCCP_PKT_ACK:
				if (dccp_sk(sk)->is_kex_sk) {
					dccp_pr_debug("(%s) ACK insert opt MP_KEY %llx %llx",
									dccp_role(sk),
									be64_to_cpu(*((__be64*)mpcb->mpdccp_loc_keys[mpcb->cur_key_idx].value)),
									be64_to_cpu(*((__be64*)mpcb->mpdccp_rem_key.value)));
					/* Insert local & remote key */
					dccp_insert_option_mp_key(skb, mpcb, NULL);
				} else {
					if (!dccp_sk(sk)->auth_done){
						/* Insert HMAC */
						dccp_pr_debug("(%s) ACK insert opt MP_HMAC %llx", dccp_role(sk),be64_to_cpu(*((u64*)dccp_sk(sk)->mpdccp_loc_hmac)));
						dccp_insert_option_mp_hmac(skb, dccp_sk(sk)->mpdccp_loc_hmac);
					}
				}
			default:
				break;
		}
	}

out:
#endif
	/* Insert padding to achieve option size as multiple of 32 bit (4 byte) */
	dccp_insert_option_padding(skb);
	return 0;
}

int dccp_insert_options_rsk(struct dccp_request_sock *dreq, struct sk_buff *skb)
{
	DCCP_SKB_CB(skb)->dccpd_opt_len = 0;

	if (dccp_feat_insert_opts(NULL, dreq, skb))
		return -1;

	/* Obtain RTT sample from Response/Ack exchange (used by TFRC). */
	if (dccp_insert_option_timestamp(skb))
		return -1;

	if (dreq->dreq_timestamp_echo != 0 &&
	    dccp_insert_option_timestamp_echo(NULL, dreq, skb))
		return -1;

	dccp_insert_option_padding(skb);
	return 0;
}

int dccp_insert_options_rsk_mp(const struct sock *sk, struct dccp_request_sock *dreq, struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_IP_MPDCCP)
	struct mpdccp_cb *mpcb;
	struct dccp_sock *dp = dccp_sk(sk);
	struct dccp_options_received *opt_recv = &dp->dccps_options_received;

	if (opt_recv->saw_mpjoin) {
		mpcb = get_mpcb(dreq->meta_sk);
		if (!mpcb) {
			dccp_pr_debug("(%s) invalid MPCB", dccp_role(sk));
			return -1;
		}
		/* Insert token and nonce */
		dccp_pr_debug("(%s) RES insert opt MP_JOIN tk:%x nc:%x", dccp_role(sk), mpcb->mpdccp_loc_token, dreq->mpdccp_loc_nonce);
		dccp_insert_option_mp_join(skb, mpcb->mpdccp_loc_token, dreq->mpdccp_loc_nonce);
		/* Insert HMAC */
		dccp_pr_debug("(%s) RES insert opt MP_HMAC %llx", dccp_role(sk), be64_to_cpu(*((u64 *)dreq->mpdccp_loc_hmac)));
		dccp_insert_option_mp_hmac(skb, dreq->mpdccp_loc_hmac);
	} else if (opt_recv->saw_mpkey) {
		dccp_pr_debug("(%s) RES insert opt MP_KEY %llx", dccp_role(sk), be64_to_cpu(*((__be64 *)dreq->mpdccp_loc_key.value)));
		/* Insert local key */
		dccp_insert_option_mp_key(skb, NULL, dreq);
	}

	dccp_insert_option_padding(skb);
#endif
	return 0;
}
