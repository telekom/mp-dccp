/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_DCCP_H
#define _UAPI_LINUX_DCCP_H

#include <linux/types.h>
#include <asm/byteorder.h>

/**
 * struct dccp_hdr - generic part of DCCP packet header
 *
 * @dccph_sport - Relevant port on the endpoint that sent this packet
 * @dccph_dport - Relevant port on the other endpoint
 * @dccph_doff - Data Offset from the start of the DCCP header, in 32-bit words
 * @dccph_ccval - Used by the HC-Sender CCID
 * @dccph_cscov - Parts of the packet that are covered by the Checksum field
 * @dccph_checksum - Internet checksum, depends on dccph_cscov
 * @dccph_x - 0 = 24 bit sequence number, 1 = 48
 * @dccph_type - packet type, see DCCP_PKT_ prefixed macros
 * @dccph_seq - sequence number high or low order 24 bits, depends on dccph_x
 */
struct dccp_hdr {
	__be16	dccph_sport,
		dccph_dport;
	__u8	dccph_doff;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	dccph_cscov:4,
		dccph_ccval:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	dccph_ccval:4,
		dccph_cscov:4;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
	__sum16	dccph_checksum;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	dccph_x:1,
		dccph_type:4,
		dccph_reserved:3;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	dccph_reserved:3,
		dccph_type:4,
		dccph_x:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
	__u8	dccph_seq2;
	__be16	dccph_seq;
};

/**
 * struct dccp_hdr_ext - the low bits of a 48 bit seq packet
 *
 * @dccph_seq_low - low 24 bits of a 48 bit seq packet
 */
struct dccp_hdr_ext {
	__be32	dccph_seq_low;
};

/**
 * struct dccp_hdr_request - Connection initiation request header
 *
 * @dccph_req_service - Service to which the client app wants to connect
 */
struct dccp_hdr_request {
	__be32	dccph_req_service;
};
/**
 * struct dccp_hdr_ack_bits - acknowledgment bits common to most packets
 *
 * @dccph_resp_ack_nr_high - 48 bit ack number high order bits, contains GSR
 * @dccph_resp_ack_nr_low - 48 bit ack number low order bits, contains GSR
 */
struct dccp_hdr_ack_bits {
	__be16	dccph_reserved1;
	__be16	dccph_ack_nr_high;
	__be32	dccph_ack_nr_low;
};
/**
 * struct dccp_hdr_response - Connection initiation response header
 *
 * @dccph_resp_ack - 48 bit Acknowledgment Number Subheader (5.3)
 * @dccph_resp_service - Echoes the Service Code on a received DCCP-Request
 */
struct dccp_hdr_response {
	struct dccp_hdr_ack_bits	dccph_resp_ack;
	__be32				dccph_resp_service;
};

/**
 * struct dccp_hdr_reset - Unconditionally shut down a connection
 *
 * @dccph_reset_ack - 48 bit Acknowledgment Number Subheader (5.6)
 * @dccph_reset_code - one of %dccp_reset_codes
 * @dccph_reset_data - the Data 1 ... Data 3 fields from 5.6
 */
struct dccp_hdr_reset {
	struct dccp_hdr_ack_bits	dccph_reset_ack;
	__u8				dccph_reset_code,
					dccph_reset_data[3];
};

enum dccp_pkt_type {
	DCCP_PKT_REQUEST = 0,
	DCCP_PKT_RESPONSE,
	DCCP_PKT_DATA,
	DCCP_PKT_ACK,
	DCCP_PKT_DATAACK,
	DCCP_PKT_CLOSEREQ,
	DCCP_PKT_CLOSE,
	DCCP_PKT_RESET,
	DCCP_PKT_SYNC,
	DCCP_PKT_SYNCACK,
	DCCP_PKT_INVALID,
};

#define DCCP_NR_PKT_TYPES DCCP_PKT_INVALID

static inline unsigned int dccp_packet_hdr_len(const __u8 type)
{
	if (type == DCCP_PKT_DATA)
		return 0;
	if (type == DCCP_PKT_DATAACK	||
	    type == DCCP_PKT_ACK	||
	    type == DCCP_PKT_SYNC	||
	    type == DCCP_PKT_SYNCACK	||
	    type == DCCP_PKT_CLOSE	||
	    type == DCCP_PKT_CLOSEREQ)
		return sizeof(struct dccp_hdr_ack_bits);
	if (type == DCCP_PKT_REQUEST)
		return sizeof(struct dccp_hdr_request);
	if (type == DCCP_PKT_RESPONSE)
		return sizeof(struct dccp_hdr_response);
	return sizeof(struct dccp_hdr_reset);
}
enum dccp_reset_codes {
	DCCP_RESET_CODE_UNSPECIFIED = 0,
	DCCP_RESET_CODE_CLOSED,
	DCCP_RESET_CODE_ABORTED,
	DCCP_RESET_CODE_NO_CONNECTION,
	DCCP_RESET_CODE_PACKET_ERROR,
	DCCP_RESET_CODE_OPTION_ERROR,
	DCCP_RESET_CODE_MANDATORY_ERROR,
	DCCP_RESET_CODE_CONNECTION_REFUSED,
	DCCP_RESET_CODE_BAD_SERVICE_CODE,
	DCCP_RESET_CODE_TOO_BUSY,
	DCCP_RESET_CODE_BAD_INIT_COOKIE,
	DCCP_RESET_CODE_AGGRESSION_PENALTY,
	DCCP_RESET_CODE_MPDCCP_ABORTED = 13,

	DCCP_MAX_RESET_CODES		/* Leave at the end!  */
};

/* DCCP options */
enum {
	DCCPO_PADDING = 0,
	DCCPO_MANDATORY = 1,
	DCCPO_MIN_RESERVED = 3,
	DCCPO_MAX_RESERVED = 31,
	DCCPO_CHANGE_L = 32,
	DCCPO_CONFIRM_L = 33,
	DCCPO_CHANGE_R = 34,
	DCCPO_CONFIRM_R = 35,
	DCCPO_NDP_COUNT = 37,
	DCCPO_ACK_VECTOR_0 = 38,
	DCCPO_ACK_VECTOR_1 = 39,
	DCCPO_TIMESTAMP = 41,
	DCCPO_TIMESTAMP_ECHO = 42,
	DCCPO_ELAPSED_TIME = 43,
	DCCPO_MULTIPATH = 46,
	DCCPO_MAX = 45,
	DCCPO_MIN_RX_CCID_SPECIFIC = 128,	/* from sender to receiver */
	DCCPO_MAX_RX_CCID_SPECIFIC = 191,
	DCCPO_MIN_TX_CCID_SPECIFIC = 192,	/* from receiver to sender */
	DCCPO_MAX_TX_CCID_SPECIFIC = 255,
};
/* maximum size of a single TLV-encoded DCCP option (sans type/len bytes) */
#define DCCP_SINGLE_OPT_MAXLEN	253

/* MP-DCCP options */
enum {
	DCCPO_MP_CONFIRM = 0,				/* Confirm reception and processing of an MP_OPT option */
	DCCPO_MP_JOIN = 1,					/* Join path to an existing MP-DCCP flow */
	DCCPO_MP_FAST_CLOSE = 2,		/* Close MP-DCCP flow */
	DCCPO_MP_KEY = 3,						/* Exchange key material for MP_HMAC */
	DCCPO_MP_SEQ = 4,						/* MPDCCP overall sequence number */
	DCCPO_MP_HMAC = 5,					/* HMA Code for authentication */
	DCCPO_MP_RTT = 6,						/* Transmit RTT values */
	DCCPO_MP_ADDADDR = 7,				/* Advertise additional Address */
	DCCPO_MP_REMOVEADDR  = 8,			/* Remove Address */
	DCCPO_MP_PRIO = 9,					/* path priorization */
	DCCPO_MP_CLOSE = 10,				/* Close MPDCCP flow */
};

/* DCCP CCIDS */
enum {
	DCCPC_CCID2 = 2,
	DCCPC_CCID3 = 3,
	DCCPC_CCID5 = 5,
	DCCPC_CCID6 = 6,
	DCCPC_CCID7 = 7,

#define DCCPC_TESTING_MIN	248
#define DCCPC_TESTING_MAX	255
	DCCPC_CCID_ZERO = DCCPC_TESTING_MIN,
};

/* DCCP features (RFC 4340 section 6.4) */
enum dccp_feature_numbers {
	DCCPF_RESERVED = 0,
	DCCPF_CCID = 1,
	DCCPF_SHORT_SEQNOS = 2,
	DCCPF_SEQUENCE_WINDOW = 3,
	DCCPF_ECN_INCAPABLE = 4,
	DCCPF_ACK_RATIO = 5,
	DCCPF_SEND_ACK_VECTOR = 6,
	DCCPF_SEND_NDP_COUNT = 7,
	DCCPF_MIN_CSUM_COVER = 8,
	DCCPF_DATA_CHECKSUM = 9,
	DCCPF_MULTIPATH = 10,	/* Used to negotiate MP support on connection establishment */
	/* 11-127 reserved */
	DCCPF_MIN_CCID_SPECIFIC = 128,
	DCCPF_SEND_LEV_RATE = 192,	/* RFC 4342, sec. 8.4 */
	DCCPF_MAX_CCID_SPECIFIC = 255,
};

/* DCCP socket control message types for cmsg */
enum dccp_cmsg_type {
	DCCP_SCM_PRIORITY = 1,
	DCCP_SCM_QPOLICY_MAX = 0xFFFF,
	/* ^-- Up to here reserved exclusively for qpolicy parameters */
	DCCP_SCM_MAX
};

/* DCCP priorities for outgoing/queued packets */
enum dccp_packet_dequeueing_policy {
	DCCPQ_POLICY_SIMPLE,
	DCCPQ_POLICY_PRIO,
	DCCPQ_POLICY_DROP_OLDEST,
	DCCPQ_POLICY_DROP_NEWEST,
	DCCPQ_POLICY_MAX
};
/* for #ifdef's */
#define DCCPQ_POLICY_DROP_OLDEST DCCPQ_POLICY_DROP_OLDEST
#define DCCPQ_POLICY_DROP_NEWEST DCCPQ_POLICY_DROP_NEWEST



/* Authentication data */
#define MPDCCP_PLAIN_KEY_SIZE 8
#define MPDCCP_C25519_KEY_SIZE 32
#define MPDCCP_MAX_KEY_SIZE MPDCCP_C25519_KEY_SIZE
#define MPDCCP_MAX_KEYS 3
#define MPDCCP_HMAC_SIZE 20

#define MPDCCP_ADDADDR_SIZE 22
#define MPDCCP_CONFIRM_SIZE 31

/* MPDCCP version type */
enum mpdccp_version {
	MPDCCP_VERS_0 = 0,
	MPDCCP_VERS_MAX = 1,
	MPDCCP_VERS_UNDEFINED = 0xF,
};

/* MPDCCP key types */
enum mpdccp_key_type {
	DCCPK_PLAIN = 0,
	DCCPK_C25519_SHA256 = 1,
	DCCPK_C25519_SHA512 = 2,
	DCCPK_INVALID  = 255,
};

enum {
	DCCPKF_PLAIN = (1 << DCCPK_PLAIN),
	DCCPKF_C25519_SHA256 = (1 << DCCPK_C25519_SHA256),
	DCCPKF_C25519_SHA512 = (1 << DCCPK_C25519_SHA512),
};

struct mpdccp_key {
	enum mpdccp_key_type type;
	__u32 size;
	__u8 value[MPDCCP_MAX_KEY_SIZE];
};

/* DCCP socket options */
#define DCCP_SOCKOPT_PACKET_SIZE	1 /* XXX deprecated, without effect */
#define DCCP_SOCKOPT_SERVICE		2
#define DCCP_SOCKOPT_CHANGE_L		3
#define DCCP_SOCKOPT_CHANGE_R		4
#define DCCP_SOCKOPT_GET_CUR_MPS	5
#define DCCP_SOCKOPT_SERVER_TIMEWAIT	6
#define DCCP_SOCKOPT_SEND_CSCOV		10
#define DCCP_SOCKOPT_RECV_CSCOV		11
#define DCCP_SOCKOPT_AVAILABLE_CCIDS	12
#define DCCP_SOCKOPT_CCID		13
#define DCCP_SOCKOPT_TX_CCID		14
#define DCCP_SOCKOPT_RX_CCID		15
#define DCCP_SOCKOPT_QPOLICY_ID		16
#define DCCP_SOCKOPT_QPOLICY_TXQLEN	17
#define DCCP_SOCKOPT_MULTIPATH		18
#define DCCP_SOCKOPT_KEEPALIVE		19
#define DCCP_SOCKOPT_KA_TIMEOUT		20
#define DCCP_SOCKOPT_MP_SCHEDULER	21
#define DCCP_SOCKOPT_MP_REORDER		22
#define DCCP_SOCKOPT_MP_FAST_CLOSE	23
#define DCCP_SOCKOPT_CCID_RX_INFO	128
#define DCCP_SOCKOPT_CCID_TX_INFO	192
#define DCCP_SOCKOPT_CCID_LIM_RTO   193

/* maximum number of services provided on the same listening port */
#define DCCP_SERVICE_LIST_MAX_LEN      32


#endif /* _UAPI_LINUX_DCCP_H */
