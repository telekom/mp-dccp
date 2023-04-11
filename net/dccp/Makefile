# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_IP_DCCP) += dccp.o dccp_ipv4.o

dccp-y := ccid.o feat.o input.o minisocks.o options.o output.o proto.o timer.o \
	  qpolicy.o
#
# CCID algorithms to be used by dccp.ko
#
# CCID-2 is default (RFC 4340, p. 77) and has Ack Vectors as dependency
dccp-y += ccids/ccid2.o ackvec.o
dccp-$(CONFIG_IP_DCCP_CCID3)	+= ccids/ccid3.o
dccp-$(CONFIG_IP_DCCP_TFRC_LIB) += ccids/lib/tfrc.o		\
				   ccids/lib/tfrc_equation.o	\
				   ccids/lib/packet_history.o	\
				   ccids/lib/loss_interval.o
dccp-$(CONFIG_IP_DCCP_CCID5) += ccids/ccid5.o
dccp-$(CONFIG_IP_DCCP_CCID6) += ccids/ccid6.o
dccp-$(CONFIG_IP_DCCP_CCID7) += ccids/ccid7.o

dccp_ipv4-y := ipv4.o

# build dccp_ipv6 as module whenever either IPv6 or DCCP is a module
obj-$(subst y,$(CONFIG_IP_DCCP),$(CONFIG_IPV6)) += dccp_ipv6.o
dccp_ipv6-y := ipv6.o

obj-$(CONFIG_INET_DCCP_DIAG) += dccp_diag.o

dccp-$(CONFIG_SYSCTL) += sysctl.o

dccp_diag-y := diag.o

# build with local directory for trace.h
CFLAGS_proto.o := -I$(src)


# mpdccp needs at least the default scheduler
obj-$(CONFIG_IP_MPDCCP) += mpdccp.o
mpdccp-$(CONFIG_IP_MPDCCP) := 	mpdccp_ctrl.o mpdccp_sysctl.o mpdccp_mod.o \
				mpdccp_proto.o mpdccp_subflow.o \
				mpdccp_pm.o pm/pm_default.o \
				mpdccp_scheduler.o scheduler/sched_default.o \
				mpdccp_reordering.o reordering/ro_default.o

obj-$(CONFIG_IP_MPDCCP) += mpdccplink.o
mpdccplink-y := mpdccp_link.o
mpdccplink-$(CONFIG_SYSFS) += mpdccp_link_sysfs.o


obj-$(CONFIG_IP_MPDCCP) += scheduler/
obj-$(CONFIG_IP_MPDCCP) += reordering/
obj-$(CONFIG_IP_MPDCCP) += pm/
obj-$(CONFIG_IP_MPDCCP) += non_gpl_scheduler/
obj-$(CONFIG_IP_MPDCCP) += non_gpl_reordering/
