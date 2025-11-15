#pragma once
#ifndef CONSTANTS_H
#define CONSTANTS_H
#include <stdint.h>

#define NAT_MAX_DNAT_RULES        64
#define NAT_MAX_SNAT_RULES        64

#define IF_NAME_MAX_LEN           64
#define OUT_IF_NAME_MAX_LEN       16
#define METRICS_ADDR_MAX_LEN      64

#define LCORE_MASK_BITS           64
#define CIDR_BUF_LEN              64

#define DEFAULT_TCP_ESTABLISHED   300U
#define DEFAULT_TCP_TRANSITORY    30U
#define DEFAULT_UDP_TIMEOUT       30U
#define DEFAULT_ICMP_TIMEOUT      10U

#define DPDK_RX_DESC              1024
#define DPDK_TX_DESC              1024
#define DPDK_MBUF_COUNT           8192
#define DPDK_MBUF_CACHE           256
#define DPDK_BURST                64

#define NEIGH_SIZE 1024
#define FIB_MAX_ROUTES 8

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0


#endif