#pragma once
#ifndef DPDK_PORTS_H
#define DPDK_PORTS_H
#include <stdint.h>
#include <rte_mempool.h>
#include "app.h"

struct dpdk_handle {
    uint16_t lan_port;
    uint16_t wan_port;
    struct rte_mempool *mbuf_pool;
};

int vdev_create(const char *progname, const struct app_config *conf);
int ports_configure(struct dpdk_handle *handle,
                    uint16_t rx_desc, uint16_t tx_desc,
                    uint32_t mbufs, uint32_t cache);
void port_print_info(uint16_t port_id, const char* tag);

#endif