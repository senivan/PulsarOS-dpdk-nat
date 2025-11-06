#pragma once
#ifndef DPDK_PORTS_H
#define DPDK_PORTS_H
#include <stdint.h>
#include <rte_mempool.h>
#include "app.h"
#include "neigh_t.h"

struct if_state {
    uint16_t port_id;                     
    struct rte_ether_addr mac;            
    uint32_t ip_be;                       
    uint16_t txq;                         
    struct rte_mempool *mbuf_pool;  
    struct neigh_table table;
};

int vdev_create(const char *progname, const struct app_config *conf);
int ports_configure(struct if_state *lan, struct if_state *wan,
                    uint16_t rx_desc, uint16_t tx_desc,
                    uint32_t mbufs, uint32_t cache);
void port_print_info(uint16_t port_id, const char* tag);

#endif