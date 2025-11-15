#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "constants.h"
#include "dpdk_port.h"



int vdev_create(const char* progname, const struct app_config *conf){
    static char v0[128], v1[128];

    const char *base[] = { (char*)progname, "-l", "0", "-n", "1", "--proc-type=auto" };
    char *argv[16];
    int argc = 0;
    for (size_t i = 0; i < sizeof(base)/sizeof(base[0]); ++i) argv[argc++] = (char*)base[i];

    if (conf->pmd == PMD_TAP) {
        snprintf(v0, sizeof(v0), "--vdev=net_tap0,iface=%s", conf->lan.name);
        snprintf(v1, sizeof(v1), "--vdev=net_tap1,iface=%s", conf->wan.name);
        argv[argc++] = v0; argv[argc++] = v1;
    } else if (conf->pmd == PMD_AFPKT) {
        snprintf(v0, sizeof(v0), "--vdev=net_af_packet0,iface=%s", conf->lan.name);
        snprintf(v1, sizeof(v1), "--vdev=net_af_packet1,iface=%s", conf->wan.name);
        argv[argc++] = v0; argv[argc++] = v1;
    } else if (conf->pmd == PMD_PHYS){
        argv[argc++] = "-a"; argv[argc++] = (char*)conf->lan.pcie_addr;
        argv[argc++] = "-a"; argv[argc++] = (char*)conf->wan.pcie_addr;
    }

    int rc = rte_eal_init(argc, argv);
    if (rc < 0) { fprintf(stderr, "EAL init failed\n"); return -1; }
    return 0;
}

static int create_pool(struct if_state *handle){
    char name[32];
    sprintf(name, "mbufs_%d",handle->port_id);
    handle->mbuf_pool = rte_pktmbuf_pool_create(name,
                                                DPDK_MBUF_COUNT,
                                                DPDK_MBUF_CACHE,
                                                0,
                                                RTE_MBUF_DEFAULT_BUF_SIZE,
                                                rte_socket_id());
    if(!handle->mbuf_pool) {fprintf(stderr, "mempool create failed\n"); return -1;}
    return 0;
}

void port_print_info(uint16_t port_id, const char* tag){
    struct rte_ether_addr mac;
    rte_eth_macaddr_get(port_id, &mac);
    struct rte_eth_link link;
    rte_eth_link_get_nowait(port_id, &link);
    printf("[%s] port %u: MAC %02x:%02x:%02x:%02x:%02x:%02x, link %s %u Mbps\n",
        tag, port_id,
        mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2],
        mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5],
        link.link_status ? "UP" : "DOWN", link.link_speed);
}

int ports_configure(struct if_state *lan, struct if_state *wan,
                    uint16_t rx_desc, uint16_t tx_desc,
                    uint32_t mbufs, uint32_t cache)
{
    (void)mbufs;
    (void)cache;

    uint16_t n = rte_eth_dev_count_avail();
    if (n < 2) { fprintf(stderr, "need >= 2 DPDK ports, have %u\n", n); return -1; }

    lan->port_id = 0;
    wan->port_id = 1;

    if(create_pool(lan) < 0) return -1;
    if(create_pool(wan) < 0) return -1;

    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));
    conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;

    // config LAN
    int rc = rte_eth_dev_configure(lan->port_id, 1, 1, &conf);
    if (rc < 0) { fprintf(stderr, "dev_configure(%u)=%d\n", lan->port_id, rc); return -1; }
    rc = rte_eth_rx_queue_setup(lan->port_id, 0, rx_desc, rte_eth_dev_socket_id(lan->port_id), NULL, lan->mbuf_pool);
    if (rc < 0) { fprintf(stderr, "rx_queue_setup(%u)=%d\n", lan->port_id, rc); return -1; }
    rc = rte_eth_tx_queue_setup(lan->port_id, 0, tx_desc, rte_eth_dev_socket_id(lan->port_id), NULL);
    if (rc < 0) { fprintf(stderr, "tx_queue_setup(%u)=%d\n", lan->port_id, rc); return -1; }
    rc = rte_eth_dev_start(lan->port_id);
    if (rc < 0) { fprintf(stderr, "dev_start(%u)=%d\n", lan->port_id, rc); return -1; }
    rte_eth_promiscuous_enable(lan->port_id);

    // config WAN
    rc = rte_eth_dev_configure(wan->port_id, 1, 1, &conf);
    if (rc < 0) { fprintf(stderr, "dev_configure(%u)=%d\n", wan->port_id, rc); return -1; }
    rc = rte_eth_rx_queue_setup(wan->port_id, 0, rx_desc, rte_eth_dev_socket_id(wan->port_id), NULL, wan->mbuf_pool);
    if (rc < 0) { fprintf(stderr, "rx_queue_setup(%u)=%d\n", wan->port_id, rc); return -1; }
    rc = rte_eth_tx_queue_setup(wan->port_id, 0, tx_desc, rte_eth_dev_socket_id(wan->port_id), NULL);
    if (rc < 0) { fprintf(stderr, "tx_queue_setup(%u)=%d\n", wan->port_id, rc); return -1; }
    rc = rte_eth_dev_start(wan->port_id);
    if (rc < 0) { fprintf(stderr, "dev_start(%u)=%d\n", wan->port_id, rc); return -1; }
    rte_eth_promiscuous_enable(wan->port_id);

    sleep(1);
    port_print_info(lan->port_id, "LAN");
    port_print_info(wan->port_id, "WAN");
    rte_eth_macaddr_get(lan->port_id, &lan->mac);
    rte_eth_macaddr_get(wan->port_id, &wan->mac);

    

    return 0;
}