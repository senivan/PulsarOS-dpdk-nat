#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_vdev.h>

#include "constants.h"
#include "dpdk_port.h"

int eal_bootstrap(const char *progname){
    const char *args[] = {progname, "-l", "0", "-n", "1", "--proc-type=auto"};
    int argc = (int)(sizeof(args) / sizeof(args[0]));
    char **argv = (char**)args;
    int rc = rte_eal_init(argc, argv);
    if (rc < 0) fprintf(stderr, "EAL init fauled\n");
    return rc < 0 ? -1 : 0;
}

int vdev_create(const struct app_config *conf){
    if (cfg->pmd == PMD_TAP) {
        char a[128], b[128];
        snprintf(a, sizeof(a), "iface=%s", cfg->lan_name);
        snprintf(b, sizeof(b), "iface=%s", cfg->wan_name);
        if (rte_vdev_init("net_tap0", a) < 0) { fprintf(stderr, "tap lan vdev failed\n"); return -1; }
        if (rte_vdev_init("net_tap1", b) < 0) { fprintf(stderr, "tap wan vdev failed\n"); return -1; }
    } else if (cfg->pmd == PMD_AFPKT) {
        char a[128], b[128];
        snprintf(a, sizeof(a), "iface=%s", cfg->lan_name);
        snprintf(b, sizeof(b), "iface=%s", cfg->wan_name);
        if (rte_vdev_init("net_af_packet0", a) < 0) { fprintf(stderr, "af_packet lan vdev failed\n"); return -1; }
        if (rte_vdev_init("net_af_packet1", b) < 0) { fprintf(stderr, "af_packet wan vdev failed\n"); return -1; }
    }
    return 0;
}

static int create_pool(struct dpdk_handle *handle){
    handle->mbuf_pool = rte_pktmbuf_pool_create("mbufs",
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

int ports_configure(struct dpdk_handle *handle,
                    uint16_t rx_desc, uint16_t tx_desc,
                    uint32_t mbufs, uint32_t cache)
{
    (void)mbufs;
    (void)cache;

    if(create_pool(handle) < 0) return -1;

    uint16_t n = rte_eth_dev_count_avail();
    if (n < 2) { fprintf(stderr, "need >= 2 DPDK ports, have %u\n", n); return -1; }
    h->lan_port = 0;
    h->wan_port = 1;

    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));
    conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;

    for (uint16_t p = 0; p < 2; p++) {
        int rc = rte_eth_dev_configure(p, 1, 1, &conf);
        if (rc < 0) { fprintf(stderr, "dev_configure(%u)=%d\n", p, rc); return -1; }

        rc = rte_eth_rx_queue_setup(p, 0, rx_desc, rte_eth_dev_socket_id(p), NULL, h->mbuf_pool);
        if (rc < 0) { fprintf(stderr, "rx_queue_setup(%u)=%d\n", p, rc); return -1; }

        rc = rte_eth_tx_queue_setup(p, 0, tx_desc, rte_eth_dev_socket_id(p), NULL);
        if (rc < 0) { fprintf(stderr, "tx_queue_setup(%u)=%d\n", p, rc); return -1; }

        rc = rte_eth_dev_start(p);
        if (rc < 0) { fprintf(stderr, "dev_start(%u)=%d\n", p, rc); return -1; }

        rte_eth_promiscuous_enable(p);
    }

    sleep(1);
    port_print_info(h->lan_port, "LAN");
    port_print_info(h->wan_port, "WAN");

    return 0;
}