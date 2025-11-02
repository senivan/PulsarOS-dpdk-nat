#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include "constants.h"
#include "config.h"
#include "arp.h"
#include "dpdk_port.h"

static volatile int keep_running = 1;
static void on_sigint(int sig){ (void)sig; keep_running = 0; }

static void wait_link(uint16_t port){
    struct rte_eth_link link;
    for (int i=0;i<20;i++){ rte_eth_link_get_nowait(port,&link); if (link.link_status) break; rte_delay_us_sleep(50*1000); }
    rte_eth_link_get_nowait(port,&link);
    printf("[port %u] link %s %u Mbps\n", port, link.link_status?"UP":"DOWN", link.link_speed);
}

static void rx_loop_arp_only(struct if_state *lan, struct if_state *wan){
    const uint16_t BURST=32;
    struct rte_mbuf *pkts[BURST];
    while (keep_running){
        uint16_t n = rte_eth_rx_burst(lan->port_id, 0, pkts, BURST);
        for (uint16_t i=0;i<n;i++){
            struct rte_mbuf *m=pkts[i];
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
            if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) arp_handle(lan, m);
            else rte_pktmbuf_free(m);
        }
        n = rte_eth_rx_burst(wan->port_id, 0, pkts, BURST);
        for (uint16_t i=0;i<n;i++){
            struct rte_mbuf *m=pkts[i];
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
            if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) arp_handle(wan, m);
            else rte_pktmbuf_free(m);
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[1], "--") != 0) { fprintf(stderr, "usage: natdpdk -- -c <config.yaml>\n"); return 2; }
    const char *cfgpath = NULL;
    for (int i = 2; i < argc; i++) if (!strcmp(argv[i], "-c") && i+1 < argc) cfgpath = argv[++i];
    if (!cfgpath) { fprintf(stderr, "config required\n"); return 2; }

    struct app_config cfg;
    if (cfg_load(cfgpath, &cfg) < 0 || cfg_validate(&cfg) < 0) return 1;

    struct if_state lan = {0}, wan = {0};
    lan.ip_be = cfg.lan.ip_addr;
    wan.ip_be = cfg.wan.ip_addr;
    lan.txq = 0; wan.txq = 0;

    if (vdev_create(argv[0], &cfg) < 0) return 1;
    if (ports_configure(&lan,&wan, DPDK_RX_DESC, DPDK_TX_DESC, DPDK_MBUF_COUNT, DPDK_MBUF_CACHE) < 0) return 1;

    wait_link(lan.port_id);
    wait_link(wan.port_id);

    signal(SIGINT, on_sigint);

    arp_send_gratuitous(&lan);
    arp_send_gratuitous(&wan);
    rte_delay_us_sleep(200*1000);
    arp_send_gratuitous(&lan);
    arp_send_gratuitous(&wan);

    rx_loop_arp_only(&lan, &wan);

    rte_eth_dev_stop(lan.port_id);
    rte_eth_dev_stop(wan.port_id);
    rte_eth_dev_close(lan.port_id);
    rte_eth_dev_close(wan.port_id);
    rte_eal_cleanup();
    return 0;
}
