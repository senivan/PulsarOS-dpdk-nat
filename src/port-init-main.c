#include <stdio.h>
#include <signal.h>
#include <string.h>

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ethdev.h>

#include "constants.h"
#include "config.h"
#include "dpdk_port.h"

static volatile int keep_running = 1;
static void on_sigint(int){ keep_running = 0; }

int main(int argc, char **argv) {
  if (argc < 3 || strcmp(argv[1], "--") != 0) {
    fprintf(stderr, "usage: natdpdk -- -c <config.yaml>\n");
    return 2;
  }
  const char *cfgpath = NULL;
  for (int i = 2; i < argc; i++) if (!strcmp(argv[i], "-c") && i+1 < argc) cfgpath = argv[++i];
  if (!cfgpath) { fprintf(stderr, "config required\n"); return 2; }

  struct app_config cfg;
  if (cfg_load(cfgpath, &cfg) < 0 || cfg_validate(&cfg) < 0) return 1;

  if (vdev_create(argv[0], &cfg) < 0) return 1;

  struct dpdk_handle h;
  if (ports_configure(&h, DPDK_RX_DESC, DPDK_TX_DESC, DPDK_MBUF_COUNT, DPDK_MBUF_CACHE) < 0)
    return 1;

  signal(SIGINT, on_sigint);

  struct rte_mbuf *pkts[DPDK_BURST];
  while (keep_running) {
    uint16_t n = rte_eth_rx_burst(h.lan_port, 0, pkts, DPDK_BURST);
    for (uint16_t i = 0; i < n; i++) {
      struct rte_mbuf *m = pkts[i];
      struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
      if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        struct rte_ipv4_hdr *ip = (void*)(eth + 1);
        if (ip->time_to_live > 1) ip->time_to_live--;
        ip->hdr_checksum = 0;
        m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
      }
      rte_eth_tx_burst(h.wan_port, 0, &m, 1);
    }

    n = rte_eth_rx_burst(h.wan_port, 0, pkts, DPDK_BURST);
    for (uint16_t i = 0; i < n; i++) {
      struct rte_mbuf *m = pkts[i];
      struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
      if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        struct rte_ipv4_hdr *ip = (void*)(eth + 1);
        if (ip->time_to_live > 1) ip->time_to_live--;
        ip->hdr_checksum = 0;
        m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
      }
      rte_eth_tx_burst(h.lan_port, 0, &m, 1);
    }
  }

  rte_eal_cleanup();
  return 0;
}
