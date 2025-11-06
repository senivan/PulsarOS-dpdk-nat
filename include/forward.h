#pragma once
#ifndef FORWARD_H
#define FORWARD_H

#include <rte_mbuf.h>
#include "dpdk_port.h"
#include "fib.h"

int ipv4_forward_one(struct if_state *lan, struct if_state *wan,
                     const struct fi_table *fib, struct rte_mbuf *m);

#endif