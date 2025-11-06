#pragma once
#ifndef NEIGH_T_H
#define NEIGH_T_H

#include <stdint.h>
#include <rte_ether.h>
#include "constants.h"
struct neigh_entry {
    uint32_t ip_be;     
    struct rte_ether_addr mac; 
    uint8_t in_use; 
};

struct neigh_table {
    struct neigh_entry slots[NEIGH_SIZE];
};

static inline void neigh_init(struct neigh_table *t){
    for (int i=0;i<NEIGH_SIZE;i++){ t->slots[i].in_use = 0; }
}

void neigh_learn(struct neigh_table *t, uint32_t ip_be, const struct rte_ether_addr *mac);
int  neigh_lookup(const struct neigh_table *t, uint32_t ip_be, struct rte_ether_addr *mac_out);
void neigh_dump(const struct neigh_table *t, const char *tag);

#endif