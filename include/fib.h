#pragma once
#ifndef FIB_H
#define FIB_H

#include <stdint.h>
#include "constants.h"

struct route {
    uint32_t dst; // network address
    uint32_t mask; // network mask

    uint8_t prefix_length;

    uint16_t egress_port;
    uint32_t next_hop; // 0 if directly connected
};

struct fi_table {
    struct route routes[FIB_MAX_ROUTES];
    uint16_t count;
};


static inline void init_fib(struct fi_table *f){ f->count = 0; }

int fib_add (struct fi_table *f, uint32_t dst, uint32_t mask, uint8_t prefix,
            uint16_t egress_port, uint32_t next_hop);

int fib_lookup(const struct fi_table *f, uint32_t dst, 
                uint16_t *egress, uint32_t *hop);

#endif 