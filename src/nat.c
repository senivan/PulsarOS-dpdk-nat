#include <string.h>
#include <time.h>


#include "nat.h"



static inline int nat_key_equal(const struct nat_entry_key *a,
                                const struct nat_entry_key *b)
{
    return a->src_ip    == b->src_ip   &&
           a->dst_ip    == b->dst_ip   &&
           a->src_port  == b->src_port &&
           a->dst_port  == b->dst_port &&
           a->proto     == b->proto    &&
           a->direction == b->direction;
}

void nat_table_init(struct nat_table *t)
{
    memset(t, 0, sizeof(*t));
}

struct nat_entry *nat_lookup(struct nat_table *t,
                             const struct nat_entry_key *key)
{
    for (uint32_t i = 0; i < t->count; i++) {
        if (nat_key_equal(&t->entries[i].orig, key) ||
            nat_key_equal(&t->entries[i].reply, key))
            return &t->entries[i];
    }
    return NULL;
}

struct nat_entry *nat_insert(struct nat_table *t,
                             const struct nat_entry_key *orig,
                             const struct nat_entry_key *reply,
                             int hairpin)
{
    if (t->count >= NAT_TABLE_SIZE)
        return NULL;

    struct nat_entry *e = &t->entries[t->count++];
    e->orig = *orig;
    e->reply = *reply;
    e->hairpin = hairpin ? 1 : 0;
    e->last_seen = time(NULL);
    return e;
}