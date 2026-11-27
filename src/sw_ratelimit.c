/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Sliding-window request counters per (rule, client), under the zone mutex.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <sys/random.h>

#include "sw_ratelimit.h"
#include "sw_siphash.h"


#define SW_RL_WAYS      8


typedef struct {
    uint8_t     key[16];
    uint32_t    rule;           /* rule + 1; 0 = empty */
    uint32_t    window;         /* window index of cur */
    uint32_t    seen;           /* seconds, for eviction */
    uint16_t    prev;
    uint16_t    cur;
    uint8_t     banned;
    uint8_t     pad[7];
} sw_rl_entry_t;

typedef struct {
    sw_rl_entry_t  e[SW_RL_WAYS];
} sw_rl_bucket_t;

typedef struct {
    uint64_t         key[2];
    uint64_t         nbuckets;
    sw_rl_bucket_t  *buckets;
} sw_rl_t;


_Static_assert(sizeof(sw_rl_entry_t) == 40, "rl entry");


ngx_int_t
sw_rl_zone_init(ngx_shm_zone_t *zone, void *data)
{
    size_t            size;
    sw_rl_t          *rl;
    ngx_slab_pool_t  *shpool;

    shpool = (ngx_slab_pool_t *) zone->shm.addr;

    if (data || zone->shm.exists) {
        zone->data = data ? data : shpool->data;
        return NGX_OK;
    }

    rl = ngx_slab_alloc(shpool, sizeof(sw_rl_t));
    if (rl == NULL) {
        return NGX_ERROR;
    }

    if (getrandom(rl->key, sizeof(rl->key), 0) != sizeof(rl->key)) {
        return NGX_ERROR;
    }

    size = zone->shm.size - (zone->shm.size / 8) - 4 * ngx_pagesize;
    rl->nbuckets = size / sizeof(sw_rl_bucket_t);

    rl->buckets = ngx_slab_calloc(shpool,
                                  rl->nbuckets * sizeof(sw_rl_bucket_t));
    if (rl->buckets == NULL) {
        return NGX_ERROR;
    }

    shpool->data = rl;
    zone->data = rl;

    return NGX_OK;
}


ngx_uint_t
sw_rl_hit(ngx_shm_zone_t *zone, ngx_uint_t rule, const u_char *key,
    ngx_uint_t rate, ngx_msec_t window)
{
    u_char            k[20];
    uint32_t          idx, now_s, oldest;
    uint64_t          h, est;
    ngx_uint_t        i, slot, rc;
    ngx_msec_t        now, elapsed;
    sw_rl_t          *rl;
    sw_rl_entry_t    *e;
    sw_rl_bucket_t   *b;
    ngx_slab_pool_t  *shpool;

    rl = zone->data;
    shpool = (ngx_slab_pool_t *) zone->shm.addr;

    ngx_memcpy(k, key, 16);
    ngx_memcpy(k + 16, &rule, 4);
    h = sw_siphash13(rl->key, k, sizeof(k));
    b = &rl->buckets[(uint64_t) ((h >> 32) * rl->nbuckets) >> 32];

    now = ngx_current_msec;
    now_s = (uint32_t) (now / 1000);
    idx = (uint32_t) (now / window);
    elapsed = now % window;

    ngx_shmtx_lock(&shpool->mutex);

    slot = SW_RL_WAYS;
    oldest = 0;

    for (i = 0; i < SW_RL_WAYS; i++) {
        e = &b->e[i];

        if (e->rule == rule + 1 && ngx_memcmp(e->key, key, 16) == 0) {
            slot = i;
            break;
        }

        if (e->rule == 0 || now_s - e->seen >= oldest) {
            oldest = (e->rule == 0) ? UINT32_MAX : now_s - e->seen;
            slot = i;
        }
    }

    e = &b->e[slot];

    if (e->rule != rule + 1 || ngx_memcmp(e->key, key, 16) != 0) {
        ngx_memzero(e, sizeof(sw_rl_entry_t));
        ngx_memcpy(e->key, key, 16);
        e->rule = (uint32_t) rule + 1;
        e->window = idx;
    }

    if (idx != e->window) {
        e->prev = (idx == e->window + 1) ? e->cur : 0;
        e->cur = 0;
        e->window = idx;

        if (e->prev < rate) {
            e->banned = 0;
        }
    }

    e->seen = now_s;

    est = (uint64_t) e->prev * (window - elapsed) / window + e->cur;

    if (est + 1 > rate) {
        rc = e->banned ? SW_RL_LIMITED : SW_RL_FIRST;
        e->banned = 1;

    } else {
        if (e->cur < UINT16_MAX) {
            e->cur++;
        }

        rc = SW_RL_OK;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    return rc;
}
