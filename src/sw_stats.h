/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SW_STATS_H
#define SW_STATS_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "sw_proto.h"


#define SW_STATS_SETS       128

enum {
    SW_STAT_CHECKED = 0,
    SW_STAT_ALLOWED,
    SW_STAT_DENIED,
    SW_STAT_DRYRUN,
    SW_STAT_FAIL_OPEN,
    SW_STAT_FAIL_CLOSED,
    SW_STAT_STALE_SERVED,
    SW_STAT_CACHE_HIT,
    SW_STAT_CACHE_MISS,
    SW_STAT_LOOKUPS,
    SW_STAT_COALESCED,
    SW_STAT_TIMEOUTS,
    SW_STAT_HELPER_ERRORS,
    SW_STAT_HELPER_DOWN,
    SW_STAT_BUSY,
    SW_STAT_LATE_REPLIES,
    SW_STAT_RATELIMITED,
    SW_STAT_TRAPPED,
    SW_STAT_ADDS,
    SW_STAT_ADDS_REFUSED,
    SW_STAT_ADDS_FAILED,
    SW_STAT_ADDS_SKIPPED,
    SW_STAT_N
};


typedef struct {
    u_char        name[SW_SETNAME_LEN];
    ngx_atomic_t  matched;
} sw_stats_set_t;

typedef struct {
    ngx_atomic_t    c[SW_STAT_N];
    sw_stats_set_t  sets[SW_STATS_SETS];
} sw_stats_t;


extern const char  *sw_stat_names[SW_STAT_N];
extern const char  *sw_stat_help[SW_STAT_N];

ngx_int_t sw_stats_zone_init(ngx_shm_zone_t *zone, void *data);
sw_stats_t *sw_stats_get(void);
void sw_stats_inc(ngx_uint_t counter);
void sw_stats_set_matched(ngx_uint_t set_index);

#endif /* SW_STATS_H */
