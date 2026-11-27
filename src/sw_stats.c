/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_sundew.h"
#include "sw_stats.h"


const char  *sw_stat_names[SW_STAT_N] = {
    "checked", "allowed", "denied", "dryrun", "fail_open", "fail_closed",
    "stale_served", "cache_hit", "cache_miss", "lookups", "coalesced",
    "timeouts", "helper_errors", "helper_down", "busy", "late_replies",
    "ratelimited", "trapped", "adds", "adds_refused", "adds_failed",
    "adds_skipped"
};


const char  *sw_stat_help[SW_STAT_N] = {
    "Requests checked.",
    "Requests let through.",
    "Requests denied.",
    "Requests that would have been denied, under ipset_dryrun.",
    "Requests let through because no answer was available.",
    "Requests denied because no answer was available.",
    "Requests decided by an expired cached answer while no answer was available.",
    "Requests answered from the cache.",
    "Requests that needed the helper.",
    "Questions sent to the helper.",
    "Requests that joined a question already on its way.",
    "Questions not answered within sundew_lookup_timeout.",
    "Questions the helper answered with an error.",
    "Questions that could not be sent because the helper is gone.",
    "Questions not sent because too many were in flight.",
    "Answers that arrived after their timeout and were still cached.",
    "Requests over an ipset_ratelimit rate.",
    "Requests to an ipset_autoadd location.",
    "Addresses added to a set.",
    "Adds the helper refused: protected address, budget or circuit breaker.",
    "Adds that failed: kernel error, set full or missing, helper unavailable.",
    "Adds not sent: dry run, browser request, early data or if=."
};


ngx_int_t
sw_stats_zone_init(ngx_shm_zone_t *zone, void *data)
{
    ngx_uint_t               i, j, n;
    sw_stats_t              *st;
    ngx_slab_pool_t         *shpool;
    ngx_sundew_set_t        *set;
    ngx_sundew_core_conf_t  *scf;

    scf = zone->data;
    shpool = (ngx_slab_pool_t *) zone->shm.addr;

    if (data) {
        st = data;

    } else if (zone->shm.exists) {
        st = shpool->data;

    } else {
        st = ngx_slab_calloc(shpool, sizeof(sw_stats_t));
        if (st == NULL) {
            return NGX_ERROR;
        }

        shpool->data = st;
    }

    zone->data = st;

    /* per-set counters are keyed by name and survive reloads */

    set = scf->sets.elts;

    for (i = 0; i < scf->sets.nelts; i++) {
        set[i].stat_slot = SW_STATS_SETS;
        n = SW_STATS_SETS;

        for (j = 0; j < SW_STATS_SETS; j++) {
            if (st->sets[j].name[0] == '\0') {
                if (n == SW_STATS_SETS) {
                    n = j;
                }
                continue;
            }

            if (ngx_strlen(st->sets[j].name) == set[i].name.len
                && ngx_strncmp(st->sets[j].name, set[i].name.data,
                               set[i].name.len) == 0)
            {
                set[i].stat_slot = j;
                break;
            }
        }

        if (set[i].stat_slot == SW_STATS_SETS && n != SW_STATS_SETS) {
            ngx_memcpy(st->sets[n].name, set[i].name.data, set[i].name.len);
            st->sets[n].name[set[i].name.len] = '\0';
            set[i].stat_slot = n;
        }
    }

    return NGX_OK;
}


sw_stats_t *
sw_stats_get(void)
{
    ngx_sundew_core_conf_t  *scf;

    scf = (ngx_sundew_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                  ngx_sundew_core_module);

    if (scf == NULL || scf->stats_zone == NULL) {
        return NULL;
    }

    return scf->stats_zone->data;
}


void
sw_stats_inc(ngx_uint_t counter)
{
    sw_stats_t  *st;

    st = sw_stats_get();

    if (st) {
        (void) ngx_atomic_fetch_add(&st->c[counter], 1);
    }
}


void
sw_stats_set_matched(ngx_uint_t set_index)
{
    sw_stats_t              *st;
    ngx_sundew_set_t        *set;
    ngx_sundew_core_conf_t  *scf;

    st = sw_stats_get();
    if (st == NULL) {
        return;
    }

    scf = (ngx_sundew_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                  ngx_sundew_core_module);
    set = scf->sets.elts;

    if (set_index < scf->sets.nelts && set[set_index].stat_slot < SW_STATS_SETS)
    {
        (void) ngx_atomic_fetch_add(&st->sets[set[set_index].stat_slot].matched,
                                    1);
    }
}
