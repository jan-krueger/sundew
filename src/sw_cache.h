/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SW_CACHE_H
#define SW_CACHE_H

#include <ngx_config.h>
#include <ngx_core.h>


#define SW_VERDICT_IN       1
#define SW_VERDICT_NOT_IN   2

/* sw_cache_put(): store whatever changed meanwhile */
#define SW_CACHE_ANY        ((uint64_t) -1)


typedef struct sw_cache_s  sw_cache_t;


ngx_int_t sw_cache_zone_init(ngx_shm_zone_t *zone, void *data);

uint64_t sw_cache_set_ident(ngx_shm_zone_t *zone, ngx_str_t *name,
    ngx_uint_t family, u_char *type, ngx_uint_t revision);

/* addr is 16 bytes, IPv4 as v4-mapped; returns NGX_OK if found */
ngx_int_t sw_cache_get(ngx_shm_zone_t *zone, uint64_t ident,
    const u_char *addr, ngx_uint_t *verdict, ngx_msec_t *age);

static ngx_inline void
sw_cache_addr(u_char *dst, ngx_uint_t family, const u_char *addr)
{
    if (family == 4) {
        ngx_memzero(dst, 10);
        dst[10] = 0xff;
        dst[11] = 0xff;
        ngx_memcpy(dst + 12, addr, 4);

    } else {
        ngx_memcpy(dst, addr, 16);
    }
}

/* max_age: seconds after which the entry is ignored, 0 for none. since: the
 * sw_cache_changes() value the answer was asked under; a drop since then
 * discards it */
void sw_cache_put(ngx_shm_zone_t *zone, uint64_t ident, const u_char *addr,
    ngx_uint_t verdict, ngx_uint_t max_age, uint64_t since);

uint64_t sw_cache_changes(ngx_shm_zone_t *zone);

/* addr (16 bytes, as for sw_cache_get) NULL: every entry of the set */
void sw_cache_drop(ngx_shm_zone_t *zone, uint64_t ident, const u_char *addr);

#endif /* SW_CACHE_H */
