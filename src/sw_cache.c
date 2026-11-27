/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Verdict cache: 7-way buckets, seqlock readers, writers under the slab
 * mutex.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <sys/random.h>

#include "ngx_sundew.h"
#include "sw_cache.h"
#include "sw_siphash.h"


#define SW_WAYS             7
#define SW_READ_TRIES       16
#define SW_TICK_MS          100


typedef struct {
    uint64_t    w[4];               /* addr[16], ident, meta */
} sw_entry_t;

typedef struct {
    uint32_t    seq;                /* odd while being written */
    uint8_t     tag[SW_WAYS];       /* 0 = empty */
    uint8_t     pad[21];
    sw_entry_t  e[SW_WAYS];
} sw_bucket_t;

struct sw_cache_s {
    uint64_t     key[2];
    uint64_t     nbuckets;
    sw_bucket_t *buckets;
};


_Static_assert(sizeof(sw_entry_t) == 32, "entry");
_Static_assert(sizeof(sw_bucket_t) == 256, "bucket");


#define sw_meta(checked, verdict, max_age)                                  \
    ((uint64_t) (uint32_t) (checked) | (uint64_t) (verdict) << 32           \
     | (uint64_t) ((max_age) & 0xffffff) << 40)
#define sw_meta_checked(m)  ((uint32_t) (m))
#define sw_meta_verdict(m)  ((ngx_uint_t) (((m) >> 32) & 0xff))
#define sw_meta_max_age(m)  ((ngx_msec_t) ((m) >> 40) * 1000)


static uint32_t
sw_now_tick(void)
{
    return (uint32_t) (ngx_current_msec / SW_TICK_MS);
}


static void
sw_cache_idents(ngx_shm_zone_t *zone, ngx_sundew_core_conf_t *scf)
{
    ngx_uint_t         i;
    ngx_sundew_set_t  *set;

    set = scf->sets.elts;

    for (i = 0; i < scf->sets.nelts; i++) {
        set[i].ident = sw_cache_set_ident(zone, &set[i].name, set[i].family,
                                          set[i].type, set[i].revision);
    }
}


ngx_int_t
sw_cache_zone_init(ngx_shm_zone_t *zone, void *data)
{
    size_t                   size;
    u_char                  *p;
    sw_cache_t              *c;
    ngx_slab_pool_t         *shpool;
    ngx_sundew_core_conf_t  *scf;

    scf = zone->data;
    shpool = (ngx_slab_pool_t *) zone->shm.addr;

    if (data || zone->shm.exists) {
        zone->data = data ? data : shpool->data;
        sw_cache_idents(zone, scf);
        return NGX_OK;
    }

    c = ngx_slab_alloc(shpool, sizeof(sw_cache_t));
    if (c == NULL) {
        return NGX_ERROR;
    }

    if (getrandom(c->key, sizeof(c->key), 0) != sizeof(c->key)) {
        ngx_log_error(NGX_LOG_EMERG, zone->shm.log, ngx_errno,
                      "sundew: getrandom() failed");
        return NGX_ERROR;
    }

    size = zone->shm.size - (zone->shm.size / 8) - 4 * ngx_pagesize;
    c->nbuckets = size / sizeof(sw_bucket_t);

    p = ngx_slab_alloc(shpool, c->nbuckets * sizeof(sw_bucket_t) + 64);
    if (p == NULL) {
        return NGX_ERROR;
    }

    c->buckets = (sw_bucket_t *) ngx_align_ptr(p, 64);
    ngx_memzero(c->buckets, c->nbuckets * sizeof(sw_bucket_t));

    shpool->data = c;
    zone->data = c;

    sw_cache_idents(zone, scf);

    ngx_log_error(NGX_LOG_INFO, zone->shm.log, 0,
                  "sundew: cache zone %V: %uL buckets, %uL entries",
                  &zone->shm.name, c->nbuckets, c->nbuckets * SW_WAYS);

    return NGX_OK;
}


uint64_t
sw_cache_set_ident(ngx_shm_zone_t *zone, ngx_str_t *name, ngx_uint_t family,
    u_char *type, ngx_uint_t revision)
{
    u_char       buf[96], *p;
    sw_cache_t  *c;

    c = zone->data;

    p = ngx_cpymem(buf, name->data, ngx_min(name->len, 31));
    *p++ = '\0';
    *p++ = (u_char) family;
    p = ngx_cpystrn(p, type, 32) + 1;
    *p++ = (u_char) revision;

    return sw_siphash13(c->key, buf, p - buf);
}


static sw_bucket_t *
sw_cache_bucket(sw_cache_t *c, uint64_t ident, const u_char *addr,
    uint8_t *tag)
{
    u_char    key[24];
    uint64_t  h;

    ngx_memcpy(key, addr, 16);
    ngx_memcpy(key + 16, &ident, 8);

    h = sw_siphash13(c->key, key, sizeof(key));

    *tag = (uint8_t) h ? (uint8_t) h : 1;

    return &c->buckets[(uint64_t) ((h >> 32) * c->nbuckets) >> 32];
}


static ngx_uint_t
sw_entry_matches(const uint64_t *w, uint64_t ident, const u_char *addr)
{
    uint64_t  a[2];

    ngx_memcpy(a, addr, 16);

    return w[0] == a[0] && w[1] == a[1] && w[2] == ident;
}


ngx_int_t
sw_cache_get(ngx_shm_zone_t *zone, uint64_t ident, const u_char *addr,
    ngx_uint_t *verdict, ngx_msec_t *age)
{
    uint8_t       tag;
    uint32_t      s1, s2;
    uint64_t      w[4], meta;
    ngx_uint_t    i, k, tries, found;
    sw_cache_t   *c;
    sw_bucket_t  *b;

    c = zone->data;
    b = sw_cache_bucket(c, ident, addr, &tag);

    for (tries = 0; tries < SW_READ_TRIES; tries++) {

        s1 = __atomic_load_n(&b->seq, __ATOMIC_ACQUIRE);

        if (s1 & 1) {
            continue;
        }

        found = 0;
        meta = 0;

        for (i = 0; i < SW_WAYS; i++) {
            if (__atomic_load_n(&b->tag[i], __ATOMIC_RELAXED) != tag) {
                continue;
            }

            for (k = 0; k < 4; k++) {
                w[k] = __atomic_load_n(&b->e[i].w[k], __ATOMIC_RELAXED);
            }

            if (sw_entry_matches(w, ident, addr)) {
                found = 1;
                meta = w[3];
                break;
            }
        }

        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        s2 = __atomic_load_n(&b->seq, __ATOMIC_RELAXED);

        if (s1 != s2) {
            continue;
        }

        if (!found) {
            return NGX_DECLINED;
        }

        *verdict = sw_meta_verdict(meta);
        *age = (ngx_msec_t) (uint32_t) (sw_now_tick() - sw_meta_checked(meta))
               * SW_TICK_MS;

        if (sw_meta_max_age(meta) != 0 && *age > sw_meta_max_age(meta)) {
            return NGX_DECLINED;
        }

        return NGX_OK;
    }

    return NGX_DECLINED;
}


void
sw_cache_put(ngx_shm_zone_t *zone, uint64_t ident, const u_char *addr,
    ngx_uint_t verdict, ngx_uint_t max_age)
{
    uint8_t           tag;
    uint32_t          s, now, oldest, age;
    uint64_t          w[4];
    ngx_uint_t        i, k, slot, empty, victim;
    sw_cache_t       *c;
    sw_bucket_t      *b;
    ngx_slab_pool_t  *shpool;

    c = zone->data;
    shpool = (ngx_slab_pool_t *) zone->shm.addr;
    b = sw_cache_bucket(c, ident, addr, &tag);
    now = sw_now_tick();

    ngx_memcpy(w, addr, 16);
    w[2] = ident;
    w[3] = sw_meta(now, verdict, max_age);

    ngx_shmtx_lock(&shpool->mutex);

    s = b->seq;

    if (s & 1) {
        /* a writer died mid-update */
        for (i = 0; i < SW_WAYS; i++) {
            __atomic_store_n(&b->tag[i], 0, __ATOMIC_RELAXED);
        }

        s++;
    }

    __atomic_store_n(&b->seq, s + 1, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_RELEASE);

    /* same key, else an empty way, else the oldest entry */

    slot = SW_WAYS;
    empty = SW_WAYS;
    victim = 0;
    oldest = 0;

    for (i = 0; i < SW_WAYS; i++) {
        if (b->tag[i] == 0) {
            if (empty == SW_WAYS) {
                empty = i;
            }

            continue;
        }

        if (b->tag[i] == tag && sw_entry_matches(b->e[i].w, ident, addr)) {
            slot = i;
            break;
        }

        age = now - sw_meta_checked(b->e[i].w[3]);

        if (age >= oldest) {
            victim = i;
            oldest = age;
        }
    }

    if (slot == SW_WAYS) {
        slot = (empty != SW_WAYS) ? empty : victim;
    }

    __atomic_store_n(&b->tag[slot], tag, __ATOMIC_RELAXED);

    for (k = 0; k < 4; k++) {
        __atomic_store_n(&b->e[slot].w[k], w[k], __ATOMIC_RELAXED);
    }

    __atomic_store_n(&b->seq, s + 2, __ATOMIC_RELEASE);

    ngx_shmtx_unlock(&shpool->mutex);
}
