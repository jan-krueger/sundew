/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef NGX_SUNDEW_H
#define NGX_SUNDEW_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "sw_proto.h"


#define SUNDEW_VERSION  "0.2.0"


typedef struct {
    ngx_str_t                name;
    ngx_uint_t               role;
    /* from READY */
    ngx_uint_t               family;        /* AF_INET / AF_INET6 */
    ngx_uint_t               revision;
    u_char                   type[SW_SETNAME_LEN];
    ngx_uint_t               has_timeout;
    ngx_uint_t               default_timeout;
    uint64_t                 ident;         /* cache key */
    ngx_uint_t               stat_slot;
    ngx_uint_t               allowlist;     /* used by ipset_allowlist */
    ngx_str_t                file;          /* where it became an add target */
    ngx_uint_t               line;
} ngx_sundew_set_t;


#define NGX_SUNDEW_ALLOWLIST     0x100     /* role bit, module only */


/* an add rule; the helper only adds through these */
typedef struct {
    ngx_uint_t               set;
    ngx_uint_t               prefix4;
    ngx_uint_t               prefix6;
    ngx_uint_t               timeout;       /* 0: set default, resolved at READY */
    ngx_uint_t               rate;
    ngx_uint_t               burst;
} ngx_sundew_rule_t;


typedef struct {
    ngx_uint_t               family;        /* 4 or 6 */
    ngx_uint_t               prefix;
    u_char                   addr[16];
} ngx_sundew_cidr_t;


typedef struct {
    ngx_str_t                helper_path;
    ngx_str_t                helper_user;
    ngx_msec_t               handshake_timeout;
    time_t                   drain_timeout;
    ngx_msec_t               debug_delay;
    size_t                   cache_size;
    size_t                   ratelimit_size;
    ngx_shm_zone_t          *cache_zone;
    ngx_shm_zone_t          *stats_zone;
    ngx_shm_zone_t          *ratelimit_zone;

    ngx_array_t              sets;          /* ngx_sundew_set_t */
    ngx_array_t              rules;         /* ngx_sundew_rule_t */
    ngx_array_t              protect;       /* ngx_sundew_cidr_t, sundew_protect */
    ngx_array_t              unprotect;     /* ngx_sundew_cidr_t, !cidr */
    ngx_array_t             *writable;      /* ngx_str_t, sundew_writable_sets */
    ngx_array_t              policy_protect;   /* final never-ban list */

    /* per cycle */
    ngx_uint_t               active;
    ngx_uint_t               generation;
    ngx_uint_t               nslots;
    ngx_fd_t                *slots;         /* worker ends, one per slot */
    uint64_t                 mask4;         /* sets of family inet */
    uint64_t                 mask6;
} ngx_sundew_core_conf_t;


extern ngx_module_t  ngx_sundew_core_module;


ngx_int_t ngx_sundew_add_set(ngx_conf_t *cf, ngx_str_t *name,
    ngx_uint_t role);
ngx_int_t ngx_sundew_add_rule(ngx_conf_t *cf, ngx_str_t *set,
    ngx_uint_t prefix4, ngx_uint_t prefix6, ngx_uint_t timeout);
ngx_shm_zone_t *ngx_sundew_ratelimit_zone(ngx_conf_t *cf);


#endif /* NGX_SUNDEW_H */
