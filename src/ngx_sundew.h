/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef NGX_SUNDEW_H
#define NGX_SUNDEW_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "sw_proto.h"


#define SUNDEW_VERSION  "0.1.0-dev"


typedef struct {
    ngx_str_t                name;
    ngx_uint_t               role;
    /* from READY */
    ngx_uint_t               family;        /* AF_INET / AF_INET6 */
    ngx_uint_t               revision;
    u_char                   type[SW_SETNAME_LEN];
    uint64_t                 ident;         /* cache key */
    ngx_uint_t               stat_slot;
} ngx_sundew_set_t;


typedef struct {
    ngx_str_t                helper_path;
    ngx_str_t                helper_user;
    ngx_msec_t               handshake_timeout;
    time_t                   drain_timeout;
    ngx_msec_t               debug_delay;
    size_t                   cache_size;
    ngx_shm_zone_t          *cache_zone;
    ngx_shm_zone_t          *stats_zone;

    ngx_array_t              sets;          /* ngx_sundew_set_t */

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


#endif /* NGX_SUNDEW_H */
