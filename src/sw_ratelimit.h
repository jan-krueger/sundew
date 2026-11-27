/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SW_RATELIMIT_H
#define SW_RATELIMIT_H

#include <ngx_config.h>
#include <ngx_core.h>


#define SW_RL_OK          0
#define SW_RL_LIMITED     1     /* over the rate, ban already handled */
#define SW_RL_FIRST       2     /* over the rate for the first time: ban */


ngx_int_t sw_rl_zone_init(ngx_shm_zone_t *zone, void *data);

/* key: 16 bytes, already masked */
ngx_uint_t sw_rl_hit(ngx_shm_zone_t *zone, ngx_uint_t rule, const u_char *key,
    ngx_uint_t rate, ngx_msec_t window);

#endif /* SW_RATELIMIT_H */
