/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SW_CLIENT_H
#define SW_CLIENT_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "sw_proto.h"


#define SW_RESULT_OK        0
#define SW_RESULT_ERROR     1       /* helper status != OK */
#define SW_RESULT_TIMEOUT   2
#define SW_RESULT_DOWN      3       /* helper gone */
#define SW_RESULT_BUSY      4       /* local limits */


typedef struct sw_waiter_s  sw_waiter_t;

typedef void (*sw_waiter_handler_pt)(sw_waiter_t *w);

struct sw_waiter_s {
    ngx_queue_t            link;
    void                  *pending;
    sw_waiter_handler_pt   handler;
    void                  *data;
    ngx_uint_t             result;
    uint64_t               decided;
    uint64_t               matched;
};


ngx_int_t sw_client_init(ngx_cycle_t *cycle, ngx_fd_t fd);
ngx_int_t sw_client_submit(sw_waiter_t *w, uint64_t mask, ngx_uint_t family,
    const u_char *addr, ngx_msec_t timeout);
void sw_client_cancel(sw_waiter_t *w);

#endif /* SW_CLIENT_H */
