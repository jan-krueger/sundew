/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Worker side of the slot channel.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include "sw_client.h"


#define SW_MAX_PENDING      1024        /* power of two */
#define SW_BUCKETS          256


typedef struct {
    ngx_queue_t      link;              /* bucket or free list */
    ngx_queue_t      waiters;
    ngx_event_t      timer;
    uint32_t         req_id;            /* 0 = free */
    uint32_t         hash;
    uint64_t         mask;
    ngx_uint_t       family;
    u_char           addr[16];
} sw_pending_t;


typedef struct {
    ngx_connection_t  *conn;
    ngx_uint_t         down;
    uint32_t           seq;
    ngx_uint_t         npending;
    sw_pending_t      *entries;
    ngx_queue_t        free;
    ngx_queue_t        buckets[SW_BUCKETS];
} sw_client_t;


static void sw_client_read_handler(ngx_event_t *rev);
static void sw_client_timeout_handler(ngx_event_t *ev);
static void sw_client_complete(sw_pending_t *p, ngx_uint_t result,
    uint64_t decided, uint64_t matched);
static void sw_client_fail_all(ngx_uint_t result);


static sw_client_t  *sw_client;


ngx_int_t
sw_client_init(ngx_cycle_t *cycle, ngx_fd_t fd)
{
    ngx_uint_t         i;
    ngx_event_t       *rev;
    ngx_connection_t  *c;

    sw_client = ngx_pcalloc(cycle->pool, sizeof(sw_client_t));
    if (sw_client == NULL) {
        return NGX_ERROR;
    }

    sw_client->entries = ngx_pcalloc(cycle->pool,
                                     SW_MAX_PENDING * sizeof(sw_pending_t));
    if (sw_client->entries == NULL) {
        return NGX_ERROR;
    }

    ngx_queue_init(&sw_client->free);

    for (i = 0; i < SW_BUCKETS; i++) {
        ngx_queue_init(&sw_client->buckets[i]);
    }

    for (i = 0; i < SW_MAX_PENDING; i++) {
        sw_client->entries[i].timer.handler = sw_client_timeout_handler;
        sw_client->entries[i].timer.data = &sw_client->entries[i];
        sw_client->entries[i].timer.log = cycle->log;
        ngx_queue_init(&sw_client->entries[i].waiters);
        ngx_queue_insert_tail(&sw_client->free, &sw_client->entries[i].link);
    }

    sw_client->seq = (uint32_t) ngx_random();

    c = ngx_get_connection(fd, cycle->log);
    if (c == NULL) {
        return NGX_ERROR;
    }

    c->recv = NULL;
    c->send = NULL;
    c->data = sw_client;

    rev = c->read;
    rev->log = cycle->log;
    rev->handler = sw_client_read_handler;
    rev->channel = 1;

    if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
        ngx_free_connection(c);
        return NGX_ERROR;
    }

    sw_client->conn = c;

    return NGX_OK;
}


static uint32_t
sw_client_hash(uint64_t mask, ngx_uint_t family, const u_char *addr)
{
    uint32_t  h;

    h = ngx_crc32_short((u_char *) &mask, sizeof(uint64_t));
    h ^= ngx_crc32_short((u_char *) addr, family == 4 ? 4 : 16);

    return h;
}


ngx_int_t
sw_client_submit(sw_waiter_t *w, uint64_t mask, ngx_uint_t family,
    const u_char *addr, ngx_msec_t timeout)
{
    size_t         len;
    uint32_t       hash;
    ngx_err_t      err;
    sw_req_t       req;
    ngx_queue_t   *q, *bucket;
    sw_pending_t  *p;

    if (sw_client == NULL || sw_client->down) {
        w->result = SW_RESULT_DOWN;
        return NGX_DECLINED;
    }

    len = (family == 4) ? 4 : 16;
    hash = sw_client_hash(mask, family, addr);
    bucket = &sw_client->buckets[hash % SW_BUCKETS];

    for (q = ngx_queue_head(bucket);
         q != ngx_queue_sentinel(bucket);
         q = ngx_queue_next(q))
    {
        p = ngx_queue_data(q, sw_pending_t, link);

        if (p->hash == hash && p->mask == mask && p->family == family
            && ngx_memcmp(p->addr, addr, len) == 0)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                           "sundew coalesce req_id:%uD", p->req_id);
            goto join;
        }
    }

    if (ngx_queue_empty(&sw_client->free)) {
        w->result = SW_RESULT_BUSY;
        return NGX_DECLINED;
    }

    q = ngx_queue_head(&sw_client->free);
    p = ngx_queue_data(q, sw_pending_t, link);

    do {
        sw_client->seq++;
        p->req_id = (sw_client->seq << 10)
                    | (uint32_t) (p - sw_client->entries);
    } while (p->req_id == 0);

    ngx_memzero(&req, sizeof(sw_req_t));
    req.magic = SW_FRAME_MAGIC;
    req.version = SW_PROTO_VERSION;
    req.op = SW_OP_TEST;
    req.req_id = p->req_id;
    req.arg = mask;
    req.family = (uint8_t) family;
    ngx_memcpy(req.addr, addr, len);

    if (send(sw_client->conn->fd, &req, sizeof(sw_req_t),
             MSG_DONTWAIT|MSG_NOSIGNAL)
        != (ssize_t) sizeof(sw_req_t))
    {
        err = ngx_socket_errno;
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, err,
                      "sundew: send to helper failed");
        p->req_id = 0;
        w->result = (err == NGX_EAGAIN) ? SW_RESULT_BUSY : SW_RESULT_DOWN;
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "sundew submit req_id:%uD", p->req_id);

    ngx_queue_remove(&p->link);
    ngx_queue_insert_tail(bucket, &p->link);

    p->hash = hash;
    p->mask = mask;
    p->family = family;
    ngx_memzero(p->addr, sizeof(p->addr));
    ngx_memcpy(p->addr, addr, len);

    ngx_add_timer(&p->timer, timeout);
    sw_client->npending++;

join:

    w->pending = p;
    ngx_queue_insert_tail(&p->waiters, &w->link);

    return NGX_OK;
}


void
sw_client_cancel(sw_waiter_t *w)
{
    if (w->pending) {
        ngx_queue_remove(&w->link);
        w->pending = NULL;
    }
}


static void
sw_client_complete(sw_pending_t *p, ngx_uint_t result, uint64_t decided,
    uint64_t matched)
{
    ngx_queue_t  *q;
    sw_waiter_t  *w;

    if (p->timer.timer_set) {
        ngx_del_timer(&p->timer);
    }

    p->req_id = 0;
    ngx_queue_remove(&p->link);
    ngx_queue_insert_tail(&sw_client->free, &p->link);
    sw_client->npending--;

    while (!ngx_queue_empty(&p->waiters)) {
        q = ngx_queue_head(&p->waiters);
        ngx_queue_remove(q);

        w = ngx_queue_data(q, sw_waiter_t, link);
        w->pending = NULL;
        w->result = result;
        w->decided = decided;
        w->matched = matched;

        w->handler(w);
    }
}


static void
sw_client_timeout_handler(ngx_event_t *ev)
{
    sw_pending_t  *p = ev->data;

    ngx_log_error(NGX_LOG_INFO, ev->log, 0,
                  "sundew: lookup timed out (req_id %uD)", p->req_id);

    sw_client_complete(p, SW_RESULT_TIMEOUT, 0, 0);
}


static void
sw_client_fail_all(ngx_uint_t result)
{
    ngx_uint_t  i;

    for (i = 0; i < SW_MAX_PENDING; i++) {
        if (sw_client->entries[i].req_id) {
            sw_client_complete(&sw_client->entries[i], result, 0, 0);
        }
    }
}


static void
sw_client_read_handler(ngx_event_t *rev)
{
    ssize_t            n;
    sw_rep_t           rep;
    ngx_err_t          err;
    sw_pending_t      *p;
    ngx_connection_t  *c;

    c = rev->data;

    for ( ;; ) {
        n = recv(c->fd, &rep, sizeof(sw_rep_t), MSG_DONTWAIT|MSG_TRUNC);

        if (n == -1) {
            err = ngx_socket_errno;

            if (err == NGX_EAGAIN) {
                return;
            }

            if (err == NGX_EINTR) {
                continue;
            }

            ngx_log_error(NGX_LOG_ALERT, rev->log, err,
                          "sundew: recv from helper failed");
            n = 0;
        }

        if (n == 0) {
            ngx_log_error(NGX_LOG_ALERT, rev->log, 0,
                          "sundew: helper channel closed; lookups now "
                          "follow the fail policy");
            sw_client->down = 1;
            sw_client->conn = NULL;
            ngx_close_connection(c);
            sw_client_fail_all(SW_RESULT_DOWN);
            return;
        }

        if (n != sizeof(sw_rep_t) || rep.magic != SW_FRAME_MAGIC
            || rep.version != SW_PROTO_VERSION)
        {
            ngx_log_error(NGX_LOG_ALERT, rev->log, 0,
                          "sundew: malformed reply from helper");
            continue;
        }

        if (rep.req_id == 0) {
            continue;                   /* LOG frame */
        }

        p = &sw_client->entries[rep.req_id & (SW_MAX_PENDING - 1)];

        if (p->req_id != rep.req_id) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                           "sundew stale reply req_id:%uD", rep.req_id);
            continue;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                       "sundew reply req_id:%uD decided:%uL matched:%uL",
                       rep.req_id, rep.decided, rep.matched);

        sw_client_complete(p, rep.status == SW_ST_OK ? SW_RESULT_OK
                                                     : SW_RESULT_ERROR,
                           rep.decided, rep.matched);
    }
}
