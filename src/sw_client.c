/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Worker side of the slot channel.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include "ngx_sundew.h"
#include "sw_cache.h"
#include "sw_client.h"
#include "sw_stats.h"


#define SW_MAX_PENDING      1024        /* power of two */
#define SW_BUCKETS          256
#define SW_LATE_GRACE       5000        /* ms a timed-out lookup waits for a late answer */


typedef struct {
    ngx_queue_t      link;              /* bucket or free list */
    ngx_queue_t      waiters;
    ngx_event_t      timer;
    uint32_t         req_id;            /* 0 = free */
    uint32_t         hash;
    ngx_uint_t       late;              /* timed out, waiting for the answer */
    ngx_uint_t       op;
    uint64_t         mask;              /* TEST: sets; ADD: rule */
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
static void sw_client_log(ngx_log_t *log, sw_rep_t *rep);
static void sw_client_release(sw_pending_t *p);


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
sw_client_hash(ngx_uint_t op, uint64_t mask, ngx_uint_t family,
    const u_char *addr)
{
    uint32_t  h;

    h = ngx_crc32_short((u_char *) &mask, sizeof(uint64_t));
    h ^= ngx_crc32_short((u_char *) addr, family == 4 ? 4 : 16);

    return h ^ (uint32_t) (op * 0x9e3779b9);
}


/*
 * NGX_OK: a new request was sent; NGX_AGAIN: the same request is already on
 * its way; NGX_DECLINED: nothing sent, *result says why.
 */

static ngx_int_t
sw_client_request(ngx_uint_t op, uint64_t mask, ngx_uint_t family,
    const u_char *addr, ngx_msec_t timeout, sw_pending_t **pp,
    ngx_uint_t *result)
{
    size_t         len;
    uint32_t       hash;
    ngx_err_t      err;
    sw_req_t       req;
    ngx_queue_t   *q, *bucket;
    sw_pending_t  *p;

    if (sw_client == NULL || sw_client->down) {
        *result = SW_RESULT_DOWN;
        return NGX_DECLINED;
    }

    len = (family == 4) ? 4 : 16;
    hash = sw_client_hash(op, mask, family, addr);
    bucket = &sw_client->buckets[hash % SW_BUCKETS];

    for (q = ngx_queue_head(bucket);
         q != ngx_queue_sentinel(bucket);
         q = ngx_queue_next(q))
    {
        p = ngx_queue_data(q, sw_pending_t, link);

        if (p->hash == hash && p->op == op && p->mask == mask
            && p->family == family && ngx_memcmp(p->addr, addr, len) == 0)
        {
            *pp = p;
            return NGX_AGAIN;
        }
    }

    if (ngx_queue_empty(&sw_client->free)) {
        *result = SW_RESULT_BUSY;
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
    req.op = (uint8_t) op;
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
        *result = (err == NGX_EAGAIN) ? SW_RESULT_BUSY : SW_RESULT_DOWN;
        return NGX_DECLINED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "sundew submit op:%ui req_id:%uD", op, p->req_id);

    ngx_queue_remove(&p->link);
    ngx_queue_insert_tail(bucket, &p->link);

    p->hash = hash;
    p->op = op;
    p->mask = mask;
    p->family = family;
    ngx_memzero(p->addr, sizeof(p->addr));
    ngx_memcpy(p->addr, addr, len);

    ngx_add_timer(&p->timer, timeout);
    sw_client->npending++;

    *pp = p;

    return NGX_OK;
}


ngx_int_t
sw_client_submit(sw_waiter_t *w, uint64_t mask, ngx_uint_t family,
    const u_char *addr, ngx_msec_t timeout)
{
    ngx_int_t      rc;
    ngx_uint_t     result;
    sw_pending_t  *p;

    rc = sw_client_request(SW_OP_TEST, mask, family, addr, timeout, &p,
                           &result);

    switch (rc) {

    case NGX_DECLINED:
        sw_stats_inc(result == SW_RESULT_DOWN ? SW_STAT_HELPER_DOWN
                                              : SW_STAT_BUSY);
        w->result = result;
        return NGX_DECLINED;

    case NGX_AGAIN:
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "sundew coalesce req_id:%uD", p->req_id);
        sw_stats_inc(SW_STAT_COALESCED);
        break;

    default:
        sw_stats_inc(SW_STAT_LOOKUPS);
    }

    w->pending = p;
    ngx_queue_insert_tail(&p->waiters, &w->link);

    return NGX_OK;
}


void
sw_client_add(ngx_uint_t rule, ngx_uint_t family, const u_char *addr)
{
    ngx_int_t      rc;
    ngx_uint_t     result;
    sw_pending_t  *p;

    rc = sw_client_request(SW_OP_ADD, rule, family, addr, 2000, &p, &result);

    if (rc == NGX_DECLINED) {
        sw_stats_inc(SW_STAT_ADDS_FAILED);
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "sundew: could not ask the helper to add an address: %s",
                      result == SW_RESULT_DOWN ? "helper down" : "busy");
    }
}


static void
sw_client_add_done(sw_pending_t *p, ngx_uint_t status, uint64_t decided)
{
    u_char                   addr[16];
    ngx_sundew_set_t        *set;
    ngx_sundew_rule_t       *rule;
    ngx_sundew_core_conf_t  *scf;

    if (p->timer.timer_set) {
        ngx_del_timer(&p->timer);
    }

    scf = (ngx_sundew_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                  ngx_sundew_core_module);

    if (status == SW_ST_OK && decided && p->mask < scf->rules.nelts) {
        sw_stats_inc(SW_STAT_ADDS);

        rule = scf->rules.elts;
        set = scf->sets.elts;

        if (scf->cache_zone && scf->cache_zone->data) {
            sw_cache_addr(addr, p->family, p->addr);
            sw_cache_put(scf->cache_zone, set[rule[p->mask].set].ident, addr,
                         SW_VERDICT_IN, rule[p->mask].timeout);
        }

    } else if (status == SW_ST_DENIED) {
        sw_stats_inc(SW_STAT_ADDS_REFUSED);

    } else {
        sw_stats_inc(SW_STAT_ADDS_FAILED);
    }

    ngx_queue_remove(&p->link);
    sw_client_release(p);
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
sw_client_store(sw_pending_t *p, uint64_t decided, uint64_t matched)
{
    u_char                   addr[16];
    ngx_uint_t               i;
    ngx_sundew_set_t        *set;
    ngx_sundew_core_conf_t  *scf;

    scf = (ngx_sundew_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                  ngx_sundew_core_module);

    if (scf->cache_zone == NULL || scf->cache_zone->data == NULL) {
        return;
    }

    sw_cache_addr(addr, p->family, p->addr);
    set = scf->sets.elts;

    for (i = 0; i < scf->sets.nelts; i++) {
        if (decided & p->mask & ((uint64_t) 1 << i)) {
            sw_cache_put(scf->cache_zone, set[i].ident, addr,
                         (matched & ((uint64_t) 1 << i)) ? SW_VERDICT_IN
                                                         : SW_VERDICT_NOT_IN,
                         0);
        }
    }
}


static void
sw_client_release(sw_pending_t *p)
{
    p->req_id = 0;
    p->late = 0;
    ngx_queue_insert_tail(&sw_client->free, &p->link);
    sw_client->npending--;
}


static void
sw_client_late(sw_pending_t *p, ngx_uint_t result, uint64_t decided,
    uint64_t matched)
{
    if (p->timer.timer_set) {
        ngx_del_timer(&p->timer);
    }

    if (result == SW_RESULT_OK) {
        sw_client_store(p, decided, matched);
        sw_stats_inc(SW_STAT_LATE_REPLIES);
    }

    sw_client_release(p);
}


static void
sw_client_complete(sw_pending_t *p, ngx_uint_t result, uint64_t decided,
    uint64_t matched)
{
    ngx_queue_t  *q;
    sw_waiter_t  *w;

    if (result == SW_RESULT_OK) {
        sw_client_store(p, decided, matched);

    } else {
        sw_stats_inc(result == SW_RESULT_TIMEOUT ? SW_STAT_TIMEOUTS
                     : result == SW_RESULT_DOWN ? SW_STAT_HELPER_DOWN
                     : SW_STAT_HELPER_ERRORS);
    }

    if (p->timer.timer_set) {
        ngx_del_timer(&p->timer);
    }

    ngx_queue_remove(&p->link);

    if (result == SW_RESULT_TIMEOUT) {
        /* stays out of the buckets, so new requests ask again */
        p->late = 1;
        ngx_queue_init(&p->link);
        ngx_add_timer(&p->timer, SW_LATE_GRACE);

    } else {
        sw_client_release(p);
    }

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

    if (p->late) {
        sw_client_release(p);
        return;
    }

    if (p->op == SW_OP_ADD) {
        sw_client_add_done(p, SW_ST_ERROR, 0);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ev->log, 0,
                  "sundew: lookup timed out (req_id %uD)", p->req_id);

    sw_client_complete(p, SW_RESULT_TIMEOUT, 0, 0);
}


static void
sw_client_fail_all(ngx_uint_t result)
{
    ngx_uint_t  i;

    for (i = 0; i < SW_MAX_PENDING; i++) {
        if (sw_client->entries[i].req_id == 0) {
            continue;
        }

        if (sw_client->entries[i].op == SW_OP_ADD) {
            sw_client_add_done(&sw_client->entries[i], SW_ST_ERROR, 0);

        } else if (sw_client->entries[i].late) {
            sw_client_late(&sw_client->entries[i], result, 0, 0);

        } else {
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
            if (rep.status & SW_ST_LOG) {
                sw_client_log(rev->log, &rep);
            }

            continue;
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

        if (p->op == SW_OP_ADD) {
            sw_client_add_done(p, rep.status, rep.decided);
            continue;
        }

        if (p->late) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                           "sundew late reply req_id:%uD cached", rep.req_id);
            sw_client_late(p, rep.status == SW_ST_OK ? SW_RESULT_OK
                                                     : SW_RESULT_ERROR,
                           rep.decided, rep.matched);
            continue;
        }

        sw_client_complete(p, rep.status == SW_ST_OK ? SW_RESULT_OK
                                                     : SW_RESULT_ERROR,
                           rep.decided, rep.matched);
    }
}


static void
sw_client_log(ngx_log_t *log, sw_rep_t *rep)
{
    int                      status;
    ngx_str_t               *name, unknown = ngx_string("?");
    ngx_uint_t               level, idx;
    ngx_sundew_set_t        *set;
    ngx_sundew_rule_t       *rule;
    ngx_sundew_core_conf_t  *scf;
    static const char       *violation[] = { "?", "wrong size", "malformed",
                                             "sets not in the configuration" };

    level = rep->status & ~SW_ST_LOG;

    if (level < NGX_LOG_ALERT || level > NGX_LOG_INFO) {
        level = NGX_LOG_ERR;
    }

    scf = (ngx_sundew_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                  ngx_sundew_core_module);
    set = scf->sets.elts;
    idx = (ngx_uint_t) (rep->matched & 0xffffffff);
    name = (idx < scf->sets.nelts) ? &set[idx].name : &unknown;

    switch (rep->decided) {

    case SW_LOG_TEST_FAILED:
        ngx_log_error(level, log, 0,
                      "sundew: lookup in set \"%V\" failed: kernel error %uD",
                      name, (uint32_t) (rep->matched >> 32));
        break;

    case SW_LOG_SET_MISSING:
        ngx_log_error(level, log, 0,
                      "sundew: set \"%V\" no longer exists; lookups in it "
                      "fail until it is recreated", name);
        break;

    case SW_LOG_NETLINK:
        ngx_log_error(level, log, (ngx_err_t) rep->matched,
                      "sundew: helper could not query the kernel");
        break;

    case SW_LOG_VIOLATION:
        ngx_log_error(level, log, 0,
                      "sundew: helper closed this worker's channel after a "
                      "request that was %s",
                      violation[rep->matched < 4 ? rep->matched : 0]);
        break;

    case SW_LOG_ENGINE_EXIT:
        status = (int) rep->matched;

        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
            ngx_log_error(level, log, 0,
                          "sundew: helper engine was killed by seccomp "
                          "(SIGSYS), restarting; please report this");

        } else if (WIFSIGNALED(status)) {
            ngx_log_error(level, log, 0,
                          "sundew: helper engine was killed by signal %d, "
                          "restarting", WTERMSIG(status));

        } else {
            ngx_log_error(level, log, 0,
                          "sundew: helper engine exited with status %d, "
                          "restarting", WEXITSTATUS(status));
        }

        break;

    case SW_LOG_GAVE_UP:
        ngx_log_error(level, log, 0,
                      "sundew: helper engine crashed %uL times in a row; the "
                      "helper stopped, lookups follow the fail policy until "
                      "the next reload", rep->matched);
        break;

    case SW_LOG_ADD_PROTECTED:
    case SW_LOG_ADD_BUDGET:
    case SW_LOG_ADD_BREAKER:
    case SW_LOG_ADD_FAILED:
        idx = (ngx_uint_t) (rep->matched & 0xffffffff);
        rule = scf->rules.elts;
        name = (idx < scf->rules.nelts) ? &set[rule[idx].set].name : &unknown;

        if (rep->decided == SW_LOG_ADD_PROTECTED) {
            ngx_log_error(level, log, 0,
                          "sundew: helper refused to add a protected address "
                          "to set \"%V\" (sundew_protect)", name);

        } else if (rep->decided == SW_LOG_ADD_BUDGET) {
            ngx_log_error(level, log, 0,
                          "sundew: helper refused adds to set \"%V\": over "
                          "20 per second", name);

        } else if (rep->decided == SW_LOG_ADD_BREAKER) {
            ngx_log_error(level, log, 0,
                          "sundew: more than 1000 adds to set \"%V\" in a "
                          "minute; adds to it are paused for 10 minutes", name);

        } else {
            ngx_log_error(level, log, 0,
                          "sundew: adding to set \"%V\" failed: kernel error "
                          "%uD", name, (uint32_t) (rep->matched >> 32));
        }

        break;

    case SW_LOG_SET_FULL:
        ngx_log_error(level, log, 0,
                      "sundew: set \"%V\" is full (maxelem); nothing more "
                      "can be added", name);
        break;

    case SW_LOG_LANDLOCK:
        ngx_log_error(level, log, (ngx_err_t) rep->matched,
                      "sundew: Landlock is unavailable, the helper runs with "
                      "seccomp only");
        break;

    default:
        ngx_log_error(level, log, 0, "sundew: helper event %uL (%uL)",
                      rep->decided, rep->matched);
    }
}
