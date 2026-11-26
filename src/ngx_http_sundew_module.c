/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_sundew.h"
#include "sw_cache.h"
#include "sw_client.h"
#include "sw_stats.h"


#define SW_STATE_NEW        0
#define SW_STATE_PENDING    1
#define SW_STATE_DONE       2

#define SW_RES_NONE         0
#define SW_RES_ALLOW        1
#define SW_RES_DENY         2
#define SW_RES_DRYRUN       3

#define SW_V_UNKNOWN        0
#define SW_V_ALLOW          1
#define SW_V_ALLOW_WL       2
#define SW_V_DENY_BL        3
#define SW_V_DENY_NOT_WL    4

#define SW_STALE_MS         (600 * 1000)


typedef struct {
    uint64_t     blacklist;
    uint64_t     whitelist;
    ngx_uint_t   blacklist_set;
    ngx_uint_t   whitelist_set;
    ngx_uint_t   status;
    ngx_flag_t   fail_open;
    ngx_flag_t   dryrun;
    ngx_msec_t   lookup_timeout;
    time_t       cache_ttl;
} ngx_http_sundew_loc_conf_t;


typedef struct {
    sw_waiter_t           waiter;
    ngx_http_request_t   *request;
    ngx_uint_t            state;
    ngx_uint_t            result;
    ngx_int_t             matched_set;      /* index or -1 */
    uint64_t              asked;
    uint64_t              decided;
    uint64_t              matched;
    uint64_t              stale_in;
} ngx_http_sundew_ctx_t;


static ngx_int_t ngx_http_sundew_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_sundew_init(ngx_conf_t *cf);
static void *ngx_http_sundew_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_sundew_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_sundew_sets(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_sundew_status(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_sundew_endpoint(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_sundew_commands[] = {

    { ngx_string("ipset_blacklist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_sundew_sets,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ipset_whitelist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_sundew_sets,
      NGX_HTTP_LOC_CONF_OFFSET,
      1,
      NULL },

    { ngx_string("ipset_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_sundew_status,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ipset_fail_open"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sundew_loc_conf_t, fail_open),
      NULL },

    { ngx_string("ipset_dryrun"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sundew_loc_conf_t, dryrun),
      NULL },

    { ngx_string("ipset_cache_ttl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sundew_loc_conf_t, cache_ttl),
      NULL },

    { ngx_string("sundew_lookup_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sundew_loc_conf_t, lookup_timeout),
      NULL },

    { ngx_string("ipset_stats"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_sundew_endpoint,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ipset_metrics"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_sundew_endpoint,
      NGX_HTTP_LOC_CONF_OFFSET,
      1,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_sundew_module_ctx = {
    ngx_http_sundew_add_variables,         /* preconfiguration */
    ngx_http_sundew_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_sundew_create_loc_conf,       /* create location configuration */
    ngx_http_sundew_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_sundew_module = {
    NGX_MODULE_V1,
    &ngx_http_sundew_module_ctx,           /* module context */
    ngx_http_sundew_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_sundew_results[] = {
    ngx_null_string,
    ngx_string("allow"),
    ngx_string("deny"),
    ngx_string("dryrun")
};

static ngx_str_t  ngx_http_sundew_no_set = ngx_string("-");


static ngx_sundew_core_conf_t *
ngx_http_sundew_core_conf(void)
{
    return (ngx_sundew_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                   ngx_sundew_core_module);
}


static ngx_int_t
ngx_http_sundew_client_addr(ngx_http_request_t *r, ngx_uint_t *family,
    u_char *addr)
{
    struct sockaddr      *sa;
#if (NGX_HAVE_INET6)
    struct in6_addr      *a6;
#endif

    sa = r->connection->sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        a6 = &((struct sockaddr_in6 *) sa)->sin6_addr;

        if (IN6_IS_ADDR_V4MAPPED(a6)) {
            *family = 4;
            ngx_memcpy(addr, &a6->s6_addr[12], 4);

        } else {
            *family = 6;
            ngx_memcpy(addr, a6->s6_addr, 16);
        }

        return NGX_OK;
#endif

    case AF_INET:
        *family = 4;
        ngx_memcpy(addr, &((struct sockaddr_in *) sa)->sin_addr, 4);
        return NGX_OK;

    default:
        return NGX_DECLINED;
    }
}


static ngx_uint_t
ngx_http_sundew_evaluate(uint64_t decided, uint64_t matched, uint64_t bl,
    uint64_t wl, ngx_uint_t has_wl)
{
    if (has_wl) {
        if (matched & wl) {
            return SW_V_ALLOW_WL;
        }

        return ((decided & wl) == wl) ? SW_V_DENY_NOT_WL : SW_V_UNKNOWN;
    }

    if (matched & bl) {
        return SW_V_DENY_BL;
    }

    return ((decided & bl) == bl) ? SW_V_ALLOW : SW_V_UNKNOWN;
}


static ngx_int_t
ngx_http_sundew_deny(ngx_http_request_t *r, ngx_http_sundew_loc_conf_t *slcf,
    ngx_http_sundew_ctx_t *ctx, const char *why)
{
    ngx_str_t               *name;
    ngx_sundew_set_t        *set;
    ngx_sundew_core_conf_t  *scf;

    name = &ngx_http_sundew_no_set;

    if (ctx->matched_set >= 0) {
        scf = ngx_http_sundew_core_conf();
        set = scf->sets.elts;
        name = &set[ctx->matched_set].name;
    }

    if (slcf->dryrun) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "sundew: dryrun, would deny %V (%s, set %V)",
                      &r->connection->addr_text, why, name);
        sw_stats_inc(SW_STAT_DRYRUN);
        ctx->result = SW_RES_DRYRUN;
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "sundew: deny %V (%s, set %V)",
                  &r->connection->addr_text, why, name);

    sw_stats_inc(SW_STAT_DENIED);
    ctx->result = SW_RES_DENY;

    return slcf->status;
}


static ngx_int_t
ngx_http_sundew_apply(ngx_http_request_t *r, ngx_http_sundew_loc_conf_t *slcf,
    ngx_http_sundew_ctx_t *ctx, ngx_uint_t v, uint64_t bl, uint64_t wl)
{
    uint64_t  hit;

    ctx->state = SW_STATE_DONE;

    switch (v) {

    case SW_V_DENY_BL:
        hit = ctx->matched & bl;
        ctx->matched_set = (ngx_int_t) __builtin_ctzll(hit);
        sw_stats_set_matched(ctx->matched_set);
        return ngx_http_sundew_deny(r, slcf, ctx, "blacklisted");

    case SW_V_DENY_NOT_WL:
        return ngx_http_sundew_deny(r, slcf, ctx, "not whitelisted");

    case SW_V_ALLOW_WL:
        hit = ctx->matched & wl;
        ctx->matched_set = (ngx_int_t) __builtin_ctzll(hit);
        sw_stats_set_matched(ctx->matched_set);
        /* fall through */

    default:
        sw_stats_inc(SW_STAT_ALLOWED);
        ctx->result = SW_RES_ALLOW;
        return NGX_DECLINED;
    }
}


static ngx_int_t
ngx_http_sundew_fail(ngx_http_request_t *r, ngx_http_sundew_loc_conf_t *slcf,
    ngx_http_sundew_ctx_t *ctx, ngx_uint_t result)
{
    static const char *why[] = { "ok", "helper error", "lookup timeout",
                                 "helper down", "busy" };

    ctx->state = SW_STATE_DONE;

    if (slcf->fail_open) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "sundew: allow %V (fail open: %s)",
                      &r->connection->addr_text, why[result]);
        sw_stats_inc(SW_STAT_FAIL_OPEN);
        sw_stats_inc(SW_STAT_ALLOWED);
        ctx->result = SW_RES_ALLOW;
        return NGX_DECLINED;
    }

    sw_stats_inc(SW_STAT_FAIL_CLOSED);

    return ngx_http_sundew_deny(r, slcf, ctx, why[result]);
}


/* verdict after the helper answered, timed out or failed */

static ngx_int_t
ngx_http_sundew_finish(ngx_http_request_t *r, ngx_http_sundew_loc_conf_t *slcf,
    ngx_http_sundew_ctx_t *ctx, uint64_t bl, uint64_t wl)
{
    ngx_uint_t    v, has_wl, result;
    sw_waiter_t  *w;

    w = &ctx->waiter;
    has_wl = (slcf->whitelist != 0);
    result = w->result;

    if (result == SW_RESULT_OK) {
        ctx->decided |= w->decided & ctx->asked;
        ctx->matched |= w->matched & w->decided & ctx->asked;
    }

    v = ngx_http_sundew_evaluate(ctx->decided, ctx->matched, bl, wl, has_wl);

    if (v != SW_V_UNKNOWN) {
        return ngx_http_sundew_apply(r, slcf, ctx, v, bl, wl);
    }

    if (ctx->stale_in) {
        ctx->decided |= ctx->stale_in;
        ctx->matched |= ctx->stale_in;

        v = ngx_http_sundew_evaluate(ctx->decided, ctx->matched, bl, wl,
                                     has_wl);

        if (v != SW_V_UNKNOWN) {
            sw_stats_inc(SW_STAT_STALE_SERVED);
            return ngx_http_sundew_apply(r, slcf, ctx, v, bl, wl);
        }
    }

    return ngx_http_sundew_fail(r, slcf, ctx,
                                result == SW_RESULT_OK ? SW_RESULT_ERROR
                                                       : result);
}


static void
ngx_http_sundew_cache_lookup(ngx_http_sundew_loc_conf_t *slcf,
    ngx_http_sundew_ctx_t *ctx, uint64_t need, ngx_uint_t family,
    u_char *addr)
{
    u_char                   key[16];
    uint64_t                 bit;
    ngx_msec_t               age, ttl;
    ngx_uint_t               i, verdict;
    ngx_sundew_set_t        *set;
    ngx_sundew_core_conf_t  *scf;

    scf = ngx_http_sundew_core_conf();

    if (scf->cache_zone == NULL || scf->cache_zone->data == NULL) {
        return;
    }

    sw_cache_addr(key, family, addr);
    set = scf->sets.elts;
    ttl = (ngx_msec_t) slcf->cache_ttl * 1000;

    for (i = 0; i < scf->sets.nelts; i++) {
        bit = (uint64_t) 1 << i;

        if (!(need & bit)
            || sw_cache_get(scf->cache_zone, set[i].ident, key, &verdict,
                            &age)
               != NGX_OK)
        {
            continue;
        }

        if (age < ttl) {
            ctx->decided |= bit;

            if (verdict == SW_VERDICT_IN) {
                ctx->matched |= bit;
            }

        } else if (verdict == SW_VERDICT_IN && age < ttl + SW_STALE_MS) {
            ctx->stale_in |= bit;
        }
    }
}


static void
ngx_http_sundew_wake(sw_waiter_t *w)
{
    ngx_http_request_t     *r;
    ngx_http_sundew_ctx_t  *ctx;

    ctx = w->data;
    r = ctx->request;

    ctx->state = SW_STATE_DONE;

    r->write_event_handler = ngx_http_core_run_phases;
    ngx_post_event(r->connection->write, &ngx_posted_events);
}


static void
ngx_http_sundew_cleanup(void *data)
{
    ngx_http_sundew_ctx_t  *ctx = data;

    sw_client_cancel(&ctx->waiter);
}


static ngx_int_t
ngx_http_sundew_handler(ngx_http_request_t *r)
{
    u_char                       addr[16];
    uint64_t                     famask, bl, wl, need, ask;
    ngx_uint_t                   family, v, has_wl;
    ngx_pool_cleanup_t          *cln;
    ngx_http_sundew_ctx_t       *ctx;
    ngx_sundew_core_conf_t      *scf;
    ngx_http_sundew_loc_conf_t  *slcf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sundew_module);

    if (slcf->blacklist == 0 && slcf->whitelist == 0) {
        return NGX_DECLINED;
    }

    if (ngx_http_sundew_client_addr(r, &family, addr) != NGX_OK) {
        return NGX_DECLINED;
    }

    scf = ngx_http_sundew_core_conf();
    famask = (family == 4) ? scf->mask4 : scf->mask6;
    bl = slcf->blacklist & famask;
    wl = slcf->whitelist & famask;
    has_wl = (slcf->whitelist != 0);

    ctx = ngx_http_get_module_ctx(r, ngx_http_sundew_module);

    if (ctx) {
        switch (ctx->state) {

        case SW_STATE_PENDING:
            return NGX_AGAIN;

        case SW_STATE_DONE:
            if (ctx->result != SW_RES_NONE) {
                return (ctx->result == SW_RES_DENY) ? (ngx_int_t) slcf->status
                                                    : NGX_DECLINED;
            }

            r->write_event_handler = ngx_http_request_empty_handler;
            r->read_event_handler = ngx_http_block_reading;
            return ngx_http_sundew_finish(r, slcf, ctx, bl, wl);

        default:
            return NGX_DECLINED;
        }
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_sundew_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;
    ctx->matched_set = -1;
    ctx->waiter.handler = ngx_http_sundew_wake;
    ctx->waiter.data = ctx;

    ngx_http_set_ctx(r, ctx, ngx_http_sundew_module);

    sw_stats_inc(SW_STAT_CHECKED);

    need = has_wl ? wl : bl;

    ngx_http_sundew_cache_lookup(slcf, ctx, need, family, addr);

    v = ngx_http_sundew_evaluate(ctx->decided, ctx->matched, bl, wl, has_wl);

    if (v != SW_V_UNKNOWN) {
        if (need) {
            sw_stats_inc(SW_STAT_CACHE_HIT);
        }

        return ngx_http_sundew_apply(r, slcf, ctx, v, bl, wl);
    }

    sw_stats_inc(SW_STAT_CACHE_MISS);

    ask = need & ~ctx->decided;
    ctx->asked = ask;

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln->handler = ngx_http_sundew_cleanup;
    cln->data = ctx;

    if (sw_client_submit(&ctx->waiter, ask, family, addr,
                         slcf->lookup_timeout)
        != NGX_OK)
    {
        return ngx_http_sundew_finish(r, slcf, ctx, bl, wl);
    }

    ctx->state = SW_STATE_PENDING;

    r->read_event_handler = ngx_http_test_reading;
    r->write_event_handler = ngx_http_request_empty_handler;

    return NGX_AGAIN;
}


/* ---- ipset_stats / ipset_metrics ---------------------------------------- */

static ngx_int_t
ngx_http_sundew_endpoint_send(ngx_http_request_t *r, ngx_uint_t metrics)
{
    size_t        len;
    u_char       *p;
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_uint_t    i, first;
    sw_stats_t   *st;
    ngx_chain_t   out;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    st = sw_stats_get();
    if (st == NULL) {
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    len = 512 + SW_STAT_N * 128 + SW_STATS_SETS * (SW_SETNAME_LEN + 96);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = b->last;

    if (metrics) {
        p = ngx_sprintf(p, "# HELP sundew_info Sundew build.\n"
                           "# TYPE sundew_info gauge\n"
                           "sundew_info{version=\"%s\"} 1\n", SUNDEW_VERSION);

        for (i = 0; i < SW_STAT_N; i++) {
            p = ngx_sprintf(p, "# TYPE sundew_%s_total counter\n"
                               "sundew_%s_total %uA\n",
                            sw_stat_names[i], sw_stat_names[i], st->c[i]);
        }

        p = ngx_sprintf(p, "# HELP sundew_set_matched_total Requests decided "
                           "by a match in this set.\n"
                           "# TYPE sundew_set_matched_total counter\n");

        for (i = 0; i < SW_STATS_SETS; i++) {
            if (st->sets[i].name[0]) {
                p = ngx_sprintf(p, "sundew_set_matched_total{set=\"%s\"} %uA\n",
                                st->sets[i].name, st->sets[i].matched);
            }
        }

        ngx_str_set(&r->headers_out.content_type,
                    "text/plain; version=0.0.4; charset=utf-8");

    } else {
        p = ngx_sprintf(p, "{\"version\":\"%s\",\"counters\":{",
                        SUNDEW_VERSION);

        for (i = 0; i < SW_STAT_N; i++) {
            p = ngx_sprintf(p, "%s\"%s\":%uA", i ? "," : "",
                            sw_stat_names[i], st->c[i]);
        }

        p = ngx_sprintf(p, "},\"sets\":{");

        for (i = 0, first = 1; i < SW_STATS_SETS; i++) {
            if (st->sets[i].name[0]) {
                p = ngx_sprintf(p, "%s\"%s\":{\"matched\":%uA}",
                                first ? "" : ",", st->sets[i].name,
                                st->sets[i].matched);
                first = 0;
            }
        }

        p = ngx_sprintf(p, "}}\n");

        ngx_str_set(&r->headers_out.content_type, "application/json");
    }

    b->last = p;
    b->last_buf = (r == r->main);
    b->last_in_chain = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_sundew_stats_handler(ngx_http_request_t *r)
{
    return ngx_http_sundew_endpoint_send(r, 0);
}


static ngx_int_t
ngx_http_sundew_metrics_handler(ngx_http_request_t *r)
{
    return ngx_http_sundew_endpoint_send(r, 1);
}


static char *
ngx_http_sundew_endpoint(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = cmd->offset ? ngx_http_sundew_metrics_handler
                                : ngx_http_sundew_stats_handler;

    return NGX_CONF_OK;
}


/* ---- variables ---------------------------------------------------------- */

static ngx_int_t
ngx_http_sundew_result_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t               *s;
    ngx_sundew_set_t        *set;
    ngx_http_sundew_ctx_t   *ctx;
    ngx_sundew_core_conf_t  *scf;

    ctx = ngx_http_get_module_ctx(r->main, ngx_http_sundew_module);

    if (ctx == NULL || ctx->result == SW_RES_NONE) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (data == 0) {
        s = &ngx_http_sundew_results[ctx->result];

    } else if (ctx->matched_set >= 0) {
        scf = ngx_http_sundew_core_conf();
        set = scf->sets.elts;
        s = &set[ctx->matched_set].name;

    } else {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = s->len;
    v->data = s->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_http_variable_t  ngx_http_sundew_vars[] = {

    { ngx_string("ipset_result"), NULL, ngx_http_sundew_result_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("ipset_matched_set"), NULL, ngx_http_sundew_result_variable,
      1, NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_sundew_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_sundew_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


/* ---- configuration ------------------------------------------------------ */

static void *
ngx_http_sundew_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_sundew_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sundew_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->status = NGX_CONF_UNSET_UINT;
    conf->fail_open = NGX_CONF_UNSET;
    conf->dryrun = NGX_CONF_UNSET;
    conf->lookup_timeout = NGX_CONF_UNSET_MSEC;
    conf->cache_ttl = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_sundew_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_sundew_loc_conf_t *prev = parent;
    ngx_http_sundew_loc_conf_t *conf = child;

    if (!conf->blacklist_set) {
        conf->blacklist = prev->blacklist;
        conf->blacklist_set = prev->blacklist_set;
    }

    if (!conf->whitelist_set) {
        conf->whitelist = prev->whitelist;
        conf->whitelist_set = prev->whitelist_set;
    }

    ngx_conf_merge_uint_value(conf->status, prev->status, NGX_HTTP_FORBIDDEN);
    ngx_conf_merge_value(conf->fail_open, prev->fail_open, 0);
    ngx_conf_merge_value(conf->dryrun, prev->dryrun, 0);
    ngx_conf_merge_msec_value(conf->lookup_timeout, prev->lookup_timeout, 100);
    ngx_conf_merge_sec_value(conf->cache_ttl, prev->cache_ttl, 60);

    return NGX_CONF_OK;
}


static char *
ngx_http_sundew_sets(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sundew_loc_conf_t *slcf = conf;

    uint64_t    *mask;
    ngx_int_t    idx;
    ngx_str_t   *value;
    ngx_uint_t   i, *seen;

    if (cmd->offset) {
        mask = &slcf->whitelist;
        seen = &slcf->whitelist_set;

    } else {
        mask = &slcf->blacklist;
        seen = &slcf->blacklist_set;
    }

    if (*seen) {
        return "is duplicate";
    }

    *seen = 1;
    value = cf->args->elts;

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
        return NGX_CONF_OK;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        idx = ngx_sundew_add_set(cf, &value[i], SW_ROLE_LOOKUP);
        if (idx == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        *mask |= (uint64_t) 1 << idx;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_sundew_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sundew_loc_conf_t *slcf = conf;

    ngx_int_t   n;
    ngx_str_t  *value;

    if (slcf->status != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    n = ngx_atoi(value[1].data, value[1].len);

    if (n == NGX_HTTP_CLOSE) {
        slcf->status = NGX_HTTP_CLOSE;
        return NGX_CONF_OK;
    }

    if (n < 400 || n > 599) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid status \"%V\": use 4xx, 5xx or 444",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    slcf->status = n;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_sundew_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_sundew_handler;

    return NGX_OK;
}
