/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_sundew.h"
#include "sw_client.h"


#define SW_STATE_NEW        0
#define SW_STATE_PENDING    1
#define SW_STATE_DONE       2

#define SW_RES_NONE         0
#define SW_RES_ALLOW        1
#define SW_RES_DENY         2
#define SW_RES_DRYRUN       3


typedef struct {
    uint64_t     blacklist;
    ngx_uint_t   blacklist_set;
    ngx_uint_t   status;
    ngx_flag_t   fail_open;
    ngx_flag_t   dryrun;
    ngx_msec_t   lookup_timeout;
} ngx_http_sundew_loc_conf_t;


typedef struct {
    sw_waiter_t           waiter;
    ngx_http_request_t   *request;
    ngx_uint_t            state;
    ngx_uint_t            result;
    ngx_int_t             matched_set;      /* index or -1 */
} ngx_http_sundew_ctx_t;


static ngx_int_t ngx_http_sundew_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_sundew_init(ngx_conf_t *cf);
static void *ngx_http_sundew_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_sundew_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_sundew_blacklist(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_sundew_status(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_sundew_commands[] = {

    { ngx_string("ipset_blacklist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_sundew_blacklist,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ipset_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_sundew_status,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sundew_loc_conf_t, status),
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

    { ngx_string("sundew_lookup_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sundew_loc_conf_t, lookup_timeout),
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
        ctx->result = SW_RES_DRYRUN;
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "sundew: deny %V (%s, set %V)",
                  &r->connection->addr_text, why, name);

    ctx->result = SW_RES_DENY;

    return slcf->status;
}


static ngx_int_t
ngx_http_sundew_fail(ngx_http_request_t *r, ngx_http_sundew_loc_conf_t *slcf,
    ngx_http_sundew_ctx_t *ctx, ngx_uint_t result)
{
    static const char *why[] = { "ok", "helper error", "lookup timeout",
                                 "helper down", "busy" };

    if (slcf->fail_open) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "sundew: allow %V (fail open: %s)",
                      &r->connection->addr_text, why[result]);
        ctx->result = SW_RES_ALLOW;
        return NGX_DECLINED;
    }

    return ngx_http_sundew_deny(r, slcf, ctx, why[result]);
}


static ngx_int_t
ngx_http_sundew_verdict(ngx_http_request_t *r,
    ngx_http_sundew_loc_conf_t *slcf, ngx_http_sundew_ctx_t *ctx,
    uint64_t mask)
{
    uint64_t      hit;
    sw_waiter_t  *w;

    w = &ctx->waiter;

    if (w->result != SW_RESULT_OK) {
        return ngx_http_sundew_fail(r, slcf, ctx, w->result);
    }

    hit = w->matched & mask;

    if (hit) {
        ctx->matched_set = (ngx_int_t) __builtin_ctzll(hit);
        return ngx_http_sundew_deny(r, slcf, ctx, "blacklisted");
    }

    if ((w->decided & mask) != mask) {
        return ngx_http_sundew_fail(r, slcf, ctx, SW_RESULT_ERROR);
    }

    ctx->result = SW_RES_ALLOW;

    return NGX_DECLINED;
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
    uint64_t                     mask;
    ngx_uint_t                   family;
    ngx_pool_cleanup_t          *cln;
    ngx_http_sundew_ctx_t       *ctx;
    ngx_sundew_core_conf_t      *scf;
    ngx_http_sundew_loc_conf_t  *slcf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sundew_module);

    if (slcf->blacklist == 0) {
        return NGX_DECLINED;
    }

    scf = ngx_http_sundew_core_conf();

    if (ngx_http_sundew_client_addr(r, &family, addr) != NGX_OK) {
        return NGX_DECLINED;
    }

    mask = slcf->blacklist & (family == 4 ? scf->mask4 : scf->mask6);

    ctx = ngx_http_get_module_ctx(r, ngx_http_sundew_module);

    if (ctx) {
        switch (ctx->state) {

        case SW_STATE_PENDING:
            return NGX_AGAIN;

        case SW_STATE_DONE:
            r->write_event_handler = ngx_http_request_empty_handler;
            r->read_event_handler = ngx_http_block_reading;
            return ngx_http_sundew_verdict(r, slcf, ctx, mask);

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

    if (mask == 0) {
        ctx->state = SW_STATE_DONE;
        ctx->result = SW_RES_ALLOW;
        return NGX_DECLINED;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln->handler = ngx_http_sundew_cleanup;
    cln->data = ctx;

    if (sw_client_submit(&ctx->waiter, mask, family, addr,
                         slcf->lookup_timeout)
        != NGX_OK)
    {
        ctx->state = SW_STATE_DONE;
        return ngx_http_sundew_fail(r, slcf, ctx, ctx->waiter.result);
    }

    ctx->state = SW_STATE_PENDING;

    r->read_event_handler = ngx_http_test_reading;
    r->write_event_handler = ngx_http_request_empty_handler;

    return NGX_AGAIN;
}


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

    ngx_conf_merge_uint_value(conf->status, prev->status, NGX_HTTP_FORBIDDEN);
    ngx_conf_merge_value(conf->fail_open, prev->fail_open, 0);
    ngx_conf_merge_value(conf->dryrun, prev->dryrun, 0);
    ngx_conf_merge_msec_value(conf->lookup_timeout, prev->lookup_timeout, 100);

    return NGX_CONF_OK;
}


static char *
ngx_http_sundew_blacklist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sundew_loc_conf_t *slcf = conf;

    ngx_int_t   idx;
    ngx_str_t  *value;
    ngx_uint_t  i;

    if (slcf->blacklist_set) {
        return "is duplicate";
    }

    slcf->blacklist_set = 1;
    value = cf->args->elts;

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
        return NGX_CONF_OK;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        idx = ngx_sundew_add_set(cf, &value[i], SW_ROLE_LOOKUP);
        if (idx == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        slcf->blacklist |= (uint64_t) 1 << idx;
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
