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
#include "sw_ratelimit.h"


#define SW_STATE_NEW        0
#define SW_STATE_PENDING    1
#define SW_STATE_DONE       2

#define SW_RES_NONE         0
#define SW_RES_ALLOW        1
#define SW_RES_DENY         2
#define SW_RES_DRYRUN       3
#define SW_RES_RATELIMITED  4

#define SW_V_UNKNOWN        0
#define SW_V_ALLOW          1
#define SW_V_ALLOW_LISTED       2
#define SW_V_DENY_LISTED        3
#define SW_V_DENY_NOT_ALLOWED    4

#define SW_STALE_MS         (600 * 1000)
#define SW_FAMILY_RULES     4               /* sets per ipset_autoadd / autoban= */


typedef struct {
    uint64_t     deny;
    uint64_t     allow;
    ngx_uint_t   deny_set;
    ngx_uint_t   allow_set;
    ngx_uint_t   status;
    ngx_flag_t   fail_open;
    ngx_flag_t   dryrun;
    ngx_msec_t   lookup_timeout;
    time_t       cache_ttl;

    ngx_int_t                  autoadd;     /* rules configured: 1, none: -1 */
    ngx_int_t                  autoadd_rules[SW_FAMILY_RULES];
    ngx_uint_t                 autoadd_n;
    ngx_uint_t                 autoadd_status;
    ngx_http_complex_value_t  *autoadd_if;

    ngx_int_t                  rl_id;       /* -1 none */
    ngx_uint_t                 rl_rate;
    ngx_msec_t                 rl_window;
    ngx_int_t                  rl_rule;     /* autoban configured: 1, none: -1 */
    ngx_int_t                  rl_rules[SW_FAMILY_RULES];
    ngx_uint_t                 rl_n;
    ngx_uint_t                 rl_key6;
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
    ngx_int_t             rc;               /* final result, for re-entry */
    ngx_uint_t            family;
    u_char                addr[16];
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
static char *ngx_http_sundew_autoadd(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_sundew_ratelimit(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_sundew_writes(ngx_http_request_t *r,
    ngx_http_sundew_loc_conf_t *slcf, ngx_http_sundew_ctx_t *ctx);


static ngx_command_t  ngx_http_sundew_commands[] = {

    { ngx_string("ipset_denylist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_sundew_sets,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ipset_allowlist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_sundew_sets,
      NGX_HTTP_LOC_CONF_OFFSET,
      1,
      NULL },

    /* names used by ngx_http_ipset_access_module */

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

    { ngx_string("ipset_autoadd"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_sundew_autoadd,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ipset_ratelimit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_sundew_ratelimit,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
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
    ngx_string("dryrun"),
    ngx_string("ratelimited")
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
ngx_http_sundew_evaluate(uint64_t decided, uint64_t matched, uint64_t dmask,
    uint64_t amask, ngx_uint_t has_allow)
{
    if (has_allow) {
        if (matched & amask) {
            return SW_V_ALLOW_LISTED;
        }

        return ((decided & amask) == amask) ? SW_V_DENY_NOT_ALLOWED : SW_V_UNKNOWN;
    }

    if (matched & dmask) {
        return SW_V_DENY_LISTED;
    }

    return ((decided & dmask) == dmask) ? SW_V_ALLOW : SW_V_UNKNOWN;
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
    ngx_http_sundew_ctx_t *ctx, ngx_uint_t v, uint64_t dmask, uint64_t amask)
{
    uint64_t  hit;

    ctx->state = SW_STATE_DONE;

    switch (v) {

    case SW_V_DENY_LISTED:
        hit = ctx->matched & dmask;
        ctx->matched_set = (ngx_int_t) __builtin_ctzll(hit);
        sw_stats_set_matched(ctx->matched_set);
        return ngx_http_sundew_deny(r, slcf, ctx, "in denylist");

    case SW_V_DENY_NOT_ALLOWED:
        return ngx_http_sundew_deny(r, slcf, ctx, "not in allowlist");

    case SW_V_ALLOW_LISTED:
        hit = ctx->matched & amask;
        ctx->matched_set = (ngx_int_t) __builtin_ctzll(hit);
        sw_stats_set_matched(ctx->matched_set);
        sw_stats_inc(SW_STAT_ALLOWED);
        ctx->result = SW_RES_ALLOW;
        return NGX_DECLINED;

    default:
        ctx->result = SW_RES_ALLOW;
        return ngx_http_sundew_writes(r, slcf, ctx);
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
    ngx_http_sundew_ctx_t *ctx, uint64_t dmask, uint64_t amask)
{
    ngx_uint_t    v, has_allow, result;
    sw_waiter_t  *w;

    w = &ctx->waiter;
    has_allow = (slcf->allow != 0);
    result = w->result;

    if (result == SW_RESULT_OK) {
        ctx->decided |= w->decided & ctx->asked;
        ctx->matched |= w->matched & w->decided & ctx->asked;
    }

    v = ngx_http_sundew_evaluate(ctx->decided, ctx->matched, dmask, amask, has_allow);

    if (v != SW_V_UNKNOWN) {
        return ngx_http_sundew_apply(r, slcf, ctx, v, dmask, amask);
    }

    if (ctx->stale_in) {
        ctx->decided |= ctx->stale_in;
        ctx->matched |= ctx->stale_in;

        v = ngx_http_sundew_evaluate(ctx->decided, ctx->matched, dmask, amask,
                                     has_allow);

        if (v != SW_V_UNKNOWN) {
            sw_stats_inc(SW_STAT_STALE_SERVED);
            return ngx_http_sundew_apply(r, slcf, ctx, v, dmask, amask);
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


/* why an autoadd must not add this request's address, or NULL */

static const char *
ngx_http_sundew_skip_add(ngx_http_request_t *r,
    ngx_http_sundew_loc_conf_t *slcf)
{
    ngx_str_t         v;
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    if (slcf->dryrun) {
        return "dry run";
    }

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len > 10
            && ngx_strncasecmp(h[i].key.data, (u_char *) "sec-fetch-", 10)
               == 0)
        {
            return "browser request (Sec-Fetch-*)";
        }

        if (((h[i].key.len == 11
              && ngx_strncasecmp(h[i].key.data, (u_char *) "sec-purpose", 11)
                 == 0)
             || (h[i].key.len == 7
                 && ngx_strncasecmp(h[i].key.data, (u_char *) "purpose", 7)
                    == 0))
            && (ngx_strlcasestrn(h[i].value.data,
                                 h[i].value.data + h[i].value.len,
                                 (u_char *) "prefetch", 8 - 1) != NULL
                || ngx_strlcasestrn(h[i].value.data,
                                    h[i].value.data + h[i].value.len,
                                    (u_char *) "prerender", 9 - 1) != NULL))
        {
            return "prefetch";
        }
    }

#if (NGX_HTTP_SSL)
    if (r->connection->ssl
        && ngx_ssl_get_early_data(r->connection, r->pool, &v) == NGX_OK
        && v.len)
    {
        return "TLS early data";
    }
#endif

    if (slcf->autoadd_if) {
        if (ngx_http_complex_value(r, slcf->autoadd_if, &v) != NGX_OK) {
            return "if= failed";
        }

        if (v.len == 0 || (v.len == 1 && v.data[0] == '0')) {
            return "if= is empty or 0";
        }
    }

    return NULL;
}


static ngx_uint_t
ngx_http_sundew_cross_site(ngx_http_request_t *r)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                return 0;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == 14
            && ngx_strncasecmp(h[i].key.data, (u_char *) "sec-fetch-site", 14)
               == 0
            && h[i].value.len == 10
            && ngx_strncasecmp(h[i].value.data, (u_char *) "cross-site", 10)
               == 0)
        {
            return 1;
        }
    }
}


/* the rule whose set has the client's family, or -1 */

static ngx_int_t
ngx_http_sundew_pick_rule(ngx_int_t *rules, ngx_uint_t n, ngx_uint_t family)
{
    ngx_uint_t               i, want;
    ngx_sundew_set_t        *set;
    ngx_sundew_rule_t       *rule;
    ngx_sundew_core_conf_t  *scf;

    scf = ngx_http_sundew_core_conf();
    set = scf->sets.elts;
    rule = scf->rules.elts;
    want = (family == 6) ? AF_INET6 : AF_INET;

    for (i = 0; i < n; i++) {
        if (set[rule[rules[i]].set].family == want) {
            return rules[i];
        }
    }

    return -1;
}


/* rate limit and autoadd, for requests the lists let through */

static ngx_int_t
ngx_http_sundew_writes(ngx_http_request_t *r,
    ngx_http_sundew_loc_conf_t *slcf, ngx_http_sundew_ctx_t *ctx)
{
    u_char                   key[16];
    ngx_int_t                pick;
    ngx_str_t               *name;
    ngx_uint_t               rc, i, bits, level;
    const char              *skip;
    ngx_sundew_set_t        *set;
    ngx_sundew_rule_t       *rule;
    ngx_sundew_core_conf_t  *scf;

    scf = ngx_http_sundew_core_conf();
    set = scf->sets.elts;
    rule = scf->rules.elts;

    if (slcf->rl_id >= 0 && scf->ratelimit_zone
        && scf->ratelimit_zone->data)
    {
        sw_cache_addr(key, ctx->family, ctx->addr);

        if (ctx->family == 6) {
            for (i = 0; i < 16; i++) {
                bits = (slcf->rl_key6 > i * 8) ? slcf->rl_key6 - i * 8 : 0;
                key[i] &= (bits >= 8) ? 0xff : (u_char) (0xff << (8 - bits));
            }
        }

        rc = sw_rl_hit(scf->ratelimit_zone, slcf->rl_id, key, slcf->rl_rate,
                       slcf->rl_window);

        if (rc != SW_RL_OK) {
            sw_stats_inc(SW_STAT_RATELIMITED);

            if (slcf->dryrun) {
                ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                              "sundew: dryrun, would rate-limit %V",
                              &r->connection->addr_text);
                ctx->result = SW_RES_DRYRUN;

            } else {
                pick = (slcf->rl_rule >= 0)
                       ? ngx_http_sundew_pick_rule(slcf->rl_rules, slcf->rl_n,
                                                   ctx->family)
                       : -1;

                if (rc == SW_RL_FIRST && slcf->rl_rule >= 0 && pick < 0) {
                    sw_stats_inc(SW_STAT_ADDS_SKIPPED);
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                  "sundew: not banning %V: no autoban= set "
                                  "for its address family",
                                  &r->connection->addr_text);

                } else if (rc == SW_RL_FIRST && pick >= 0) {
                    name = &set[rule[pick].set].name;

                    if (ngx_http_sundew_cross_site(r)) {
                        sw_stats_inc(SW_STAT_ADDS_SKIPPED);
                        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                      "sundew: not banning %V: cross-site "
                                      "request", &r->connection->addr_text);

                    } else {
                        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                                      "sundew: banning %V in set \"%V\" "
                                      "for %uis (rate limit)",
                                      &r->connection->addr_text, name,
                                      rule[pick].timeout);
                        sw_client_add(pick, ctx->family, ctx->addr);
                    }
                }

                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "sundew: rate-limited %V",
                              &r->connection->addr_text);
                ctx->result = SW_RES_RATELIMITED;

                return NGX_HTTP_TOO_MANY_REQUESTS;
            }
        }
    }

    if (slcf->autoadd >= 0) {
        sw_stats_inc(SW_STAT_TRAPPED);

        pick = ngx_http_sundew_pick_rule(slcf->autoadd_rules, slcf->autoadd_n,
                                         ctx->family);
        skip = ngx_http_sundew_skip_add(r, slcf);

        if (pick < 0) {
            sw_stats_inc(SW_STAT_ADDS_SKIPPED);
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "sundew: no ipset_autoadd set for the address "
                          "family of %V", &r->connection->addr_text);

        } else if (skip) {
            sw_stats_inc(SW_STAT_ADDS_SKIPPED);
            level = slcf->dryrun ? NGX_LOG_NOTICE : NGX_LOG_INFO;
            ngx_log_error(level, r->connection->log, 0,
                          "sundew: %s, not adding %V to set \"%V\"",
                          skip, &r->connection->addr_text,
                          &set[rule[pick].set].name);

        } else {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                          "sundew: adding %V to set \"%V\" for %uis",
                          &r->connection->addr_text,
                          &set[rule[pick].set].name, rule[pick].timeout);
            sw_client_add(pick, ctx->family, ctx->addr);
        }

        if (slcf->dryrun) {
            ctx->result = SW_RES_DRYRUN;
            return NGX_DECLINED;
        }

        ctx->result = SW_RES_DENY;
        ctx->matched_set = (pick >= 0) ? (ngx_int_t) rule[pick].set : -1;
        r->keepalive = 0;

        return slcf->autoadd_status;
    }

    sw_stats_inc(SW_STAT_ALLOWED);

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
    uint64_t                     famask, dmask, amask, need, ask;
    ngx_uint_t                   family, v, has_allow;
    ngx_pool_cleanup_t          *cln;
    ngx_http_sundew_ctx_t       *ctx;
    ngx_sundew_core_conf_t      *scf;
    ngx_http_sundew_loc_conf_t  *slcf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sundew_module);

    if (slcf->deny == 0 && slcf->allow == 0 && slcf->autoadd < 0
        && slcf->rl_id < 0)
    {
        return NGX_DECLINED;
    }

    if (ngx_http_sundew_client_addr(r, &family, addr) != NGX_OK) {
        return NGX_DECLINED;
    }

    scf = ngx_http_sundew_core_conf();
    famask = (family == 4) ? scf->mask4 : scf->mask6;
    dmask = slcf->deny & famask;
    amask = slcf->allow & famask;
    has_allow = (slcf->allow != 0);

    ctx = ngx_http_get_module_ctx(r, ngx_http_sundew_module);

    if (ctx) {
        switch (ctx->state) {

        case SW_STATE_PENDING:
            return NGX_AGAIN;

        case SW_STATE_DONE:
            if (ctx->result != SW_RES_NONE) {
                return ctx->rc;
            }

            r->write_event_handler = ngx_http_request_empty_handler;
            r->read_event_handler = ngx_http_block_reading;
            ctx->rc = ngx_http_sundew_finish(r, slcf, ctx, dmask, amask);
            return ctx->rc;

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
    ctx->family = family;
    ngx_memcpy(ctx->addr, addr, 16);

    ngx_http_set_ctx(r, ctx, ngx_http_sundew_module);

    sw_stats_inc(SW_STAT_CHECKED);

    if (slcf->deny == 0 && slcf->allow == 0) {
        ctx->state = SW_STATE_DONE;
        ctx->result = SW_RES_ALLOW;
        ctx->rc = ngx_http_sundew_writes(r, slcf, ctx);
        return ctx->rc;
    }

    need = has_allow ? amask : dmask;

    ngx_http_sundew_cache_lookup(slcf, ctx, need, family, addr);

    v = ngx_http_sundew_evaluate(ctx->decided, ctx->matched, dmask, amask, has_allow);

    if (v != SW_V_UNKNOWN) {
        if (need) {
            sw_stats_inc(SW_STAT_CACHE_HIT);
        }

        ctx->rc = ngx_http_sundew_apply(r, slcf, ctx, v, dmask, amask);
        return ctx->rc;
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
        ctx->rc = ngx_http_sundew_finish(r, slcf, ctx, dmask, amask);
        return ctx->rc;
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

    len = 512 + SW_STAT_N * 256 + SW_STATS_SETS * (SW_SETREF_LEN + 96);

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
            p = ngx_sprintf(p, "# HELP sundew_%s_total %s\n"
                               "# TYPE sundew_%s_total counter\n"
                               "sundew_%s_total %uA\n",
                            sw_stat_names[i], sw_stat_help[i],
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
    conf->autoadd = NGX_CONF_UNSET;
    conf->rl_id = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_sundew_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_sundew_loc_conf_t *prev = parent;
    ngx_http_sundew_loc_conf_t *conf = child;

    if (!conf->deny_set) {
        conf->deny = prev->deny;
        conf->deny_set = prev->deny_set;
    }

    if (!conf->allow_set) {
        conf->allow = prev->allow;
        conf->allow_set = prev->allow_set;
    }

    ngx_conf_merge_uint_value(conf->status, prev->status, NGX_HTTP_FORBIDDEN);
    ngx_conf_merge_value(conf->fail_open, prev->fail_open, 0);
    ngx_conf_merge_value(conf->dryrun, prev->dryrun, 0);
    ngx_conf_merge_msec_value(conf->lookup_timeout, prev->lookup_timeout, 100);
    ngx_conf_merge_sec_value(conf->cache_ttl, prev->cache_ttl, 60);

    if (conf->autoadd == NGX_CONF_UNSET) {
        conf->autoadd = (prev->autoadd == NGX_CONF_UNSET) ? -1 : prev->autoadd;
        ngx_memcpy(conf->autoadd_rules, prev->autoadd_rules,
                   sizeof(conf->autoadd_rules));
        conf->autoadd_n = prev->autoadd_n;
        conf->autoadd_status = prev->autoadd_status;
        conf->autoadd_if = prev->autoadd_if;
    }

    if (conf->rl_id == NGX_CONF_UNSET) {
        conf->rl_id = (prev->rl_id == NGX_CONF_UNSET) ? -1 : prev->rl_id;
        conf->rl_rate = prev->rl_rate;
        conf->rl_window = prev->rl_window;
        conf->rl_rule = prev->rl_rule;
        ngx_memcpy(conf->rl_rules, prev->rl_rules, sizeof(conf->rl_rules));
        conf->rl_n = prev->rl_n;
        conf->rl_key6 = prev->rl_key6;
    }

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
        mask = &slcf->allow;
        seen = &slcf->allow_set;

    } else {
        mask = &slcf->deny;
        seen = &slcf->deny_set;
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
        idx = ngx_sundew_add_set(cf, &value[i],
                                 SW_ROLE_LOOKUP
                                 | (cmd->offset ? NGX_SUNDEW_ALLOWLIST : 0));
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
ngx_http_sundew_parse_status(ngx_conf_t *cf, ngx_str_t *v, ngx_uint_t *status)
{
    ngx_int_t  n;

    n = ngx_atoi(v->data, v->len);

    if (n != NGX_HTTP_CLOSE && (n < 400 || n > 599)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid status \"%V\": use 4xx, 5xx or 444", v);
        return NGX_ERROR;
    }

    *status = n;

    return NGX_OK;
}


static ngx_int_t
ngx_http_sundew_parse_timeout(ngx_conf_t *cf, ngx_str_t *v, ngx_uint_t *t)
{
    time_t  s;

    s = ngx_parse_time(v, 1);

    if (s == (time_t) NGX_ERROR || s < 1 || s > SW_MAX_TIMEOUT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid time \"%V\": use 1s to 24d", v);
        return NGX_ERROR;
    }

    *t = (ngx_uint_t) s;

    return NGX_OK;
}


static char *
ngx_http_sundew_autoadd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sundew_loc_conf_t *slcf = conf;

    ngx_int_t                          n, rule;
    ngx_str_t                         *value, v, sets[SW_FAMILY_RULES];
    ngx_uint_t                         i, nsets, timeout, prefix4, prefix6;
    ngx_http_compile_complex_value_t   ccv;

    if (slcf->autoadd != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
        slcf->autoadd = -1;
        return NGX_CONF_OK;
    }

    timeout = 0;
    prefix4 = 32;
    prefix6 = 128;
    nsets = 0;
    slcf->autoadd_status = NGX_HTTP_NOT_FOUND;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strlchr(value[i].data, value[i].data + value[i].len, '=')
            == NULL)
        {
            if (nsets == SW_FAMILY_RULES) {
                return "has too many sets";
            }

            sets[nsets++] = value[i];
            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            v.data = value[i].data + 8;
            v.len = value[i].len - 8;

            if (ngx_http_sundew_parse_timeout(cf, &v, &timeout) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "status=", 7) == 0) {
            v.data = value[i].data + 7;
            v.len = value[i].len - 7;

            if (ngx_http_sundew_parse_status(cf, &v, &slcf->autoadd_status)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "prefix4=", 8) == 0
            || ngx_strncmp(value[i].data, "prefix6=", 8) == 0)
        {
            n = ngx_atoi(value[i].data + 8, value[i].len - 8);

            if (value[i].data[6] == '4') {
                if (n < 1 || n > 32) {
                    return "has an invalid prefix4=, use 1-32";
                }

                prefix4 = n;

            } else {
                if (n < 1 || n > 128) {
                    return "has an invalid prefix6=, use 1-128";
                }

                prefix6 = n;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "if=", 3) == 0) {
            v.data = value[i].data + 3;
            v.len = value[i].len - 3;

            slcf->autoadd_if = ngx_palloc(cf->pool,
                                          sizeof(ngx_http_complex_value_t));
            if (slcf->autoadd_if == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
            ccv.cf = cf;
            ccv.value = &v;
            ccv.complex_value = slcf->autoadd_if;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (nsets == 0) {
        return "needs a set";
    }

    for (i = 0; i < nsets; i++) {
        rule = ngx_sundew_add_rule(cf, &sets[i], prefix4, prefix6, timeout);
        if (rule == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        slcf->autoadd_rules[i] = rule;
    }

    slcf->autoadd_n = nsets;
    slcf->autoadd = 1;

    return NGX_CONF_OK;
}


static char *
ngx_http_sundew_ratelimit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sundew_loc_conf_t *slcf = conf;

    u_char            *p, *last, *comma;
    ngx_int_t          n, rule;
    ngx_str_t         *value, v, set, one;
    ngx_uint_t         i, ban_time;
    ngx_msec_t         ms;
    static ngx_uint_t  next_id;

    if (slcf->rl_id != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
        slcf->rl_id = -1;
        return NGX_CONF_OK;
    }

    slcf->rl_rate = 0;
    slcf->rl_window = 60000;
    slcf->rl_key6 = 64;
    slcf->rl_rule = -1;
    ban_time = 3600;
    ngx_str_null(&set);

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "rate=", 5) == 0) {
            n = ngx_atoi(value[i].data + 5, value[i].len - 5);
            if (n < 1 || n > 65535) {
                return "has an invalid rate=, use 1-65535";
            }

            slcf->rl_rate = n;
            continue;
        }

        if (ngx_strncmp(value[i].data, "window=", 7) == 0) {
            v.data = value[i].data + 7;
            v.len = value[i].len - 7;

            ms = ngx_parse_time(&v, 0);
            if (ms == (ngx_msec_t) NGX_ERROR || ms < 1000 || ms > 86400000) {
                return "has an invalid window=, use 1s to 1d";
            }

            slcf->rl_window = ms;
            continue;
        }

        if (ngx_strncmp(value[i].data, "autoban=", 8) == 0) {
            set.data = value[i].data + 8;
            set.len = value[i].len - 8;
            continue;
        }

        if (ngx_strncmp(value[i].data, "ban_time=", 9) == 0) {
            v.data = value[i].data + 9;
            v.len = value[i].len - 9;

            if (ngx_http_sundew_parse_timeout(cf, &v, &ban_time) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "key6=", 5) == 0) {
            n = ngx_atoi(value[i].data + 5, value[i].len - 5);
            if (n < 1 || n > 128) {
                return "has an invalid key6=, use 1-128";
            }

            slcf->rl_key6 = n;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (slcf->rl_rate == 0) {
        return "needs rate=";
    }

    slcf->rl_n = 0;

    for (p = set.data, last = set.data + set.len; p < last; p = comma + 1) {
        comma = ngx_strlchr(p, last, ',');
        if (comma == NULL) {
            comma = last;
        }

        one.data = p;
        one.len = comma - p;

        if (slcf->rl_n == SW_FAMILY_RULES) {
            return "has too many autoban= sets";
        }

        rule = ngx_sundew_add_rule(cf, &one, 32, 128, ban_time);
        if (rule == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        slcf->rl_rules[slcf->rl_n++] = rule;
        slcf->rl_rule = 1;
    }

    if (ngx_sundew_ratelimit_zone(cf) == NULL) {
        return NGX_CONF_ERROR;
    }

    slcf->rl_id = next_id++;

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
