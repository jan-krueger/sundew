/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <libgen.h>
#include <poll.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "ngx_sundew.h"
#include "sw_cache.h"
#include "sw_client.h"
#include "sw_stats.h"
#include "sw_ratelimit.h"


#ifndef SYS_pidfd_open
#define SYS_pidfd_open          434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal   424
#endif
#ifndef SYS_close_range
#define SYS_close_range         436
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH           0x1000
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING       0x0002U
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS             1033
#define F_SEAL_SEAL             0x0001
#define F_SEAL_SHRINK           0x0002
#define F_SEAL_GROW             0x0004
#define F_SEAL_WRITE            0x0008
#endif

#define SW_MAX_HELPERS          64
#define SW_HELPER_NAME          "sundew-helper"


typedef struct {
    pid_t       pid;
    int         pidfd;
    int         ctl;
    ngx_uint_t  generation;
    time_t      deadline;
} ngx_sundew_helper_t;


static void *ngx_sundew_core_create_conf(ngx_cycle_t *cycle);
static char *ngx_sundew_core_init_conf(ngx_cycle_t *cycle, void *conf);
static ngx_int_t ngx_sundew_core_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_sundew_core_init_process(ngx_cycle_t *cycle);
static void ngx_sundew_core_exit_master(ngx_cycle_t *cycle);

static ngx_int_t ngx_sundew_check_binary(ngx_cycle_t *cycle, ngx_str_t *path,
    int *hfd);
static ngx_int_t ngx_sundew_spawn(ngx_cycle_t *cycle,
    ngx_sundew_core_conf_t *scf, ngx_core_conf_t *ccf);
static ngx_int_t ngx_sundew_handshake(ngx_cycle_t *cycle,
    ngx_sundew_core_conf_t *scf, int ctl);
static void ngx_sundew_reap(ngx_cycle_t *cycle);
static void ngx_sundew_drain(ngx_cycle_t *cycle, ngx_sundew_helper_t *h,
    uint32_t deadline_s);
static void ngx_sundew_kill(ngx_sundew_helper_t *h);
static void ngx_sundew_close_slots(void *data);
static ngx_int_t ngx_sundew_verify_no_caps(ngx_cycle_t *cycle);
static char *ngx_sundew_protect(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_sundew_writable_sets(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_sundew_build_protect(ngx_cycle_t *cycle,
    ngx_sundew_core_conf_t *scf);
static ngx_int_t ngx_sundew_check_writes(ngx_cycle_t *cycle,
    ngx_sundew_core_conf_t *scf);


static ngx_sundew_helper_t  ngx_sundew_helpers[SW_MAX_HELPERS];
static ngx_uint_t           ngx_sundew_nhelpers;
static ngx_uint_t           ngx_sundew_generation;

static ngx_str_t  sw_cache_zone_name = ngx_string("sundew_cache");
static ngx_str_t  sw_stats_zone_name = ngx_string("sundew_stats");
static ngx_str_t  sw_rl_zone_name = ngx_string("sundew_ratelimit");


static ngx_command_t  ngx_sundew_core_commands[] = {

    { ngx_string("sundew_helper_path"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_sundew_core_conf_t, helper_path),
      NULL },

    { ngx_string("sundew_helper_user"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_sundew_core_conf_t, helper_user),
      NULL },

    { ngx_string("sundew_handshake_timeout"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_sundew_core_conf_t, handshake_timeout),
      NULL },

    { ngx_string("sundew_helper_drain_timeout"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      0,
      offsetof(ngx_sundew_core_conf_t, drain_timeout),
      NULL },

    { ngx_string("sundew_protect"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_1MORE,
      ngx_sundew_protect,
      0,
      0,
      NULL },

    { ngx_string("sundew_writable_sets"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_1MORE,
      ngx_sundew_writable_sets,
      0,
      0,
      NULL },

    { ngx_string("sundew_ratelimit_zone_size"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      0,
      offsetof(ngx_sundew_core_conf_t, ratelimit_size),
      NULL },

    { ngx_string("sundew_cache_size"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      0,
      offsetof(ngx_sundew_core_conf_t, cache_size),
      NULL },

#if (NGX_DEBUG)
    { ngx_string("sundew_debug_delay"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_sundew_core_conf_t, debug_delay),
      NULL },
#endif

      ngx_null_command
};


static ngx_core_module_t  ngx_sundew_core_module_ctx = {
    ngx_string("sundew"),
    ngx_sundew_core_create_conf,
    ngx_sundew_core_init_conf
};


ngx_module_t  ngx_sundew_core_module = {
    NGX_MODULE_V1,
    &ngx_sundew_core_module_ctx,           /* module context */
    ngx_sundew_core_commands,              /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_sundew_core_init_module,           /* init module */
    ngx_sundew_core_init_process,          /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    ngx_sundew_core_exit_master,           /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_sundew_core_create_conf(ngx_cycle_t *cycle)
{
    ngx_sundew_core_conf_t  *scf;

    scf = ngx_pcalloc(cycle->pool, sizeof(ngx_sundew_core_conf_t));
    if (scf == NULL) {
        return NULL;
    }

    scf->handshake_timeout = NGX_CONF_UNSET_MSEC;
    scf->drain_timeout = NGX_CONF_UNSET;
    scf->debug_delay = NGX_CONF_UNSET_MSEC;
    scf->cache_size = NGX_CONF_UNSET_SIZE;
    scf->ratelimit_size = NGX_CONF_UNSET_SIZE;
    scf->writable = NGX_CONF_UNSET_PTR;

    if (ngx_array_init(&scf->sets, cycle->pool, 4, sizeof(ngx_sundew_set_t))
        != NGX_OK
        || ngx_array_init(&scf->rules, cycle->pool, 4,
                          sizeof(ngx_sundew_rule_t))
           != NGX_OK
        || ngx_array_init(&scf->protect, cycle->pool, 4,
                          sizeof(ngx_sundew_cidr_t))
           != NGX_OK
        || ngx_array_init(&scf->unprotect, cycle->pool, 4,
                          sizeof(ngx_sundew_cidr_t))
           != NGX_OK
        || ngx_array_init(&scf->policy_protect, cycle->pool, 32,
                          sizeof(ngx_sundew_cidr_t))
           != NGX_OK)
    {
        return NULL;
    }

    return scf;
}


static ngx_int_t
ngx_sundew_valid_name(ngx_str_t *s, size_t max, const char *extra)
{
    u_char  *p;

    if (s->len == 0 || s->len >= max) {
        return 0;
    }

    for (p = s->data; p < s->data + s->len; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
              || (*p >= '0' && *p <= '9')
              || *p == '_' || *p == '.' || *p == '-'
              || (*p != '\0' && ngx_strchr(extra, *p) != NULL)))
        {
            return 0;
        }
    }

    return 1;
}


/* "nft:family/table/set"; the set name may contain "/" */
static ngx_int_t
ngx_sundew_parse_nft(ngx_str_t *ref, ngx_uint_t *family, ngx_str_t *table,
    ngx_str_t *set)
{
    u_char     *p, *last, *slash;
    ngx_str_t   fam;

    p = ref->data + 4;
    last = ref->data + ref->len;

    slash = ngx_strlchr(p, last, '/');
    if (slash == NULL) {
        return NGX_ERROR;
    }

    fam.data = p;
    fam.len = slash - p;
    p = slash + 1;

    slash = ngx_strlchr(p, last, '/');
    if (slash == NULL) {
        return NGX_ERROR;
    }

    table->data = p;
    table->len = slash - p;
    set->data = slash + 1;
    set->len = last - set->data;

    if (fam.len == 4 && ngx_strncmp(fam.data, "inet", 4) == 0) {
        *family = SW_NFPROTO_INET;

    } else if (fam.len == 2 && ngx_strncmp(fam.data, "ip", 2) == 0) {
        *family = SW_NFPROTO_IPV4;

    } else if (fam.len == 3 && ngx_strncmp(fam.data, "ip6", 3) == 0) {
        *family = SW_NFPROTO_IPV6;

    } else {
        return NGX_ERROR;
    }

    if (!ngx_sundew_valid_name(table, SW_NFT_NAMELEN, "")
        || !ngx_sundew_valid_name(set, SW_NFT_NAMELEN, "/"))
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_sundew_add_set(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t role)
{
    ngx_str_t                table, kname;
    ngx_uint_t               i, backend, family;
    ngx_sundew_set_t        *set;
    ngx_sundew_core_conf_t  *scf;

    scf = (ngx_sundew_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                  ngx_sundew_core_module);

    ngx_str_null(&table);
    family = 0;

    if (name->len > 4 && ngx_strncmp(name->data, "nft:", 4) == 0) {
        backend = SW_BACKEND_NFT;

        if (ngx_sundew_parse_nft(name, &family, &table, &kname) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid nftables set \"%V\": expected "
                               "\"nft:FAMILY/TABLE/SET\" with FAMILY ip, ip6 "
                               "or inet, and TABLE and SET 1-%d characters "
                               "of letters, digits, \"_\", \".\" and \"-\"",
                               name, SW_NFT_NAMELEN - 1);
            return NGX_ERROR;
        }

    } else {
        backend = SW_BACKEND_IPSET;
        kname = *name;

        if (name->len == 0 || name->len >= SW_SETNAME_LEN) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid set name \"%V\": must be 1-%d "
                               "characters", name, SW_SETNAME_LEN - 1);
            return NGX_ERROR;
        }

        if (!ngx_sundew_valid_name(name, SW_SETNAME_LEN, ":")) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid character in set name \"%V\"", name);
            return NGX_ERROR;
        }
    }

    set = scf->sets.elts;
    for (i = 0; i < scf->sets.nelts; i++) {
        if (set[i].name.len == name->len
            && ngx_strncmp(set[i].name.data, name->data, name->len) == 0)
        {
            set[i].role |= role;

            if ((role & SW_ROLE_ADD) && set[i].file.len == 0) {
                set[i].file = cf->conf_file->file.name;
                set[i].line = cf->conf_file->line;
            }

            return i;
        }
    }

    if (scf->cache_zone == NULL) {
        scf->cache_zone = ngx_shared_memory_add(cf, &sw_cache_zone_name, 0,
                                                &ngx_sundew_core_module);
        scf->stats_zone = ngx_shared_memory_add(cf, &sw_stats_zone_name,
                                                SW_STATS_ZONE_SIZE,
                                                &ngx_sundew_core_module);

        if (scf->cache_zone == NULL || scf->stats_zone == NULL) {
            return NGX_ERROR;
        }

        scf->cache_zone->init = sw_cache_zone_init;
        scf->cache_zone->data = scf;
        scf->stats_zone->init = sw_stats_zone_init;
        scf->stats_zone->data = scf;
    }

    if (scf->sets.nelts >= SW_MAX_SETS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "too many sets (max %d)", SW_MAX_SETS);
        return NGX_ERROR;
    }

    set = ngx_array_push(&scf->sets);
    if (set == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(set, sizeof(ngx_sundew_set_t));
    set->name = *name;
    set->role = role;
    set->backend = backend;
    set->nft_family = family;
    set->table = table;
    set->set = kname;

    if (role & SW_ROLE_ADD) {
        set->file = cf->conf_file->file.name;
        set->line = cf->conf_file->line;
    }

    return scf->sets.nelts - 1;
}


ngx_int_t
ngx_sundew_add_rule(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t prefix4,
    ngx_uint_t prefix6, ngx_uint_t timeout)
{
    ngx_int_t                idx;
    ngx_uint_t               i;
    ngx_sundew_rule_t       *rule;
    ngx_sundew_core_conf_t  *scf;

    idx = ngx_sundew_add_set(cf, name, SW_ROLE_ADD);
    if (idx == NGX_ERROR) {
        return NGX_ERROR;
    }

    scf = (ngx_sundew_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                  ngx_sundew_core_module);
    rule = scf->rules.elts;

    for (i = 0; i < scf->rules.nelts; i++) {
        if (rule[i].set == (ngx_uint_t) idx && rule[i].prefix4 == prefix4
            && rule[i].prefix6 == prefix6 && rule[i].timeout == timeout)
        {
            return i;
        }
    }

    if (scf->rules.nelts >= SW_MAX_RULES) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "too many different add rules (max %d)",
                           SW_MAX_RULES);
        return NGX_ERROR;
    }

    rule = ngx_array_push(&scf->rules);
    if (rule == NULL) {
        return NGX_ERROR;
    }

    rule->set = idx;
    rule->prefix4 = prefix4;
    rule->prefix6 = prefix6;
    rule->timeout = timeout;
    rule->rate = 20;
    rule->burst = 100;

    return scf->rules.nelts - 1;
}


ngx_shm_zone_t *
ngx_sundew_ratelimit_zone(ngx_conf_t *cf)
{
    ngx_sundew_core_conf_t  *scf;

    scf = (ngx_sundew_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                  ngx_sundew_core_module);

    if (scf->ratelimit_zone == NULL) {
        scf->ratelimit_zone = ngx_shared_memory_add(cf, &sw_rl_zone_name, 0,
                                                    &ngx_sundew_core_module);
        if (scf->ratelimit_zone == NULL) {
            return NULL;
        }

        scf->ratelimit_zone->init = sw_rl_zone_init;
    }

    return scf->ratelimit_zone;
}


static ngx_int_t
ngx_sundew_parse_cidr(ngx_str_t *s, ngx_sundew_cidr_t *c)
{
    ngx_int_t   rc;
    ngx_uint_t  i, n;
    ngx_cidr_t  cidr;
    u_char     *m;

    rc = ngx_ptocidr(s, &cidr);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_memzero(c, sizeof(ngx_sundew_cidr_t));

    switch (cidr.family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        c->family = 6;
        ngx_memcpy(c->addr, cidr.u.in6.addr.s6_addr, 16);
        m = cidr.u.in6.mask.s6_addr;
        n = 16;
        break;
#endif

    case AF_INET:
        c->family = 4;
        ngx_memcpy(c->addr, &cidr.u.in.addr, 4);
        m = (u_char *) &cidr.u.in.mask;
        n = 4;
        break;

    default:
        return NGX_ERROR;
    }

    for (i = 0; i < n; i++) {
        c->prefix += __builtin_popcount(m[i]);
    }

    return NGX_OK;
}


static char *
ngx_sundew_protect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sundew_core_conf_t *scf = conf;

    ngx_str_t          *value, s;
    ngx_uint_t          i;
    ngx_sundew_cidr_t  *c;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        s = value[i];

        if (s.len && s.data[0] == '!') {
            s.data++;
            s.len--;
            c = ngx_array_push(&scf->unprotect);

        } else {
            c = ngx_array_push(&scf->protect);
        }

        if (c == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_sundew_parse_cidr(&s, c) != NGX_OK) {
            return "has an invalid address or prefix";
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_sundew_writable_sets(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sundew_core_conf_t *scf = conf;

    ngx_str_t   *value, *s;
    ngx_uint_t   i;

    if (scf->writable == NGX_CONF_UNSET_PTR) {
        scf->writable = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (scf->writable == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        s = ngx_array_push(scf->writable);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }

        *s = value[i];
    }

    return NGX_CONF_OK;
}


static const char  *ngx_sundew_default_protect[] = {
    "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
    "240.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "100.64.0.0/10",
    "::/128", "::1/128", "fe80::/10", "ff00::/8", "fc00::/7",
    "::ffff:0:0/96",
    NULL
};


static ngx_int_t
ngx_sundew_build_protect(ngx_cycle_t *cycle, ngx_sundew_core_conf_t *scf)
{
    ngx_str_t           s;
    ngx_uint_t          i, j, removed;
    ngx_sundew_cidr_t   c, *out, *un, *add;

    un = scf->unprotect.elts;
    add = scf->protect.elts;
    scf->policy_protect.nelts = 0;

    for (i = 0; ngx_sundew_default_protect[i]; i++) {
        s.data = (u_char *) ngx_sundew_default_protect[i];
        s.len = ngx_strlen(ngx_sundew_default_protect[i]);

        if (ngx_sundew_parse_cidr(&s, &c) != NGX_OK) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "sundew: bad built-in protected prefix \"%V\"", &s);
            return NGX_ERROR;
        }

        removed = 0;

        for (j = 0; j < scf->unprotect.nelts; j++) {
            if (un[j].family == c.family && un[j].prefix == c.prefix
                && ngx_memcmp(un[j].addr, c.addr, 16) == 0)
            {
                removed = 1;
            }
        }

        if (removed) {
            continue;
        }

        out = ngx_array_push(&scf->policy_protect);
        if (out == NULL) {
            return NGX_ERROR;
        }

        *out = c;
    }

    for (i = 0; i < scf->protect.nelts; i++) {
        out = ngx_array_push(&scf->policy_protect);
        if (out == NULL) {
            return NGX_ERROR;
        }

        *out = add[i];
    }

    if (scf->policy_protect.nelts > SW_MAX_PROTECT) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: too many sundew_protect entries (max %d)",
                      SW_MAX_PROTECT);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_sundew_check_writes(ngx_cycle_t *cycle, ngx_sundew_core_conf_t *scf)
{
    ngx_str_t         *w;
    ngx_uint_t         i, j, found;
    ngx_sundew_set_t  *set;

    set = scf->sets.elts;

    for (i = 0; i < scf->sets.nelts; i++) {
        if (!(set[i].role & SW_ROLE_ADD)) {
            continue;
        }

        if (set[i].role & NGX_SUNDEW_ALLOWLIST) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "sundew: set \"%V\" is used by ipset_allowlist and "
                          "is also added to in %V:%ui; an allowlist must not "
                          "be written to", &set[i].name, &set[i].file,
                          set[i].line);
            return NGX_ERROR;
        }

        found = 0;

        if (scf->writable != NGX_CONF_UNSET_PTR) {
            w = scf->writable->elts;

            for (j = 0; j < scf->writable->nelts; j++) {
                if (w[j].len == set[i].name.len
                    && ngx_strncmp(w[j].data, set[i].name.data, w[j].len) == 0)
                {
                    found = 1;
                }
            }
        }

        if (!found) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "sundew: %V:%ui adds to set \"%V\", which is not "
                          "listed in \"sundew_writable_sets\"; add "
                          "\"sundew_writable_sets %V;\" at the top level of "
                          "nginx.conf", &set[i].file, set[i].line,
                          &set[i].name, &set[i].name);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static char *
ngx_sundew_core_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_sundew_core_conf_t *scf = conf;

    ngx_core_conf_t  *ccf;

    ngx_conf_init_msec_value(scf->handshake_timeout, 5000);
    ngx_conf_init_value(scf->drain_timeout, 3600);
    ngx_conf_init_msec_value(scf->debug_delay, 0);
    ngx_conf_init_size_value(scf->cache_size, 16 * 1024 * 1024);

    if (scf->cache_size < 1024 * 1024) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "\"sundew_cache_size\" must be at least 1m");
        return NGX_CONF_ERROR;
    }

    if (scf->cache_zone) {
        scf->cache_zone->shm.size = scf->cache_size;
    }

    ngx_conf_init_size_value(scf->ratelimit_size, 8 * 1024 * 1024);

    if (scf->ratelimit_size < 1024 * 1024) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "\"sundew_ratelimit_zone_size\" must be at least 1m");
        return NGX_CONF_ERROR;
    }

    if (scf->ratelimit_zone) {
        scf->ratelimit_zone->shm.size = scf->ratelimit_size;
    }

    if (ngx_sundew_check_writes(cycle, scf) != NGX_OK
        || ngx_sundew_build_protect(cycle, scf) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (scf->helper_user.len == 0) {
        ngx_str_set(&scf->helper_user, "sundew");
    }

    if (scf->sets.nelts == 0) {
        return NGX_CONF_OK;
    }

    if (ngx_test_config || ngx_process == NGX_PROCESS_SIGNALLER) {
        return NGX_CONF_OK;
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (!ccf->master) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew requires \"master_process on\"");
        return NGX_CONF_ERROR;
    }

    if (geteuid() != 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew requires the nginx master to run as root; "
                      "workers drop privileges and the helper keeps only "
                      "CAP_NET_ADMIN");
        return NGX_CONF_ERROR;
    }

    if (ccf->user == 0 || ccf->user == (ngx_uid_t) NGX_CONF_UNSET_UINT) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew refuses to run with workers as root: "
                      "set \"user\" to an unprivileged account");
        return NGX_CONF_ERROR;
    }

    if (ngx_sundew_spawn(cycle, scf, ccf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_sundew_check_binary(ngx_cycle_t *cycle, ngx_str_t *path, int *hfd)
{
    int           fd;
    char          dir[PATH_MAX], *d;
    struct stat   st;

    fd = open((char *) path->data, O_PATH|O_CLOEXEC);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sundew: cannot open helper \"%V\"", path);
        return NGX_ERROR;
    }

    if (fstat(fd, &st) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sundew: fstat(\"%V\") failed", path);
        goto failed;
    }

    if (!S_ISREG(st.st_mode) || st.st_uid != 0
        || (st.st_mode & (S_IWGRP|S_IWOTH|S_ISUID|S_ISGID)))
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: helper \"%V\" must be a regular file owned "
                      "by root, not group/world-writable, not setuid/setgid",
                      path);
        goto failed;
    }

    if (path->len >= sizeof(dir)) {
        goto failed;
    }

    ngx_cpystrn((u_char *) dir, path->data, path->len + 1);

    for ( ;; ) {
        d = dirname(dir);

        if (stat(d, &st) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "sundew: stat(\"%s\") failed", d);
            goto failed;
        }

        if (st.st_uid != 0 || (st.st_mode & (S_IWGRP|S_IWOTH))) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "sundew: directory \"%s\" of the helper must be "
                          "owned by root and not group/world-writable", d);
            goto failed;
        }

        if (d[0] == '/' && d[1] == '\0') {
            break;
        }

        if (d != dir) {
            ngx_cpystrn((u_char *) dir, (u_char *) d, sizeof(dir));
        }
    }

    *hfd = fd;
    return NGX_OK;

failed:

    close(fd);
    return NGX_ERROR;
}


/* hex digits at p; NULL if none or more than 16 */
static char *
ngx_sundew_hex(char *p, uint64_t *v)
{
    char      *start;
    u_char     c;
    uint64_t   x;

    x = 0;

    for (start = p; ; p++) {
        c = (u_char) *p;

        if (c >= '0' && c <= '9') {
            c -= '0';

        } else if ((c | 0x20) >= 'a' && (c | 0x20) <= 'f') {
            c = (c | 0x20) - 'a' + 10;

        } else {
            break;
        }

        if (p - start == 16) {
            return NULL;
        }

        x = (x << 4) | c;
    }

    if (p == start) {
        return NULL;
    }

    *v = x;
    return p;
}


/* file of the mapping that holds this code; dladdr() needs glibc 2.34 */
static ngx_int_t
ngx_sundew_module_file(char *buf, size_t size)
{
    char       line[PATH_MAX + 128], *p, *file;
    FILE      *f;
    size_t     n;
    uint64_t   start, end, addr;
    ngx_int_t  rc;

    addr = (uint64_t) (uintptr_t) ngx_sundew_core_init_conf;
    rc = NGX_ERROR;

    f = fopen("/proc/self/maps", "re");
    if (f == NULL) {
        return NGX_ERROR;
    }

    while (fgets(line, sizeof(line), f)) {
        p = ngx_sundew_hex(line, &start);
        if (p == NULL || *p != '-') {
            continue;
        }

        p = ngx_sundew_hex(p + 1, &end);
        if (p == NULL || addr < start || addr >= end) {
            continue;
        }

        file = strchr(p, '/');
        if (file == NULL) {
            break;
        }

        n = strcspn(file, "\n");
        if (n < size) {
            ngx_memcpy(buf, file, n);
            buf[n] = '\0';
            rc = NGX_OK;
        }

        break;
    }

    fclose(f);
    return rc;
}


static ngx_int_t
ngx_sundew_helper_path(ngx_cycle_t *cycle, ngx_sundew_core_conf_t *scf,
    ngx_str_t *path)
{
    size_t    len;
    char      buf[PATH_MAX], *dir;

    if (scf->helper_path.len) {
        *path = scf->helper_path;
        return NGX_OK;
    }

    if (ngx_sundew_module_file(buf, sizeof(buf)) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: cannot determine module location; "
                      "set \"sundew_helper_path\"");
        return NGX_ERROR;
    }

    dir = dirname(buf);

    len = ngx_strlen(dir) + sizeof("/" SW_HELPER_NAME);

    path->data = ngx_pnalloc(cycle->pool, len);
    if (path->data == NULL) {
        return NGX_ERROR;
    }

    path->len = ngx_sprintf(path->data, "%s/" SW_HELPER_NAME "%Z", dir)
                - path->data - 1;

    return NGX_OK;
}


static int
ngx_sundew_policy_fd(ngx_cycle_t *cycle, ngx_sundew_core_conf_t *scf,
    uid_t huid, gid_t hgid, uid_t wuid)
{
    int                   fd;
    size_t                size;
    u_char               *buf, *p;
    ngx_uint_t            i;
    sw_policy_hdr_t      *hdr;
    sw_policy_set_t      *ps;
    sw_policy_rule_t     *pr;
    sw_policy_protect_t  *pp;
    ngx_sundew_set_t     *set;
    ngx_sundew_rule_t    *rule;
    ngx_sundew_cidr_t    *cidr;

    size = sizeof(sw_policy_hdr_t)
           + scf->sets.nelts * sizeof(sw_policy_set_t)
           + scf->rules.nelts * sizeof(sw_policy_rule_t)
           + scf->policy_protect.nelts * sizeof(sw_policy_protect_t);

    buf = ngx_pcalloc(cycle->pool, size);
    if (buf == NULL) {
        return -1;
    }

    hdr = (sw_policy_hdr_t *) buf;
    hdr->magic = SW_POLICY_MAGIC;
    hdr->version = SW_POLICY_VERSION;
    hdr->nsets = (uint16_t) scf->sets.nelts;
    hdr->nslots = (uint32_t) scf->nslots;
    hdr->helper_uid = huid;
    hdr->helper_gid = hgid;
    hdr->worker_uid = wuid;
    hdr->generation = (uint32_t) scf->generation;
    hdr->debug_delay_ms = (uint32_t) scf->debug_delay;
    hdr->nrules = (uint16_t) scf->rules.nelts;
    hdr->nprotect = (uint16_t) scf->policy_protect.nelts;

    p = buf + sizeof(sw_policy_hdr_t);
    set = scf->sets.elts;

    for (i = 0; i < scf->sets.nelts; i++) {
        ps = (sw_policy_set_t *) p;
        ps->backend = (uint8_t) set[i].backend;
        ps->role = (uint8_t) (set[i].role & (SW_ROLE_LOOKUP|SW_ROLE_ADD));
        ps->family = (uint8_t) set[i].nft_family;
        ngx_memcpy(ps->table, set[i].table.data, set[i].table.len);
        ngx_memcpy(ps->name, set[i].set.data, set[i].set.len);
        p += sizeof(sw_policy_set_t);
    }

    rule = scf->rules.elts;

    for (i = 0; i < scf->rules.nelts; i++) {
        pr = (sw_policy_rule_t *) p;
        pr->set = (uint8_t) rule[i].set;
        pr->prefix4 = (uint8_t) rule[i].prefix4;
        pr->prefix6 = (uint8_t) rule[i].prefix6;
        pr->timeout = (uint32_t) rule[i].timeout;
        pr->rate = (uint32_t) rule[i].rate;
        pr->burst = (uint32_t) rule[i].burst;
        p += sizeof(sw_policy_rule_t);
    }

    cidr = scf->policy_protect.elts;

    for (i = 0; i < scf->policy_protect.nelts; i++) {
        pp = (sw_policy_protect_t *) p;
        pp->family = (uint8_t) cidr[i].family;
        pp->prefix = (uint8_t) cidr[i].prefix;
        ngx_memcpy(pp->addr, cidr[i].addr, 16);
        p += sizeof(sw_policy_protect_t);
    }

    fd = memfd_create("sundew-policy", MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sundew: memfd_create() failed");
        return -1;
    }

    if (write(fd, buf, size) != (ssize_t) size
        || fcntl(fd, F_ADD_SEALS,
                 F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL) == -1)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sundew: cannot write policy");
        close(fd);
        return -1;
    }

    return fd;
}


static void
ngx_sundew_close_all(int *fds, ngx_uint_t n)
{
    ngx_uint_t  i;

    for (i = 0; i < n; i++) {
        if (fds[i] != -1) {
            close(fds[i]);
            fds[i] = -1;
        }
    }
}


/* async-signal-safe only */

static void
ngx_sundew_exec_helper(int hfd, int devnull, int policy, int ctl,
    int *slots, ngx_uint_t nslots, int *tmp)
{
    int               i, n, sig;
    struct rlimit     rl;
    sigset_t          set;
    struct sigaction  sa;
    char             *argv[] = { SW_HELPER_NAME, NULL };
    char             *envp[] = { NULL };

    ngx_memzero(&sa, sizeof(struct sigaction));
    sa.sa_handler = SIG_DFL;

    for (sig = 1; sig < NSIG; sig++) {
        (void) sigaction(sig, &sa, NULL);
    }

    sigemptyset(&set);
    (void) sigprocmask(SIG_SETMASK, &set, NULL);

    (void) setsid();

    n = SW_FD_SLOT0 + (int) nslots + 1;

    tmp[0] = fcntl(hfd, F_DUPFD_CLOEXEC, n);
    tmp[1] = fcntl(devnull, F_DUPFD_CLOEXEC, n);
    tmp[2] = fcntl(policy, F_DUPFD_CLOEXEC, n);
    tmp[3] = fcntl(ctl, F_DUPFD_CLOEXEC, n);

    for (i = 0; i < (int) nslots; i++) {
        tmp[4 + i] = fcntl(slots[i], F_DUPFD_CLOEXEC, n);
    }

    for (i = 0; i < 4 + (int) nslots; i++) {
        if (tmp[i] == -1) {
            _exit(127);
        }
    }

    if (dup2(tmp[1], 0) == -1 || dup2(tmp[1], 1) == -1
#if !(NGX_DEBUG)
        || dup2(tmp[1], 2) == -1
#endif
        || dup2(tmp[2], SW_FD_POLICY) == -1
        || dup2(tmp[3], SW_FD_CTL) == -1)
    {
        _exit(127);
    }

    for (i = 0; i < (int) nslots; i++) {
        if (dup2(tmp[4 + i], SW_FD_SLOT0 + i) == -1) {
            _exit(127);
        }
    }

    hfd = SW_FD_SLOT0 + (int) nslots;

    if (dup3(tmp[0], hfd, O_CLOEXEC) == -1) {
        _exit(127);
    }

    if (syscall(SYS_close_range, (unsigned) hfd + 1, ~0U, 0) == -1) {
        if (getrlimit(RLIMIT_NOFILE, &rl) == -1) {
            _exit(127);
        }

        for (i = hfd + 1; i < (int) rl.rlim_cur; i++) {
            (void) close(i);
        }
    }

    (void) syscall(SYS_execveat, hfd, "", argv, envp, AT_EMPTY_PATH);

    _exit(127);
}


static ngx_int_t
ngx_sundew_spawn(ngx_cycle_t *cycle, ngx_sundew_core_conf_t *scf,
    ngx_core_conf_t *ccf)
{
    int                    hfd, devnull, policy, ctl[2], pipefd[2], status;
    int                   *slots_h, *tmp, pidfd;
    pid_t                  pid, helper;
    ssize_t                n;
    sigset_t               all, old;
    ngx_str_t              path;
    ngx_uint_t             i;
    struct passwd         *pw;
    ngx_pool_cleanup_t    *cln;
    ngx_sundew_helper_t   *h;

    ngx_sundew_reap(cycle);

    if (ngx_sundew_nhelpers >= SW_MAX_HELPERS) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: too many helpers still draining (%d); "
                      "lower sundew_helper_drain_timeout or set "
                      "worker_shutdown_timeout", SW_MAX_HELPERS);
        return NGX_ERROR;
    }

    pw = getpwnam((char *) scf->helper_user.data);
    if (pw == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: helper user \"%V\" does not exist; create a "
                      "dedicated system user (e.g. \"useradd -r -s "
                      "/usr/sbin/nologin sundew\")", &scf->helper_user);
        return NGX_ERROR;
    }

    if (pw->pw_uid == ccf->user || pw->pw_uid == 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: helper user \"%V\" must differ from the "
                      "worker user and from root", &scf->helper_user);
        return NGX_ERROR;
    }

    scf->generation = ++ngx_sundew_generation;
    scf->nslots = ccf->worker_processes;

    if (ngx_sundew_helper_path(cycle, scf, &path) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_sundew_check_binary(cycle, &path, &hfd) != NGX_OK) {
        return NGX_ERROR;
    }

    devnull = -1;
    policy = -1;
    ctl[0] = ctl[1] = -1;
    pipefd[0] = pipefd[1] = -1;

    scf->slots = ngx_pcalloc(cycle->pool, scf->nslots * sizeof(ngx_fd_t));
    slots_h = ngx_pcalloc(cycle->pool, scf->nslots * sizeof(int));
    tmp = ngx_pcalloc(cycle->pool, (4 + scf->nslots) * sizeof(int));

    if (scf->slots == NULL || slots_h == NULL || tmp == NULL) {
        close(hfd);
        return NGX_ERROR;
    }

    for (i = 0; i < scf->nslots; i++) {
        scf->slots[i] = -1;
        slots_h[i] = -1;
    }

    cln = ngx_pool_cleanup_add(cycle->pool, 0);
    if (cln == NULL) {
        close(hfd);
        return NGX_ERROR;
    }

    cln->handler = ngx_sundew_close_slots;
    cln->data = scf;

    policy = ngx_sundew_policy_fd(cycle, scf, pw->pw_uid, pw->pw_gid,
                                  ccf->user);
    if (policy == -1) {
        goto failed;
    }

    devnull = open("/dev/null", O_RDWR|O_CLOEXEC);
    if (devnull == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sundew: open(\"/dev/null\") failed");
        goto failed;
    }

    if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, ctl) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sundew: socketpair() failed");
        goto failed;
    }

    for (i = 0; i < scf->nslots; i++) {
        int  sp[2];

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, sp) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "sundew: socketpair() failed");
            goto failed;
        }

        scf->slots[i] = sp[0];
        slots_h[i] = sp[1];
    }

    if (pipe2(pipefd, O_CLOEXEC) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sundew: pipe2() failed");
        goto failed;
    }

    /* keep nginx's SIGCHLD handler from reaping the intermediate */

    sigfillset(&all);
    sigprocmask(SIG_SETMASK, &all, &old);

    pid = fork();

    if (pid == 0) {
        (void) prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

        helper = fork();

        if (helper == 0) {
            ngx_sundew_exec_helper(hfd, devnull, policy, ctl[1], slots_h,
                                   scf->nslots, tmp);
        }

        if (write(pipefd[1], &helper, sizeof(pid_t)) != sizeof(pid_t)
            || helper == -1)
        {
            _exit(1);
        }

        _exit(0);
    }

    if (pid == -1) {
        sigprocmask(SIG_SETMASK, &old, NULL);
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sundew: fork() failed");
        goto failed;
    }

    close(pipefd[1]);
    pipefd[1] = -1;

    helper = -1;

    do {
        n = read(pipefd[0], &helper, sizeof(pid_t));
    } while (n == -1 && ngx_errno == NGX_EINTR);

    while (waitpid(pid, &status, 0) == -1 && ngx_errno == NGX_EINTR) {
        /* void */
    }

    sigprocmask(SIG_SETMASK, &old, NULL);

    close(pipefd[0]);
    pipefd[0] = -1;

    if (n != sizeof(pid_t) || helper <= 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: failed to start helper");
        goto failed;
    }

    close(ctl[1]);
    ctl[1] = -1;
    ngx_sundew_close_all(slots_h, scf->nslots);
    close(policy);
    policy = -1;
    close(devnull);
    devnull = -1;
    close(hfd);
    hfd = -1;

    pidfd = (int) syscall(SYS_pidfd_open, helper, 0);
    if (pidfd != -1) {
        (void) fcntl(pidfd, F_SETFD, FD_CLOEXEC);
    }

    h = &ngx_sundew_helpers[ngx_sundew_nhelpers++];
    h->pid = helper;
    h->pidfd = pidfd;
    h->ctl = ctl[0];
    h->generation = scf->generation;
    h->deadline = 0;

    ctl[0] = -1;

    if (ngx_sundew_handshake(cycle, scf, h->ctl) != NGX_OK) {
        ngx_sundew_kill(h);
        close(h->ctl);
        h->ctl = -1;
        h->deadline = ngx_time();
        goto failed_slots;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "sundew: helper %P started (generation %ui, %ui slots, "
                  "%ui sets)", helper, scf->generation, scf->nslots,
                  scf->sets.nelts);

    scf->active = 1;

    return NGX_OK;

failed:

    if (hfd != -1) {
        close(hfd);
    }

    if (devnull != -1) {
        close(devnull);
    }

    if (policy != -1) {
        close(policy);
    }

    ngx_sundew_close_all(ctl, 2);
    ngx_sundew_close_all(pipefd, 2);
    ngx_sundew_close_all(slots_h, scf->nslots);

failed_slots:

    ngx_sundew_close_all(scf->slots, scf->nslots);

    return NGX_ERROR;
}


static const char *
ngx_sundew_strerr(int32_t err)
{
    switch (-err) {
    case EOPNOTSUPP:
        return "unsupported set type (supported: hash:ip, hash:net, "
               "bitmap:ip)";
    case EPERM:
        return "permission denied (CAP_NET_ADMIN missing?)";
    case 4097:
        return "kernel ipset protocol mismatch";
    case 4102:
        return "set type mismatch";
    default:
        return "kernel error";
    }
}


/* READY errors of nftables sets; NGX_DECLINED if not one of them */
static ngx_int_t
ngx_sundew_nft_error(ngx_cycle_t *cycle, ngx_sundew_set_t *set, int32_t err)
{
    const char  *fam, *flags;

    fam = set->nft_family == SW_NFPROTO_INET ? "inet"
          : set->nft_family == SW_NFPROTO_IPV6 ? "ip6" : "ip";
    flags = (set->role & SW_ROLE_ADD) ? " flags timeout;" : "";

    switch (err) {

    case -ENOENT:
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: set \"%V\": table or set does not exist; "
                      "create it, e.g. \"nft add set %s %V %V "
                      "'{ type ipv4_addr;%s }'\"", &set->name, fam,
                      &set->table, &set->set, flags);
        return NGX_ERROR;

    case -EOPNOTSUPP:
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: set \"%V\": nftables unavailable (is the "
                      "nf_tables kernel module loaded? \"modprobe "
                      "nf_tables\")", &set->name);
        return NGX_ERROR;

    case SW_SETERR_NO_TIMEOUT:
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: set \"%V\" is added to (%V:%ui) but has no "
                      "\"flags timeout\", so bans would never expire; "
                      "recreate it, e.g. \"nft add set %s %V %V "
                      "'{ type ipv4_addr; flags timeout; }'\"", &set->name,
                      &set->file, set->line, fam, &set->table, &set->set);
        return NGX_ERROR;

    case SW_SETERR_NFT_KEY:
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: set \"%V\" is not supported: it must be a "
                      "set, not a map, of type ipv4_addr or ipv6_addr "
                      "without concatenations", &set->name);
        return NGX_ERROR;

    case SW_SETERR_NFT_INTERVAL:
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: set \"%V\" is added to (%V:%ui) but has "
                      "\"flags interval\"; bans need a set without it",
                      &set->name, &set->file, set->line);
        return NGX_ERROR;

    case SW_SETERR_NFT_CONSTANT:
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: set \"%V\" is added to (%V:%ui) but has "
                      "\"flags constant\"", &set->name, &set->file,
                      set->line);
        return NGX_ERROR;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_sundew_handshake(ngx_cycle_t *cycle, ngx_sundew_core_conf_t *scf, int ctl)
{
    u_char             buf[sizeof(sw_ctl_hdr_t)
                           + SW_MAX_SETS * sizeof(sw_ready_set_t)];
    ssize_t            n;
    ngx_int_t          rc;
    ngx_uint_t         i;
    struct pollfd      pfd;
    sw_ctl_hdr_t      *hdr;
    sw_ready_set_t    *rs;
    ngx_sundew_set_t  *set;
    ngx_sundew_rule_t *rule;
    static const char *helper_err[] = {
        "ok", "invalid policy", "capability setup failed",
        "netlink unavailable (is the ip_set kernel module loaded? "
        "\"modprobe ip_set\")",
        "unsupported kernel ipset protocol", "sandbox setup failed"
    };

    pfd.fd = ctl;
    pfd.events = POLLIN;

    do {
        rc = poll(&pfd, 1, (int) scf->handshake_timeout);
    } while (rc == -1 && ngx_errno == NGX_EINTR);

    if (rc == 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: helper did not become ready within %M ms",
                      scf->handshake_timeout);
        return NGX_ERROR;
    }

    n = recv(ctl, buf, sizeof(buf), MSG_TRUNC);

    if (n <= 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, n ? ngx_errno : 0,
                      "sundew: helper exited during startup "
                      "(check the helper binary and its capabilities)");
        return NGX_ERROR;
    }

    hdr = (sw_ctl_hdr_t *) buf;

    if ((size_t) n < sizeof(sw_ctl_hdr_t) || (size_t) n > sizeof(buf)
        || hdr->magic != SW_FRAME_MAGIC || hdr->version != SW_PROTO_VERSION
        || hdr->type != SW_CTL_READY)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: malformed READY from helper "
                      "(module and helper versions differ?)");
        return NGX_ERROR;
    }

    if (hdr->status != SW_ERR_NONE) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: helper startup failed: %s",
                      hdr->status < sizeof(helper_err) / sizeof(char *)
                      ? helper_err[hdr->status] : "unknown error");
        return NGX_ERROR;
    }

    if (hdr->nsets != scf->sets.nelts
        || (size_t) n != sizeof(sw_ctl_hdr_t)
                         + hdr->nsets * sizeof(sw_ready_set_t))
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: READY set count mismatch");
        return NGX_ERROR;
    }

    rs = (sw_ready_set_t *) (buf + sizeof(sw_ctl_hdr_t));
    set = scf->sets.elts;
    rc = NGX_OK;

    for (i = 0; i < scf->sets.nelts; i++) {

        if (rs[i].err != 0 && set[i].backend == SW_BACKEND_NFT
            && ngx_sundew_nft_error(cycle, &set[i], rs[i].err) == NGX_ERROR)
        {
            rc = NGX_ERROR;
            continue;
        }

        if (rs[i].err == -ENOENT) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "sundew: set \"%V\": set does not exist; create "
                          "it, e.g. \"ipset create %V hash:ip\"",
                          &set[i].name, &set[i].name);
            rc = NGX_ERROR;
            continue;
        }

        if (rs[i].err == SW_SETERR_NO_TIMEOUT) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "sundew: set \"%V\" is added to (%V:%ui) but has "
                          "no timeout support, so bans would never expire; "
                          "recreate it with a timeout, e.g. \"ipset create "
                          "%V hash:ip timeout 3600\"", &set[i].name,
                          &set[i].file, set[i].line, &set[i].name);
            rc = NGX_ERROR;
            continue;
        }

        if (rs[i].err == SW_SETERR_NEED_TIMEOUT) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "sundew: set \"%V\" is added to (%V:%ui) without "
                          "a timeout, and the set's default timeout is 0 "
                          "(permanent); give \"timeout=\" or \"ban_time=\"",
                          &set[i].name, &set[i].file, set[i].line);
            rc = NGX_ERROR;
            continue;
        }

        if (rs[i].err != 0) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "sundew: set \"%V\": %s (%D)", &set[i].name,
                          ngx_sundew_strerr(rs[i].err), rs[i].err);
            rc = NGX_ERROR;
            continue;
        }

        set[i].family = rs[i].family;
        set[i].revision = rs[i].revision;
        set[i].has_timeout = rs[i].has_timeout;
        set[i].default_timeout = rs[i].default_timeout;

        if (set[i].family == AF_INET6) {
            scf->mask6 |= (uint64_t) 1 << i;

        } else {
            scf->mask4 |= (uint64_t) 1 << i;
        }

        ngx_memcpy(set[i].type, rs[i].type, SW_SETNAME_LEN);
        set[i].type[SW_SETNAME_LEN - 1] = '\0';

        ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                      "sundew: set \"%V\" %s family %s", &set[i].name,
                      set[i].type,
                      set[i].family == AF_INET6 ? "inet6" : "inet");
    }

    if (rc != NGX_OK) {
        return rc;
    }

    rule = scf->rules.elts;

    for (i = 0; i < scf->rules.nelts; i++) {
        if ((rule[i].prefix4 != 32 || rule[i].prefix6 != 128)
            && ngx_strcmp(set[rule[i].set].type, "hash:net") != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "sundew: prefix4= and prefix6= need a hash:net "
                          "set; \"%V\" is %s (%V:%ui)",
                          &set[rule[i].set].name, set[rule[i].set].type,
                          &set[rule[i].set].file, set[rule[i].set].line);
            return NGX_ERROR;
        }

        if (rule[i].timeout == 0) {
            rule[i].timeout = set[rule[i].set].default_timeout;
        }
    }

    return rc;
}


static void
ngx_sundew_close_slots(void *data)
{
    ngx_sundew_core_conf_t *scf = data;

    if (scf->slots) {
        ngx_sundew_close_all(scf->slots, scf->nslots);
    }
}


static void
ngx_sundew_kill(ngx_sundew_helper_t *h)
{
    if (h->pidfd != -1) {
        (void) syscall(SYS_pidfd_send_signal, h->pidfd, SIGKILL, NULL, 0);

    } else if (h->pid > 0) {
        (void) kill(h->pid, SIGKILL);
    }
}


static void
ngx_sundew_drain(ngx_cycle_t *cycle, ngx_sundew_helper_t *h,
    uint32_t deadline_s)
{
    sw_drain_t  d;

    if (h->ctl == -1) {
        return;
    }

    ngx_memzero(&d, sizeof(sw_drain_t));
    d.hdr.magic = SW_FRAME_MAGIC;
    d.hdr.version = SW_PROTO_VERSION;
    d.hdr.type = SW_CTL_DRAIN;
    d.deadline_s = deadline_s;

    if (send(h->ctl, &d, sizeof(sw_drain_t), MSG_DONTWAIT|MSG_NOSIGNAL)
        != sizeof(sw_drain_t))
    {
        ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
                      "sundew: cannot drain helper %P, killing it", h->pid);
        ngx_sundew_kill(h);
    }

    close(h->ctl);
    h->ctl = -1;
    h->deadline = ngx_time() + deadline_s;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "sundew: draining helper %P (generation %ui, deadline %uDs)",
                  h->pid, h->generation, deadline_s);
}


static void
ngx_sundew_reap(ngx_cycle_t *cycle)
{
    ngx_uint_t            i, j;
    struct pollfd         pfd;
    ngx_sundew_helper_t  *h;

    for (i = 0, j = 0; i < ngx_sundew_nhelpers; i++) {
        h = &ngx_sundew_helpers[i];

        if (h->deadline && h->pidfd != -1) {
            pfd.fd = h->pidfd;
            pfd.events = POLLIN;

            if (poll(&pfd, 1, 0) == 1) {
                close(h->pidfd);
                continue;
            }

            if (ngx_time() > h->deadline + 30) {
                ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                              "sundew: helper %P overstayed its drain "
                              "deadline, killing it", h->pid);
                ngx_sundew_kill(h);
            }
        }

        if (h->deadline && h->pidfd == -1 && kill(h->pid, 0) == -1) {
            continue;
        }

        ngx_sundew_helpers[j++] = *h;
    }

    ngx_sundew_nhelpers = j;
}


static ngx_int_t
ngx_sundew_core_init_module(ngx_cycle_t *cycle)
{
    ngx_uint_t               i;
    ngx_core_conf_t         *ccf;
    ngx_sundew_helper_t     *h;
    ngx_sundew_core_conf_t  *scf;

    if (ngx_test_config || ngx_process == NGX_PROCESS_SIGNALLER) {
        return NGX_OK;
    }

    scf = (ngx_sundew_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_sundew_core_module);
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    for (i = 0; i < ngx_sundew_nhelpers; i++) {
        h = &ngx_sundew_helpers[i];

        if (h->deadline == 0
            && (!scf->active || h->generation < scf->generation))
        {
            ngx_sundew_drain(cycle, h,
                             ccf->shutdown_timeout
                             ? (uint32_t) (ccf->shutdown_timeout / 1000 + 60)
                             : (uint32_t) scf->drain_timeout);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_sundew_core_init_process(ngx_cycle_t *cycle)
{
    ngx_uint_t               i;
    ngx_sundew_core_conf_t  *scf;

    scf = (ngx_sundew_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_sundew_core_module);

    for (i = 0; i < ngx_sundew_nhelpers; i++) {
        if (ngx_sundew_helpers[i].ctl != -1) {
            close(ngx_sundew_helpers[i].ctl);
            ngx_sundew_helpers[i].ctl = -1;
        }

        if (ngx_sundew_helpers[i].pidfd != -1) {
            close(ngx_sundew_helpers[i].pidfd);
            ngx_sundew_helpers[i].pidfd = -1;
        }
    }

    ngx_sundew_nhelpers = 0;

    if (!scf->active) {
        return NGX_OK;
    }

    for (i = 0; i < scf->nslots; i++) {
        if (ngx_process == NGX_PROCESS_WORKER && i == (ngx_uint_t) ngx_worker) {
            if (ngx_nonblocking(scf->slots[i]) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              ngx_nonblocking_n " failed");
                return NGX_ERROR;
            }

            continue;
        }

        if (scf->slots[i] != -1) {
            close(scf->slots[i]);
            scf->slots[i] = -1;
        }
    }

    if (ngx_sundew_verify_no_caps(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_process == NGX_PROCESS_WORKER
        && sw_client_init(cycle, scf->slots[ngx_worker]) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sundew: prctl(PR_SET_NO_NEW_PRIVS) failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_sundew_verify_no_caps(ngx_cycle_t *cycle)
{
    char            path[64], line[256];
    FILE           *f;
    DIR            *dir;
    uint64_t        v;
    ngx_uint_t      bad;
    struct dirent  *de;

    dir = opendir("/proc/self/task");
    if (dir == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sundew: cannot verify worker capabilities: "
                      "opendir(\"/proc/self/task\") failed");
        return NGX_ERROR;
    }

    bad = 0;

    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') {
            continue;
        }

        ngx_snprintf((u_char *) path, sizeof(path),
                     "/proc/self/task/%s/status%Z", de->d_name);

        f = fopen(path, "re");
        if (f == NULL) {
            continue;
        }

        while (fgets(line, sizeof(line), f)) {
            v = 0;

            /* unparsable counts as holding capabilities */
            if ((ngx_strncmp(line, "CapEff:", 7) == 0
                 || ngx_strncmp(line, "CapPrm:", 7) == 0
                 || ngx_strncmp(line, "CapAmb:", 7) == 0)
                && (ngx_sundew_hex(line + 7 + strspn(line + 7, " \t"), &v)
                    == NULL || v != 0))
            {
                line[6] = '\0';
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                              "sundew: worker task %s has %s=%016xL; "
                              "workers must hold no capabilities",
                              de->d_name, line, (uint64_t) v);
                bad = 1;
            }
        }

        fclose(f);
    }

    closedir(dir);

    return bad ? NGX_ERROR : NGX_OK;
}


static void
ngx_sundew_core_exit_master(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    for (i = 0; i < ngx_sundew_nhelpers; i++) {
        ngx_sundew_drain(cycle, &ngx_sundew_helpers[i], 0);
    }
}
