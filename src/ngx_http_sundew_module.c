/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <poll.h>

#include "ngx_sundew.h"


typedef struct {
    uint64_t    blacklist;      /* set bitmask */
    ngx_uint_t  blacklist_set;
} ngx_http_sundew_loc_conf_t;


static ngx_int_t ngx_http_sundew_init(ngx_conf_t *cf);
static void *ngx_http_sundew_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_sundew_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_sundew_blacklist(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_sundew_debug_test(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static uint32_t  ngx_http_sundew_req_id;


static ngx_command_t  ngx_http_sundew_commands[] = {

    { ngx_string("ipset_blacklist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_sundew_blacklist,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("sundew_debug_test"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_sundew_debug_test,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_sundew_module_ctx = {
    NULL,                                  /* preconfiguration */
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


static void *
ngx_http_sundew_create_loc_conf(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(ngx_http_sundew_loc_conf_t));
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


static ngx_int_t
ngx_http_sundew_preaccess_handler(ngx_http_request_t *r)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sundew preaccess handler: %V", &r->connection->addr_text);

    return NGX_DECLINED;
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

    *h = ngx_http_sundew_preaccess_handler;

    return NGX_OK;
}


/* debug location: synchronous TEST */

static ngx_int_t
ngx_http_sundew_parse_addr(ngx_http_request_t *r, sw_req_t *req)
{
    ngx_str_t   ip;
    ngx_addr_t  addr;

    if (ngx_http_arg(r, (u_char *) "ip", 2, &ip) == NGX_OK) {
        if (ngx_parse_addr(r->pool, &addr, ip.data, ip.len) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        addr.sockaddr = r->connection->sockaddr;
        addr.socklen = r->connection->socklen;
    }

    switch (addr.sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6: {
        struct in6_addr *a6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;

        if (IN6_IS_ADDR_V4MAPPED(a6)) {
            req->family = 4;
            ngx_memcpy(req->addr, &a6->s6_addr[12], 4);

        } else {
            req->family = 6;
            ngx_memcpy(req->addr, a6->s6_addr, 16);
        }

        return NGX_OK;
    }
#endif

    case AF_INET:
        req->family = 4;
        ngx_memcpy(req->addr,
                   &((struct sockaddr_in *) addr.sockaddr)->sin_addr, 4);
        return NGX_OK;

    default:
        return NGX_ERROR;
    }
}


static ngx_int_t
ngx_http_sundew_debug_handler(ngx_http_request_t *r)
{
    int                      rc;
    u_char                  *p;
    ssize_t                  n;
    ngx_fd_t                 fd;
    ngx_buf_t               *b;
    ngx_msec_t               start, left;
    ngx_uint_t               i;
    sw_req_t                 req;
    sw_rep_t                 rep;
    ngx_chain_t              out;
    struct pollfd            pfd;
    ngx_sundew_set_t        *set;
    ngx_sundew_core_conf_t  *scf;

    scf = (ngx_sundew_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                  ngx_sundew_core_module);

    fd = ngx_sundew_worker_slot((ngx_cycle_t *) ngx_cycle);
    if (fd == NGX_INVALID_FILE) {
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    ngx_memzero(&req, sizeof(sw_req_t));
    req.magic = SW_FRAME_MAGIC;
    req.version = SW_PROTO_VERSION;
    req.op = SW_OP_TEST;

    if (ngx_http_sundew_parse_addr(r, &req) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    set = scf->sets.elts;

    for (i = 0; i < scf->sets.nelts; i++) {
        if ((set[i].family == AF_INET && req.family == 4)
            || (set[i].family == AF_INET6 && req.family == 6))
        {
            req.arg |= (uint64_t) 1 << i;
        }
    }

    b = ngx_create_temp_buf(r->pool, 64 + scf->sets.nelts * 48);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = b->last;

    if (req.arg == 0) {
        p = ngx_sprintf(p, "status=no-sets-for-family\n");
        goto done;
    }

    if (ngx_http_sundew_req_id == 0) {
        ngx_http_sundew_req_id = (uint32_t) ngx_random() | 1;
    }

    req.req_id = ngx_http_sundew_req_id++;

    if (send(fd, &req, sizeof(sw_req_t), MSG_DONTWAIT|MSG_NOSIGNAL)
        != sizeof(sw_req_t))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "sundew: send to helper failed");
        p = ngx_sprintf(p, "status=helper-unreachable\n");
        goto done;
    }

    start = ngx_current_msec;
    ngx_time_update();

    for ( ;; ) {
        left = 100 - (ngx_current_msec - start);

        if ((ngx_msec_int_t) left <= 0) {
            p = ngx_sprintf(p, "status=timeout\n");
            goto done;
        }

        pfd.fd = fd;
        pfd.events = POLLIN;

        rc = poll(&pfd, 1, (int) left);
        ngx_time_update();

        if (rc == 0) {
            continue;
        }

        if (rc == -1) {
            if (ngx_errno == NGX_EINTR) {
                continue;
            }

            p = ngx_sprintf(p, "status=poll-error\n");
            goto done;
        }

        n = recv(fd, &rep, sizeof(sw_rep_t), MSG_DONTWAIT|MSG_TRUNC);

        if (n == 0) {
            p = ngx_sprintf(p, "status=helper-gone\n");
            goto done;
        }

        if (n != sizeof(sw_rep_t) || rep.magic != SW_FRAME_MAGIC) {
            continue;
        }

        if (rep.req_id != req.req_id) {
            continue;
        }

        break;
    }

    p = ngx_sprintf(p, "status=%d decided=%016xL matched=%016xL\n",
                    (int) rep.status, rep.decided, rep.matched);

    for (i = 0; i < scf->sets.nelts; i++) {
        if (rep.decided & ((uint64_t) 1 << i)) {
            p = ngx_sprintf(p, "%V=%s\n", &set[i].name,
                            (rep.matched & ((uint64_t) 1 << i)) ? "in"
                                                                : "not-in");
        }
    }

done:

    b->last = p;
    b->last_buf = 1;
    b->last_in_chain = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;
    ngx_str_set(&r->headers_out.content_type, "text/plain");

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_http_sundew_debug_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_sundew_debug_handler;

    return NGX_CONF_OK;
}
