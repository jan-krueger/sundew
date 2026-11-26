/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <dlfcn.h>
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


static ngx_sundew_helper_t  ngx_sundew_helpers[SW_MAX_HELPERS];
static ngx_uint_t           ngx_sundew_nhelpers;
static ngx_uint_t           ngx_sundew_generation;

static ngx_str_t  sw_cache_zone_name = ngx_string("sundew_cache");
static ngx_str_t  sw_stats_zone_name = ngx_string("sundew_stats");


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

    if (ngx_array_init(&scf->sets, cycle->pool, 4, sizeof(ngx_sundew_set_t))
        != NGX_OK)
    {
        return NULL;
    }

    return scf;
}


ngx_int_t
ngx_sundew_add_set(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t role)
{
    u_char                  *p;
    ngx_uint_t               i;
    ngx_sundew_set_t        *set;
    ngx_sundew_core_conf_t  *scf;

    scf = (ngx_sundew_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                  ngx_sundew_core_module);

    if (name->len == 0 || name->len >= SW_SETNAME_LEN) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid set name \"%V\": must be 1-%d characters",
                           name, SW_SETNAME_LEN - 1);
        return NGX_ERROR;
    }

    for (p = name->data; p < name->data + name->len; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
              || (*p >= '0' && *p <= '9')
              || *p == '_' || *p == '.' || *p == ':' || *p == '-'))
        {
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
            return i;
        }
    }

    if (scf->cache_zone == NULL) {
        scf->cache_zone = ngx_shared_memory_add(cf, &sw_cache_zone_name, 0,
                                                &ngx_sundew_core_module);
        scf->stats_zone = ngx_shared_memory_add(cf, &sw_stats_zone_name,
                                                64 * 1024,
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

    return scf->sets.nelts - 1;
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


static ngx_int_t
ngx_sundew_helper_path(ngx_cycle_t *cycle, ngx_sundew_core_conf_t *scf,
    ngx_str_t *path)
{
    size_t    len;
    char      buf[PATH_MAX], *dir;
    Dl_info   info;

    if (scf->helper_path.len) {
        *path = scf->helper_path;
        return NGX_OK;
    }

    if (dladdr((void *) ngx_sundew_core_init_conf, &info) == 0
        || info.dli_fname == NULL || info.dli_fname[0] != '/')
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "sundew: cannot determine module location; "
                      "set \"sundew_helper_path\"");
        return NGX_ERROR;
    }

    ngx_cpystrn((u_char *) buf, (u_char *) info.dli_fname, sizeof(buf));
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
    int                fd;
    size_t             size;
    u_char            *buf, *p;
    ngx_uint_t         i;
    sw_policy_hdr_t   *hdr;
    sw_policy_set_t   *ps;
    ngx_sundew_set_t  *set;

    size = sizeof(sw_policy_hdr_t) + scf->sets.nelts * sizeof(sw_policy_set_t);

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

    p = buf + sizeof(sw_policy_hdr_t);
    set = scf->sets.elts;

    for (i = 0; i < scf->sets.nelts; i++) {
        ps = (sw_policy_set_t *) p;
        ngx_memcpy(ps->name, set[i].name.data, set[i].name.len);
        ps->role = (uint8_t) set[i].role;
        p += sizeof(sw_policy_set_t);
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

        if (rs[i].err == -ENOENT) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "sundew: set \"%V\": set does not exist; create "
                          "it, e.g. \"ipset create %V hash:ip\"",
                          &set[i].name, &set[i].name);
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
    ngx_uint_t      bad;
    unsigned long   v;
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
            if ((ngx_strncmp(line, "CapEff:", 7) == 0
                 || ngx_strncmp(line, "CapPrm:", 7) == 0
                 || ngx_strncmp(line, "CapAmb:", 7) == 0)
                && sscanf(line + 7, "%lx", &v) == 1 && v != 0)
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
