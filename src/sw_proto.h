/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Wire formats. Mirror: helper/src/proto.rs
 */

#ifndef SW_PROTO_H
#define SW_PROTO_H

#include <stdint.h>
#include <stddef.h>

#define SW_PROTO_VERSION        4
#define SW_FRAME_MAGIC          0x5357          /* "SW" */
#define SW_MAX_SETS             64
#define SW_SETNAME_LEN          32              /* IPSET_MAXNAMELEN */
#define SW_NFT_NAMELEN          64              /* nft table and set names */
#define SW_SETREF_LEN           144             /* "nft:family/table/set" */
#define SW_MAX_RULES            64
#define SW_MAX_PROTECT          256
#define SW_MAX_TIMEOUT          2147483         /* IPSET_MAX_TIMEOUT */

/* helper fd layout */
#define SW_FD_POLICY            3
#define SW_FD_CTL               4
#define SW_FD_SLOT0             5


/* ---- policy (memfd, master -> helper, sealed) ------------------------ */

#define SW_POLICY_MAGIC         0x4c505753      /* "SWPL" */
#define SW_POLICY_VERSION       3

#define SW_ROLE_LOOKUP          1
#define SW_ROLE_ADD             2

#define SW_BACKEND_IPSET        1
#define SW_BACKEND_NFT          2

#define SW_NFPROTO_INET         1
#define SW_NFPROTO_IPV4         2
#define SW_NFPROTO_IPV6         10

typedef struct {
    uint32_t  magic;
    uint16_t  version;
    uint16_t  nsets;
    uint32_t  nslots;
    uint32_t  helper_uid;
    uint32_t  helper_gid;
    uint32_t  worker_uid;
    uint32_t  generation;
    uint32_t  debug_delay_ms;                   /* test builds only */
    uint16_t  nrules;
    uint16_t  nprotect;
    uint32_t  zero;
} sw_policy_hdr_t;

typedef struct {
    uint8_t   backend;
    uint8_t   role;
    uint8_t   family;                           /* nft table family, 0 for ipset */
    uint8_t   zero[5];
    char      table[SW_NFT_NAMELEN];            /* nft only; NUL-padded */
    char      name[SW_NFT_NAMELEN];             /* NUL-padded; ipset < 32 */
} sw_policy_set_t;

/* follows the sets */
typedef struct {
    uint8_t   set;
    uint8_t   prefix4;
    uint8_t   prefix6;
    uint8_t   zero;
    uint32_t  timeout;                          /* 0: the set's default */
    uint32_t  rate;                             /* adds per second */
    uint32_t  burst;
} sw_policy_rule_t;

/* follows the rules: the never-ban list */
typedef struct {
    uint8_t   family;                           /* 4 or 6 */
    uint8_t   prefix;
    uint8_t   zero[2];
    uint8_t   addr[16];
} sw_policy_protect_t;


/* ---- ctl channel (master <-> helper) --------------------------------- */

#define SW_CTL_READY            1               /* helper -> master */
#define SW_CTL_DRAIN            2               /* master -> helper */

typedef struct {
    uint16_t  magic;
    uint8_t   version;
    uint8_t   type;
    uint16_t  nsets;
    uint16_t  status;                           /* 0 = ok, else SW_ERR_* */
    uint32_t  kproto_min;
    uint32_t  kproto_max;
} sw_ctl_hdr_t;

typedef struct {
    int32_t   err;                              /* 0, -errno, -IPSET_ERR_*, SW_SETERR_* */
    uint8_t   family;                           /* AF_INET / AF_INET6 / 0 */
    uint8_t   revision;
    uint8_t   has_timeout;
    uint8_t   netmask;                          /* hash:ip netmask, 0 if none */
    char      type[SW_SETNAME_LEN];             /* e.g. "hash:ip" */
    uint32_t  default_timeout;
    uint32_t  zero;
} sw_ready_set_t;

#define SW_SETERR_NO_TIMEOUT    -9001           /* add target without timeout support */
#define SW_SETERR_NEED_TIMEOUT  -9002           /* no timeout given and no set default */
#define SW_SETERR_NFT_KEY       -9003           /* nft set key not ipv4_addr / ipv6_addr */
#define SW_SETERR_NFT_INTERVAL  -9004           /* nft interval set as add target */
#define SW_SETERR_NFT_CONSTANT  -9005           /* nft constant set as add target */

typedef struct {
    sw_ctl_hdr_t  hdr;                          /* type = SW_CTL_DRAIN */
    uint32_t      deadline_s;
    uint32_t      zero;
} sw_drain_t;

/* sw_ctl_hdr_t.status */
#define SW_ERR_NONE             0
#define SW_ERR_POLICY           1
#define SW_ERR_CAPS             2
#define SW_ERR_NETLINK          3
#define SW_ERR_KPROTO           4
#define SW_ERR_SANDBOX          5


/* ---- slot channels (worker <-> helper) ------------------------------- */

#define SW_OP_TEST              1
#define SW_OP_ADD               2

#define SW_ST_OK                0
#define SW_ST_BUSY              1
#define SW_ST_DENIED            2
#define SW_ST_ERROR             3
#define SW_ST_SET_MISSING       4
#define SW_ST_DRAINING          5

/* helper -> worker log frame: req_id 0, status SW_ST_LOG | nginx log level,
 * decided = event, matched = argument */
#define SW_ST_LOG               0x80

#define SW_LOG_TEST_FAILED      1       /* set index | errno << 32 */
#define SW_LOG_SET_MISSING      2       /* set index */
#define SW_LOG_NETLINK          3       /* errno */
#define SW_LOG_VIOLATION        4       /* reason: 1 size, 2 frame, 3 set mask */
#define SW_LOG_ENGINE_EXIT      5       /* wait status */
#define SW_LOG_LANDLOCK         6       /* errno */
#define SW_LOG_GAVE_UP          7       /* crashes */
#define SW_LOG_ADD_PROTECTED    8       /* rule */
#define SW_LOG_ADD_BUDGET       9       /* rule */
#define SW_LOG_ADD_BREAKER      10      /* rule */
#define SW_LOG_ADD_FAILED       11      /* rule | errno << 32 */
#define SW_LOG_SET_FULL         12      /* set index */

typedef struct {
    uint16_t  magic;
    uint8_t   version;
    uint8_t   op;
    uint32_t  req_id;
    uint64_t  arg;                              /* TEST: set bitmask; ADD: rule */
    uint8_t   family;                           /* 4 or 6 */
    uint8_t   zero0[7];
    uint8_t   addr[16];
    uint8_t   zero1[8];
} sw_req_t;

typedef struct {
    uint16_t  magic;
    uint8_t   version;
    uint8_t   status;
    uint32_t  req_id;
    uint64_t  decided;
    uint64_t  matched;
} sw_rep_t;

/* helper -> one worker: an nftables set changed; drop cached answers */
#define SW_ST_INVALIDATE        0x40

typedef struct {
    uint16_t  magic;
    uint8_t   version;
    uint8_t   status;                           /* SW_ST_INVALIDATE */
    uint32_t  req_id;                           /* 0 */
    uint32_t  set;                              /* set index */
    uint8_t   family;                           /* 4, 6; 0: every address */
    uint8_t   zero0[3];
    uint8_t   addr[16];
    uint8_t   zero1[16];
} sw_inval_t;


_Static_assert(sizeof(sw_policy_hdr_t) == 40, "policy hdr");
_Static_assert(sizeof(sw_policy_rule_t) == 16, "policy rule");
_Static_assert(sizeof(sw_policy_protect_t) == 20, "policy protect");
_Static_assert(sizeof(sw_policy_set_t) == 136, "policy set");
_Static_assert(sizeof(sw_ctl_hdr_t) == 16, "ctl hdr");
_Static_assert(sizeof(sw_ready_set_t) == 48, "ready set");
_Static_assert(sizeof(sw_drain_t) == 24, "drain");
_Static_assert(sizeof(sw_req_t) == 48, "req");
_Static_assert(offsetof(sw_req_t, arg) == 8, "req.arg");
_Static_assert(offsetof(sw_req_t, family) == 16, "req.family");
_Static_assert(offsetof(sw_req_t, addr) == 24, "req.addr");
_Static_assert(sizeof(sw_rep_t) == 24, "rep");
_Static_assert(sizeof(sw_inval_t) == 48, "inval");
_Static_assert(offsetof(sw_inval_t, addr) == 16, "inval.addr");

#endif /* SW_PROTO_H */
