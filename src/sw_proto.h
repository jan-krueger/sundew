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

#define SW_PROTO_VERSION        1
#define SW_FRAME_MAGIC          0x5357          /* "SW" */
#define SW_MAX_SETS             64
#define SW_SETNAME_LEN          32              /* IPSET_MAXNAMELEN */

/* helper fd layout */
#define SW_FD_POLICY            3
#define SW_FD_CTL               4
#define SW_FD_SLOT0             5


/* ---- policy (memfd, master -> helper, sealed) ------------------------ */

#define SW_POLICY_MAGIC         0x4c505753      /* "SWPL" */
#define SW_POLICY_VERSION       1

#define SW_ROLE_LOOKUP          1

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
} sw_policy_hdr_t;

typedef struct {
    char      name[SW_SETNAME_LEN];             /* NUL-padded */
    uint8_t   role;
    uint8_t   zero[7];
} sw_policy_set_t;


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
    int32_t   err;                              /* 0, -errno or -IPSET_ERR_* */
    uint8_t   family;                           /* AF_INET / AF_INET6 / 0 */
    uint8_t   revision;
    uint8_t   zero[2];
    char      type[SW_SETNAME_LEN];             /* e.g. "hash:ip" */
} sw_ready_set_t;

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

typedef struct {
    uint16_t  magic;
    uint8_t   version;
    uint8_t   op;
    uint32_t  req_id;
    uint64_t  arg;                              /* TEST: set bitmask */
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


_Static_assert(sizeof(sw_policy_hdr_t) == 32, "policy hdr");
_Static_assert(sizeof(sw_policy_set_t) == 40, "policy set");
_Static_assert(sizeof(sw_ctl_hdr_t) == 16, "ctl hdr");
_Static_assert(sizeof(sw_ready_set_t) == 40, "ready set");
_Static_assert(sizeof(sw_drain_t) == 24, "drain");
_Static_assert(sizeof(sw_req_t) == 48, "req");
_Static_assert(offsetof(sw_req_t, arg) == 8, "req.arg");
_Static_assert(offsetof(sw_req_t, family) == 16, "req.family");
_Static_assert(offsetof(sw_req_t, addr) == 24, "req.addr");
_Static_assert(sizeof(sw_rep_t) == 24, "rep");

#endif /* SW_PROTO_H */
