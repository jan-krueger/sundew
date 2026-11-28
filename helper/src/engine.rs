//! Engine: answers worker requests via netlink.

use crate::keeper::{fail, read_policy, verify};
use crate::nl::{self, Reply};
use crate::proto::{self, Addr, Policy, ReadySet};
use crate::sys::{self, CAP_NET_ADMIN, CapSets, bit};

#[derive(Clone, Copy, PartialEq, Eq)]
enum SetType {
    HashIp,
    HashNet,
    BitmapIp,
}

enum Backend {
    Ipset {
        kind: SetType,
        netmask: u8,
    },
    Nft {
        family: u8, // table family
        table: Vec<u8>,
        /// last time the set was seen to exist
        checked_ms: u64,
    },
}

struct SetInfo {
    name: Vec<u8>,
    family: u8, // address family NFPROTO_IPV4/6, 0 = unusable
    backend: Backend,
    default_timeout: u32,
}

struct Rule {
    set: usize,
    prefix4: u8,
    prefix6: u8,
    timeout: u32,
    rate: f64,
    burst: f64,
    tokens: f64,
    refilled_ms: u64,
    minute_start: u64,
    minute_adds: u32,
    paused_until: u64,
}

struct Engine {
    last_log: [u64; 16],
    nl: i32,
    proto: u8,
    seq: u32,
    sets: Vec<SetInfo>,
    rules: Vec<Rule>,
    protect: Vec<proto::Cidr>,
    recent: std::collections::HashMap<(usize, [u8; 16]), u64>,
    draining: bool,
    /// requests to the kernel, built in place
    wbuf: Vec<u8>,
    /// replies from the kernel, RCHUNK bytes each
    rbuf: Vec<u8>,
    rlens: [(usize, i32); RCHUNKS],
    /// errno per message of the last transact
    res: Vec<i32>,
}

/// A TEST from a worker, waiting for the next batch.
struct Lookup {
    fd: i32,
    req_id: u32,
    mask: u64,
    addr: Addr,
}

const NL_TIMEOUT_MS: i32 = 1000;
const RCHUNK: usize = 8192;
const RCHUNKS: usize = 32;
const PENDING: i32 = i32::MIN;
/// netlink messages per batch; their replies fit sys::NETLINK_RCVBUF
const MAX_BATCH_MSGS: usize = 512;
/// receive slot per worker frame; larger frames are violations
const FRAME_SLOT: usize = 64;
const RECENT_MS: u64 = 10_000;
const BREAKER_PER_MINUTE: u32 = 1000;
const BREAKER_PAUSE_MS: u64 = 600_000;
/// nft lookups answer -ENOENT for a missing set too
const NFT_RECHECK_MS: u64 = 10_000;

fn addr_bytes(addr: &Addr) -> ([u8; 16], bool) {
    match addr {
        Addr::V4(a) => {
            let mut x = [0u8; 16];
            x[..4].copy_from_slice(a);
            (x, false)
        }
        Addr::V6(a) => (*a, true),
    }
}

fn mask(addr: &mut [u8; 16], prefix: u8) {
    for (i, b) in addr.iter_mut().enumerate() {
        let bits = (prefix as usize).saturating_sub(i * 8).min(8);
        *b &= if bits == 0 { 0 } else { 0xffu8 << (8 - bits) };
    }
}

/// True if two prefixes of one family overlap: one contains the other.
fn overlaps(a: &[u8; 16], alen: u8, b: &[u8; 16], blen: u8) -> bool {
    let (mut x, mut y) = (*a, *b);
    let len = alen.min(blen);
    mask(&mut x, len);
    mask(&mut y, len);
    x == y
}

impl Engine {
    /// Log frame to a worker, at most one per event and second.
    fn log(&mut self, fd: i32, level: u8, event: u64, arg: u64) {
        let now = sys::monotonic_ms();
        let slot = (event as usize).min(self.last_log.len() - 1);
        if self.last_log[slot] != 0 && now.saturating_sub(self.last_log[slot]) < 1000 {
            return;
        }
        self.last_log[slot] = now;
        let _ = sys::send(fd, &proto::encode_log(level, event, arg));
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1).max(1);
        self.seq
    }

    /// Sends the messages in `buf`, with sequence numbers `first`..`first + n`,
    /// at once. Errno per message lands in `self.res`. A message completes with
    /// its ACK, or with DONE for dumps.
    fn transact(
        &mut self,
        buf: &[u8],
        first: u32,
        n: usize,
        mut on_data: impl FnMut(u16, u16, &[u8]),
    ) -> Result<(), i32> {
        let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(libc::EIO);
        self.res.clear();
        self.res.resize(n, PENDING);
        if sys::send(self.nl, buf).map_err(errno)? != buf.len() {
            return Err(libc::EMSGSIZE);
        }
        let mut left = n;
        while left > 0 {
            // replies to most requests are queued before send() returns
            let k = match sys::recv_many(self.nl, &mut self.rbuf, RCHUNK, &mut self.rlens) {
                Ok(k) => k,
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {
                    if !sys::poll_in(self.nl, NL_TIMEOUT_MS).map_err(errno)? {
                        log!("netlink timeout");
                        return Err(libc::ETIMEDOUT);
                    }
                    continue;
                }
                Err(e) => {
                    log!("netlink recv: {e}");
                    return Err(errno(e));
                }
            };
            for i in 0..k {
                let (len, flags) = self.rlens[i];
                if flags & libc::MSG_TRUNC != 0 || len > RCHUNK {
                    log!("netlink reply truncated");
                    return Err(libc::EMSGSIZE);
                }
                let res = &mut self.res;
                let r = nl::parse_each(&self.rbuf[i * RCHUNK..i * RCHUNK + len], |r| {
                    let (seq, code) = match r {
                        Reply::Ack { seq, errno } => (seq, errno),
                        Reply::Done { seq } => (seq, 0),
                        Reply::Data { subsys, cmd, attrs } => {
                            on_data(subsys, cmd, attrs);
                            return;
                        }
                    };
                    let i = seq.wrapping_sub(first) as usize;
                    if i < n && res[i] == PENDING {
                        res[i] = code;
                        left -= 1;
                    }
                });
                if let Err(e) = r {
                    log!("netlink parse: {e}");
                    return Err(libc::EPROTO);
                }
            }
        }
        Ok(())
    }

    /// One request message, built by `build` into the reused buffer.
    fn transact_one(
        &mut self,
        build: impl FnOnce(&mut Vec<u8>, u32),
        on_data: impl FnMut(u16, u16, &[u8]),
    ) -> Result<i32, i32> {
        let seq = self.next_seq();
        let mut buf = std::mem::take(&mut self.wbuf);
        buf.clear();
        build(&mut buf, seq);
        let r = self.transact(&buf, seq, 1, on_data);
        self.wbuf = buf;
        r.map(|()| self.res[0])
    }

    fn negotiate(&mut self) -> (u8, u8) {
        let (mut kmin, mut kmax) = (0u8, 0u8);
        let r = self.transact_one(nl::msg_protocol, |sub, cmd, attrs| {
            if sub != nl::NFNL_SUBSYS_IPSET || cmd != nl::IPSET_CMD_PROTOCOL {
                return;
            }
            for (ty, v) in nl::attrs(attrs).flatten() {
                match (ty, v) {
                    (nl::IPSET_ATTR_PROTOCOL, [p, ..]) => kmax = *p,
                    (nl::IPSET_ATTR_PROTOCOL_MIN, [p, ..]) => kmin = *p,
                    _ => {}
                }
            }
        });
        match r {
            Ok(0) if kmax >= nl::IPSET_PROTOCOL_MIN => {}
            Ok(v) => fail(
                proto::ERR_KPROTO,
                &format!("ipset protocol query failed ({v})"),
                None,
            ),
            Err(_) => fail(proto::ERR_NETLINK, "ipset protocol query failed", None),
        }
        if kmin == 0 {
            kmin = kmax;
        }
        (kmin, kmax)
    }

    /// Type, family and create options of one set (header-only LIST).
    fn describe(&mut self, name: &[u8]) -> (ReadySet, Option<SetType>) {
        let mut rs = ReadySet::default();
        let mut messages = 0;
        let proto = self.proto;
        let build = |b: &mut Vec<u8>, seq| nl::msg_list_header(b, seq, proto, name);
        let r = self.transact_one(build, |sub, cmd, attrs| {
            if sub != nl::NFNL_SUBSYS_IPSET || cmd != nl::IPSET_CMD_LIST {
                return;
            }
            messages += 1;
            for (ty, v) in nl::attrs(attrs).flatten() {
                match ty {
                    nl::IPSET_ATTR_TYPENAME => {
                        let s = v.split(|&c| c == 0).next().unwrap_or(&[]);
                        let n = s.len().min(proto::SETNAME_LEN - 1);
                        rs.type_name[..n].copy_from_slice(&s[..n]);
                    }
                    nl::IPSET_ATTR_REVISION => rs.revision = v.first().copied().unwrap_or(0),
                    nl::IPSET_ATTR_FAMILY => rs.family = v.first().copied().unwrap_or(0),
                    nl::IPSET_ATTR_DATA => {
                        for (dty, dv) in nl::attrs(v).flatten() {
                            match (dty, dv) {
                                (nl::IPSET_ATTR_TIMEOUT, [a, b, c, d]) => {
                                    rs.has_timeout = true;
                                    rs.default_timeout = u32::from_be_bytes([*a, *b, *c, *d]);
                                }
                                (nl::IPSET_ATTR_NETMASK, [m, ..]) => rs.netmask = *m,
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        });
        rs.err = r.unwrap_or_else(|e| -e);
        if rs.err == 0 && messages != 1 {
            rs.err = -libc::EPROTO;
        }
        let tn = rs.type_name.split(|&c| c == 0).next().unwrap_or(&[]);
        let kind = match tn {
            b"hash:ip" => Some(SetType::HashIp),
            b"hash:net" => Some(SetType::HashNet),
            b"bitmap:ip" => Some(SetType::BitmapIp),
            _ => None,
        };
        if rs.err == 0
            && (kind.is_none() || !(rs.family == nl::NFPROTO_IPV4 || rs.family == nl::NFPROTO_IPV6))
        {
            rs.err = -libc::EOPNOTSUPP;
        }
        (rs, kind)
    }

    /// Flags, key and default timeout of one nft set (GETSET).
    fn describe_nft(
        &mut self,
        family: u8,
        table: &[u8],
        name: &[u8],
        role: u8,
    ) -> (ReadySet, bool) {
        let (mut flags, mut ktype, mut klen, mut map, mut timeout_ms, mut messages) =
            (0u32, 0u32, 0u32, false, 0u64, 0);
        let build = |b: &mut Vec<u8>, seq| nl::msg_nft_getset(b, seq, family, table, name);
        let be32 = |v: &[u8]| v.try_into().map(u32::from_be_bytes).unwrap_or(u32::MAX);
        let r = self.transact_one(build, |sub, cmd, attrs| {
            if sub != nl::NFNL_SUBSYS_NFTABLES || cmd != nl::NFT_MSG_NEWSET {
                return;
            }
            messages += 1;
            for (ty, v) in nl::attrs(attrs).flatten() {
                match ty {
                    nl::NFTA_SET_FLAGS => flags = be32(v),
                    nl::NFTA_SET_KEY_TYPE => ktype = be32(v),
                    nl::NFTA_SET_KEY_LEN => klen = be32(v),
                    nl::NFTA_SET_DATA_TYPE => map = true,
                    nl::NFTA_SET_TIMEOUT => {
                        timeout_ms = v.try_into().map(u64::from_be_bytes).unwrap_or(0)
                    }
                    _ => {}
                }
            }
        });
        let mut rs = ReadySet {
            err: r.unwrap_or_else(|e| -e),
            ..ReadySet::default()
        };
        if rs.err == 0 && messages != 1 {
            rs.err = -libc::EPROTO;
        }
        if rs.err != 0 {
            return (rs, false);
        }
        let interval = flags & nl::NFT_SET_INTERVAL != 0;
        rs.family = match (ktype, klen) {
            (nl::NFT_TYPE_IPADDR, 4) => nl::NFPROTO_IPV4,
            (nl::NFT_TYPE_IP6ADDR, 16) => nl::NFPROTO_IPV6,
            _ => 0,
        };
        let tn: &[u8] = if interval { b"nft interval" } else { b"nft" };
        rs.type_name[..tn.len()].copy_from_slice(tn);
        rs.has_timeout = flags & nl::NFT_SET_TIMEOUT != 0;
        rs.default_timeout = timeout_ms.div_ceil(1000).min(proto::MAX_TIMEOUT as u64) as u32;
        let unsupported =
            nl::NFT_SET_ANONYMOUS | nl::NFT_SET_MAP | nl::NFT_SET_OBJECT | nl::NFT_SET_CONCAT;
        if rs.family == 0 || map || flags & unsupported != 0 {
            rs.err = proto::SETERR_NFT_KEY;
        } else if role & proto::ROLE_ADD != 0 && interval {
            rs.err = proto::SETERR_NFT_INTERVAL;
        } else if role & proto::ROLE_ADD != 0 && flags & nl::NFT_SET_CONSTANT != 0 {
            rs.err = proto::SETERR_NFT_CONSTANT;
        }
        (rs, interval)
    }

    /// Answers `lookups` with one netlink round trip; replies go to `out`.
    fn lookup_batch(&mut self, lookups: &[Lookup], out: &mut Vec<(i32, [u8; proto::REP_LEN])>) {
        let total: u64 = lookups.iter().map(|l| l.mask.count_ones() as u64).sum();
        if self.seq as u64 + total >= u32::MAX as u64 {
            // consecutive numbers for the whole batch
            self.seq = 0;
        }
        let first = self.seq + 1;
        let mut buf = std::mem::take(&mut self.wbuf);
        buf.clear();
        let mut n = 0;
        for l in lookups {
            for i in 0..self.sets.len() {
                if l.mask & (1u64 << i) == 0 {
                    continue;
                }
                let seq = self.next_seq();
                let set = &self.sets[i];
                match &set.backend {
                    Backend::Ipset { .. } => {
                        nl::msg_test(&mut buf, seq, self.proto, &set.name, &l.addr)
                    }
                    Backend::Nft { family, table, .. } => nl::msg_nft_get(
                        &mut buf,
                        seq,
                        *family,
                        table,
                        &set.name,
                        addr_slice(&l.addr),
                    ),
                }
                n += 1;
            }
        }
        let r = self.transact(&buf, first, n, |_, _, _| {});
        self.wbuf = buf;
        if let Err(errno) = r {
            for l in lookups {
                self.log(l.fd, proto::LVL_ERR, proto::LOG_NETLINK, errno as u64);
                out.push((l.fd, proto::encode_rep(proto::ST_ERROR, l.req_id, 0, 0)));
            }
            return;
        }
        let res = std::mem::take(&mut self.res);
        let now = sys::monotonic_ms();
        let mut k = 0;
        for l in lookups {
            let (mut decided, mut matched) = (0u64, 0u64);
            for i in 0..self.sets.len() {
                if l.mask & (1u64 << i) == 0 {
                    continue;
                }
                let errno = res[k];
                k += 1;
                let b = 1u64 << i;
                let nft = match self.sets[i].backend {
                    Backend::Nft { checked_ms, .. } => Some(checked_ms),
                    Backend::Ipset { .. } => None,
                };
                match errno {
                    0 => {
                        decided |= b;
                        matched |= b;
                    }
                    e if nft.is_none() && e == -nl::IPSET_ERR_EXIST => decided |= b,
                    e if e == -libc::ENOENT
                        && nft.is_some_and(|t| now.saturating_sub(t) < NFT_RECHECK_MS) =>
                    {
                        decided |= b
                    }
                    e if e == -libc::ENOENT && nft.is_some() && self.nft_exists(i, now) => {
                        decided |= b
                    }
                    e if e == -libc::ENOENT => {
                        self.log(l.fd, proto::LVL_ERR, proto::LOG_SET_MISSING, i as u64)
                    }
                    e => self.log(
                        l.fd,
                        proto::LVL_ERR,
                        proto::LOG_TEST_FAILED,
                        i as u64 | ((-e) as u32 as u64) << 32,
                    ),
                }
            }
            out.push((
                l.fd,
                proto::encode_rep(proto::ST_OK, l.req_id, decided, matched),
            ));
        }
        self.res = res;
    }

    /// Re-check after -ENOENT that an nft set still exists and fits.
    fn nft_exists(&mut self, i: usize, now: u64) -> bool {
        let Backend::Nft {
            family, ref table, ..
        } = self.sets[i].backend
        else {
            return false;
        };
        let (table, name, want) = (
            table.clone(),
            self.sets[i].name.clone(),
            self.sets[i].family,
        );
        let (rs, _) = self.describe_nft(family, &table, &name, proto::ROLE_LOOKUP);
        let ok = rs.err == 0 && rs.family == want;
        if ok {
            if let Backend::Nft { checked_ms, .. } = &mut self.sets[i].backend {
                *checked_ms = now;
            }
        }
        ok
    }

    fn mask_valid(&self, mask: u64, addr: &Addr) -> bool {
        let fam = family_of(addr);
        if self.sets.len() < 64 && mask >> self.sets.len() != 0 {
            return false;
        }
        (0..self.sets.len()).all(|i| mask & (1u64 << i) == 0 || self.sets[i].family == fam)
    }

    fn rule_valid(&self, rule: u64, addr: &Addr) -> bool {
        (rule as usize) < self.rules.len()
            && self.sets[self.rules[rule as usize].set].family == family_of(addr)
    }

    /// Token bucket and circuit breaker of one rule.
    fn admit(&mut self, fd: i32, r: usize, now: u64) -> bool {
        let rule = &mut self.rules[r];
        if now < rule.paused_until {
            return false;
        }
        if now.saturating_sub(rule.minute_start) >= 60_000 {
            rule.minute_start = now;
            rule.minute_adds = 0;
        }
        rule.tokens = (rule.tokens
            + now.saturating_sub(rule.refilled_ms) as f64 * rule.rate / 1000.0)
            .min(rule.burst);
        rule.refilled_ms = now;
        if rule.tokens < 1.0 {
            self.log(fd, proto::LVL_WARN, proto::LOG_ADD_BUDGET, r as u64);
            return false;
        }
        rule.tokens -= 1.0;
        rule.minute_adds += 1;
        if rule.minute_adds > BREAKER_PER_MINUTE {
            rule.paused_until = now + BREAKER_PAUSE_MS;
            self.log(fd, proto::LVL_ALERT, proto::LOG_ADD_BREAKER, r as u64);
            return false;
        }
        true
    }

    /// (status, decided)
    fn add(&mut self, fd: i32, r: usize, addr: &Addr) -> (u8, u64) {
        if self.draining {
            return (proto::ST_DRAINING, 0);
        }
        let rule = &self.rules[r];
        let set = &self.sets[rule.set];
        let (mut elem, v6) = addr_bytes(addr);
        let host = if v6 { 128 } else { 32 };
        let (prefix, cidr) = match set.backend {
            Backend::Ipset {
                kind: SetType::HashNet,
                ..
            } => {
                let p = if v6 { rule.prefix6 } else { rule.prefix4 };
                (p, (p < host).then_some(p))
            }
            Backend::Ipset {
                kind: SetType::HashIp,
                netmask,
            } if netmask != 0 => (netmask.min(host), None),
            _ => (host, None),
        };
        mask(&mut elem, prefix);

        if self
            .protect
            .iter()
            .any(|c| c.v6 == v6 && overlaps(&elem, prefix, &c.addr, c.prefix))
        {
            self.log(fd, proto::LVL_WARN, proto::LOG_ADD_PROTECTED, r as u64);
            return (proto::ST_DENIED, 0);
        }

        let now = sys::monotonic_ms();
        if let Some(&t) = self.recent.get(&(r, elem)) {
            if now.saturating_sub(t) < RECENT_MS {
                return (proto::ST_OK, 1);
            }
        }
        if !self.admit(fd, r, now) {
            return (proto::ST_DENIED, 0);
        }

        let rule = &self.rules[r];
        let timeout = rule.timeout;
        let set_idx = rule.set;
        let target = if v6 {
            Addr::V6(elem)
        } else {
            Addr::V4([elem[0], elem[1], elem[2], elem[3]])
        };
        let nft = matches!(self.sets[set_idx].backend, Backend::Nft { .. });
        if nft {
            // the batch around the add takes the numbers either side
            self.next_seq();
        }
        let seq = self.next_seq();
        if nft {
            self.next_seq();
        }
        let mut buf = std::mem::take(&mut self.wbuf);
        buf.clear();
        let set = &self.sets[set_idx];
        match &set.backend {
            Backend::Ipset { .. } => {
                nl::msg_add(&mut buf, seq, self.proto, &set.name, &target, cidr, timeout)
            }
            Backend::Nft { family, table, .. } => nl::msg_nft_add(
                &mut buf,
                seq,
                *family,
                table,
                &set.name,
                addr_slice(&target),
                timeout as u64 * 1000,
            ),
        }
        let sent = self.transact(&buf, seq, 1, |_, _, _| {});
        self.wbuf = buf;
        let res = match sent {
            Ok(()) => self.res[0],
            Err(errno) => {
                self.log(fd, proto::LVL_ERR, proto::LOG_NETLINK, errno as u64);
                return (proto::ST_ERROR, 0);
            }
        };
        let (exist, full) = if nft {
            (-libc::EEXIST, -libc::ENFILE)
        } else {
            (-nl::IPSET_ERR_EXIST, -nl::IPSET_ERR_HASH_FULL)
        };
        match res {
            0 => {}
            e if e == exist => {}
            e if e == -libc::ENOENT => {
                self.log(fd, proto::LVL_ERR, proto::LOG_SET_MISSING, set_idx as u64);
                return (proto::ST_SET_MISSING, 0);
            }
            e if e == full => {
                self.log(fd, proto::LVL_ERR, proto::LOG_SET_FULL, set_idx as u64);
                return (proto::ST_ERROR, 0);
            }
            e => {
                self.log(
                    fd,
                    proto::LVL_ERR,
                    proto::LOG_ADD_FAILED,
                    r as u64 | ((-e) as u32 as u64) << 32,
                );
                return (proto::ST_ERROR, 0);
            }
        }

        if self.recent.len() > 4096 {
            self.recent
                .retain(|_, t| now.saturating_sub(*t) < RECENT_MS);
        }
        self.recent.insert((r, elem), now);
        (proto::ST_OK, 1)
    }
}

fn addr_slice(addr: &Addr) -> &[u8] {
    match addr {
        Addr::V4(a) => a,
        Addr::V6(a) => a,
    }
}

fn family_of(addr: &Addr) -> u8 {
    match addr {
        Addr::V4(_) => nl::NFPROTO_IPV4,
        Addr::V6(_) => nl::NFPROTO_IPV6,
    }
}

/// Returns the Landlock errno, if Landlock could not be enforced.
fn harden() -> Option<i32> {
    let _ = sys::prctl(libc::PR_SET_DUMPABLE, 0, 0);
    // debug builds of the module log to the error log via stderr
    let stderr_is_file = sys::fstat(2).is_ok_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFREG);
    for (res, v) in [
        (libc::RLIMIT_CORE, 0),
        (
            libc::RLIMIT_FSIZE,
            if stderr_is_file {
                libc::RLIM_INFINITY
            } else {
                0
            },
        ),
        (libc::RLIMIT_NPROC, 0),
    ] {
        if let Err(e) = sys::set_rlimit(res, v) {
            fail(proto::ERR_SANDBOX, "setrlimit", Some(e));
        }
    }

    #[cfg(target_arch = "x86_64")]
    let arch_only: &[libc::c_long] = &[libc::SYS_epoll_wait, libc::SYS_poll];
    #[cfg(not(target_arch = "x86_64"))]
    let arch_only: &[libc::c_long] = &[];

    let mut allow: Vec<libc::c_long> = vec![
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_sendmmsg,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_ctl,
        libc::SYS_ppoll,
        libc::SYS_close,
        libc::SYS_shutdown,
        libc::SYS_clock_gettime,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_brk,
        libc::SYS_madvise,
        libc::SYS_getrandom,
        libc::SYS_futex,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_write,
        libc::SYS_tgkill,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_restart_syscall,
    ];
    allow.extend_from_slice(arch_only);

    let landlock = sys::landlock_deny_all();
    match &landlock {
        Ok(abi) => log!("landlock enforced (abi {abi})"),
        Err(e) => log!("landlock unavailable: {e}"),
    }

    if let Err(e) = sys::seccomp_allowlist(&allow, &[libc::SYS_clone3]) {
        fail(proto::ERR_SANDBOX, "seccomp", Some(e));
    }

    landlock
        .err()
        .map(|e| e.raw_os_error().unwrap_or(libc::EIO))
}

pub fn run(restarted: bool) -> ! {
    sys::set_name(c"sundew-engine");
    let policy: Policy = read_policy();
    let last_cap =
        sys::cap_last_cap().unwrap_or_else(|e| fail(proto::ERR_CAPS, "cap_last_cap", Some(e)));

    if let Err(e) = sys::prctl(
        libc::PR_CAP_AMBIENT,
        libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
        0,
    ) {
        fail(proto::ERR_CAPS, "PR_CAP_AMBIENT_CLEAR_ALL", Some(e));
    }
    let na = bit(CAP_NET_ADMIN);
    if let Err(e) = sys::capset(CapSets {
        effective: na,
        permitted: na,
        inheritable: 0,
    }) {
        fail(proto::ERR_CAPS, "capset", Some(e));
    }
    verify(&policy, last_cap, false);

    log!(
        "engine up (generation {}, restarted={restarted})",
        policy.generation
    );

    let nlfd = sys::netlink_socket()
        .unwrap_or_else(|e| fail(proto::ERR_NETLINK, "netlink socket", Some(e)));

    let mut eng = Engine {
        last_log: [0; 16],
        nl: nlfd,
        proto: nl::IPSET_PROTOCOL,
        seq: 0,
        sets: Vec::new(),
        rules: Vec::new(),
        protect: policy.protect.clone(),
        recent: std::collections::HashMap::new(),
        draining: false,
        wbuf: Vec::with_capacity(MAX_BATCH_MSGS * 80),
        rbuf: vec![0u8; RCHUNK * RCHUNKS],
        rlens: [(0, 0); RCHUNKS],
        res: Vec::with_capacity(MAX_BATCH_MSGS),
    };
    // nft-only configurations work without the ip_set module
    let (kmin, kmax) = if policy
        .sets
        .iter()
        .any(|s| s.backend == proto::BACKEND_IPSET)
    {
        eng.negotiate()
    } else {
        (0, 0)
    };
    eng.proto = kmax.min(nl::IPSET_PROTOCOL);

    let mut ready = Vec::new();
    let now = sys::monotonic_ms();
    for s in &policy.sets {
        let (mut rs, backend) = if s.backend == proto::BACKEND_NFT {
            let (rs, _) = eng.describe_nft(s.family, &s.table, &s.name, s.role);
            let b = Backend::Nft {
                family: s.family,
                table: s.table.clone(),
                checked_ms: now,
            };
            (rs, b)
        } else {
            let (rs, kind) = eng.describe(&s.name);
            let b = Backend::Ipset {
                kind: kind.unwrap_or(SetType::HashIp),
                netmask: rs.netmask,
            };
            (rs, b)
        };
        if rs.err == 0 && s.role & proto::ROLE_ADD != 0 && !rs.has_timeout {
            rs.err = proto::SETERR_NO_TIMEOUT;
        }
        eng.sets.push(SetInfo {
            name: s.name.clone(),
            family: if rs.err == 0 { rs.family } else { 0 },
            backend,
            default_timeout: rs.default_timeout,
        });
        ready.push(rs);
    }

    for r in &policy.rules {
        let set = &eng.sets[r.set];
        let timeout = if r.timeout != 0 {
            r.timeout
        } else {
            set.default_timeout
        };
        if ready[r.set].err == 0 && timeout == 0 {
            ready[r.set].err = proto::SETERR_NEED_TIMEOUT;
        }
        eng.rules.push(Rule {
            set: r.set,
            prefix4: r.prefix4,
            prefix6: r.prefix6,
            timeout: timeout.min(proto::MAX_TIMEOUT),
            rate: r.rate as f64,
            burst: r.burst as f64,
            tokens: r.burst as f64,
            refilled_ms: now,
            minute_start: now,
            minute_adds: 0,
            paused_until: 0,
        });
    }

    if !restarted {
        let msg = proto::encode_ready(proto::ERR_NONE, kmin as u32, kmax as u32, &ready);
        if sys::send(proto::FD_CTL, &msg).is_err() {
            sys::exit(2);
        }
        if ready.iter().any(|r| r.err != 0) {
            sys::exit(2);
        }
    }

    let ep =
        sys::epoll_create().unwrap_or_else(|e| fail(proto::ERR_SANDBOX, "epoll_create", Some(e)));
    let _ = sys::epoll_add(ep, proto::FD_CTL);
    let mut open_slots = 0u32;
    for i in 0..policy.nslots as i32 {
        if sys::epoll_add(ep, proto::FD_SLOT0 + i).is_ok() {
            open_slots += 1;
        }
    }

    if let Some(errno) = harden() {
        let log = proto::encode_log(proto::LVL_NOTICE, proto::LOG_LANDLOCK, errno as u64);
        sys::send_first(proto::FD_SLOT0, policy.nslots as i32, &log);
    }

    if policy.debug_delay_ms != 0 && !cfg!(feature = "test-delay") {
        fail(
            proto::ERR_POLICY,
            "sundew_debug_delay needs a test-delay build",
            None,
        );
    }
    let delay = policy.debug_delay_ms as u64;
    let mut delayed: std::collections::VecDeque<(u64, i32, [u8; proto::REP_LEN])> =
        std::collections::VecDeque::new();

    let mut ctl_open = true;
    let mut lookups: Vec<Lookup> = Vec::with_capacity(256);
    let mut replies: Vec<(i32, [u8; proto::REP_LEN])> = Vec::with_capacity(256);
    let mut closed: Vec<i32> = Vec::new();
    let mut deadline: Option<u64> = None;
    let mut evs = [libc::epoll_event { events: 0, u64: 0 }; 32];
    let mut fbuf = [0u8; 256];
    let mut frames = [0u8; FRAME_SLOT * 64];
    let mut flens = [(0usize, 0i32); 64];
    let mut out = [[0u8; proto::REP_LEN]; 64];

    loop {
        let now = sys::monotonic_ms();
        while let Some(&(due, fd, rep)) = delayed.front() {
            if due > now {
                break;
            }
            delayed.pop_front();
            let _ = sys::send(fd, &rep);
        }

        let mut timeout = match deadline {
            Some(d) => {
                if now >= d {
                    sys::exit(0);
                }
                (d - now).min(i32::MAX as u64) as i32
            }
            None => -1,
        };
        if let Some(&(due, _, _)) = delayed.front() {
            let t = due.saturating_sub(now) as i32;
            timeout = if timeout < 0 { t } else { timeout.min(t) };
        }

        let n = match sys::epoll_wait(ep, &mut evs, timeout) {
            Ok(n) => n,
            Err(_) => sys::exit(1),
        };

        lookups.clear();
        replies.clear();
        closed.clear();
        let mut batch_msgs = 0usize;

        for ev in &evs[..n] {
            let fd = ev.u64 as i32;

            if fd == proto::FD_CTL {
                match sys::recv(fd, &mut fbuf) {
                    Ok((0, _)) | Err(_) if ctl_open => {
                        sys::epoll_del(ep, fd);
                        ctl_open = false;
                    }
                    Ok((len, flags)) if flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0 => {
                        match proto::decode_drain(&fbuf[..len.min(fbuf.len())]) {
                            Ok(0) => sys::exit(0),
                            Ok(s) => {
                                eng.draining = true;
                                deadline = Some(sys::monotonic_ms() + s as u64 * 1000);
                            }
                            Err(e) => log!("bad ctl frame: {e}"),
                        }
                    }
                    _ => {}
                }
                continue;
            }

            // up to 64 frames per worker and pass, as before
            let got = match sys::recv_frames(fd, &mut frames, FRAME_SLOT, &mut flens) {
                Ok(k) => k,
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => continue,
                Err(_) => 0,
            };
            for i in 0..got.max(1) {
                let (len, flags) = if got == 0 { (0, 0) } else { flens[i] };
                let fbuf = &frames[i * FRAME_SLOT..i * FRAME_SLOT + len.min(FRAME_SLOT)];
                let close: Option<Option<u64>> = match (len, flags) {
                    (0, _) => Some(None),
                    (len, flags)
                        if flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
                            || len != proto::REQ_LEN =>
                    {
                        Some(Some(proto::VIOLATION_SIZE))
                    }
                    _ => match proto::decode_req(fbuf) {
                        Ok(req)
                            if req.op == proto::OP_TEST && eng.mask_valid(req.arg, &req.addr) =>
                        {
                            let k = req.arg.count_ones() as usize;
                            if batch_msgs + k > MAX_BATCH_MSGS && !lookups.is_empty() {
                                eng.lookup_batch(&lookups, &mut replies);
                                lookups.clear();
                                batch_msgs = 0;
                            }
                            lookups.push(Lookup {
                                fd,
                                req_id: req.req_id,
                                mask: req.arg,
                                addr: req.addr,
                            });
                            batch_msgs += k;
                            None
                        }
                        Ok(req)
                            if req.op == proto::OP_ADD && eng.rule_valid(req.arg, &req.addr) =>
                        {
                            let (st, d) = eng.add(fd, req.arg as usize, &req.addr);
                            replies.push((fd, proto::encode_rep(st, req.req_id, d, 0)));
                            None
                        }
                        Ok(_) => Some(Some(proto::VIOLATION_MASK)),
                        Err(_) => Some(Some(proto::VIOLATION_FRAME)),
                    },
                };

                if let Some(reason) = close {
                    close_slot(ep, fd, reason);
                    closed.push(fd);
                    open_slots -= 1;
                    // nothing more goes to this descriptor number
                    lookups.retain(|l| l.fd != fd);
                    replies.retain(|r| r.0 != fd);
                    batch_msgs = lookups.iter().map(|l| l.mask.count_ones() as usize).sum();
                    break;
                }
            }
        }

        if !lookups.is_empty() {
            eng.lookup_batch(&lookups, &mut replies);
        }

        // one call per worker
        replies.sort_by_key(|r| r.0);
        let mut i = 0;
        while i < replies.len() {
            let fd = replies[i].0;
            let mut j = i;
            while j < replies.len() && replies[j].0 == fd && j - i < 64 {
                out[j - i] = replies[j].1;
                j += 1;
            }
            let run = &out[..j - i];
            i = j;
            if closed.contains(&fd) {
                continue;
            }
            if delay > 0 {
                let due = sys::monotonic_ms() + delay;
                delayed.extend(run.iter().map(|rep| (due, fd, *rep)));
                continue;
            }
            match sys::send_frames(fd, run) {
                // a full channel drops the rest; those lookups time out
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {}
                Err(_) => {
                    close_slot(ep, fd, None);
                    closed.push(fd);
                    open_slots -= 1;
                }
            }
        }

        if open_slots == 0 {
            sys::exit(0);
        }
    }
}

fn close_slot(ep: i32, fd: i32, violation: Option<u64>) {
    if let Some(reason) = violation {
        log!("protocol violation on fd {fd} ({reason})");
        let _ = sys::send(
            fd,
            &proto::encode_log(proto::LVL_ALERT, proto::LOG_VIOLATION, reason),
        );
    }
    sys::epoll_del(ep, fd);
    sys::shutdown(fd); // the keeper holds a duplicate
    sys::close(fd);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a4(x: [u8; 4]) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&x);
        a
    }

    #[test]
    fn overlap() {
        assert!(overlaps(&a4([10, 1, 2, 3]), 32, &a4([10, 0, 0, 0]), 8));
        assert!(overlaps(&a4([10, 0, 0, 0]), 8, &a4([10, 1, 2, 3]), 32));
        assert!(!overlaps(&a4([11, 0, 0, 1]), 32, &a4([10, 0, 0, 0]), 8));
        // a /8 ban would cover a protected /16 inside it
        assert!(overlaps(&a4([192, 0, 0, 0]), 8, &a4([192, 168, 0, 0]), 16));
        assert!(!overlaps(
            &a4([192, 0, 2, 1]),
            32,
            &a4([192, 168, 0, 0]),
            16
        ));
    }

    #[test]
    fn masking() {
        let mut a = a4([198, 51, 100, 77]);
        mask(&mut a, 24);
        assert_eq!(&a[..4], &[198, 51, 100, 0]);
        let mut b = [0xffu8; 16];
        mask(&mut b, 64);
        assert_eq!(
            b,
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }
}
