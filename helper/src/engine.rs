//! Engine: answers worker requests via netlink.

use crate::keeper::{fail, read_policy, verify};
use crate::nl::{self, Reply};
use crate::proto::{self, Addr, Policy, ReadySet};
use crate::sys::{self, CAP_NET_ADMIN, CapSets, bit};

struct SetInfo {
    name: Vec<u8>,
    family: u8, // NFPROTO_*, 0 = unusable
}

struct Engine {
    nl: i32,
    proto: u8,
    seq: u32,
    sets: Vec<SetInfo>,
    rbuf: Vec<u8>,
}

const SUPPORTED_TYPES: &[&[u8]] = &[b"hash:ip", b"hash:net", b"bitmap:ip"];
const NL_TIMEOUT_MS: i32 = 1000;

impl Engine {
    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1).max(1);
        self.seq
    }

    /// Returns errno per message; None on timeout or socket error.
    fn transact(
        &mut self,
        msgs: &[(u32, Vec<u8>)],
        mut on_data: impl FnMut(u32, u16, &[u8]),
    ) -> Option<Vec<i32>> {
        for (_, m) in msgs {
            if sys::send(self.nl, m).ok()? != m.len() {
                return None;
            }
        }
        let mut res: Vec<Option<i32>> = vec![None; msgs.len()];
        let mut left = msgs.len();
        while left > 0 {
            if !sys::poll_in(self.nl, NL_TIMEOUT_MS).ok()? {
                eprintln!("sundew-helper: netlink timeout");
                return None;
            }
            let (n, flags) = match sys::recv(self.nl, &mut self.rbuf) {
                Ok(x) => x,
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => continue,
                Err(e) => {
                    eprintln!("sundew-helper: netlink recv: {e}");
                    return None;
                }
            };
            if flags & libc::MSG_TRUNC != 0 || n > self.rbuf.len() {
                eprintln!("sundew-helper: netlink reply truncated");
                return None;
            }
            let replies = match nl::parse(&self.rbuf[..n]) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("sundew-helper: netlink parse: {e}");
                    return None;
                }
            };
            for r in replies {
                match r {
                    Reply::Ack { seq, errno } => {
                        if let Some(i) = msgs.iter().position(|(s, _)| *s == seq) {
                            if res[i].is_none() {
                                res[i] = Some(errno);
                                left -= 1;
                            }
                        }
                    }
                    Reply::Data { seq, cmd, attrs } => on_data(seq, cmd, attrs),
                    Reply::Done => {}
                }
            }
        }
        Some(res.into_iter().map(|r| r.unwrap_or(-libc::EIO)).collect())
    }

    fn negotiate(&mut self) -> (u8, u8) {
        let seq = self.next_seq();
        let (mut kmin, mut kmax) = (0u8, 0u8);
        let r = self.transact(&[(seq, nl::msg_protocol(seq))], |_, cmd, attrs| {
            if cmd != nl::IPSET_CMD_PROTOCOL {
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
            Some(v) if v[0] == 0 && kmax >= nl::IPSET_PROTOCOL_MIN => {}
            Some(v) => fail(
                proto::ERR_KPROTO,
                &format!("ipset protocol query failed ({})", v[0]),
                None,
            ),
            None => fail(proto::ERR_NETLINK, "ipset protocol query timed out", None),
        }
        if kmin == 0 {
            kmin = kmax;
        }
        (kmin, kmax)
    }

    fn header(&mut self, name: &[u8]) -> ReadySet {
        let seq = self.next_seq();
        let mut rs = ReadySet::default();
        let msg = nl::msg_header(seq, self.proto, name);
        let r = self.transact(&[(seq, msg)], |_, cmd, attrs| {
            if cmd != nl::IPSET_CMD_HEADER {
                return;
            }
            for (ty, v) in nl::attrs(attrs).flatten() {
                match ty {
                    nl::IPSET_ATTR_TYPENAME => {
                        let s = v.split(|&c| c == 0).next().unwrap_or(&[]);
                        let n = s.len().min(proto::SETNAME_LEN - 1);
                        rs.type_name[..n].copy_from_slice(&s[..n]);
                    }
                    nl::IPSET_ATTR_REVISION => rs.revision = v.first().copied().unwrap_or(0),
                    nl::IPSET_ATTR_FAMILY => rs.family = v.first().copied().unwrap_or(0),
                    _ => {}
                }
            }
        });
        rs.err = match r {
            Some(v) => v[0],
            None => -libc::ETIMEDOUT,
        };
        if rs.err == 0 {
            let tn = rs.type_name.split(|&c| c == 0).next().unwrap_or(&[]);
            if !SUPPORTED_TYPES.contains(&tn)
                || !(rs.family == nl::NFPROTO_IPV4 || rs.family == nl::NFPROTO_IPV6)
            {
                rs.err = -libc::EOPNOTSUPP;
            }
        }
        rs
    }

    /// (status, decided, matched)
    fn test(&mut self, mask: u64, addr: &Addr) -> (u8, u64, u64) {
        let mut msgs = Vec::new();
        let mut idx = Vec::new();
        for i in 0..self.sets.len() {
            if mask & (1u64 << i) != 0 {
                let seq = self.next_seq();
                let m = nl::msg_test(seq, self.proto, &self.sets[i].name, addr);
                msgs.push((seq, m));
                idx.push(i);
            }
        }
        let Some(res) = self.transact(&msgs, |_, _, _| {}) else {
            return (proto::ST_ERROR, 0, 0);
        };
        let (mut decided, mut matched) = (0u64, 0u64);
        for (k, errno) in res.into_iter().enumerate() {
            let b = 1u64 << idx[k];
            match errno {
                0 => {
                    decided |= b;
                    matched |= b;
                }
                e if e == -nl::IPSET_ERR_EXIST => decided |= b,
                e => eprintln!(
                    "sundew-helper: TEST {} failed: {}",
                    String::from_utf8_lossy(&self.sets[idx[k]].name),
                    e
                ),
            }
        }
        (proto::ST_OK, decided, matched)
    }

    fn mask_valid(&self, mask: u64, addr: &Addr) -> bool {
        let fam = match addr {
            Addr::V4(_) => nl::NFPROTO_IPV4,
            Addr::V6(_) => nl::NFPROTO_IPV6,
        };
        if self.sets.len() < 64 && mask >> self.sets.len() != 0 {
            return false;
        }
        (0..self.sets.len()).all(|i| mask & (1u64 << i) == 0 || self.sets[i].family == fam)
    }
}

fn harden() {
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

    if let Err(e) = sys::seccomp_allowlist(&allow, &[libc::SYS_clone3]) {
        fail(proto::ERR_SANDBOX, "seccomp", Some(e));
    }
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

    eprintln!(
        "sundew-helper: engine up (generation {}, restarted={restarted})",
        policy.generation
    );

    let nlfd = sys::netlink_socket()
        .unwrap_or_else(|e| fail(proto::ERR_NETLINK, "netlink socket", Some(e)));

    let mut eng = Engine {
        nl: nlfd,
        proto: nl::IPSET_PROTOCOL,
        seq: 0,
        sets: Vec::new(),
        rbuf: vec![0u8; 65536],
    };
    let (kmin, kmax) = eng.negotiate();
    eng.proto = kmax.min(nl::IPSET_PROTOCOL);

    let mut ready = Vec::new();
    for s in &policy.sets {
        let rs = eng.header(&s.name);
        eng.sets.push(SetInfo {
            name: s.name.clone(),
            family: if rs.err == 0 { rs.family } else { 0 },
        });
        ready.push(rs);
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

    harden();

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
    let mut deadline: Option<u64> = None;
    let mut evs = [libc::epoll_event { events: 0, u64: 0 }; 32];
    let mut fbuf = [0u8; 256];

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
                            Ok(s) => deadline = Some(sys::monotonic_ms() + s as u64 * 1000),
                            Err(e) => eprintln!("sundew-helper: bad ctl frame: {e}"),
                        }
                    }
                    _ => {}
                }
                continue;
            }

            for _ in 0..64 {
                let close_slot = match sys::recv(fd, &mut fbuf) {
                    Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => break,
                    Err(_) | Ok((0, _)) => true,
                    Ok((len, flags)) => {
                        if flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
                            || len != proto::REQ_LEN
                        {
                            eprintln!(
                                "sundew-helper: protocol violation on fd {fd}: bad frame size/flags"
                            );
                            true
                        } else {
                            match proto::decode_req(&fbuf[..len]) {
                                Ok(req) if eng.mask_valid(req.mask, &req.addr) => {
                                    let (st, d, m) = eng.test(req.mask, &req.addr);
                                    let rep = proto::encode_rep(st, req.req_id, d, m);
                                    if delay > 0 {
                                        delayed.push_back((sys::monotonic_ms() + delay, fd, rep));
                                        continue;
                                    }
                                    match sys::send(fd, &rep) {
                                        Ok(_) => false,
                                        Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => false,
                                        Err(_) => true,
                                    }
                                }
                                Ok(_) => {
                                    eprintln!(
                                        "sundew-helper: protocol violation on fd {fd}: bad set mask"
                                    );
                                    true
                                }
                                Err(e) => {
                                    eprintln!("sundew-helper: protocol violation on fd {fd}: {e}");
                                    true
                                }
                            }
                        }
                    }
                };

                if close_slot {
                    sys::epoll_del(ep, fd);
                    sys::shutdown(fd); // the keeper holds a duplicate
                    sys::close(fd);
                    open_slots -= 1;
                    break;
                }
            }

            if open_slots == 0 {
                sys::exit(0);
            }
        }
    }
}
