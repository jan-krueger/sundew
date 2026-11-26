//! Wire formats. Mirror: src/sw_proto.h

pub const PROTO_VERSION: u8 = 1;
pub const FRAME_MAGIC: u16 = 0x5357;
pub const MAX_SETS: usize = 64;
pub const SETNAME_LEN: usize = 32;

pub const FD_POLICY: i32 = 3;
pub const FD_CTL: i32 = 4;
pub const FD_SLOT0: i32 = 5;

pub const POLICY_MAGIC: u32 = 0x4c50_5753;
pub const POLICY_VERSION: u16 = 1;
pub const POLICY_HDR_LEN: usize = 32;
pub const POLICY_SET_LEN: usize = 40;
pub const ROLE_LOOKUP: u8 = 1;

pub const CTL_READY: u8 = 1;
pub const CTL_DRAIN: u8 = 2;
pub const CTL_HDR_LEN: usize = 16;
pub const READY_SET_LEN: usize = 40;
pub const DRAIN_LEN: usize = 24;

pub const ERR_NONE: u16 = 0;
pub const ERR_POLICY: u16 = 1;
pub const ERR_CAPS: u16 = 2;
pub const ERR_NETLINK: u16 = 3;
pub const ERR_KPROTO: u16 = 4;
pub const ERR_SANDBOX: u16 = 5;

pub const OP_TEST: u8 = 1;

pub const ST_OK: u8 = 0;
pub const ST_ERROR: u8 = 3;
pub const ST_LOG: u8 = 0x80;

// nginx log levels
pub const LVL_ALERT: u8 = 2;
pub const LVL_ERR: u8 = 4;
pub const LVL_NOTICE: u8 = 6;

pub const LOG_TEST_FAILED: u64 = 1;
pub const LOG_SET_MISSING: u64 = 2;
pub const LOG_NETLINK: u64 = 3;
pub const LOG_VIOLATION: u64 = 4;
pub const LOG_ENGINE_EXIT: u64 = 5;
pub const LOG_LANDLOCK: u64 = 6;
pub const LOG_GAVE_UP: u64 = 7;

pub const VIOLATION_SIZE: u64 = 1;
pub const VIOLATION_FRAME: u64 = 2;
pub const VIOLATION_MASK: u64 = 3;

pub const REQ_LEN: usize = 48;
pub const REP_LEN: usize = 24;

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_ne_bytes([b[o], b[o + 1]])
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_ne_bytes(a)
}

#[derive(Debug, Clone)]
pub struct PolicySet {
    pub name: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub nslots: u32,
    pub helper_uid: u32,
    pub helper_gid: u32,
    pub worker_uid: u32,
    pub generation: u32,
    pub debug_delay_ms: u32,
    pub sets: Vec<PolicySet>,
}

fn valid_setname(n: &[u8]) -> bool {
    !n.is_empty()
        && n.len() < SETNAME_LEN
        && n.iter()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(c))
}

impl Policy {
    pub fn decode(b: &[u8]) -> Result<Policy, &'static str> {
        if b.len() < POLICY_HDR_LEN {
            return Err("short policy");
        }
        if u32_at(b, 0) != POLICY_MAGIC || u16_at(b, 4) != POLICY_VERSION {
            return Err("bad policy magic/version");
        }
        let nsets = u16_at(b, 6) as usize;
        if nsets == 0 || nsets > MAX_SETS {
            return Err("bad set count");
        }
        if b.len() != POLICY_HDR_LEN + nsets * POLICY_SET_LEN {
            return Err("bad policy length");
        }
        let nslots = u32_at(b, 8);
        if nslots == 0 || nslots > 1024 {
            return Err("bad slot count");
        }
        let mut sets = Vec::with_capacity(nsets);
        for i in 0..nsets {
            let r = &b[POLICY_HDR_LEN + i * POLICY_SET_LEN..][..POLICY_SET_LEN];
            let name_raw = &r[..SETNAME_LEN];
            let len = name_raw
                .iter()
                .position(|&c| c == 0)
                .ok_or("name not terminated")?;
            if name_raw[len..].iter().any(|&c| c != 0)
                || r[SETNAME_LEN + 1..].iter().any(|&c| c != 0)
            {
                return Err("nonzero padding");
            }
            let name = name_raw[..len].to_vec();
            if !valid_setname(&name) {
                return Err("invalid set name");
            }
            if r[SETNAME_LEN] != ROLE_LOOKUP {
                return Err("unsupported role");
            }
            sets.push(PolicySet { name });
        }
        Ok(Policy {
            nslots,
            helper_uid: u32_at(b, 12),
            helper_gid: u32_at(b, 16),
            worker_uid: u32_at(b, 20),
            generation: u32_at(b, 24),
            debug_delay_ms: u32_at(b, 28),
            sets,
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ReadySet {
    pub err: i32,
    pub family: u8,
    pub revision: u8,
    pub type_name: [u8; SETNAME_LEN],
}

pub fn encode_ready(status: u16, kmin: u32, kmax: u32, sets: &[ReadySet]) -> Vec<u8> {
    let mut v = Vec::with_capacity(CTL_HDR_LEN + sets.len() * READY_SET_LEN);
    v.extend_from_slice(&FRAME_MAGIC.to_ne_bytes());
    v.push(PROTO_VERSION);
    v.push(CTL_READY);
    v.extend_from_slice(&(sets.len() as u16).to_ne_bytes());
    v.extend_from_slice(&status.to_ne_bytes());
    v.extend_from_slice(&kmin.to_ne_bytes());
    v.extend_from_slice(&kmax.to_ne_bytes());
    for s in sets {
        v.extend_from_slice(&s.err.to_ne_bytes());
        v.push(s.family);
        v.push(s.revision);
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(&s.type_name);
    }
    v
}

pub fn decode_drain(b: &[u8]) -> Result<u32, &'static str> {
    if b.len() != DRAIN_LEN {
        return Err("bad drain length");
    }
    if u16_at(b, 0) != FRAME_MAGIC || b[2] != PROTO_VERSION || b[3] != CTL_DRAIN {
        return Err("bad drain header");
    }
    if b[4..16].iter().any(|&c| c != 0) || u32_at(b, 20) != 0 {
        return Err("nonzero padding");
    }
    Ok(u32_at(b, 16))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[derive(Debug, Clone, Copy)]
pub struct Req {
    pub req_id: u32,
    pub mask: u64,
    pub addr: Addr,
}

pub fn decode_req(b: &[u8]) -> Result<Req, &'static str> {
    if b.len() != REQ_LEN {
        return Err("bad length");
    }
    if u16_at(b, 0) != FRAME_MAGIC || b[2] != PROTO_VERSION {
        return Err("bad magic/version");
    }
    if b[3] != OP_TEST {
        return Err("unsupported op");
    }
    let mask = u64_at(b, 8);
    if mask == 0 {
        return Err("empty mask");
    }
    if b[17..24].iter().any(|&c| c != 0) || b[40..48].iter().any(|&c| c != 0) {
        return Err("nonzero padding");
    }
    let a = &b[24..40];
    let addr = match b[16] {
        4 => {
            if a[4..].iter().any(|&c| c != 0) {
                return Err("v4 address with trailing bytes");
            }
            Addr::V4([a[0], a[1], a[2], a[3]])
        }
        6 => {
            let mut x = [0u8; 16];
            x.copy_from_slice(a);
            Addr::V6(x)
        }
        _ => return Err("bad family"),
    };
    Ok(Req {
        req_id: u32_at(b, 4),
        mask,
        addr,
    })
}

pub fn encode_rep(status: u8, req_id: u32, decided: u64, matched: u64) -> [u8; REP_LEN] {
    let mut r = [0u8; REP_LEN];
    r[0..2].copy_from_slice(&FRAME_MAGIC.to_ne_bytes());
    r[2] = PROTO_VERSION;
    r[3] = status;
    r[4..8].copy_from_slice(&req_id.to_ne_bytes());
    r[8..16].copy_from_slice(&decided.to_ne_bytes());
    r[16..24].copy_from_slice(&matched.to_ne_bytes());
    r
}

pub fn encode_log(level: u8, event: u64, arg: u64) -> [u8; REP_LEN] {
    encode_rep(ST_LOG | level, 0, event, arg)
}

#[cfg(test)]
pub(crate) mod fuzz {
    pub struct Rng(u64);

    impl Rng {
        pub fn new(seed: u64) -> Rng {
            Rng(seed | 1)
        }
        pub fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        pub fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        /// Random bytes, or a mutated copy of `seed`.
        pub fn input(&mut self, seed: &[u8], max: usize) -> Vec<u8> {
            if seed.is_empty() || self.below(4) == 0 {
                let n = self.below(max + 1);
                return (0..n).map(|_| self.next() as u8).collect();
            }
            let mut v = seed.to_vec();
            for _ in 0..=self.below(4) {
                match self.below(3) {
                    0 if !v.is_empty() => {
                        let i = self.below(v.len());
                        v[i] ^= 1 << self.below(8);
                    }
                    1 => v.truncate(self.below(v.len() + 1)),
                    _ => v.push(self.next() as u8),
                }
            }
            v
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fuzz::Rng;
    use super::*;

    #[test]
    fn fuzz_decoders() {
        let mut rng = Rng::new(0x5357_5357);
        let good_req = req(4, 1);
        let mut good_policy = vec![0u8; POLICY_HDR_LEN + POLICY_SET_LEN];
        good_policy[0..4].copy_from_slice(&POLICY_MAGIC.to_ne_bytes());
        good_policy[4..6].copy_from_slice(&POLICY_VERSION.to_ne_bytes());
        good_policy[6..8].copy_from_slice(&1u16.to_ne_bytes());
        good_policy[8..12].copy_from_slice(&2u32.to_ne_bytes());
        good_policy[POLICY_HDR_LEN..POLICY_HDR_LEN + 3].copy_from_slice(b"bad");
        good_policy[POLICY_HDR_LEN + SETNAME_LEN] = ROLE_LOOKUP;
        assert!(Policy::decode(&good_policy).is_ok());

        for _ in 0..200_000 {
            let _ = decode_req(&rng.input(&good_req, 64));
            let _ = decode_drain(&rng.input(&[], 32));
            let _ = Policy::decode(&rng.input(&good_policy, 128));
        }
    }

    fn req(fam: u8, mask: u64) -> [u8; REQ_LEN] {
        let mut b = [0u8; REQ_LEN];
        b[0..2].copy_from_slice(&FRAME_MAGIC.to_ne_bytes());
        b[2] = PROTO_VERSION;
        b[3] = OP_TEST;
        b[4..8].copy_from_slice(&7u32.to_ne_bytes());
        b[8..16].copy_from_slice(&mask.to_ne_bytes());
        b[16] = fam;
        b[24..28].copy_from_slice(&[192, 0, 2, 1]);
        b
    }

    #[test]
    fn req_ok() {
        let r = decode_req(&req(4, 1)).unwrap();
        assert_eq!(r.req_id, 7);
        assert_eq!(r.addr, Addr::V4([192, 0, 2, 1]));
    }

    #[test]
    fn req_rejects() {
        assert!(decode_req(&req(4, 0)).is_err());
        assert!(decode_req(&req(5, 1)).is_err());
        let mut b = req(4, 1);
        b[30] = 1;
        assert!(decode_req(&b).is_err());
        let mut b = req(4, 1);
        b[45] = 1;
        assert!(decode_req(&b).is_err());
        assert!(decode_req(&req(4, 1)[..47]).is_err());
    }
}
