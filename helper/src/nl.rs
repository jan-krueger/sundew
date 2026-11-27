//! nfnetlink / ipset codec.

pub const NFNL_SUBSYS_IPSET: u16 = 6;

pub const IPSET_PROTOCOL: u8 = 7;
pub const IPSET_PROTOCOL_MIN: u8 = 6;

pub const IPSET_CMD_PROTOCOL: u16 = 1;
pub const IPSET_CMD_LIST: u16 = 7;
pub const IPSET_CMD_ADD: u16 = 9;
pub const IPSET_CMD_TEST: u16 = 11;

pub const IPSET_ATTR_PROTOCOL: u16 = 1;
pub const IPSET_ATTR_SETNAME: u16 = 2;
pub const IPSET_ATTR_TYPENAME: u16 = 3;
pub const IPSET_ATTR_REVISION: u16 = 4;
pub const IPSET_ATTR_FAMILY: u16 = 5;
pub const IPSET_ATTR_FLAGS: u16 = 6;
pub const IPSET_ATTR_DATA: u16 = 7;
pub const IPSET_ATTR_PROTOCOL_MIN: u16 = 10;

pub const IPSET_ATTR_IP: u16 = 1;
pub const IPSET_ATTR_CIDR: u16 = 3;
pub const IPSET_ATTR_TIMEOUT: u16 = 6;
pub const IPSET_ATTR_NETMASK: u16 = 20;

pub const IPSET_FLAG_LIST_HEADER: u32 = 1 << 2;
pub const IPSET_ATTR_IPADDR_IPV4: u16 = 1;
pub const IPSET_ATTR_IPADDR_IPV6: u16 = 2;

pub const IPSET_ERR_EXIST: i32 = 4103;
pub const IPSET_ERR_HASH_FULL: i32 = 4352;

pub const NLA_F_NESTED: u16 = 1 << 15;
pub const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_DUMP: u16 = 0x300;

pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;

pub const NFPROTO_IPV4: u8 = 2;
pub const NFPROTO_IPV6: u8 = 10;

const NLMSG_HDRLEN: usize = 16;
const NFGEN_HDRLEN: usize = 4;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

pub struct Builder {
    buf: Vec<u8>,
    nests: Vec<usize>,
}

impl Builder {
    pub fn new(cmd: u16, flags: u16, seq: u32, family: u8) -> Builder {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // len
        buf.extend_from_slice(&((NFNL_SUBSYS_IPSET << 8) | cmd).to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // portid
        buf.push(family);
        buf.push(0); // NFNETLINK_V0
        buf.extend_from_slice(&0u16.to_be_bytes()); // res_id
        Builder {
            buf,
            nests: Vec::new(),
        }
    }

    pub fn attr(&mut self, ty: u16, data: &[u8]) -> &mut Self {
        let len = 4 + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.buf.resize(align4(self.buf.len()), 0);
        self
    }

    pub fn attr_u8(&mut self, ty: u16, v: u8) -> &mut Self {
        self.attr(ty, &[v])
    }

    pub fn attr_str(&mut self, ty: u16, s: &[u8]) -> &mut Self {
        let mut v = s.to_vec();
        v.push(0);
        self.attr(ty, &v)
    }

    pub fn nest(&mut self, ty: u16) -> &mut Self {
        self.nests.push(self.buf.len());
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf
            .extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
        self
    }

    pub fn end(&mut self) -> &mut Self {
        let start = self.nests.pop().expect("unbalanced nest");
        let len = (self.buf.len() - start) as u16;
        self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
        self
    }

    pub fn finish(mut self) -> Vec<u8> {
        assert!(self.nests.is_empty(), "unbalanced nest");
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

pub fn msg_protocol(seq: u32) -> Vec<u8> {
    let mut b = Builder::new(
        IPSET_CMD_PROTOCOL,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        NFPROTO_IPV4,
    );
    b.attr_u8(IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
    b.finish()
}

/// Header-only LIST: type, family, revision and create options of one set.
pub fn msg_list_header(seq: u32, proto: u8, set: &[u8]) -> Vec<u8> {
    let mut b = Builder::new(
        IPSET_CMD_LIST,
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
        NFPROTO_IPV4,
    );
    b.attr_u8(IPSET_ATTR_PROTOCOL, proto)
        .attr_str(IPSET_ATTR_SETNAME, set)
        .attr(
            IPSET_ATTR_FLAGS | NLA_F_NET_BYTEORDER,
            &IPSET_FLAG_LIST_HEADER.to_be_bytes(),
        );
    b.finish()
}

/// ADD with NLM_F_EXCL: an existing element keeps its timeout. `cidr` only
/// for hash:net; hash:ip would expand it into a range.
pub fn msg_add(
    seq: u32,
    proto: u8,
    set: &[u8],
    addr: &crate::proto::Addr,
    cidr: Option<u8>,
    timeout: u32,
) -> Vec<u8> {
    use crate::proto::Addr;
    let (fam, ty, bytes): (u8, u16, &[u8]) = match addr {
        Addr::V4(a) => (NFPROTO_IPV4, IPSET_ATTR_IPADDR_IPV4, a),
        Addr::V6(a) => (NFPROTO_IPV6, IPSET_ATTR_IPADDR_IPV6, a),
    };
    let mut b = Builder::new(
        IPSET_CMD_ADD,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL,
        seq,
        fam,
    );
    b.attr_u8(IPSET_ATTR_PROTOCOL, proto)
        .attr_str(IPSET_ATTR_SETNAME, set)
        .nest(IPSET_ATTR_DATA)
        .nest(IPSET_ATTR_IP)
        .attr(ty | NLA_F_NET_BYTEORDER, bytes)
        .end();
    if let Some(c) = cidr {
        b.attr_u8(IPSET_ATTR_CIDR, c);
    }
    b.attr(
        IPSET_ATTR_TIMEOUT | NLA_F_NET_BYTEORDER,
        &timeout.to_be_bytes(),
    )
    .end();
    b.finish()
}

pub fn msg_test(seq: u32, proto: u8, set: &[u8], addr: &crate::proto::Addr) -> Vec<u8> {
    use crate::proto::Addr;
    let (fam, ty, bytes): (u8, u16, &[u8]) = match addr {
        Addr::V4(a) => (NFPROTO_IPV4, IPSET_ATTR_IPADDR_IPV4, a),
        Addr::V6(a) => (NFPROTO_IPV6, IPSET_ATTR_IPADDR_IPV6, a),
    };
    let mut b = Builder::new(IPSET_CMD_TEST, NLM_F_REQUEST | NLM_F_ACK, seq, fam);
    b.attr_u8(IPSET_ATTR_PROTOCOL, proto)
        .attr_str(IPSET_ATTR_SETNAME, set)
        .nest(IPSET_ATTR_DATA)
        .nest(IPSET_ATTR_IP)
        .attr(ty | NLA_F_NET_BYTEORDER, bytes)
        .end()
        .end();
    b.finish()
}

#[derive(Debug)]
pub enum Reply<'a> {
    Ack { seq: u32, errno: i32 },
    Done { seq: u32 },
    Data { seq: u32, cmd: u16, attrs: &'a [u8] },
}

pub fn parse(buf: &[u8]) -> Result<Vec<Reply<'_>>, &'static str> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < buf.len() {
        let rest = &buf[off..];
        if rest.len() < NLMSG_HDRLEN {
            return Err("truncated nlmsghdr");
        }
        let len = u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        if len < NLMSG_HDRLEN || len > rest.len() {
            return Err("bad nlmsg_len");
        }
        let ty = u16::from_ne_bytes([rest[4], rest[5]]);
        let seq = u32::from_ne_bytes([rest[8], rest[9], rest[10], rest[11]]);
        let body = &rest[NLMSG_HDRLEN..len];
        match ty {
            NLMSG_ERROR => {
                if body.len() < 4 {
                    return Err("short nlmsgerr");
                }
                let errno = i32::from_ne_bytes([body[0], body[1], body[2], body[3]]);
                out.push(Reply::Ack { seq, errno });
            }
            NLMSG_DONE => out.push(Reply::Done { seq }),
            t if t >> 8 == NFNL_SUBSYS_IPSET => {
                if body.len() < NFGEN_HDRLEN {
                    return Err("short nfgenmsg");
                }
                out.push(Reply::Data {
                    seq,
                    cmd: t & 0xff,
                    attrs: &body[NFGEN_HDRLEN..],
                });
            }
            _ => return Err("unexpected message type"),
        }
        off += align4(len).min(rest.len());
    }
    Ok(out)
}

pub fn attrs(mut b: &[u8]) -> impl Iterator<Item = Result<(u16, &[u8]), &'static str>> {
    std::iter::from_fn(move || {
        if b.is_empty() {
            return None;
        }
        if b.len() < 4 {
            b = &[];
            return Some(Err("truncated nlattr"));
        }
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        let ty = u16::from_ne_bytes([b[2], b[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > b.len() {
            b = &[];
            return Some(Err("bad nla_len"));
        }
        let payload = &b[4..len];
        b = &b[align4(len).min(b.len())..];
        Some(Ok((ty, payload)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Addr;
    use crate::proto::fuzz::Rng;

    #[test]
    fn fuzz_parse() {
        let mut rng = Rng::new(0x6e6c);
        let seed = msg_test(1, 7, b"set", &Addr::V6([1; 16]));
        for _ in 0..200_000 {
            let input = rng.input(&seed, 96);
            if let Ok(msgs) = parse(&input) {
                for m in msgs {
                    if let Reply::Data { attrs: a, .. } = m {
                        for r in attrs(a) {
                            let _ = r;
                        }
                    }
                }
            }
            for r in attrs(&input) {
                let _ = r;
            }
        }
    }

    #[test]
    fn test_msg_layout() {
        let m = msg_test(9, 7, b"bad", &Addr::V4([192, 0, 2, 1]));
        assert_eq!(m.len() % 4, 0);
        assert_eq!(
            u32::from_ne_bytes([m[0], m[1], m[2], m[3]]) as usize,
            m.len()
        );
        assert_eq!(u16::from_ne_bytes([m[4], m[5]]), (6 << 8) | 11);
        assert_eq!(&m[20..25], &[5, 0, 1, 0, 7]);
        assert_eq!(&m[m.len() - 4..], &[192, 0, 2, 1]);
    }

    #[test]
    fn add_msg_layout() {
        let m = msg_add(3, 7, b"ban", &Addr::V4([192, 0, 2, 1]), None, 3600);
        assert_eq!(
            u16::from_ne_bytes([m[6], m[7]]),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL
        );
        // timeout is the last attribute: be32 with NLA_F_NET_BYTEORDER
        assert_eq!(&m[m.len() - 8..m.len() - 4], &[8, 0, 6, 0x40]);
        assert_eq!(&m[m.len() - 4..], &3600u32.to_be_bytes());
        let n = msg_add(3, 7, b"ban", &Addr::V4([192, 0, 2, 1]), Some(24), 60);
        assert_eq!(n.len(), m.len() + 8);
    }

    #[test]
    fn parse_hostile() {
        assert!(parse(&[0u8; 3]).is_err());
        let mut b = vec![0u8; 16];
        b[0] = 200; // len beyond buffer
        assert!(parse(&b).is_err());
        let mut ack = vec![0u8; 20];
        ack[0] = 20;
        ack[4] = NLMSG_ERROR as u8;
        ack[16..20].copy_from_slice(&(-IPSET_ERR_EXIST).to_ne_bytes());
        match &parse(&ack).unwrap()[0] {
            Reply::Ack { errno, .. } => assert_eq!(*errno, -IPSET_ERR_EXIST),
            _ => panic!(),
        }
        for r in attrs(&[8, 0, 1, 0, 1]) {
            let _ = r;
        }
        assert!(attrs(&[200, 0, 1, 0]).any(|r| r.is_err()));
    }
}
