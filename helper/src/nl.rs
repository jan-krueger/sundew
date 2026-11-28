//! nfnetlink codec: ipset and nf_tables sets.

pub const NFNL_SUBSYS_IPSET: u16 = 6;
pub const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
const NFNL_MSG_BATCH_END: u16 = 0x11;

pub const NFT_MSG_NEWTABLE: u16 = 0;
pub const NFT_MSG_DELTABLE: u16 = 2;
pub const NFT_MSG_NEWSET: u16 = 9;
pub const NFT_MSG_DELSET: u16 = 11;
pub const NFT_MSG_DELSETELEM: u16 = 14;
pub const NFT_MSG_DESTROYTABLE: u16 = 26;
pub const NFT_MSG_DESTROYSET: u16 = 29;
pub const NFT_MSG_DESTROYSETELEM: u16 = 30;
pub const NFTA_TABLE_NAME: u16 = 1;
pub const NFTA_SET_ELEM_KEY_END: u16 = 9;
const NFT_MSG_GETSET: u16 = 10;
pub const NFT_MSG_NEWSETELEM: u16 = 12;
const NFT_MSG_GETSETELEM: u16 = 13;

pub const NFTA_SET_TABLE: u16 = 1;
pub const NFTA_SET_NAME: u16 = 2;
pub const NFTA_SET_FLAGS: u16 = 3;
pub const NFTA_SET_KEY_TYPE: u16 = 4;
pub const NFTA_SET_KEY_LEN: u16 = 5;
pub const NFTA_SET_DATA_TYPE: u16 = 6;
pub const NFTA_SET_TIMEOUT: u16 = 11;

pub const NFT_SET_ANONYMOUS: u32 = 0x1;
pub const NFT_SET_CONSTANT: u32 = 0x2;
pub const NFT_SET_INTERVAL: u32 = 0x4;
pub const NFT_SET_MAP: u32 = 0x8;
pub const NFT_SET_TIMEOUT: u32 = 0x10;
pub const NFT_SET_OBJECT: u32 = 0x40;
pub const NFT_SET_CONCAT: u32 = 0x80;

/// nft datatypes ipv4_addr and ipv6_addr
pub const NFT_TYPE_IPADDR: u32 = 7;
pub const NFT_TYPE_IP6ADDR: u32 = 8;

pub const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
pub const NFTA_SET_ELEM_LIST_SET: u16 = 2;
pub const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
pub const NFTA_LIST_ELEM: u16 = 1;
pub const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_SET_ELEM_TIMEOUT: u16 = 4;
pub const NFTA_DATA_VALUE: u16 = 1;

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
pub const NLM_F_CREATE: u16 = 0x400;
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

/// Appends one netlink message to a buffer.
pub struct Builder<'a> {
    buf: &'a mut Vec<u8>,
    start: usize,
    nests: [usize; 8],
    depth: usize,
}

impl<'a> Builder<'a> {
    pub fn new(buf: &'a mut Vec<u8>, cmd: u16, flags: u16, seq: u32, family: u8) -> Builder<'a> {
        Builder::raw(buf, (NFNL_SUBSYS_IPSET << 8) | cmd, flags, seq, family, 0)
    }

    pub fn nft(buf: &'a mut Vec<u8>, cmd: u16, flags: u16, seq: u32, family: u8) -> Builder<'a> {
        Builder::raw(
            buf,
            (NFNL_SUBSYS_NFTABLES << 8) | cmd,
            flags,
            seq,
            family,
            0,
        )
    }

    fn raw(
        buf: &'a mut Vec<u8>,
        ty: u16,
        flags: u16,
        seq: u32,
        family: u8,
        res_id: u16,
    ) -> Builder<'a> {
        let start = buf.len();
        buf.extend_from_slice(&0u32.to_ne_bytes()); // len
        buf.extend_from_slice(&ty.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // portid
        buf.push(family);
        buf.push(0); // NFNETLINK_V0
        buf.extend_from_slice(&res_id.to_be_bytes());
        Builder {
            buf,
            start,
            nests: [0; 8],
            depth: 0,
        }
    }

    fn header(&mut self, ty: u16, len: usize) {
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
    }

    pub fn attr(&mut self, ty: u16, data: &[u8]) -> &mut Self {
        self.header(ty, 4 + data.len());
        self.buf.extend_from_slice(data);
        self.buf.resize(align4(self.buf.len()), 0);
        self
    }

    pub fn attr_u8(&mut self, ty: u16, v: u8) -> &mut Self {
        self.attr(ty, &[v])
    }

    pub fn attr_str(&mut self, ty: u16, s: &[u8]) -> &mut Self {
        self.header(ty, 4 + s.len() + 1);
        self.buf.extend_from_slice(s);
        self.buf.push(0);
        self.buf.resize(align4(self.buf.len()), 0);
        self
    }

    pub fn nest(&mut self, ty: u16) -> &mut Self {
        self.nests[self.depth] = self.buf.len();
        self.depth += 1;
        self.header(ty | NLA_F_NESTED, 0);
        self
    }

    pub fn end(&mut self) -> &mut Self {
        self.depth -= 1;
        let start = self.nests[self.depth];
        let len = (self.buf.len() - start) as u16;
        self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
        self
    }

    pub fn finish(self) {
        assert!(self.depth == 0, "unbalanced nest");
        let len = (self.buf.len() - self.start) as u32;
        self.buf[self.start..self.start + 4].copy_from_slice(&len.to_ne_bytes());
    }
}

pub fn msg_protocol(out: &mut Vec<u8>, seq: u32) {
    let mut b = Builder::new(
        out,
        IPSET_CMD_PROTOCOL,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        NFPROTO_IPV4,
    );
    b.attr_u8(IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
    b.finish()
}

/// Header-only LIST: type, family, revision and create options of one set.
pub fn msg_list_header(out: &mut Vec<u8>, seq: u32, proto: u8, set: &[u8]) {
    let mut b = Builder::new(
        out,
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

fn ip_attr(addr: &crate::proto::Addr) -> (u8, u16, &[u8]) {
    use crate::proto::Addr;
    match addr {
        Addr::V4(a) => (NFPROTO_IPV4, IPSET_ATTR_IPADDR_IPV4, a),
        Addr::V6(a) => (NFPROTO_IPV6, IPSET_ATTR_IPADDR_IPV6, a),
    }
}

/// ADD with NLM_F_EXCL: an existing element keeps its timeout. `cidr` only
/// for hash:net; hash:ip would expand it into a range.
pub fn msg_add(
    out: &mut Vec<u8>,
    seq: u32,
    proto: u8,
    set: &[u8],
    addr: &crate::proto::Addr,
    cidr: Option<u8>,
    timeout: u32,
) {
    let (fam, ty, bytes) = ip_attr(addr);
    let mut b = Builder::new(
        out,
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

pub fn msg_test(out: &mut Vec<u8>, seq: u32, proto: u8, set: &[u8], addr: &crate::proto::Addr) {
    let (fam, ty, bytes) = ip_attr(addr);
    let mut b = Builder::new(out, IPSET_CMD_TEST, NLM_F_REQUEST | NLM_F_ACK, seq, fam);
    b.attr_u8(IPSET_ATTR_PROTOCOL, proto)
        .attr_str(IPSET_ATTR_SETNAME, set)
        .nest(IPSET_ATTR_DATA)
        .nest(IPSET_ATTR_IP)
        .attr(ty | NLA_F_NET_BYTEORDER, bytes)
        .end()
        .end();
    b.finish()
}

/// nft set: flags, key type and length, default timeout in ms.
pub fn msg_nft_getset(out: &mut Vec<u8>, seq: u32, family: u8, table: &[u8], set: &[u8]) {
    let mut b = Builder::nft(out, NFT_MSG_GETSET, NLM_F_REQUEST | NLM_F_ACK, seq, family);
    b.attr_str(NFTA_SET_TABLE, table)
        .attr_str(NFTA_SET_NAME, set);
    b.finish()
}

fn nft_elem(b: &mut Builder, table: &[u8], set: &[u8], key: &[u8], timeout_ms: Option<u64>) {
    b.attr_str(NFTA_SET_ELEM_LIST_TABLE, table)
        .attr_str(NFTA_SET_ELEM_LIST_SET, set)
        .nest(NFTA_SET_ELEM_LIST_ELEMENTS)
        .nest(NFTA_LIST_ELEM)
        .nest(NFTA_SET_ELEM_KEY)
        .attr(NFTA_DATA_VALUE, key)
        .end();
    if let Some(t) = timeout_ms {
        b.attr(NFTA_SET_ELEM_TIMEOUT, &t.to_be_bytes());
    }
    b.end().end();
}

/// Element lookup: data and ACK 0 if present; -ENOENT if absent, and also
/// if the set or table is missing. Interval sets match a containing range.
pub fn msg_nft_get(out: &mut Vec<u8>, seq: u32, family: u8, table: &[u8], set: &[u8], key: &[u8]) {
    let mut b = Builder::nft(
        out,
        NFT_MSG_GETSETELEM,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        family,
    );
    nft_elem(&mut b, table, set, key, None);
    b.finish()
}

/// Element add in a batch of its own; only `seq` is acknowledged. EXCL: an
/// existing element keeps its timeout (-EEXIST).
pub fn msg_nft_add(
    out: &mut Vec<u8>,
    seq: u32,
    family: u8,
    table: &[u8],
    set: &[u8],
    key: &[u8],
    timeout_ms: u64,
) {
    Builder::raw(
        out,
        NFNL_MSG_BATCH_BEGIN,
        NLM_F_REQUEST,
        seq.wrapping_sub(1),
        0,
        NFNL_SUBSYS_NFTABLES,
    )
    .finish();
    let mut b = Builder::nft(
        out,
        NFT_MSG_NEWSETELEM,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq,
        family,
    );
    nft_elem(&mut b, table, set, key, Some(timeout_ms));
    b.finish();
    Builder::raw(
        out,
        NFNL_MSG_BATCH_END,
        NLM_F_REQUEST,
        seq.wrapping_add(1),
        0,
        NFNL_SUBSYS_NFTABLES,
    )
    .finish();
}

#[derive(Debug)]
pub enum Reply<'a> {
    Ack {
        seq: u32,
        errno: i32,
    },
    Done {
        seq: u32,
    },
    Data {
        subsys: u16,
        cmd: u16,
        /// nfgenmsg family: the table family for nftables
        family: u8,
        attrs: &'a [u8],
    },
}

#[cfg(test)]
pub fn parse(buf: &[u8]) -> Result<Vec<Reply<'_>>, &'static str> {
    let mut out = Vec::new();
    parse_each(buf, |r| out.push(r))?;
    Ok(out)
}

/// Calls `f` for each message in `buf`, up to the first malformed one.
pub fn parse_each<'a>(buf: &'a [u8], mut f: impl FnMut(Reply<'a>)) -> Result<(), &'static str> {
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
                f(Reply::Ack { seq, errno });
            }
            NLMSG_DONE => f(Reply::Done { seq }),
            t if t >> 8 == NFNL_SUBSYS_IPSET || t >> 8 == NFNL_SUBSYS_NFTABLES => {
                if body.len() < NFGEN_HDRLEN {
                    return Err("short nfgenmsg");
                }
                f(Reply::Data {
                    subsys: t >> 8,
                    cmd: t & 0xff,
                    family: body[0],
                    attrs: &body[NFGEN_HDRLEN..],
                });
            }
            _ => return Err("unexpected message type"),
        }
        off += align4(len).min(rest.len());
    }
    Ok(())
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
        let mut seed = Vec::new();
        msg_test(&mut seed, 1, 7, b"set", &Addr::V6([1; 16]));
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
        let mut m = Vec::new();
        msg_test(&mut m, 9, 7, b"bad", &Addr::V4([192, 0, 2, 1]));
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
        let mut m = Vec::new();
        msg_add(&mut m, 3, 7, b"ban", &Addr::V4([192, 0, 2, 1]), None, 3600);
        assert_eq!(
            u16::from_ne_bytes([m[6], m[7]]),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL
        );
        // timeout is the last attribute: be32 with NLA_F_NET_BYTEORDER
        assert_eq!(&m[m.len() - 8..m.len() - 4], &[8, 0, 6, 0x40]);
        assert_eq!(&m[m.len() - 4..], &3600u32.to_be_bytes());
        let mut n = Vec::new();
        msg_add(
            &mut n,
            3,
            7,
            b"ban",
            &Addr::V4([192, 0, 2, 1]),
            Some(24),
            60,
        );
        assert_eq!(n.len(), m.len() + 8);
    }

    #[test]
    fn batch_in_one_buffer() {
        let mut b = Vec::new();
        for seq in 40..45 {
            msg_test(&mut b, seq, 7, b"s", &Addr::V4([192, 0, 2, seq as u8]));
        }
        msg_nft_get(&mut b, 45, 1, b"filter", b"ban", &[2u8; 16]);
        let mut off = 0;
        let mut seqs = Vec::new();
        while off < b.len() {
            let len = u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) as usize;
            assert_eq!(len % 4, 0);
            seqs.push(u32::from_ne_bytes([
                b[off + 8],
                b[off + 9],
                b[off + 10],
                b[off + 11],
            ]));
            off += len;
        }
        assert_eq!(off, b.len());
        assert_eq!(seqs, (40..46).collect::<Vec<u32>>());
    }

    #[test]
    fn nft_add_layout() {
        let mut m = Vec::new();
        msg_nft_add(&mut m, 10, 1, b"filter", b"ban", &[192, 0, 2, 1], 60_000);
        let msgs: Vec<(u16, u16, u32)> = {
            let mut v = Vec::new();
            let mut off = 0;
            while off < m.len() {
                let len = u32::from_ne_bytes([m[off], m[off + 1], m[off + 2], m[off + 3]]) as usize;
                v.push((
                    u16::from_ne_bytes([m[off + 4], m[off + 5]]),
                    u16::from_ne_bytes([m[off + 6], m[off + 7]]),
                    u32::from_ne_bytes([m[off + 8], m[off + 9], m[off + 10], m[off + 11]]),
                ));
                off += len;
            }
            v
        };
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0], (0x10, NLM_F_REQUEST, 9));
        assert_eq!(msgs[1].0, (10 << 8) | 12);
        assert_eq!(
            msgs[1].1,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        );
        assert_eq!(msgs[2], (0x11, NLM_F_REQUEST, 11));
        // batch begin: res_id NFNL_SUBSYS_NFTABLES, big-endian
        assert_eq!(&m[18..20], &[0, 10]);
        assert!(m.windows(8).any(|w| w == 60_000u64.to_be_bytes()));
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
