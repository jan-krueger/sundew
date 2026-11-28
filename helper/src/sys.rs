//! Syscall wrappers.

use std::ffi::CStr;
use std::io;

pub const CAP_SETPCAP: u32 = 8;
pub const CAP_NET_ADMIN: u32 = 12;

pub const SECBIT_NOROOT: libc::c_ulong = 1 << 0;
pub const SECBIT_NOROOT_LOCKED: libc::c_ulong = 1 << 1;
pub const SECBIT_NO_SETUID_FIXUP: libc::c_ulong = 1 << 2;
pub const SECBIT_NO_SETUID_FIXUP_LOCKED: libc::c_ulong = 1 << 3;
pub const SECBIT_KEEP_CAPS: libc::c_ulong = 1 << 4;
pub const SECBIT_KEEP_CAPS_LOCKED: libc::c_ulong = 1 << 5;
pub const SECBIT_NO_CAP_AMBIENT_RAISE: libc::c_ulong = 1 << 6;
pub const SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED: libc::c_ulong = 1 << 7;

fn check(r: libc::c_long) -> io::Result<libc::c_long> {
    if r == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn checki(r: libc::c_int) -> io::Result<libc::c_int> {
    if r == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

pub fn set_name(n: &CStr) {
    // SAFETY: valid C string, at most 16 bytes used.
    unsafe {
        libc::prctl(libc::PR_SET_NAME, n.as_ptr());
    }
}

pub fn prctl(op: libc::c_int, a: libc::c_ulong, b: libc::c_ulong) -> io::Result<libc::c_int> {
    // SAFETY: prctl with integer arguments only.
    checki(unsafe { libc::prctl(op, a, b, 0 as libc::c_ulong, 0 as libc::c_ulong) })
}

// ---- capabilities ------------------------------------------------------

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapSets {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
}

pub fn bit(cap: u32) -> u64 {
    1u64 << cap
}

pub fn capget() -> io::Result<CapSets> {
    let mut h = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut d = [CapData::default(); 2];
    // SAFETY: header and a 2-element data array as required by v3.
    check(unsafe { libc::syscall(libc::SYS_capget, &mut h as *mut CapHeader, d.as_mut_ptr()) })?;
    Ok(CapSets {
        effective: d[0].effective as u64 | (d[1].effective as u64) << 32,
        permitted: d[0].permitted as u64 | (d[1].permitted as u64) << 32,
        inheritable: d[0].inheritable as u64 | (d[1].inheritable as u64) << 32,
    })
}

pub fn capset(c: CapSets) -> io::Result<()> {
    let mut h = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let d = [
        CapData {
            effective: c.effective as u32,
            permitted: c.permitted as u32,
            inheritable: c.inheritable as u32,
        },
        CapData {
            effective: (c.effective >> 32) as u32,
            permitted: (c.permitted >> 32) as u32,
            inheritable: (c.inheritable >> 32) as u32,
        },
    ];
    // SAFETY: as capget.
    check(unsafe { libc::syscall(libc::SYS_capset, &mut h as *mut CapHeader, d.as_ptr()) })?;
    Ok(())
}

pub fn bounding_set(last_cap: u32) -> io::Result<u64> {
    let mut v = 0u64;
    for c in 0..=last_cap {
        if prctl(libc::PR_CAPBSET_READ, c as libc::c_ulong, 0)? == 1 {
            v |= bit(c);
        }
    }
    Ok(v)
}

pub fn ambient_set(last_cap: u32) -> io::Result<u64> {
    let mut v = 0u64;
    for c in 0..=last_cap {
        if prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_IS_SET as libc::c_ulong,
            c as libc::c_ulong,
        )? == 1
        {
            v |= bit(c);
        }
    }
    Ok(v)
}

pub fn cap_last_cap() -> io::Result<u32> {
    let s = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")?;
    s.trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "cap_last_cap"))
}

// ---- identity ----------------------------------------------------------

pub fn drop_to(uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: plain syscalls with integer arguments.
    unsafe {
        checki(libc::setgroups(0, std::ptr::null()))?;
        checki(libc::setresgid(gid, gid, gid))?;
        checki(libc::setresuid(uid, uid, uid))?;
    }
    Ok(())
}

pub fn ids() -> (u32, u32, u32, u32) {
    let (mut r, mut e, mut s) = (0, 0, 0);
    let (mut gr, mut ge, mut gs) = (0, 0, 0);
    // SAFETY: out-pointers to locals.
    unsafe {
        libc::getresuid(&mut r, &mut e, &mut s);
        libc::getresgid(&mut gr, &mut ge, &mut gs);
    }
    (
        if r == e && e == s { r } else { u32::MAX },
        e,
        if gr == ge && ge == gs { gr } else { u32::MAX },
        ge,
    )
}

// ---- fds ---------------------------------------------------------------

pub fn sock_type(fd: i32) -> io::Result<(i32, i32)> {
    let mut ty: libc::c_int = 0;
    let mut dom: libc::c_int = 0;
    let mut l = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: int-sized out buffers.
    unsafe {
        checki(libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut ty as *mut _ as *mut _,
            &mut l,
        ))?;
        l = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        checki(libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            &mut dom as *mut _ as *mut _,
            &mut l,
        ))?;
    }
    Ok((dom, ty))
}

pub fn peer_uid(fd: i32) -> io::Result<u32> {
    let mut c: libc::ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut l = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: ucred-sized out buffer.
    checki(unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut c as *mut _ as *mut _,
            &mut l,
        )
    })?;
    Ok(c.uid)
}

pub fn fstat(fd: i32) -> io::Result<libc::stat> {
    // SAFETY: zeroed stat is a valid out buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    checki(unsafe { libc::fstat(fd, &mut st) })?;
    Ok(st)
}

pub fn pread_all(fd: i32, len: usize) -> io::Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    let mut off = 0usize;
    while off < len {
        // SAFETY: writes within v.
        let n = unsafe {
            libc::pread(
                fd,
                v[off..].as_mut_ptr() as *mut _,
                len - off,
                off as libc::off_t,
            )
        };
        if n == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            break;
        }
        off += n as usize;
    }
    v.truncate(off);
    Ok(v)
}

pub fn shutdown(fd: i32) {
    // SAFETY: plain syscall.
    unsafe {
        libc::shutdown(fd, libc::SHUT_RDWR);
    }
}

pub fn close(fd: i32) {
    // SAFETY: closing an fd we own.
    unsafe {
        libc::close(fd);
    }
}

pub fn open_path(p: &CStr) -> io::Result<i32> {
    // SAFETY: valid C string.
    checki(unsafe { libc::open(p.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) })
}

pub fn has_file_caps(p: &CStr) -> bool {
    let name = c"security.capability";
    // SAFETY: size query only (NULL buffer, size 0).
    let r = unsafe { libc::getxattr(p.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    r >= 0
}

pub fn execveat_self(fd: i32, args: &[&CStr]) -> io::Error {
    let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    // SAFETY: NULL-terminated argv/envp of valid C strings.
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            fd,
            c"".as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
    }
    io::Error::last_os_error()
}

pub fn fork() -> io::Result<libc::pid_t> {
    // SAFETY: the helper is single-threaded.
    checki(unsafe { libc::fork() })
}

pub fn waitpid(pid: libc::pid_t) -> io::Result<libc::c_int> {
    let mut st = 0;
    loop {
        // SAFETY: out-pointer to a local.
        let r = unsafe { libc::waitpid(pid, &mut st, 0) };
        if r == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        return Ok(st);
    }
}

pub fn exit(code: i32) -> ! {
    // SAFETY: terminates the process without running destructors.
    unsafe { libc::_exit(code) }
}

#[cfg(target_env = "gnu")]
pub type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))]
pub type RlimitResource = libc::c_int;

pub fn set_rlimit(res: RlimitResource, v: u64) -> io::Result<()> {
    let r = libc::rlimit {
        rlim_cur: v,
        rlim_max: v,
    };
    // SAFETY: pointer to a local.
    checki(unsafe { libc::setrlimit(res, &r) })?;
    Ok(())
}

// ---- sockets -----------------------------------------------------------

pub fn netlink_socket() -> io::Result<i32> {
    // SAFETY: plain syscalls.
    let fd = checki(unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_NETFILTER,
        )
    })?;
    // SAFETY: zeroed sockaddr_nl is valid.
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    checki(unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    })?;
    let one: libc::c_int = 1;
    for opt in [libc::NETLINK_CAP_ACK, libc::NETLINK_EXT_ACK] {
        unsafe {
            libc::setsockopt(fd, libc::SOL_NETLINK, opt, &one as *const _ as *const _, 4);
        }
    }
    // a batch of replies must fit: the kernel drops what does not
    let rcvbuf: libc::c_int = NETLINK_RCVBUF;
    for opt in [libc::SO_RCVBUFFORCE, libc::SO_RCVBUF] {
        // SAFETY: int option.
        let r = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &rcvbuf as *const _ as *const _,
                4,
            )
        };
        if r == 0 {
            break;
        }
    }
    Ok(fd)
}

pub const NETLINK_RCVBUF: libc::c_int = 4 << 20;

/// Netlink socket that receives the nftables change notifications.
pub fn netlink_nft_events() -> io::Result<i32> {
    const NFNLGRP_NFTABLES: u32 = 7;
    // SAFETY: plain syscalls.
    let fd = checki(unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_NETFILTER,
        )
    })?;
    // SAFETY: zeroed sockaddr_nl is valid.
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    sa.nl_groups = 1 << (NFNLGRP_NFTABLES - 1);
    if let Err(e) = checki(unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    }) {
        close(fd);
        return Err(e);
    }
    let rcvbuf: libc::c_int = 16 << 20;
    for opt in [libc::SO_RCVBUFFORCE, libc::SO_RCVBUF] {
        // SAFETY: int option.
        let r = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &rcvbuf as *const _ as *const _,
                4,
            )
        };
        if r == 0 {
            break;
        }
    }
    Ok(fd)
}

/// Datagrams into consecutive `chunk`-sized pieces of `buf`, without
/// waiting: (count, lens and msg_flags in `out`).
pub fn recv_many(
    fd: i32,
    buf: &mut [u8],
    chunk: usize,
    out: &mut [(usize, i32)],
) -> io::Result<usize> {
    const MAX: usize = 64;
    let n = (buf.len() / chunk).min(out.len()).min(MAX);
    // SAFETY: zeroed iovec and mmsghdr are valid.
    let mut iov: [libc::iovec; MAX] = unsafe { std::mem::zeroed() };
    let mut hdr: [libc::mmsghdr; MAX] = unsafe { std::mem::zeroed() };
    for i in 0..n {
        iov[i].iov_base = buf[i * chunk..].as_mut_ptr() as *mut _;
        iov[i].iov_len = chunk;
        hdr[i].msg_hdr.msg_iov = &mut iov[i];
        hdr[i].msg_hdr.msg_iovlen = 1;
    }
    // SAFETY: n headers pointing into buf.
    let r = unsafe {
        libc::recvmmsg(
            fd,
            hdr.as_mut_ptr(),
            n as libc::c_uint,
            libc::MSG_DONTWAIT as _, // c_int on glibc, c_uint on musl
            std::ptr::null_mut(),
        )
    };
    if r == -1 {
        return Err(io::Error::last_os_error());
    }
    for i in 0..r as usize {
        out[i] = (hdr[i].msg_len as usize, hdr[i].msg_hdr.msg_flags);
    }
    Ok(r as usize)
}

pub fn send(fd: i32, b: &[u8]) -> io::Result<usize> {
    // SAFETY: valid buffer.
    let n = unsafe {
        libc::send(
            fd,
            b.as_ptr() as *const _,
            b.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if n == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// (len, msg_flags)
pub fn recv(fd: i32, buf: &mut [u8]) -> io::Result<(usize, i32)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    let mut cmsg = [0u8; 64];
    // SAFETY: zeroed msghdr is valid; pointers reference locals.
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    m.msg_control = cmsg.as_mut_ptr() as *mut _;
    m.msg_controllen = cmsg.len() as _;
    let n = unsafe {
        libc::recvmsg(
            fd,
            &mut m,
            libc::MSG_DONTWAIT | libc::MSG_TRUNC | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if n == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut flags = m.msg_flags;
    if m.msg_controllen != 0 {
        flags |= libc::MSG_CTRUNC;
    }
    Ok((n as usize, flags))
}

/// Frames from a worker, up to `out.len()`, without waiting. A frame that
/// came with ancillary data (e.g. a file descriptor) reports MSG_CTRUNC.
pub fn recv_frames(
    fd: i32,
    buf: &mut [u8],
    frame: usize,
    out: &mut [(usize, i32)],
) -> io::Result<usize> {
    const MAX: usize = 64;
    const CMSG: usize = 64;
    let n = (buf.len() / frame).min(out.len()).min(MAX);
    let mut cmsg = [0u8; MAX * CMSG];
    // SAFETY: zeroed iovec and mmsghdr are valid.
    let mut iov: [libc::iovec; MAX] = unsafe { std::mem::zeroed() };
    let mut hdr: [libc::mmsghdr; MAX] = unsafe { std::mem::zeroed() };
    for i in 0..n {
        iov[i].iov_base = buf[i * frame..].as_mut_ptr() as *mut _;
        iov[i].iov_len = frame;
        hdr[i].msg_hdr.msg_iov = &mut iov[i];
        hdr[i].msg_hdr.msg_iovlen = 1;
        hdr[i].msg_hdr.msg_control = cmsg[i * CMSG..].as_mut_ptr() as *mut _;
        hdr[i].msg_hdr.msg_controllen = CMSG as _;
    }
    // SAFETY: n headers pointing into buf and cmsg.
    let r = unsafe {
        libc::recvmmsg(
            fd,
            hdr.as_mut_ptr(),
            n as libc::c_uint,
            (libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC) as _,
            std::ptr::null_mut(),
        )
    };
    if r == -1 {
        return Err(io::Error::last_os_error());
    }
    for i in 0..r as usize {
        let mut flags = hdr[i].msg_hdr.msg_flags;
        if hdr[i].msg_hdr.msg_controllen != 0 {
            flags |= libc::MSG_CTRUNC;
        }
        out[i] = (hdr[i].msg_len as usize, flags);
    }
    Ok(r as usize)
}

/// Sends frames to one fd in one call: how many went out.
pub fn send_frames(fd: i32, frames: &[[u8; crate::proto::REP_LEN]]) -> io::Result<usize> {
    const MAX: usize = 64;
    let n = frames.len().min(MAX);
    // SAFETY: zeroed iovec and mmsghdr are valid.
    let mut iov: [libc::iovec; MAX] = unsafe { std::mem::zeroed() };
    let mut hdr: [libc::mmsghdr; MAX] = unsafe { std::mem::zeroed() };
    for i in 0..n {
        iov[i].iov_base = frames[i].as_ptr() as *mut _;
        iov[i].iov_len = frames[i].len();
        hdr[i].msg_hdr.msg_iov = &mut iov[i];
        hdr[i].msg_hdr.msg_iovlen = 1;
    }
    // SAFETY: n headers pointing into frames, which sendmmsg only reads.
    let r = unsafe {
        libc::sendmmsg(
            fd,
            hdr.as_mut_ptr(),
            n as libc::c_uint,
            (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as _,
        )
    };
    if r == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

/// Sends to the first fd in [first, first + n) that accepts it.
pub fn send_first(first: i32, n: i32, b: &[u8]) {
    for fd in first..first + n {
        if send(fd, b).is_ok() {
            return;
        }
    }
}

/// True if every fd in [first, first + n) reports POLLHUP.
pub fn all_hung_up(first: i32, n: i32) -> bool {
    let mut fds: Vec<libc::pollfd> = (first..first + n)
        .map(|fd| libc::pollfd {
            fd,
            events: 0,
            revents: 0,
        })
        .collect();
    // SAFETY: fds.len() pollfds.
    let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 0) };
    r == n
        && fds
            .iter()
            .all(|p| p.revents & (libc::POLLHUP | libc::POLLNVAL) != 0)
}

pub fn poll_in(fd: i32, timeout_ms: i32) -> io::Result<bool> {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: one pollfd.
        let r = unsafe { libc::poll(&mut p, 1, timeout_ms) };
        if r == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        return Ok(r == 1);
    }
}

// ---- epoll -------------------------------------------------------------

pub fn epoll_create() -> io::Result<i32> {
    // SAFETY: plain syscall.
    checki(unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) })
}

pub fn epoll_add(ep: i32, fd: i32) -> io::Result<()> {
    let mut ev = libc::epoll_event {
        events: (libc::EPOLLIN | libc::EPOLLRDHUP) as u32,
        u64: fd as u64,
    };
    // SAFETY: pointer to a local.
    checki(unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) })?;
    Ok(())
}

pub fn epoll_del(ep: i32, fd: i32) {
    // SAFETY: NULL event is allowed for DEL.
    unsafe {
        libc::epoll_ctl(ep, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
    }
}

pub fn epoll_wait(ep: i32, evs: &mut [libc::epoll_event], timeout_ms: i32) -> io::Result<usize> {
    // SAFETY: buffer of evs.len() events.
    let n = unsafe { libc::epoll_wait(ep, evs.as_mut_ptr(), evs.len() as i32, timeout_ms) };
    if n == -1 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            return Ok(0);
        }
        return Err(e);
    }
    Ok(n as usize)
}

pub fn monotonic_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: pointer to a local.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000
}

// ---- seccomp -----------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const BPF_JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

// ---- landlock ----------------------------------------------------------

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// Restricts the process to no filesystem access, no TCP bind/connect and
/// (ABI 6+) no abstract unix sockets or signals.  Returns the ABI used.
pub fn landlock_deny_all() -> io::Result<u32> {
    // SAFETY: version query: NULL attr, size 0.
    let abi = check(unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1u32,
        )
    })? as u32;

    let mut fs: u64 = (1 << 13) - 1;
    if abi >= 2 {
        fs |= 1 << 13;
    }
    if abi >= 3 {
        fs |= 1 << 14;
    }
    if abi >= 5 {
        fs |= 1 << 15;
    }
    let attr = LandlockRulesetAttr {
        handled_access_fs: fs,
        handled_access_net: if abi >= 4 { 0b11 } else { 0 },
        scoped: if abi >= 6 { 0b11 } else { 0 },
    };
    let size: usize = match abi {
        0..=3 => 8,
        4 | 5 => 16,
        _ => 24,
    };

    // SAFETY: attr outlives the call; size never exceeds the struct.
    let fd = check(unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            size,
            0u32,
        )
    })? as i32;
    // SAFETY: plain syscall on our own fd.
    let r = check(unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd, 0u32) });
    close(fd);
    r?;
    Ok(abi)
}

pub fn seccomp_allowlist(allow: &[libc::c_long], enosys: &[libc::c_long]) -> io::Result<()> {
    let mut f = vec![
        stmt(BPF_LD_W_ABS, 4), // seccomp_data.arch
        jump(BPF_JEQ_K, AUDIT_ARCH, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD_W_ABS, 0), // seccomp_data.nr
    ];
    #[cfg(target_arch = "x86_64")]
    {
        f.push(jump(BPF_JGE_K, 0x4000_0000, 0, 1)); // __X32_SYSCALL_BIT
        f.push(stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    }
    for &nr in enosys {
        f.push(jump(BPF_JEQ_K, nr as u32, 0, 1));
        f.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::ENOSYS as u32));
    }
    for &nr in allow {
        f.push(jump(BPF_JEQ_K, nr as u32, 0, 1));
        f.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    }
    f.push(stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));

    let prog = SockFprog {
        len: f.len() as u16,
        filter: f.as_ptr(),
    };
    // SAFETY: prog points to a live filter array; flags = TSYNC.
    check(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1, /* SET_MODE_FILTER */
            1, /* TSYNC */
            &prog as *const SockFprog,
        )
    })?;
    Ok(())
}
