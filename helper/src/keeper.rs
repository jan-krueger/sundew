//! Keeper: drops privileges, (re)starts the engine.

use crate::proto::{self, Policy};
use crate::sys::{self, CAP_NET_ADMIN, CAP_SETPCAP, CapSets, bit};
use std::time::Duration;

pub fn fail(status: u16, what: &str, err: Option<std::io::Error>) -> ! {
    match err {
        Some(e) => eprintln!("sundew-helper: {what}: {e}"),
        None => eprintln!("sundew-helper: {what}"),
    }
    let _ = sys::send(proto::FD_CTL, &proto::encode_ready(status, 0, 0, &[]));
    sys::exit(2);
}

pub fn read_policy() -> Policy {
    let st = sys::fstat(proto::FD_POLICY)
        .unwrap_or_else(|e| fail(proto::ERR_POLICY, "policy fd", Some(e)));
    if st.st_mode & libc::S_IFMT != libc::S_IFREG || st.st_size as usize > 64 * 1024 {
        fail(
            proto::ERR_POLICY,
            "policy fd is not a small regular file",
            None,
        );
    }
    let buf = sys::pread_all(proto::FD_POLICY, st.st_size as usize)
        .unwrap_or_else(|e| fail(proto::ERR_POLICY, "read policy", Some(e)));
    Policy::decode(&buf).unwrap_or_else(|e| fail(proto::ERR_POLICY, e, None))
}

fn check_fds(p: &Policy) {
    let want = (libc::AF_UNIX, libc::SOCK_SEQPACKET);
    match sys::sock_type(proto::FD_CTL) {
        Ok(t) if t == want => {}
        _ => fail(
            proto::ERR_POLICY,
            "fd 4 is not an AF_UNIX SOCK_SEQPACKET socket",
            None,
        ),
    }
    match sys::peer_uid(proto::FD_CTL) {
        Ok(0) => {}
        _ => fail(proto::ERR_POLICY, "ctl peer is not root", None),
    }
    for i in 0..p.nslots as i32 {
        match sys::sock_type(proto::FD_SLOT0 + i) {
            Ok(t) if t == want => {}
            _ => fail(
                proto::ERR_POLICY,
                "slot fd is not an AF_UNIX SOCK_SEQPACKET socket",
                None,
            ),
        }
    }
}

fn check_self() -> i32 {
    let exe = c"/proc/self/exe";
    let fd = sys::open_path(exe)
        .unwrap_or_else(|e| fail(proto::ERR_SANDBOX, "open /proc/self/exe", Some(e)));
    let st = sys::fstat(fd).unwrap_or_else(|e| fail(proto::ERR_SANDBOX, "fstat self", Some(e)));
    if st.st_mode & (libc::S_ISUID | libc::S_ISGID) != 0 {
        fail(
            proto::ERR_SANDBOX,
            "helper binary must not be setuid/setgid",
            None,
        );
    }
    if sys::has_file_caps(exe) {
        fail(
            proto::ERR_SANDBOX,
            "helper binary must not carry file capabilities",
            None,
        );
    }
    fd
}

fn drop_privileges(p: &Policy, last_cap: u32) {
    let e = |what: &str, r: std::io::Result<libc::c_int>| {
        if let Err(err) = r {
            fail(proto::ERR_CAPS, what, Some(err));
        }
    };

    if p.helper_uid == 0 || p.helper_uid == p.worker_uid {
        fail(
            proto::ERR_CAPS,
            "helper uid must be neither root nor the worker uid",
            None,
        );
    }

    // 1. bounding set = {NET_ADMIN}
    for c in 0..=last_cap {
        if c != CAP_NET_ADMIN {
            e(
                "PR_CAPBSET_DROP",
                sys::prctl(libc::PR_CAPBSET_DROP, c as libc::c_ulong, 0),
            );
        }
    }

    // 2. securebits
    let base = sys::SECBIT_KEEP_CAPS
        | sys::SECBIT_NOROOT
        | sys::SECBIT_NOROOT_LOCKED
        | sys::SECBIT_NO_SETUID_FIXUP
        | sys::SECBIT_NO_SETUID_FIXUP_LOCKED;
    e(
        "PR_SET_SECUREBITS",
        sys::prctl(libc::PR_SET_SECUREBITS, base, 0),
    );

    // 3. identity
    if let Err(err) = sys::drop_to(p.helper_uid, p.helper_gid) {
        fail(proto::ERR_CAPS, "setresuid/setresgid", Some(err));
    }

    // 4. P = E = {NET_ADMIN, SETPCAP}, I = {NET_ADMIN}
    let na = bit(CAP_NET_ADMIN);
    if let Err(err) = sys::capset(CapSets {
        effective: na | bit(CAP_SETPCAP),
        permitted: na | bit(CAP_SETPCAP),
        inheritable: na,
    }) {
        fail(proto::ERR_CAPS, "capset (step 4)", Some(err));
    }

    // 5. ambient NET_ADMIN
    e(
        "PR_CAP_AMBIENT_RAISE",
        sys::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
            CAP_NET_ADMIN as libc::c_ulong,
        ),
    );

    // 6. lock securebits
    let locked = base
        | sys::SECBIT_NO_CAP_AMBIENT_RAISE
        | sys::SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED
        | sys::SECBIT_KEEP_CAPS_LOCKED;
    e(
        "PR_SET_SECUREBITS (lock)",
        sys::prctl(libc::PR_SET_SECUREBITS, locked, 0),
    );

    // 7. drop SETPCAP
    if let Err(err) = sys::capset(CapSets {
        effective: na,
        permitted: na,
        inheritable: na,
    }) {
        fail(proto::ERR_CAPS, "capset (step 7)", Some(err));
    }

    // 8. no_new_privs
    e(
        "PR_SET_NO_NEW_PRIVS",
        sys::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0),
    );
    e("PR_SET_DUMPABLE", sys::prctl(libc::PR_SET_DUMPABLE, 0, 0));

    // 9. verify
    verify(p, last_cap, true);
}

pub fn verify(p: &Policy, last_cap: u32, keeper: bool) {
    let na = bit(CAP_NET_ADMIN);
    let c = sys::capget().unwrap_or_else(|e| fail(proto::ERR_CAPS, "capget", Some(e)));
    let bnd = sys::bounding_set(last_cap)
        .unwrap_or_else(|e| fail(proto::ERR_CAPS, "bounding set", Some(e)));
    let amb = sys::ambient_set(last_cap)
        .unwrap_or_else(|e| fail(proto::ERR_CAPS, "ambient set", Some(e)));
    let nnp = sys::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0).unwrap_or(0);
    let (ruid, _, rgid, _) = sys::ids();

    let ok = c.effective == na
        && c.permitted == na
        && bnd == na
        && amb == if keeper { na } else { 0 }
        && nnp == 1
        && ruid == p.helper_uid
        && rgid == p.helper_gid;

    if !ok {
        eprintln!(
            "sundew-helper: credential check failed: eff={:x} prm={:x} inh={:x} bnd={:x} amb={:x} nnp={} uid={} gid={}",
            c.effective, c.permitted, c.inheritable, bnd, amb, nnp, ruid, rgid
        );
        fail(proto::ERR_CAPS, "credential check failed", None);
    }
}

pub fn run() -> ! {
    sys::set_name(c"sundew-keeper");
    let exe_fd = check_self();
    let policy = read_policy();
    check_fds(&policy);

    let last_cap =
        sys::cap_last_cap().unwrap_or_else(|e| fail(proto::ERR_CAPS, "cap_last_cap", Some(e)));
    if last_cap >= 64 {
        fail(proto::ERR_CAPS, "unsupported cap_last_cap", None);
    }

    drop_privileges(&policy, last_cap);

    let mut restarted = false;
    let mut backoff = Duration::from_millis(100);

    loop {
        let started = sys::monotonic_ms();
        let pid = sys::fork().unwrap_or_else(|e| fail(proto::ERR_SANDBOX, "fork", Some(e)));

        if pid == 0 {
            let args: &[&std::ffi::CStr] = if restarted {
                &[c"sundew-helper", c"--engine", c"--restarted"]
            } else {
                &[c"sundew-helper", c"--engine"]
            };
            let err = sys::execveat_self(exe_fd, args);
            eprintln!("sundew-helper: execveat engine: {err}");
            sys::exit(127);
        }

        let st = sys::waitpid(pid).unwrap_or_else(|e| fail(proto::ERR_SANDBOX, "waitpid", Some(e)));

        if libc::WIFEXITED(st) {
            match libc::WEXITSTATUS(st) {
                0 => sys::exit(0),
                2 if !restarted => sys::exit(1),
                code => eprintln!("sundew-helper: engine exited with status {code}, restarting"),
            }
        } else if libc::WIFSIGNALED(st) {
            let sig = libc::WTERMSIG(st);
            if sig == libc::SIGSYS {
                eprintln!("sundew-helper: engine killed by seccomp (SIGSYS), restarting");
            } else {
                eprintln!("sundew-helper: engine killed by signal {sig}, restarting");
            }
        }

        if sys::monotonic_ms().saturating_sub(started) > 60_000 {
            backoff = Duration::from_millis(100);
        }

        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_secs(30));
        restarted = true;
    }
}
