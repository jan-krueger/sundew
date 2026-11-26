"""Hostile-worker frames. Usage: hostile.py <case> <worker-pid> <good-worker-pid>"""

import ctypes
import os
import socket
import struct
import sys

SYS_pidfd_open = 434
SYS_pidfd_getfd = 438
libc = ctypes.CDLL(None, use_errno=True)

MAGIC, VERSION, OP_TEST = 0x5357, 1, 1


def slot_of(pid):
    pidfd = libc.syscall(SYS_pidfd_open, pid, 0)
    if pidfd < 0:
        raise OSError(ctypes.get_errno(), "pidfd_open")
    for name in os.listdir(f"/proc/{pid}/fd"):
        if not os.readlink(f"/proc/{pid}/fd/{name}").startswith("socket:"):
            continue
        fd = libc.syscall(SYS_pidfd_getfd, pidfd, int(name), 0)
        if fd < 0:
            continue
        s = socket.socket(fileno=fd)
        if s.type == socket.SOCK_SEQPACKET and s.family == socket.AF_UNIX:
            return s
        s.detach()
        os.close(fd)
    raise SystemExit(f"no slot in {pid}")


def frame(req_id=1, mask=1, fam=4, addr=bytes([192, 0, 2, 1]), magic=MAGIC, op=OP_TEST, pad0=b"\0" * 7, pad1=b"\0" * 8):
    return struct.pack("=HBBIQB7s16s8s", magic, VERSION, op, req_id, mask, fam, pad0, addr.ljust(16, b"\0"), pad1)


def roundtrip(s, f):
    s.settimeout(2)
    s.send(f)
    while True:
        rep = s.recv(64)
        if not rep:
            return None
        magic, _, status, rid, decided, matched = struct.unpack("=HBBIQQ", rep)
        if rid == struct.unpack_from("=I", f, 4)[0]:
            return status, decided, matched


def closed(s):
    s.settimeout(2)
    try:
        return s.recv(64) == b""
    except (ConnectionResetError, BrokenPipeError):
        return True
    except socket.timeout:
        return False


CASES = {
    "short": lambda: frame()[:47],
    "long": lambda: frame() + b"\0",
    "magic": lambda: frame(magic=0x1234),
    "op": lambda: frame(op=9),
    "family": lambda: frame(fam=5),
    "pad0": lambda: frame(pad0=b"\0\0\0\x01\0\0\0"),
    "pad1": lambda: frame(pad1=b"\0" * 7 + b"\x01"),
    "v4-trailing": lambda: frame(addr=bytes([192, 0, 2, 1, 9])),
    "empty-mask": lambda: frame(mask=0),
    "mask-range": lambda: frame(mask=1 << 40),
    "cross-family": lambda: frame(mask=0b10),
}


def main():
    case, bad_pid, good_pid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    bad, good = slot_of(bad_pid), slot_of(good_pid)

    assert roundtrip(bad, frame(req_id=11)) is not None, "baseline request failed"

    if case == "ancillary":
        r, w = os.pipe()
        bad.sendmsg([frame(req_id=12)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", r))])
    else:
        bad.send(CASES[case]())

    if not closed(bad):
        raise SystemExit(f"{case}: channel not closed")

    r = roundtrip(good, frame(req_id=13))
    if r is None or r[1] & 1 == 0 or r[2] & 1 == 0:
        raise SystemExit(f"{case}: other channel broken: {r}")


if __name__ == "__main__":
    main()
