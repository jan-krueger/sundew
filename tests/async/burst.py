"""Opens N connections at once, each with its own X-Forwarded-For, and
prints how many answers of each status arrived within the deadline."""

import collections
import resource
import selectors
import socket
import sys
import time

n, deadline = int(sys.argv[1]), float(sys.argv[2])
_, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
sel = selectors.DefaultSelector()
for i in range(n):
    s = socket.create_connection(("127.0.0.1", 8080))
    s.setblocking(False)
    addr = f"10.77.{i >> 8}.{i & 255}"
    s.send(f"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: {addr}\r\nConnection: close\r\n\r\n".encode())
    sel.register(s, selectors.EVENT_READ, b"")

codes = collections.Counter()
end = time.monotonic() + deadline
while len(sel.get_map()) and time.monotonic() < end:
    for key, _ in sel.select(timeout=0.1):
        data = key.fileobj.recv(4096)
        if data:
            codes[data.split(b" ", 2)[1].decode()] += 1
        sel.unregister(key.fileobj)
        key.fileobj.close()
codes["none"] = len(sel.get_map())
print(" ".join(f"{k}:{v}" for k, v in sorted(codes.items())))
