"""Rate limit across a window boundary: 5 requests late in one 1 s window,
the 6th just after the next one starts. Prints the status codes."""

import sys
import time
import urllib.error
import urllib.request


def get(addr):
    req = urllib.request.Request("http://127.0.0.1:8080/rl1", headers={"X-Forwarded-For": addr})
    try:
        return urllib.request.urlopen(req, timeout=5).status
    except urllib.error.HTTPError as e:
        return e.code


def wait_until(ms_in_second):
    # nginx counts windows with CLOCK_MONOTONIC, as time.monotonic() does
    while int(time.monotonic() * 1000) % 1000 != ms_in_second:
        time.sleep(0.0005)


addr = sys.argv[1]
wait_until(850)
codes = [get(addr) for _ in range(5)]
wait_until(20)
codes.append(get(addr))
print(" ".join(str(c) for c in codes))
