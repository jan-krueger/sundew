# Use nftables sets

Sundew reads and writes nftables sets as well as ipsets. Name an nftables set
as `nft:FAMILY/TABLE/SET` wherever a set goes; ipsets keep their plain names,
and both kinds mix in one list. The commands below need root.

## 1. Create the sets

```bash
nft add table inet sundew
nft add set inet sundew blocklist '{ type ipv4_addr; flags interval; }'
nft add set inet sundew banned  '{ type ipv4_addr; flags timeout; timeout 1h; }'
nft add set inet sundew banned6 '{ type ipv6_addr; flags timeout; timeout 1h; }'
nft add element inet sundew blocklist '{ 192.0.2.0/24, 198.51.100.7 }'
```

- A set holds one address family: `ipv4_addr` or `ipv6_addr`. The table's
  family (`ip`, `ip6`, `inet`) is part of the name and must match.
- `flags interval` lets a set hold prefixes and ranges. Sundew can look up in
  such a set, but not add to it.
- Sets Sundew adds to need `flags timeout`, so bans expire. `timeout 1h` is the
  default; `timeout=` and `ban_time=` override it per rule.

Like ipsets, the sets must exist before nginx starts. Put them in
`/etc/nftables.conf`, which the `nftables` service loads at boot:

```nft title="/etc/nftables.conf (excerpt)"
table inet sundew {
    set blocklist { type ipv4_addr; flags interval; }
    set banned    { type ipv4_addr; flags timeout; timeout 1h; }
    set banned6   { type ipv6_addr; flags timeout; timeout 1h; }
}
```

## 2. Use them in nginx

```nginx
sundew_writable_sets nft:inet/sundew/banned nft:inet/sundew/banned6;

http {
    ipset_denylist nft:inet/sundew/blocklist
                   nft:inet/sundew/banned nft:inet/sundew/banned6;

    server {
        location = /wp-login.php {
            ipset_autoadd nft:inet/sundew/banned nft:inet/sundew/banned6;
        }
    }
}
```

## 3. Check

```console
$ curl -s -o /dev/null -w '%{http_code}\n' http://example.com/wp-login.php
404
$ sudo nft list set inet sundew banned
table inet sundew {
	set banned {
		type ipv4_addr
		flags timeout
		timeout 1h
		elements = { 203.0.113.9 timeout 1h expires 59m58s }
	}
}
```

## Differences from ipset

- `prefix4=` and `prefix6=` need an ipset `hash:net` set; an nftables set
  Sundew adds to holds single addresses.
- Changes to nftables sets reach nginx at once; changes to ipsets once the
  cached answer expires, after at most
  [`ipset_cache_ttl`](../reference/directives.md#ipset_cache_ttl). See
  [Caching](../concepts/caching.md#nftables).
- Elements that expire by their own `timeout` are not announced: for those, a
  ban that ran out still applies for at most `ipset_cache_ttl`.
- A configuration that uses only nftables sets does not need the `ip_set`
  kernel module.
