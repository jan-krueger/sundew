# Feed a set from fail2ban

fail2ban finds abusive addresses in your logs; Sundew makes nginx deny them.
The two meet in an ipset: fail2ban adds, Sundew reads.

--8<-- "fail2ban.html"

## 1. Create the set at boot

nginx refuses to start when a set it names is missing, so the set must exist
before nginx, not only once fail2ban runs. A systemd unit that runs first:

```ini title="/etc/systemd/system/ipset-f2b-web.service"
[Unit]
Description=ipset for fail2ban and Sundew
Before=nginx.service fail2ban.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ipset -exist create f2b-web hash:ip timeout 3600

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now ipset-f2b-web
```

## 2. A fail2ban action that only touches the set

fail2ban's stock `iptables-ipset` actions also add firewall rules. To let nginx
do the blocking, use an action that only adds to the set:

```ini title="/etc/fail2ban/action.d/sundew.conf"
[Definition]
actionban   = ipset -exist add <ipset> <ip> timeout <bantime>
actionunban = ipset -exist del <ipset> <ip>

[Init]
ipset = f2b-web
```

```ini title="/etc/fail2ban/jail.d/nginx.local"
[nginx-http-auth]
enabled  = true
bantime  = 3600
action   = sundew[ipset=f2b-web]
```

`bantime` must be finite: ipset has no `timeout -1`.

## 3. Deny the set in nginx

```nginx
http {
    ipset_denylist f2b-web;
}
```

## 4. Check

```console
$ sudo fail2ban-client set nginx-http-auth banip 198.51.100.7
$ sudo ipset test f2b-web 198.51.100.7
198.51.100.7 is in set f2b-web.
```

A ban reaches nginx within [`ipset_cache_ttl`](../reference/directives.md#ipset_cache_ttl)
(60 s by default) for addresses nginx has seen recently, and at once for
others. Lower it if bans must apply faster:

```nginx
ipset_cache_ttl 5s;
```

!!! tip "IPv6"
    A `hash:ip` set holds one address family. Create a second set with
    `family inet6` and list both: `ipset_denylist f2b-web f2b-web6;`.
