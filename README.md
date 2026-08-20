# KevVPN

Blocks VPNs and proxies from connecting to a CS:GO server. I wrote this because ban evasion
through cheap VPNs was eating most of my moderation time, so this one is pure prevention:
stop the reconnect instead of catching it later.

Written for SourceMod on CS:GO. Uses REST in Pawn for the lookups and MySQL or SQLite for
storage.

## Install

Drop the `addons` folder into your `csgo` folder. That gives you:

```
addons/sourcemod/plugins/KevVPN.smx           the compiled plugin
addons/sourcemod/scripting/KevVPN.sp          source, if you want to build it yourself
addons/sourcemod/configs/kevvpn/sources.ini   the blocklist feeds it downloads
```

You also need the **REST in Pawn** extension, and a `kevvpn` section in `databases.cfg`. If
you skip the database section it falls back to `default`.

## How it works

Three layers, checked in order, and it stops at the first one that answers. The point of the
order is to spend nothing before you have to.

**Layer 0, manual ranges.** Anything an admin confirmed by hand with `sm_kevvpn_addvpn`.
Checked first because an admin who looked at a case outranks a third party list.

**Layer 1, downloaded ranges.** CIDR feeds from `sources.ini`, held **in RAM**, not queried
from SQL. This is the layer that does most of the work, and it costs no network call at all.
Ranges are bucketed by the first octet, so a lookup reads one bucket instead of scanning
200,000 entries.

**Layer 2, reputation APIs.** Only for addresses the ranges miss. It tries proxycheck.io
first (needs a free key for real volume), then ip-api.com, then blackbox.ipinfo.app. Every
verdict is cached in the database with a TTL, default 168 hours, so a repeat visitor never
costs a second lookup.

## Configuration

14 convars, all written to `cfg/sourcemod/KevVPN.cfg` on first run. The ones that matter:

| Convar | What it does |
|---|---|
| `kevvpn_action` | 0 log, 1 kick, 2 SourceMod ban, 3 SourceBans++ with fallback |
| `kevvpn_proxycheck_key` | your proxycheck.io key, protected so it never prints |
| `kevvpn_cache_hours` | how long a stored verdict stays valid, default 168 |
| `kevvpn_admin_immunity` | 0 by default, meaning admin status alone exempts nobody |

On `kevvpn_admin_immunity`: with it off, the whitelist is the only way through, and the code
deliberately does **not** call `CheckCommandAccess` in that case. A ROOT admin satisfies
every flag by definition, so that check returns true for them no matter what you pass it,
including overrides they were never granted. There is no flag based way to exclude root, so
the only correct answer is not to ask.

## Commands

All admin only.

```
sm_kevvpn_check <player|ip>        look an address up now, and act if it names a live player
sm_kevvpn_whitelist <target> [why] let someone through
sm_kevvpn_unwhitelist <target>     take it back
sm_kevvpn_addvpn <cidr> [why]      block a range by hand
sm_kevvpn_delvpn <cidr>            unblock it
sm_kevvpn_allowdc <provider>       allow a hosting provider by name, e.g. NVIDIA
sm_kevvpn_denydc <provider>        stop allowing it
sm_kevvpn_dclist                   list allowed providers
sm_kevvpn_alts <target>            addresses a SteamID has connected from
sm_kevvpn_status                   ranges loaded, cache size, database and layer state
sm_kevvpn_list / _vpnlist          whitelist and manual blocklist
sm_kevvpn_update                   re-download the feeds now
sm_kevvpn_reload                   re-read the database tables after editing them by hand
```

Whitelisting takes a SteamID rather than an address wherever it can, because VPN and mobile
exits hand out a different address every session, so an address based entry quietly stops
matching on the next connect.

## Feeds

`configs/kevvpn/sources.ini` is one URL per line. The defaults are public lists:

* X4BNet/lists_vpn, VPN egress and datacenter ranges
* firehol blocklist-ipsets, Tor exits
* ipverse/asn-ip, per ASN prefixes for providers the general lists miss

A dead URL gets logged and the rest still load, so one broken feed does not take the layer
down.

## Credits

Written by me, but it is a deliberate merge of three older plugins that each did one piece:

* **CIDR_Blocker** by **RumbleFrog**
  ([github.com/CIDR-Blocker/CIDR-Blocker](https://github.com/CIDR-Blocker/CIDR-Blocker)) did
  range blocking, but ran a MySQL query on every connect. Here the ranges live in RAM and the
  database only stores results.
* **Lrthrome**, also by **RumbleFrog**
  ([github.com/rumblefrog/lrthrome](https://github.com/rumblefrog/lrthrome)) did large remote
  CIDR feeds, but needed a separate Rust daemon and the socket extension. Here the feeds are
  fetched over HTTP straight into the plugin.
* **ProxyKiller** by **Sikari**
  ([bitbucket.org/Sikarii/proxykiller](https://bitbucket.org/Sikarii/proxykiller)) did live
  reputation lookups with a SQL cache and whitelist. Kept, minus SteamWorks and its custom
  config parser.

Blocklist data comes from X4BNet, firehol and ipverse. Reputation data from proxycheck.io,
ip-api.com and ipinfo.

## License

GPL-3.0, see `LICENSE`.
