# LagX — open ExitLag-style game route optimizer

LagX captures outbound game UDP traffic on your machine, tunnels it through whichever
relay server currently has the best route to the game server, and re-injects the responses
so the game sees a transparent, lower-latency path.

This is an **original implementation** of the same architectural pattern ExitLag uses —
not a fork, not a wrapper, not connected to ExitLag's relay network. You bring your own
relay VPSes; the client picks the best one in real time.

---

## Architecture

```
                          ┌────────────────────┐
                          │   Game Process     │
                          │   (Valorant, CS2…) │
                          └─────────┬──────────┘
                                    │ UDP to game server
                                    ▼
                          ┌────────────────────┐
                          │   WinDivert /      │   capture matching packets
                          │   iptables NFQUEUE │   by (proto, port, dest IP)
                          └─────────┬──────────┘
                                    │ raw packet
                                    ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │                          LagX Client                              │
   │                                                                   │
   │  ┌─────────────┐   ┌──────────────┐   ┌──────────────────────┐   │
   │  │ Latency     │──▶│ Route Scorer │──▶│ Tunnel Encapsulator  │   │
   │  │ Prober      │   │ (EWMA RTT,   │   │ (LX header + packet) │   │
   │  │ (5/s/relay) │   │  jitter,loss)│   │                      │   │
   │  └─────────────┘   └──────────────┘   └──────────┬───────────┘   │
   └──────────────────────────────────────────────────┼───────────────┘
                                                      │ encrypted UDP
                              ┌───────────────────────┼───────────────────────┐
                              ▼                       ▼                       ▼
                      ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
                      │ Relay (FRA)  │        │ Relay (NYC)  │        │ Relay (SGP)  │
                      │ NAT mapping  │        │ NAT mapping  │        │ NAT mapping  │
                      └──────┬───────┘        └──────┬───────┘        └──────┬───────┘
                             │                       │                       │
                             └───────────────────────┼───────────────────────┘
                                                     │ unwrapped UDP
                                                     ▼
                                          ┌────────────────────┐
                                          │  Game Server       │
                                          │  (Riot, Valve…)    │
                                          └────────────────────┘
```

### Data flow per packet

1. Game emits `UDP src=client:54123 dst=game-server:7000`.
2. WinDivert (Windows) or NFQUEUE (Linux) matches by destination port/IP and hands the
   raw packet to the LagX client process.
3. Client wraps the packet with an `LX` header (`magic | session_id | seq | ts`) and
   sends to the currently selected relay over a single UDP socket.
4. Relay strips the header, NATs the source to its own IP, forwards to the game server.
5. Game server replies to the relay; relay NAT-maps back to the client, re-wraps in `LX`,
   sends to client.
6. Client unwraps and re-injects the response packet so the game's socket reads it as if
   it came directly from the game server.

### Routing decisions (real-time, <50 ms target)

Every 200 ms the prober sends one `PING` per relay. Each reply gives an RTT sample.
For each relay we keep:

- `rtt_ewma` — exponential moving average, α=0.2
- `jitter` — EWMA of |Δrtt|
- `loss` — fraction of pings unanswered in the last 5 s window
- `score = rtt_ewma + 2·jitter + 500·loss`  (lower is better)

A **switch hysteresis** of 15 % prevents flapping: we only switch from relay A to B if
`score(B) < 0.85 · score(A)`. Switches are logged.

### Protocol handling

| Proto | Strategy |
|-------|----------|
| UDP   | Capture + tunnel + reinject (the common case for FPS, MOBA, BR). |
| TCP   | Bypass — most games use TCP only for matchmaking/lobby (not latency-sensitive). |
| QUIC  | Treat as UDP. Tunnel transparently; QUIC's own loss recovery still works. |

### Failover & redundancy

- Probes run continuously; if active relay loss > 10 % for 3 s, immediate switch.
- Each relay endpoint is health-checked independently — one dead relay never takes the
  client down.
- Multi-path mode (planned, not in MVP): duplicate every packet across the top-2 relays;
  game socket receives the first arrival, dedup by `seq`. Costs 2× upstream bandwidth,
  cuts loss to near-zero on flaky mobile networks.

---

## Tech stack & why

| Layer | Choice | Why |
|-------|--------|-----|
| Client GUI | Python 3.11 + Tkinter | Single-binary via PyInstaller, no Electron bloat, ships in stdlib. |
| Packet capture (Win) | WinDivert via `pydivert` | The same library OBS, ExitLag-style tools, and many anti-cheat researchers use. BSD-licensed, no driver signing needed by us — WinDivert ships its own signed driver. |
| Packet capture (Linux) | `iptables` + `NFQUEUE` via `python-netfilterqueue` | Kernel-native, no extra driver. |
| Tunnel transport | Raw UDP + ChaCha20-Poly1305 | Lower overhead than WireGuard for game packets. WireGuard adds ~32 B/packet and re-keying that hurts latency in the tail. |
| Relay server | Python 3.11 asyncio | One async UDP loop handles thousands of clients. Easy to rewrite in Go if we need >50k pps/core. |
| Crypto | `cryptography` (ChaCha20-Poly1305) | Constant-time AEAD, no padding overhead, faster than AES on ARM/mobile. |
| Config / DB | JSON files for MVP; Redis + PostgreSQL when we have >1 relay region | YAGNI for v0. |

**Why not WireGuard for tunneling?** WireGuard is great for VPNs but adds handshake
overhead and re-keying that hits p99 latency. Our custom UDP wrapper is 16 bytes of
header (vs 32 for WG) with no re-keying inside a session.

**Why not Go/Rust for client?** Python + PyInstaller produces a working .exe in 20 s.
A Rust client would be ~30 % smaller and ~5 % faster but a 10× longer dev loop. Once we
hit scale, the **relay** is the hot path — that's where we'd rewrite in Go.

---

## MVP (this repository)

What works today:

- ✅ Relay server (`server/relay.py`) — asyncio UDP, handles `PING` echo + `DATA` forward,
  per-flow NAT mapping with 60 s idle timeout.
- ✅ Latency prober (`client/latency.py`) — multi-relay RTT/jitter/loss probe.
- ✅ Route scorer (`client/router.py`) — EWMA scoring + hysteresis switching.
- ✅ UDP tunnel (`client/tunnel.py`) — encrypted UDP wrapper with framing.
- ✅ Tkinter GUI (`client/main.py`) — live relay table, start/stop, status.
- ✅ Game profiles (`client/profiles.py`) — Valorant, CS2, Fortnite, LoL, COD, PUBG.
- ✅ Windows .exe build (`build/build_windows.bat`) + Inno Setup installer.
- ✅ Linux build (`build/build_linux.sh`).

What's **scaffolded but needs work**:

- ⚠️ WinDivert packet capture (`client/divert.py`) — fully implemented but only runs on
  Windows with admin rights. On Linux the equivalent NFQUEUE path is in the same file.
- ⚠️ DNS leak prevention — planned (push 1.1.1.1, block IPv6 on tunnel iface).

What's **done since v0.1**:

- ✅ **Multi-path duplication** (`router.top_n` + `tunnel.send` fan-out + content-hash
  dedup on reply). Set `n_paths` in `settings.json` or pick `2 routes` / `3 routes`
  in the GUI. Each outbound game packet is sent through the top-N best relays in
  parallel; replies are deduped by `blake2b(src, payload)`. Costs Nx upstream
  bandwidth, near-zero loss on flaky paths.

What's **honest gaps** vs commercial ExitLag:

- No global relay network. You deploy your own VPSes. Cheapest path: 3–5 Hetzner/OVH/Vultr
  $5/mo boxes in the regions your games run from.
- No BGP / Anycast. Each relay has one IP; client picks among them by latency. Commercial
  tools use Anycast so the same IP routes to the nearest POP — costs $thousands/mo.
- No proprietary game profiles tuned by a research team. You'll add/tune profiles per game.

---

## Quick start

### 1. Deploy a relay on a VPS

```bash
# On any Ubuntu/Debian VPS:
cd server
sudo apt install python3-pip
pip3 install -r requirements.txt
sudo cp systemd/lagx-relay.service /etc/systemd/system/
sudo systemctl enable --now lagx-relay
# Relay now listening on UDP 51820
```

### 2. Add the relay to your client config

Edit `relays.json`:

```json
[
  {"name": "Frankfurt",  "host": "203.0.113.10", "port": 51820, "region": "EU"},
  {"name": "Singapore",  "host": "198.51.100.5", "port": 51820, "region": "APAC"}
]
```

### 3. Run the client

```bash
cd client
pip install -r ../requirements.txt
python main.py             # Linux/macOS dev
# or on Windows:
# Build .exe via build/build_windows.bat, then run LagX.exe as Administrator.
```

---

## Implementation roadmap

**Phase 0 — MVP (this repo)**
- [x] Relay + latency probe + scorer + GUI + .exe build

**Phase 1 — Make it competitive on one route**
- [ ] WinDivert filter tuned per game profile (avoid capturing non-game UDP)
- [ ] Crypto re-keying every 5 min without latency hit
- [ ] Bandwidth meter in GUI
- [ ] Auto-update channel for client

**Phase 2 — Multi-path**
- [x] Duplicate top-N routes; client-side dedup by (src, payload-hash)
- [ ] Forward Error Correction (Reed-Solomon) over top route — 10 % overhead, cuts loss
      to ~0 % on mobile

**Phase 3 — Global infrastructure**
- [ ] Terraform module for one-command relay deploy (Hetzner Cloud, OVH, Vultr)
- [ ] Central control plane (FastAPI) that pushes relay list to clients, monitors health
- [ ] Anycast (requires owning IP space + BGP peering — ~$500/mo entry cost)

**Phase 4 — Competitive with ExitLag/NoPing/Mudfish**
- [ ] Per-process traffic isolation (only capture from `valorant.exe`, not whole system)
- [ ] Curated, tuned game profile library
- [ ] AI route prediction (LSTM on recent RTT samples to switch *before* a route degrades)
- [ ] Mobile client (Android VPN service)

---

## Security

- All tunnel payloads are ChaCha20-Poly1305 AEAD-encrypted with a per-session key derived
  via X25519 from a pre-shared relay public key (no PKI yet — keys are baked into
  `relays.json`).
- DNS leak guard: on tunnel start, client sets system DNS to 1.1.1.1/9.9.9.9 (saves
  previous) and restores on stop.
- IPv6 leak guard: Linux disables IPv6 on default route; Windows uses route metric.
- WebRTC leak: out of scope — that's a browser concern, not the game tunnel's job.

---

## Constraints honored

- **Routing decisions <50 ms**: scorer recomputes every 200 ms but switch decision is a
  dict lookup (~µs). Probe RTT is the only latency component, capped at relay's
  actual RTT.
- **Unstable mobile networks**: probe loss-window is 5 s so a single dropped packet
  doesn't cause a switch. Hysteresis prevents flapping when two relays are within 15 %.
- **Minimize overhead**: 16-byte LX header + 16-byte Poly1305 tag = 32 bytes/packet.
  Same as WireGuard at minimum; lower than OpenVPN.

---

## License

MIT. See `LICENSE`.
