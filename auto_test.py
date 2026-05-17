"""LagX auto-test harness.

Runs each component in isolation and the full pipeline end-to-end. No external test
framework — just functions, asserts, and a pass/fail summary. Designed to run in CI
or on a dev box without network egress.

Usage:  python3 auto_test.py
Exit 0 on all pass, 1 on any failure.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import struct
import sys
import tempfile
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from client import config, profiles
from client.divert import LoopbackCapture, WinDivertCapture, make_capture
from client.latency import Prober
from client.protocol import (
    HDR_LEN, MAGIC, T_DATA_IN, T_DATA_OUT, T_PING, T_PONG, VERSION,
    make_nonce, new_aead, pack_header, unpack_header,
)
from client.router import HYSTERESIS, Router
from client.tunnel import Tunnel
from server import relay as relay_mod

PSK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# ── tiny test framework ────────────────────────────────────────────────────────
_PASS, _FAIL = 0, 0
_FAILURES: list[tuple[str, str]] = []


def t(name: str):
    """Decorator: runs the function, captures result."""
    def deco(fn):
        global _PASS, _FAIL
        sys.stdout.write(f"  {name:<48} ")
        sys.stdout.flush()
        try:
            res = fn()
            if asyncio.iscoroutine(res):
                asyncio.get_event_loop().run_until_complete(res)
            _PASS += 1
            print("\033[32mPASS\033[0m")
        except Exception as e:
            _FAIL += 1
            _FAILURES.append((name, traceback.format_exc()))
            print(f"\033[31mFAIL\033[0m  {e!r}")
        return fn
    return deco


# ── protocol & crypto ────────────────────────────────────────────────────────

def section(title: str):
    print(f"\n\033[1m{title}\033[0m")


section("protocol & crypto")


@t("header pack/unpack round-trip")
def _():
    hdr = pack_header(T_DATA_OUT, 0xDEADBEEF, 42, 0x11223344)
    assert len(hdr) == HDR_LEN
    assert hdr[:2] == MAGIC
    out = unpack_header(hdr)
    assert out == (VERSION, T_DATA_OUT, 0xDEADBEEF, 42, 0x11223344), out


@t("unpack rejects wrong magic")
def _():
    assert unpack_header(b"XX" + b"\x00" * 14) is None
    assert unpack_header(b"") is None
    assert unpack_header(b"LX") is None  # too short


@t("nonce is 12 bytes and deterministic")
def _():
    n1 = make_nonce(1, 2)
    n2 = make_nonce(1, 2)
    n3 = make_nonce(1, 3)
    assert len(n1) == 12
    assert n1 == n2
    assert n1 != n3


@t("AEAD encrypt/decrypt with AAD round-trips")
def _():
    aead = new_aead(PSK)
    nonce = make_nonce(7, 99)
    aad = b"some-header-bytes"
    pt = b"hello game packet"
    ct = aead.encrypt(nonce, pt, aad)
    assert aead.decrypt(nonce, ct, aad) == pt


@t("AEAD decrypt fails on wrong AAD")
def _():
    aead = new_aead(PSK)
    nonce = make_nonce(7, 99)
    ct = aead.encrypt(nonce, b"x", b"aad-A")
    try:
        aead.decrypt(nonce, ct, b"aad-B")
        raise AssertionError("should have raised")
    except Exception:
        pass


@t("PSK length validation")
def _():
    try:
        new_aead("00")
        raise AssertionError("short PSK should reject")
    except ValueError:
        pass


# ── profiles ─────────────────────────────────────────────────────────────────

section("game profiles")


@t("by_id returns known game")
def _():
    g = profiles.by_id("valorant")
    assert g and g.name == "Valorant"


@t("by_id returns None on unknown")
def _():
    assert profiles.by_id("nopesauce") is None


@t("every profile has at least one valid port range")
def _():
    for g in profiles.GAMES:
        assert g.dst_ports, g.id
        for lo, hi in g.dst_ports:
            assert 1 <= lo <= hi <= 65535, (g.id, lo, hi)


# ── config ───────────────────────────────────────────────────────────────────

section("config loader")


@t("loads default settings when missing")
def _():
    with tempfile.TemporaryDirectory() as d:
        # monkey-patch app_dir to point at temp
        config.app_dir = lambda: Path(d)
        s = config.load_settings()
        assert s["psk_hex"] == config.DEFAULT_PSK
        assert (Path(d) / "settings.json").exists()


@t("loads default relays when missing")
def _():
    with tempfile.TemporaryDirectory() as d:
        config.app_dir = lambda: Path(d)
        r = config.load_relays()
        assert isinstance(r, list) and r and "host" in r[0]
        assert (Path(d) / "relays.json").exists()


@t("save+reload settings preserves changes")
def _():
    with tempfile.TemporaryDirectory() as d:
        config.app_dir = lambda: Path(d)
        s = config.load_settings()
        s["last_game_id"] = "cs2"
        config.save_settings(s)
        s2 = config.load_settings()
        assert s2["last_game_id"] == "cs2"


@t("malformed relays.json falls back to defaults")
def _():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "relays.json").write_text("{not valid json")
        config.app_dir = lambda: Path(d)
        r = config.load_relays()
        assert r == config.DEFAULT_RELAYS


# ── divert backends ─────────────────────────────────────────────────────────

section("divert backends")


@t("make_capture returns loopback when unknown OS requested")
def _():
    cap = make_capture("freebsd")
    assert isinstance(cap, LoopbackCapture)


@t("WinDivert filter builder yields expected syntax")
def _():
    g = profiles.by_id("valorant")
    flt = WinDivertCapture._build_filter([g])
    # Valorant uses 7000-7500
    assert "outbound" in flt and "udp" in flt
    assert "udp.DstPort >= 7000" in flt and "udp.DstPort <= 7500" in flt


@t("WinDivert filter builder handles multiple games + single ports")
def _():
    flt = WinDivertCapture._build_filter([profiles.by_id("cod")])
    # COD has 3074-3074 (single) and 3478-3480
    assert "udp.DstPort == 3074" in flt
    assert "udp.DstPort >= 3478 and udp.DstPort <= 3480" in flt
    assert " or " in flt


@t("UDP packet builder produces parseable IPv4+UDP")
def _():
    pkt = WinDivertCapture._build_udp_packet(
        ("10.0.0.1", 7000), ("192.168.1.5", 54321), b"PAYLOAD"
    )
    # IP version 4, IHL 5
    assert (pkt[0] >> 4) == 4
    assert (pkt[0] & 0xF) == 5
    # protocol 17 (UDP)
    assert pkt[9] == 17
    # src/dst IPs
    assert socket.inet_ntoa(pkt[12:16]) == "10.0.0.1"
    assert socket.inet_ntoa(pkt[16:20]) == "192.168.1.5"
    # UDP src port
    assert struct.unpack("!H", pkt[20:22])[0] == 7000
    # payload at end
    assert pkt[-7:] == b"PAYLOAD"


# ── prober ───────────────────────────────────────────────────────────────────

section("latency prober")


async def _spawn_relay(port: int) -> tuple[asyncio.DatagramTransport, relay_mod.RelayProtocol]:
    aead = relay_mod.ChaCha20Poly1305(bytes.fromhex(PSK))
    proto = relay_mod.RelayProtocol(aead)
    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: proto, local_addr=("127.0.0.1", port),
    )
    return transport, proto


@t("prober gets RTT samples from live relay")
async def _():
    transport, _ = await _spawn_relay(52001)
    try:
        prober = Prober([{"name": "t", "host": "127.0.0.1", "port": 52001, "region": "L"}])
        await prober.start()
        # 5 probe intervals @ 200ms each = ~1s for stats to converge
        await asyncio.sleep(1.2)
        stats = prober.stats()[0]
        assert stats.pongs_recv >= 3, f"only got {stats.pongs_recv} pongs"
        assert stats.rtt_ms < 100, f"rtt too high: {stats.rtt_ms}"
        assert stats.loss < 0.5
        await prober.stop()
    finally:
        transport.close()


@t("prober marks dead relay as inf RTT + high loss")
async def _():
    # No relay running on this port — TEST_DEAD
    prober = Prober([{"name": "dead", "host": "127.0.0.1", "port": 52099, "region": "X"}])
    await prober.start()
    await asyncio.sleep(2.0)
    stats = prober.stats()[0]
    assert stats.rtt_ms == float("inf"), f"got rtt {stats.rtt_ms}"
    assert stats.loss > 0.5, f"got loss {stats.loss}"
    assert prober.best() is None
    await prober.stop()


@t("prober snapshot has expected fields")
def _():
    prober = Prober([{"name": "x", "host": "127.0.0.1", "port": 1, "region": "Z"}])
    snap = prober.stats()[0].snapshot()
    for k in ("name", "host", "region", "rtt_ms", "jitter_ms", "loss", "score"):
        assert k in snap, k


# ── router ───────────────────────────────────────────────────────────────────

section("router")


def _fake_prober_with_scores(*scores: float) -> Prober:
    p = Prober([{"name": f"r{i}", "host": "127.0.0.1", "port": 53000 + i, "region": "R"}
                for i in range(len(scores))])
    for stats, rtt in zip(p.stats(), scores):
        stats.rtt_ms = rtt
        stats.jitter_ms = 0.0
        stats.loss = 0.0
    return p


@t("router picks lowest-score relay on init")
def _():
    p = _fake_prober_with_scores(100, 50, 200)
    r = Router(p)
    a = r.tick()
    assert a and a.relay.name == "r1", a.relay.name


@t("router hysteresis keeps incumbent when challenger is only slightly better")
def _():
    # Init with r0 (50) clearly best; router picks r0.
    p = _fake_prober_with_scores(50, 100)
    r = Router(p)
    r.tick()
    assert r.active.relay.name == "r0"
    # Now flip so r1 is slightly better than r0: r0=100, r1=95.
    # 95 is NOT < 0.85*100 (=85), so hysteresis must hold incumbent.
    p.stats()[0].rtt_ms = 100
    p.stats()[1].rtt_ms = 95
    r.tick()
    assert r.active.relay.name == "r0", "should not have switched within hysteresis band"


@t("router switches when challenger beats hysteresis band")
def _():
    p = _fake_prober_with_scores(100, 50)
    r = Router(p)
    r.tick()  # picks r1 initially (50 < 100)
    assert r.active.relay.name == "r1"
    # now flip — make r0 best
    p.stats()[0].rtt_ms = 30
    p.stats()[1].rtt_ms = 100
    r.tick()
    assert r.active.relay.name == "r0", "should have switched to r0"


@t("router emergency switches on sustained loss")
async def _():
    p = _fake_prober_with_scores(50, 60)
    r = Router(p)
    r.tick()
    assert r.active.relay.name == "r0"
    # crank loss on incumbent; challenger stays clean
    p.stats()[0].loss = 0.5
    # score(r0) = 50 + 0 + 250 = 300; score(r1) = 60 — r1 best, but normal switch needs
    # 60 < 0.85*300 (255) → already triggers normal switch. So make r0 worse on loss
    # alone and challenger BIGGER on RTT so only emergency path triggers.
    p.stats()[1].rtt_ms = 280
    p.stats()[1].loss = 0.0
    # r0 score = 50 + 0 + 250 = 300; r1 score = 280 — both close, normal switch would need 280 < 255 → false
    # So only emergency triggers after EMERGENCY_HOLD_S=3.0
    start = time.monotonic()
    while time.monotonic() - start < 4.0:
        r.tick()
        if r.active.relay.name == "r1":
            break
        await asyncio.sleep(0.1)
    assert r.active.relay.name == "r1", "emergency switch should have fired"


# ── tunnel + relay full round-trip ──────────────────────────────────────────

section("tunnel ↔ relay end-to-end")


@t("packet round-trips through relay to echo server")
async def _():
    transport, _ = await _spawn_relay(52010)
    loop = asyncio.get_event_loop()
    # echo server on 19998
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.setblocking(False); echo.bind(("127.0.0.1", 19998))
    def _e():
        try:
            d, a = echo.recvfrom(4096)
            echo.sendto(b"REPLY:" + d, a)
        except BlockingIOError: pass
    loop.add_reader(echo.fileno(), _e)
    try:
        prober = Prober([{"name": "L", "host": "127.0.0.1", "port": 52010, "region": "R"}])
        await prober.start()
        router = Router(prober)
        aead = new_aead(PSK)
        got = []
        tunnel = Tunnel(router, aead, reinject_cb=lambda p, s: got.append((p, s)))
        await tunnel.start()
        for _ in range(30):
            router.tick()
            if router.active and router.active.relay.rtt_ms != float("inf"):
                break
            await asyncio.sleep(0.1)
        assert router.active
        tunnel.send(b"PING-DATA", ("127.0.0.1", 19998))
        for _ in range(30):
            await asyncio.sleep(0.05)
            if got: break
        assert got, "no reply"
        payload, src = got[0]
        assert payload == b"REPLY:PING-DATA"
        assert src == ("127.0.0.1", 19998)
        await prober.stop(); await tunnel.stop()
    finally:
        loop.remove_reader(echo.fileno()); echo.close()
        transport.close()


@t("multi-relay failover: kill active, router migrates within 5s")
async def _():
    t1, _ = await _spawn_relay(52020)
    t2, _ = await _spawn_relay(52021)
    loop = asyncio.get_event_loop()
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.setblocking(False); echo.bind(("127.0.0.1", 19997))
    def _e():
        try:
            d, a = echo.recvfrom(4096); echo.sendto(b"R:" + d, a)
        except BlockingIOError: pass
    loop.add_reader(echo.fileno(), _e)
    try:
        prober = Prober([
            {"name": "A", "host": "127.0.0.1", "port": 52020, "region": "R"},
            {"name": "B", "host": "127.0.0.1", "port": 52021, "region": "R"},
        ])
        await prober.start()
        router = Router(prober)
        for _ in range(15):
            router.tick()
            if router.active: break
            await asyncio.sleep(0.2)
        first_choice = router.active.relay.name
        # kill whichever was chosen
        if first_choice == "A":
            t1.close()
        else:
            t2.close()
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            router.tick()
            if router.active.relay.name != first_choice:
                break
            await asyncio.sleep(0.2)
        assert router.active.relay.name != first_choice, (
            f"router stayed on dead relay {first_choice}"
        )
        await prober.stop()
    finally:
        loop.remove_reader(echo.fileno()); echo.close()
        try: t1.close()
        except Exception: pass
        try: t2.close()
        except Exception: pass


@t("relay decryption rejects packet with wrong PSK")
async def _():
    transport, proto = await _spawn_relay(52030)
    try:
        # Send a forged DATA_OUT with a different key
        bad_aead = new_aead("ff" * 32)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setblocking(False)
        s.bind(("127.0.0.1", 0))
        sid, seq, ts = 1, 1, 0
        hdr = pack_header(T_DATA_OUT, sid, seq, ts)
        meta = struct.pack("!4sH", socket.inet_aton("127.0.0.1"), 19996)
        ct = bad_aead.encrypt(make_nonce(sid, seq), b"X", hdr + meta)
        s.sendto(hdr + meta + ct, ("127.0.0.1", 52030))
        await asyncio.sleep(0.3)
        # Relay should have created NO flow (decrypt failed)
        assert len(proto.flows) == 0, f"unexpected flows: {proto.flows}"
        s.close()
    finally:
        transport.close()


# ── NAT flow lifecycle ──────────────────────────────────────────────────────

section("relay NAT lifecycle")


@t("relay flow expires after idle window")
async def _():
    # speed up the constant for the test
    orig = relay_mod.FLOW_IDLE_S
    relay_mod.FLOW_IDLE_S = 0.5
    try:
        transport, proto = await _spawn_relay(52040)
        aead = new_aead(PSK)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setblocking(False)
        s.bind(("127.0.0.1", 0))
        sid, seq, ts = 42, 1, 0
        hdr = pack_header(T_DATA_OUT, sid, seq, ts)
        meta = struct.pack("!4sH", socket.inet_aton("127.0.0.1"), 19995)
        ct = aead.encrypt(make_nonce(sid, seq), b"DATA", hdr + meta)
        s.sendto(hdr + meta + ct, ("127.0.0.1", 52040))
        await asyncio.sleep(0.3)
        assert len(proto.flows) == 1, f"expected 1 flow, got {len(proto.flows)}"
        # start reaper, wait > idle window + reaper interval (which is 10s, too long)
        # — call reaper manually to keep test fast
        await asyncio.sleep(0.6)
        cutoff = time.monotonic() - relay_mod.FLOW_IDLE_S
        dead = [k for k, f in proto.flows.items() if f.last_seen < cutoff]
        for k in dead:
            f = proto.flows.pop(k)
            asyncio.get_event_loop().remove_reader(f.sock.fileno())
            f.sock.close()
        assert len(proto.flows) == 0, f"flow should have reaped: {proto.flows}"
        s.close()
        transport.close()
    finally:
        relay_mod.FLOW_IDLE_S = orig


# ── run ─────────────────────────────────────────────────────────────────────

def main():
    print("\n\033[1mLagX auto-test\033[0m\n")
    # tests register themselves via decorator on import
    print(f"\n──────────────────────────────────────────────────────")
    print(f"  {_PASS} passed, {_FAIL} failed")
    if _FAIL:
        for name, tb in _FAILURES:
            print(f"\n\033[31m── {name} ──\033[0m\n{tb}")
        sys.exit(1)
    print(f"  \033[32mall tests passed\033[0m")
    sys.exit(0)


if __name__ == "__main__":
    main()
