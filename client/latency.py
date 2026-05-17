"""Multi-relay latency prober.

Sends one PING per relay every PROBE_INTERVAL seconds, computes RTT, jitter (EWMA of
|dRTT|), and loss (fraction unanswered in the last LOSS_WINDOW seconds).

Designed so the routing engine can read RelayStats at any time and get a snapshot
without blocking. The prober itself runs in its own asyncio task.
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket
import time
from collections import deque
from dataclasses import dataclass, field

from .protocol import HDR_LEN, T_PING, T_PONG, pack_header, unpack_header

LOG = logging.getLogger("lagx.latency")

PROBE_INTERVAL_S = 0.2
LOSS_WINDOW_S = 5.0
RTT_ALPHA = 0.2          # EWMA weight for new RTT samples
JITTER_ALPHA = 0.2
PROBE_TIMEOUT_S = 1.5


@dataclass
class Sample:
    seq: int
    sent_at: float
    rtt_ms: float | None = None  # None = still pending or lost


@dataclass
class RelayStats:
    name: str
    host: str
    port: int
    region: str = ""
    rtt_ms: float = float("inf")
    jitter_ms: float = 0.0
    loss: float = 1.0           # 0..1
    last_seen: float = 0.0
    pings_sent: int = 0
    pongs_recv: int = 0
    history: deque[Sample] = field(default_factory=lambda: deque(maxlen=128))

    @property
    def score(self) -> float:
        """Lower = better. inf if we've never heard back."""
        if self.rtt_ms == float("inf"):
            return float("inf")
        return self.rtt_ms + 2.0 * self.jitter_ms + 500.0 * self.loss

    def snapshot(self) -> dict:
        return {
            "name": self.name,
            "host": self.host,
            "region": self.region,
            "rtt_ms": round(self.rtt_ms, 1) if self.rtt_ms != float("inf") else None,
            "jitter_ms": round(self.jitter_ms, 1),
            "loss": round(self.loss, 3),
            "score": round(self.score, 1) if self.score != float("inf") else None,
        }


class Prober:
    """One Prober instance probes a set of relays concurrently."""

    def __init__(self, relays: list[dict]):
        self.relays: dict[tuple[str, int], RelayStats] = {}
        for r in relays:
            key = (r["host"], r["port"])
            self.relays[key] = RelayStats(
                name=r["name"], host=r["host"], port=r["port"], region=r.get("region", ""),
            )
        self.session_id = random.randint(1, 0x7FFFFFFF)
        self._seq = 0
        self._pending: dict[int, tuple[tuple[str, int], float]] = {}  # seq -> (addr, sent_at)
        self._sock: socket.socket | None = None
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setblocking(False)
        self._sock.bind(("0.0.0.0", 0))
        self._running = True
        loop = asyncio.get_event_loop()
        loop.add_reader(self._sock.fileno(), self._on_recv)
        self._task = asyncio.create_task(self._probe_loop())
        LOG.info("prober started for %d relays", len(self.relays))

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
        if self._sock:
            asyncio.get_event_loop().remove_reader(self._sock.fileno())
            self._sock.close()
            self._sock = None

    def stats(self) -> list[RelayStats]:
        return list(self.relays.values())

    def best(self) -> RelayStats | None:
        ranked = sorted(self.relays.values(), key=lambda r: r.score)
        return ranked[0] if ranked and ranked[0].score != float("inf") else None

    async def _probe_loop(self):
        try:
            while self._running:
                now = time.monotonic()
                for addr, stats in self.relays.items():
                    self._seq = (self._seq + 1) & 0xFFFFFFFF
                    ts = int(time.time() * 1_000_000) & 0xFFFFFFFF
                    hdr = pack_header(T_PING, self.session_id, self._seq, ts)
                    try:
                        self._sock.sendto(hdr, addr)
                    except OSError as e:
                        LOG.debug("send fail to %s: %s", addr, e)
                        continue
                    stats.pings_sent += 1
                    stats.history.append(Sample(seq=self._seq, sent_at=now))
                    self._pending[self._seq] = (addr, now)
                self._reap_and_score(now)
                await asyncio.sleep(PROBE_INTERVAL_S)
        except asyncio.CancelledError:
            pass

    def _on_recv(self):
        try:
            data, _ = self._sock.recvfrom(2048)
        except (BlockingIOError, OSError):
            return
        hdr = unpack_header(data)
        if hdr is None:
            return
        _, ptype, sid, seq, _ts = hdr
        if ptype != T_PONG or sid != self.session_id:
            return
        meta = self._pending.pop(seq, None)
        if meta is None:
            return
        addr, sent_at = meta
        stats = self.relays.get(addr)
        if not stats:
            return
        rtt_ms = (time.monotonic() - sent_at) * 1000.0
        stats.pongs_recv += 1
        stats.last_seen = time.monotonic()
        if stats.rtt_ms == float("inf"):
            stats.rtt_ms = rtt_ms
            stats.jitter_ms = 0.0
        else:
            d = abs(rtt_ms - stats.rtt_ms)
            stats.rtt_ms = (1 - RTT_ALPHA) * stats.rtt_ms + RTT_ALPHA * rtt_ms
            stats.jitter_ms = (1 - JITTER_ALPHA) * stats.jitter_ms + JITTER_ALPHA * d
        for s in stats.history:
            if s.seq == seq:
                s.rtt_ms = rtt_ms
                break

    def _reap_and_score(self, now: float):
        """Mark old pending pings as lost; recompute loss ratio."""
        cutoff = now - PROBE_TIMEOUT_S
        dropped = [s for s, (_a, t) in self._pending.items() if t < cutoff]
        for s in dropped:
            self._pending.pop(s, None)
        window_cut = now - LOSS_WINDOW_S
        for stats in self.relays.values():
            recent = [s for s in stats.history if s.sent_at >= window_cut]
            if not recent:
                continue
            lost = sum(1 for s in recent if s.rtt_ms is None and s.sent_at < cutoff)
            answered = sum(1 for s in recent if s.rtt_ms is not None)
            total_resolved = lost + answered
            if total_resolved > 0:
                stats.loss = lost / total_resolved
