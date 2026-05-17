"""Client-side UDP tunnel encapsulator.

The packet-capture layer (divert.py) hands us raw outbound game packets along with
their destination (ip, port). We:
  1. Look up the top-N active relays from the Router.
  2. Build a DATA_OUT packet, encrypt the payload, send to *each* of those relays
     in parallel (multi-path). The game's own protocol layer deduplicates by its
     internal sequence numbers — UDP game protocols (RakNet, ENet, Riot's
     proprietary one) are all designed to tolerate duplicate datagrams.
  3. On DATA_IN reply, decrypt, dedupe (the same reply may arrive from each of
     the N paths), then call the reinject_cb so divert.py can spoof the response
     back into the game's UDP socket.

This module is transport-only — it doesn't know how packets were captured (WinDivert,
NFQUEUE, or a unit test piping raw bytes in).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import socket
import struct
import time
from collections import OrderedDict
from collections.abc import Callable

from .protocol import (
    HDR_LEN, T_DATA_IN, T_DATA_OUT, make_nonce, pack_header, unpack_header,
)
from .router import Router

LOG = logging.getLogger("lagx.tunnel")

ReinjectCB = Callable[[bytes, tuple[str, int]], None]
# (payload, source_addr) — source_addr is the game server (so the game's socket sees
# the reply as coming from the right peer).

DEDUP_WINDOW_S = 0.5     # drop duplicate replies arriving within this window
DEDUP_MAX = 1024         # LRU size for the dedup cache (~1 s of typical game traffic)


class Tunnel:
    def __init__(
        self,
        router: Router,
        aead,
        reinject_cb: ReinjectCB | None = None,
        n_paths: int = 1,
    ):
        self.router = router
        self.aead = aead
        self.reinject_cb = reinject_cb or (lambda *_: None)
        self.session_id = random.randint(1, 0x7FFFFFFF)
        self.n_paths = max(1, min(n_paths, 4))
        self._seq = 0
        self._sock: socket.socket | None = None
        self._running = False
        self.pkts_out = 0          # total per-path sends (n_paths * logical packets)
        self.pkts_in = 0           # total decrypted replies received (incl. duplicates)
        self.pkts_reinjected = 0   # logical packets handed to game (after dedup)
        self.pkts_deduped = 0
        self._dedup: OrderedDict[bytes, float] = OrderedDict()

    async def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setblocking(False)
        # Big buffers so we don't drop bursts on a flaky path
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        self._sock.bind(("0.0.0.0", 0))
        self._running = True
        asyncio.get_event_loop().add_reader(self._sock.fileno(), self._on_relay_recv)
        LOG.info("tunnel session=%x local=%s", self.session_id, self._sock.getsockname())

    async def stop(self):
        self._running = False
        if self._sock:
            asyncio.get_event_loop().remove_reader(self._sock.fileno())
            self._sock.close()
            self._sock = None

    def send(self, payload: bytes, dest: tuple[str, int]) -> bool:
        """Encapsulate `payload` (destined for game server `dest`) and send through the
        top-N currently-best relays in parallel. Returns False if no route is available."""
        if self._sock is None:
            return False
        relays = self.router.top_n(self.n_paths)
        if not relays:
            # Fall back to the currently-active relay even if scoring is incomplete
            if self.router.active is None:
                return False
            relays = [self.router.active.relay]

        self._seq = (self._seq + 1) & 0xFFFFFFFF
        ts = int(time.time() * 1_000_000) & 0xFFFFFFFF
        hdr = pack_header(T_DATA_OUT, self.session_id, self._seq, ts)
        meta = struct.pack("!4sH", socket.inet_aton(dest[0]), dest[1])
        aad = hdr + meta
        try:
            ct = self.aead.encrypt(make_nonce(self.session_id, self._seq), payload, aad)
        except Exception:
            LOG.exception("encrypt failed")
            return False
        wire = hdr + meta + ct
        sent_any = False
        for relay in relays:
            try:
                self._sock.sendto(wire, (relay.host, relay.port))
                self.pkts_out += 1
                sent_any = True
            except OSError as e:
                LOG.debug("send fail to %s: %s", relay.name, e)
        return sent_any

    def _on_relay_recv(self):
        try:
            data, _ = self._sock.recvfrom(65535)
        except (BlockingIOError, OSError):
            return
        h = unpack_header(data)
        if h is None:
            return
        _, ptype, sid, seq, _ = h
        if ptype != T_DATA_IN or sid != self.session_id:
            return
        if len(data) < HDR_LEN + 6:
            return
        meta = data[HDR_LEN:HDR_LEN + 6]
        ip_b, port = struct.unpack("!4sH", meta)
        src = (socket.inet_ntoa(ip_b), port)
        ct = data[HDR_LEN + 6:]
        aad = data[:HDR_LEN] + meta
        try:
            payload = self.aead.decrypt(make_nonce(sid, seq), ct, aad)
        except Exception as e:
            LOG.debug("decrypt reply: %s", e)
            return
        self.pkts_in += 1
        if self._is_duplicate(src, payload):
            self.pkts_deduped += 1
            return
        self.pkts_reinjected += 1
        try:
            self.reinject_cb(payload, src)
        except Exception:
            LOG.exception("reinject callback raised")

    def _is_duplicate(self, src: tuple[str, int], payload: bytes) -> bool:
        """Drop replies we've already seen within DEDUP_WINDOW_S. Multi-path makes
        the same game reply arrive once per active path."""
        now = time.monotonic()
        key = hashlib.blake2b(
            payload, digest_size=16, key=f"{src[0]}:{src[1]}".encode()
        ).digest()
        # Evict anything outside the window first (cheap because OrderedDict).
        cutoff = now - DEDUP_WINDOW_S
        while self._dedup:
            k, t = next(iter(self._dedup.items()))
            if t >= cutoff:
                break
            self._dedup.popitem(last=False)
        if key in self._dedup:
            return True
        self._dedup[key] = now
        if len(self._dedup) > DEDUP_MAX:
            self._dedup.popitem(last=False)
        return False
