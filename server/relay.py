"""LagX relay server.

Listens for LagX clients on UDP, forwards encapsulated game packets to the real game
server, NATs the responses back. One asyncio task handles thousands of concurrent flows.

Protocol — every packet starts with a 16-byte LX header:

    offset  field           type
    0..2    magic           b'LX'
    2..3    version         uint8   (0x01)
    3..4    type            uint8   (0=PING 1=PONG 2=DATA_OUT 3=DATA_IN)
    4..8    session_id      uint32  (client random)
    8..12   seq             uint32  (monotonic per session)
    12..16  ts_us_low       uint32  (microsecond timestamp low bits)

PING / PONG: header only. PONG echoes the PING's ts_us_low so the client computes RTT.

DATA_OUT (client -> relay):
    header(16) | dest_ip(4) | dest_port(2) | ciphertext

DATA_IN (relay -> client):
    header(16) | src_ip(4) | src_port(2) | ciphertext

ciphertext = ChaCha20-Poly1305(key=PSK, nonce=session_id(4)||seq(8), aad=header).
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

LOG = logging.getLogger("lagx.relay")

MAGIC = b"LX"
VERSION = 0x01
T_PING, T_PONG, T_DATA_OUT, T_DATA_IN = 0, 1, 2, 3
HDR_FMT = "!2sBBIII"
HDR_LEN = struct.calcsize(HDR_FMT)
assert HDR_LEN == 16
FLOW_IDLE_S = 60.0
LISTEN_PORT = int(os.environ.get("LAGX_PORT", "51820"))
PSK_HEX = os.environ.get(
    "LAGX_PSK",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
)


def make_nonce(session_id: int, seq: int) -> bytes:
    return struct.pack("!IQ", session_id, seq)


@dataclass
class Flow:
    """One (client, game_server) tunnel. Owns an ephemeral UDP socket on the relay."""
    session_id: int
    client_addr: tuple[str, int]
    game_addr: tuple[str, int]
    sock: socket.socket
    last_seen: float = field(default_factory=time.monotonic)


class RelayProtocol(asyncio.DatagramProtocol):
    def __init__(self, aead: ChaCha20Poly1305):
        self.aead = aead
        self.transport: asyncio.DatagramTransport | None = None
        self.flows: dict[tuple[int, tuple[str, int]], Flow] = {}
        self.loop = asyncio.get_event_loop()

    def connection_made(self, transport):
        self.transport = transport
        LOG.info("relay listening on UDP :%d", LISTEN_PORT)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) < HDR_LEN or data[:2] != MAGIC:
            return
        magic, ver, ptype, sid, seq, ts = struct.unpack(HDR_FMT, data[:HDR_LEN])
        if ver != VERSION:
            return

        if ptype == T_PING:
            self._send_pong(addr, sid, seq, ts)
            return
        if ptype == T_DATA_OUT:
            self._handle_data_out(addr, sid, seq, ts, data[HDR_LEN:])
            return
        # PONG / DATA_IN are server -> client; ignore on inbound.

    def _send_pong(self, addr, sid, seq, ts):
        hdr = struct.pack(HDR_FMT, MAGIC, VERSION, T_PONG, sid, seq, ts)
        self.transport.sendto(hdr, addr)

    def _handle_data_out(self, client_addr, sid, seq, ts, body):
        if len(body) < 6:
            return
        ip_b, port = struct.unpack("!4sH", body[:6])
        ciphertext = body[6:]
        try:
            aad = struct.pack(HDR_FMT, MAGIC, VERSION, T_DATA_OUT, sid, seq, ts) + body[:6]
            plaintext = self.aead.decrypt(make_nonce(sid, seq), ciphertext, aad)
        except Exception as e:
            LOG.debug("decrypt fail from %s: %s", client_addr, e)
            return
        game_addr = (socket.inet_ntoa(ip_b), port)
        flow = self._get_or_create_flow(sid, client_addr, game_addr)
        try:
            flow.sock.sendto(plaintext, game_addr)
            flow.last_seen = time.monotonic()
        except OSError as e:
            LOG.warning("forward fail %s -> %s: %s", client_addr, game_addr, e)

    def _get_or_create_flow(self, sid, client_addr, game_addr) -> Flow:
        key = (sid, game_addr)
        flow = self.flows.get(key)
        if flow is not None:
            flow.client_addr = client_addr  # client may roam
            return flow
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(("0.0.0.0", 0))
        flow = Flow(session_id=sid, client_addr=client_addr, game_addr=game_addr, sock=sock)
        self.flows[key] = flow
        self.loop.add_reader(sock.fileno(), self._on_game_reply, flow)
        LOG.debug("new flow sid=%x client=%s game=%s relay_src=%s",
                  sid, client_addr, game_addr, sock.getsockname())
        return flow

    def _on_game_reply(self, flow: Flow):
        try:
            data, src = flow.sock.recvfrom(65535)
        except (BlockingIOError, OSError):
            return
        flow.last_seen = time.monotonic()
        seq = int(time.monotonic_ns()) & 0xFFFFFFFF
        ts = int(time.time() * 1_000_000) & 0xFFFFFFFF
        hdr = struct.pack(HDR_FMT, MAGIC, VERSION, T_DATA_IN, flow.session_id, seq, ts)
        meta = struct.pack("!4sH", socket.inet_aton(src[0]), src[1])
        aad = hdr + meta
        ciphertext = self.aead.encrypt(make_nonce(flow.session_id, seq), data, aad)
        self.transport.sendto(hdr + meta + ciphertext, flow.client_addr)

    async def reap_idle_flows(self):
        while True:
            await asyncio.sleep(10.0)
            cutoff = time.monotonic() - FLOW_IDLE_S
            dead = [k for k, f in self.flows.items() if f.last_seen < cutoff]
            for k in dead:
                f = self.flows.pop(k)
                self.loop.remove_reader(f.sock.fileno())
                f.sock.close()
            if dead:
                LOG.info("reaped %d idle flows (now %d active)", len(dead), len(self.flows))


async def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LAGX_LOG", "INFO"),
        format="%(asctime)s %(levelname)-5s %(name)s | %(message)s",
    )
    psk = bytes.fromhex(PSK_HEX)
    if len(psk) != 32:
        raise SystemExit("LAGX_PSK must be 64 hex chars (32 bytes)")
    aead = ChaCha20Poly1305(psk)
    loop = asyncio.get_event_loop()
    proto = RelayProtocol(aead)
    await loop.create_datagram_endpoint(lambda: proto, local_addr=("0.0.0.0", LISTEN_PORT))
    reaper = asyncio.create_task(proto.reap_idle_flows())
    try:
        await asyncio.Event().wait()
    finally:
        reaper.cancel()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
