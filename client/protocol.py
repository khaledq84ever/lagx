"""LagX wire protocol — shared by client and server.

See README.md for the spec. This module is the single source of truth for header layout
and encryption framing.
"""

from __future__ import annotations

import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAGIC = b"LX"
VERSION = 0x01
T_PING, T_PONG, T_DATA_OUT, T_DATA_IN = 0, 1, 2, 3
HDR_FMT = "!2sBBIII"
HDR_LEN = struct.calcsize(HDR_FMT)
assert HDR_LEN == 16


def make_nonce(session_id: int, seq: int) -> bytes:
    return struct.pack("!IQ", session_id, seq)


def pack_header(ptype: int, session_id: int, seq: int, ts_us: int) -> bytes:
    return struct.pack(HDR_FMT, MAGIC, VERSION, ptype, session_id, seq, ts_us & 0xFFFFFFFF)


def unpack_header(buf: bytes) -> tuple[int, int, int, int, int] | None:
    """Returns (version, ptype, session_id, seq, ts_us) or None if malformed."""
    if len(buf) < HDR_LEN or buf[:2] != MAGIC:
        return None
    _, ver, ptype, sid, seq, ts = struct.unpack(HDR_FMT, buf[:HDR_LEN])
    return ver, ptype, sid, seq, ts


def new_aead(psk_hex: str) -> ChaCha20Poly1305:
    raw = bytes.fromhex(psk_hex)
    if len(raw) != 32:
        raise ValueError("PSK must be 64 hex chars (32 bytes)")
    return ChaCha20Poly1305(raw)
