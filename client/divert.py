"""Packet capture + reinjection.

Two backends, picked at runtime:

  Windows -> pydivert (WinDivert kernel driver, BSD license). Requires admin/UAC.
  Linux   -> NFQUEUE via python-netfilterqueue + iptables rule.

Both expose the same `PacketCapture` interface:
  cap.start(filter, on_packet)   # on_packet(payload, dst_addr) -> None
  cap.reinject(payload, src_addr)
  cap.stop()

`filter` is a list of GameProfile (see profiles.py). Backends translate it into the
native filter syntax.
"""

from __future__ import annotations

import logging
import platform
import socket
import struct
from collections.abc import Callable
from typing import Protocol

LOG = logging.getLogger("lagx.divert")

PacketCB = Callable[[bytes, tuple[str, int]], None]


class PacketCapture(Protocol):
    def start(self, profiles: list, on_packet: PacketCB) -> None: ...
    def reinject(self, payload: bytes, src_addr: tuple[str, int]) -> None: ...
    def stop(self) -> None: ...


# ---------------------------------------------------------------------------
# Windows backend — WinDivert via pydivert
# ---------------------------------------------------------------------------

class WinDivertCapture:
    """Captures outbound UDP packets matching the active game profile.

    WinDivert filter syntax doc: https://reqrypt.org/windivert-doc.html
    Reinjection: we mark inbound reply packets as if they came from the game server
    (the relay's NAT is transparent — we just send the inner UDP payload through a
    raw socket spoofing src=game_server). On Windows, easier path is to inject as
    a fully-formed IP+UDP packet via WinDivert.send() with direction=INBOUND.
    """

    def __init__(self):
        self.handle = None
        self._on_packet: PacketCB | None = None
        self._thread = None
        self._stop = False
        self._local_ip: str | None = None

    def start(self, profiles, on_packet):
        import pydivert  # imported lazily so non-Windows can import this module
        from threading import Thread

        self._on_packet = on_packet
        flt = self._build_filter(profiles)
        LOG.info("WinDivert filter: %s", flt)
        self.handle = pydivert.WinDivert(flt)
        self.handle.open()
        self._local_ip = self._detect_local_ip()
        self._stop = False
        self._thread = Thread(target=self._loop, daemon=True)
        self._thread.start()

    def reinject(self, payload, src_addr):
        """Inject a UDP packet as if it arrived FROM src_addr TO our local IP."""
        if self.handle is None or self._local_ip is None:
            return
        import pydivert
        # Build packet: IP + UDP + payload
        # pydivert.Packet allows construction by handing a raw buffer; easier to use its
        # high-level builder when available, else assemble manually.
        try:
            pkt = pydivert.Packet(
                self._build_udp_packet(src_addr, (self._local_ip, 0), payload),
                interface=(0, 0),
                direction=pydivert.Direction.INBOUND,
            )
            self.handle.send(pkt)
        except Exception:
            LOG.exception("reinject failed")

    def stop(self):
        self._stop = True
        if self.handle:
            try:
                self.handle.close()
            except Exception:
                pass
            self.handle = None

    # --- internals ---

    def _loop(self):
        try:
            while not self._stop and self.handle:
                pkt = self.handle.recv()
                if pkt is None:
                    continue
                if pkt.udp is None or pkt.dst_addr is None:
                    self.handle.send(pkt)  # pass through non-UDP we accidentally matched
                    continue
                payload = bytes(pkt.payload)
                dst = (pkt.dst_addr, pkt.dst_port)
                # Don't re-emit — we *consume* the original; the relay path replaces it.
                try:
                    if self._on_packet:
                        self._on_packet(payload, dst)
                except Exception:
                    LOG.exception("on_packet raised; dropping pkt")
        except Exception:
            LOG.exception("WinDivert loop crashed")

    @staticmethod
    def _build_filter(profiles) -> str:
        """Compose a WinDivert filter string from GameProfile entries."""
        if not profiles:
            return "udp and outbound"
        clauses = []
        for p in profiles:
            for port_range in p.dst_ports:
                lo, hi = port_range
                if lo == hi:
                    clauses.append(f"udp.DstPort == {lo}")
                else:
                    clauses.append(f"(udp.DstPort >= {lo} and udp.DstPort <= {hi})")
        return f"outbound and udp and ({' or '.join(clauses)})"

    @staticmethod
    def _detect_local_ip() -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    @staticmethod
    def _build_udp_packet(src, dst, payload) -> bytes:
        """Hand-assemble IPv4+UDP. Used for reinjection."""
        src_ip = socket.inet_aton(src[0]); src_port = src[1]
        dst_ip = socket.inet_aton(dst[0]); dst_port = dst[1]
        udp_len = 8 + len(payload)
        udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload  # checksum 0 = optional
        total = 20 + udp_len
        ihl_ver = (4 << 4) | 5
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            ihl_ver, 0, total, 0, 0, 64, 17, 0, src_ip, dst_ip,
        )
        # IP checksum
        s = 0
        for i in range(0, len(ip_hdr), 2):
            s += (ip_hdr[i] << 8) | ip_hdr[i + 1]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        chk = (~s) & 0xFFFF
        ip_hdr = ip_hdr[:10] + struct.pack("!H", chk) + ip_hdr[12:]
        return ip_hdr + udp


# ---------------------------------------------------------------------------
# Linux backend — NFQUEUE
# ---------------------------------------------------------------------------

class NfqueueCapture:
    """Linux capture via iptables NFQUEUE + python-netfilterqueue.

    Caller must have set the iptables rule before start():
      sudo iptables -I OUTPUT -p udp --dport <PORT> -j NFQUEUE --queue-num 17
    """

    QUEUE_NUM = 17

    def __init__(self):
        self.nfq = None
        self._on_packet: PacketCB | None = None
        self._thread = None
        self._stop = False

    def start(self, profiles, on_packet):
        from netfilterqueue import NetfilterQueue  # type: ignore
        from threading import Thread
        self._on_packet = on_packet
        self.nfq = NetfilterQueue()
        self.nfq.bind(self.QUEUE_NUM, self._cb)
        self._stop = False
        self._thread = Thread(target=self._loop, daemon=True)
        self._thread.start()
        LOG.info("NFQUEUE bound to queue %d", self.QUEUE_NUM)

    def reinject(self, payload, src_addr):
        # Linux reinjection: open a raw socket and spoof src. Requires CAP_NET_RAW.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            local_ip = self._detect_local_ip()
            pkt = WinDivertCapture._build_udp_packet(src_addr, (local_ip, 0), payload)
            s.sendto(pkt, (local_ip, 0))
            s.close()
        except Exception:
            LOG.exception("nfq reinject failed")

    def stop(self):
        self._stop = True
        if self.nfq:
            try:
                self.nfq.unbind()
            except Exception:
                pass
            self.nfq = None

    def _cb(self, pkt):
        try:
            # We accept the packet for kernel forwarding but DROP it — the tunnel will
            # carry it via the relay. The reply gets reinjected via raw socket.
            data = pkt.get_payload()
            if len(data) < 28 or data[9] != 17:  # IPv4 + UDP
                pkt.accept()
                return
            ihl = (data[0] & 0xF) * 4
            dst_ip = socket.inet_ntoa(data[16:20])
            dst_port = struct.unpack("!H", data[ihl + 2:ihl + 4])[0]
            udp_payload = data[ihl + 8:]
            if self._on_packet:
                self._on_packet(udp_payload, (dst_ip, dst_port))
            pkt.drop()
        except Exception:
            LOG.exception("nfq cb failed")
            try: pkt.accept()
            except Exception: pass

    def _loop(self):
        try:
            self.nfq.run()
        except Exception:
            LOG.exception("nfq loop crashed")

    @staticmethod
    def _detect_local_ip() -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()


# ---------------------------------------------------------------------------
# Loopback (no-op) backend — for dev/testing without admin rights.
# ---------------------------------------------------------------------------

class LoopbackCapture:
    """A backend that captures nothing. Lets the GUI and probe run without admin.

    In this mode the tunnel + router still work; only real game traffic isn't
    redirected. Use this to test relay deployment + scoring.
    """

    def start(self, profiles, on_packet):
        LOG.info("loopback capture: no packets will be intercepted")

    def reinject(self, payload, src_addr):
        pass

    def stop(self):
        pass


def make_capture(prefer: str | None = None) -> PacketCapture:
    """Auto-pick a capture backend.

    `prefer` can be 'windivert', 'nfqueue', 'loopback'. Default = best for current OS.
    """
    sys = (prefer or platform.system()).lower()
    if sys in ("windivert", "windows"):
        try:
            import pydivert  # noqa: F401
            return WinDivertCapture()
        except ImportError:
            LOG.warning("pydivert not installed; falling back to loopback")
            return LoopbackCapture()
    if sys in ("nfqueue", "linux"):
        try:
            from netfilterqueue import NetfilterQueue  # noqa: F401
            return NfqueueCapture()
        except ImportError:
            LOG.warning("netfilterqueue not installed; falling back to loopback")
            return LoopbackCapture()
    return LoopbackCapture()
