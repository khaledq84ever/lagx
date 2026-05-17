"""LagX GUI — single-window Tkinter dark-themed control panel.

Layout:
  ┌─────────────────────────────────────────────────────────────┐
  │  LagX                                       v0.1   [⚙]      │
  ├─────────────────────────────────────────────────────────────┤
  │  Game: [ Valorant       ▾ ]      Backend: [ auto    ▾ ]     │
  ├─────────────────────────────────────────────────────────────┤
  │  Relay           Region   RTT    Jitter   Loss    Score     │
  │  ▶ Frankfurt     EU       42 ms  3 ms     0%      48        │
  │    New York      NA       113 ms 8 ms     1%      131       │
  │    Singapore     APAC     220 ms 12 ms    0%      244       │
  ├─────────────────────────────────────────────────────────────┤
  │  [    START OPTIMIZATION    ]      ● connected — Frankfurt  │
  ├─────────────────────────────────────────────────────────────┤
  │  20:14:01 prober started for 3 relays                       │
  │  20:14:03 initial route: Frankfurt rtt=42.0ms              │
  │  20:14:42 switched route Frankfurt -> New York (better...)  │
  └─────────────────────────────────────────────────────────────┘

The GUI runs in the main thread (Tkinter requirement). All networking runs in a
background asyncio loop. Bridge: GUI polls thread-safe getters every 250ms via
`root.after`. Start/Stop call thread-safe asyncio.run_coroutine_threadsafe.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

# allow running as `python client/main.py` from repo root
if __package__ in (None, ""):
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
    from client import config, profiles
    from client.divert import make_capture
    from client.latency import Prober
    from client.protocol import new_aead
    from client.router import Router
    from client.tunnel import Tunnel
else:
    from . import config, profiles
    from .divert import make_capture
    from .latency import Prober
    from .protocol import new_aead
    from .router import Router
    from .tunnel import Tunnel

LOG = logging.getLogger("lagx.gui")

# ─── Theme ────────────────────────────────────────────────────────────────────
BG       = "#0a0a0a"
SURFACE  = "#161616"
SURFACE2 = "#222222"
BORDER   = "#2a2a2a"
TEXT     = "#f5f5f5"
MUTED    = "#888888"
ACCENT   = "#10b981"   # green = good
WARN     = "#f59e0b"   # amber = degraded
BAD      = "#ef4444"   # red = bad
BRAND    = "#7c3aed"   # purple for branding


# ─── Async engine running in a background thread ──────────────────────────────

class Engine:
    """Owns the asyncio loop + Prober + Router + Tunnel + capture backend."""

    def __init__(self):
        self.relays = config.load_relays()
        self.settings = config.load_settings()
        self.aead = new_aead(self.settings["psk_hex"])
        self.prober = Prober(self.relays)
        self.router = Router(self.prober)
        self.tunnel = Tunnel(self.router, self.aead, reinject_cb=self._reinject)
        self.capture = make_capture(self.settings.get("capture_backend"))
        self.running = False
        self.loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._tick_task: asyncio.Task | None = None
        self.log_lines: list[str] = []
        self._setup_logging()

    def _setup_logging(self):
        class GuiHandler(logging.Handler):
            def __init__(self, sink): super().__init__(); self.sink = sink
            def emit(self, record):
                self.sink(f"{time.strftime('%H:%M:%S')} {self.format(record)}")
        h = GuiHandler(self._append_log)
        h.setLevel(logging.INFO)
        h.setFormatter(logging.Formatter("%(message)s"))
        root = logging.getLogger("lagx")
        root.setLevel(logging.INFO)
        root.addHandler(h)
        root.propagate = False

    def _append_log(self, line: str):
        self.log_lines.append(line)
        if len(self.log_lines) > 200:
            self.log_lines = self.log_lines[-200:]

    def start_loop(self):
        ready = threading.Event()
        def runner():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            ready.set()
            self.loop.run_forever()
        self._loop_thread = threading.Thread(target=runner, daemon=True)
        self._loop_thread.start()
        ready.wait()

    def stop_loop(self):
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)

    # --- user actions (thread-safe; callable from GUI) ---

    def start(self, game_id: str):
        asyncio.run_coroutine_threadsafe(self._start(game_id), self.loop)

    def stop(self):
        asyncio.run_coroutine_threadsafe(self._stop(), self.loop)

    def start_probing_only(self):
        asyncio.run_coroutine_threadsafe(self._start_probe_only(), self.loop)

    # --- coroutines ---

    async def _start_probe_only(self):
        await self.prober.start()
        self._tick_task = asyncio.create_task(self._scoring_tick())

    async def _start(self, game_id: str):
        if self.running:
            return
        self.running = True
        if not self.prober._running:
            await self.prober.start()
        await self.tunnel.start()
        if self._tick_task is None or self._tick_task.done():
            self._tick_task = asyncio.create_task(self._scoring_tick())
        game = profiles.by_id(game_id)
        try:
            self.capture.start([game] if game else [], self._on_packet)
        except Exception:
            LOG.exception("capture.start failed; will continue without packet redirection")

    async def _stop(self):
        if not self.running:
            return
        self.running = False
        try:
            self.capture.stop()
        except Exception:
            LOG.exception("capture.stop failed")
        await self.tunnel.stop()

    async def _scoring_tick(self):
        while True:
            self.router.tick()
            await asyncio.sleep(0.2)

    def _on_packet(self, payload: bytes, dest: tuple[str, int]):
        # Called from capture's thread. Hand off to asyncio for sending.
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.tunnel.send, payload, dest)

    def _reinject(self, payload: bytes, src: tuple[str, int]):
        try:
            self.capture.reinject(payload, src)
        except Exception:
            LOG.exception("reinject failed")


# ─── Tk GUI ────────────────────────────────────────────────────────────────────

class App:
    def __init__(self, engine: Engine):
        self.engine = engine
        self.root = tk.Tk()
        self.root.title("LagX — Game Route Optimizer")
        self.root.configure(bg=BG)
        self.root.geometry("760x540")
        self.root.minsize(720, 480)
        self._style()
        self._build()
        self._tick()

    def _style(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=TEXT, fieldbackground=SURFACE)
        s.configure("TFrame", background=BG)
        s.configure("Card.TFrame", background=SURFACE, relief="flat")
        s.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        s.configure("Muted.TLabel", foreground=MUTED, font=("Segoe UI", 9))
        s.configure("H1.TLabel", font=("Segoe UI Semibold", 16))
        s.configure("Brand.TLabel", foreground=BRAND, font=("Segoe UI Black", 18))
        s.configure("TButton",
                    background=SURFACE2, foreground=TEXT,
                    bordercolor=BORDER, lightcolor=SURFACE2, darkcolor=SURFACE2,
                    focusthickness=0, padding=(14, 8), font=("Segoe UI Semibold", 10))
        s.map("TButton", background=[("active", BORDER)])
        s.configure("Primary.TButton",
                    background=ACCENT, foreground="#06120c",
                    lightcolor=ACCENT, darkcolor=ACCENT,
                    font=("Segoe UI Black", 11), padding=(20, 11))
        s.map("Primary.TButton", background=[("active", "#0d8e6a")])
        s.configure("Danger.TButton",
                    background=BAD, foreground="#1a0707",
                    lightcolor=BAD, darkcolor=BAD,
                    font=("Segoe UI Black", 11), padding=(20, 11))
        s.map("Danger.TButton", background=[("active", "#b33232")])
        s.configure("TCombobox",
                    fieldbackground=SURFACE2, background=SURFACE2,
                    foreground=TEXT, arrowcolor=TEXT, bordercolor=BORDER)
        s.configure("Treeview",
                    background=SURFACE, fieldbackground=SURFACE,
                    foreground=TEXT, rowheight=28,
                    bordercolor=BORDER, font=("Segoe UI", 10))
        s.configure("Treeview.Heading",
                    background=SURFACE2, foreground=MUTED,
                    font=("Segoe UI Semibold", 9), padding=(8, 6),
                    bordercolor=BORDER)
        s.map("Treeview.Heading", background=[("active", BORDER)])
        s.map("Treeview", background=[("selected", BORDER)], foreground=[("selected", TEXT)])

    def _build(self):
        # Header
        header = ttk.Frame(self.root, style="TFrame")
        header.pack(fill="x", padx=18, pady=(16, 8))
        ttk.Label(header, text="◆ LagX", style="Brand.TLabel").pack(side="left")
        ttk.Label(header, text="v0.1 · MVP", style="Muted.TLabel").pack(side="left", padx=(8, 0), pady=(8, 0))

        # Picker row
        picker = ttk.Frame(self.root, style="TFrame")
        picker.pack(fill="x", padx=18, pady=(0, 12))
        ttk.Label(picker, text="Game").pack(side="left", padx=(0, 6))
        game_names = [g.name for g in profiles.GAMES]
        self.game_var = tk.StringVar(value=self._default_game_name())
        cb = ttk.Combobox(picker, values=game_names, textvariable=self.game_var,
                          state="readonly", width=28)
        cb.pack(side="left")

        # Relay table
        table_card = ttk.Frame(self.root, style="Card.TFrame")
        table_card.pack(fill="both", expand=True, padx=18, pady=(0, 10))
        cols = ("name", "region", "rtt", "jitter", "loss", "score")
        self.tree = ttk.Treeview(table_card, columns=cols, show="headings", height=8)
        self.tree.heading("name",   text="RELAY")
        self.tree.heading("region", text="REGION")
        self.tree.heading("rtt",    text="RTT")
        self.tree.heading("jitter", text="JITTER")
        self.tree.heading("loss",   text="LOSS")
        self.tree.heading("score",  text="SCORE")
        self.tree.column("name",   width=180, anchor="w")
        self.tree.column("region", width=80,  anchor="center")
        self.tree.column("rtt",    width=80,  anchor="e")
        self.tree.column("jitter", width=80,  anchor="e")
        self.tree.column("loss",   width=70,  anchor="e")
        self.tree.column("score",  width=90,  anchor="e")
        self.tree.pack(fill="both", expand=True, padx=1, pady=1)
        self.tree.tag_configure("active", background="#10241c", foreground="#7ef0c4")
        self.tree.tag_configure("bad",    foreground=BAD)
        self.tree.tag_configure("warn",   foreground=WARN)

        # Action row
        action = ttk.Frame(self.root, style="TFrame")
        action.pack(fill="x", padx=18, pady=(0, 8))
        self.start_btn = ttk.Button(action, text="START OPTIMIZATION",
                                    style="Primary.TButton", command=self._toggle)
        self.start_btn.pack(side="left")
        self.status_dot = tk.Canvas(action, width=12, height=12, bg=BG, highlightthickness=0)
        self.status_dot.pack(side="left", padx=(16, 6))
        self._draw_dot(BAD)
        self.status_lbl = ttk.Label(action, text="idle — pick a game and start", style="Muted.TLabel")
        self.status_lbl.pack(side="left")

        # Log box
        log_card = ttk.Frame(self.root, style="Card.TFrame")
        log_card.pack(fill="x", padx=18, pady=(0, 16))
        self.log_text = tk.Text(log_card, height=8, bg=SURFACE, fg=MUTED,
                                insertbackground=TEXT, relief="flat", padx=10, pady=8,
                                font=("Consolas", 9), wrap="none", borderwidth=0)
        self.log_text.pack(fill="both", expand=True, padx=1, pady=1)
        self.log_text.configure(state="disabled")

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        # Start probing immediately so the user sees live latencies before starting
        self.engine.start_probing_only()

    def _default_game_name(self) -> str:
        gid = self.engine.settings.get("last_game_id", "valorant")
        for g in profiles.GAMES:
            if g.id == gid:
                return g.name
        return profiles.GAMES[0].name

    def _toggle(self):
        if self.engine.running:
            self.engine.stop()
            self.start_btn.configure(text="START OPTIMIZATION", style="Primary.TButton")
        else:
            game_name = self.game_var.get()
            game = next((g for g in profiles.GAMES if g.name == game_name), profiles.GAMES[0])
            self.engine.settings["last_game_id"] = game.id
            config.save_settings(self.engine.settings)
            self.engine.start(game.id)
            self.start_btn.configure(text="STOP", style="Danger.TButton")

    def _draw_dot(self, color: str):
        self.status_dot.delete("all")
        self.status_dot.create_oval(2, 2, 10, 10, fill=color, outline=color)

    def _tick(self):
        # Refresh relay table
        stats = self.engine.prober.stats()
        existing = set(self.tree.get_children())
        active_relay = self.engine.router.active.relay if self.engine.router.active else None
        for s in stats:
            iid = f"{s.host}:{s.port}"
            tags: list[str] = []
            if active_relay and s is active_relay:
                tags.append("active")
            if s.loss > 0.05:
                tags.append("bad")
            elif s.loss > 0.01 or s.jitter_ms > 20:
                tags.append("warn")
            prefix = "▶  " if "active" in tags else "    "
            values = (
                prefix + s.name,
                s.region or "—",
                f"{s.rtt_ms:.0f} ms" if s.rtt_ms != float("inf") else "—",
                f"{s.jitter_ms:.0f} ms",
                f"{s.loss * 100:.0f}%",
                f"{s.score:.0f}" if s.score != float("inf") else "—",
            )
            if iid in existing:
                self.tree.item(iid, values=values, tags=tags)
            else:
                self.tree.insert("", "end", iid=iid, values=values, tags=tags)

        # Status pill
        if self.engine.running and active_relay:
            self._draw_dot(ACCENT)
            self.status_lbl.configure(
                text=f"connected — {active_relay.name}  ·  out {self.engine.tunnel.pkts_out}  in {self.engine.tunnel.pkts_in}",
            )
        elif active_relay:
            self._draw_dot(WARN)
            self.status_lbl.configure(text=f"probing — best so far: {active_relay.name}")
        else:
            self._draw_dot(BAD)
            self.status_lbl.configure(text="probing relays…")

        # Log tail
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.insert("end", "\n".join(self.engine.log_lines[-12:]))
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

        self.root.after(250, self._tick)

    def _on_close(self):
        try:
            if self.engine.running:
                self.engine.stop()
            self.engine.stop_loop()
        finally:
            self.root.destroy()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(name)s | %(message)s",
        handlers=[logging.StreamHandler()],
    )
    engine = Engine()
    engine.start_loop()
    app = App(engine)
    app.root.mainloop()


if __name__ == "__main__":
    main()
