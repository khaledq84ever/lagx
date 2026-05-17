"""Route scoring + active-route selection with hysteresis.

The Prober (latency.py) keeps live RelayStats. The Router decides which relay should
currently carry traffic, with 15% hysteresis so we don't flap when two relays are
within noise of each other.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from .latency import Prober, RelayStats

LOG = logging.getLogger("lagx.router")

HYSTERESIS = 0.85       # switch only if challenger.score < 0.85 * incumbent.score
EMERGENCY_LOSS = 0.10   # always switch if active relay loss exceeds this
EMERGENCY_HOLD_S = 3.0


@dataclass
class ActiveRoute:
    relay: RelayStats
    since: float
    switches: int = 0


class Router:
    def __init__(self, prober: Prober):
        self.prober = prober
        self.active: ActiveRoute | None = None
        self._high_loss_since: float | None = None

    def tick(self) -> ActiveRoute | None:
        """Call this every ~200ms. Returns the current active route (may have just switched)."""
        best = self.prober.best()
        if best is None:
            return self.active

        if self.active is None:
            self.active = ActiveRoute(relay=best, since=time.monotonic())
            LOG.info("initial route: %s rtt=%.1fms score=%.1f",
                     best.name, best.rtt_ms, best.score)
            return self.active

        now = time.monotonic()

        # Emergency switch: sustained loss on the active relay
        if self.active.relay.loss > EMERGENCY_LOSS:
            self._high_loss_since = self._high_loss_since or now
            if now - self._high_loss_since > EMERGENCY_HOLD_S and best is not self.active.relay:
                self._switch(best, reason=f"emergency (loss {self.active.relay.loss:.0%})")
                self._high_loss_since = None
                return self.active
        else:
            self._high_loss_since = None

        # Normal hysteresis switch
        if best is not self.active.relay:
            if best.score < HYSTERESIS * self.active.relay.score:
                self._switch(
                    best,
                    reason=f"better route ({best.score:.0f} < {self.active.relay.score:.0f})",
                )
        return self.active

    def _switch(self, new: RelayStats, reason: str):
        old = self.active.relay if self.active else None
        switches = (self.active.switches + 1) if self.active else 0
        self.active = ActiveRoute(relay=new, since=time.monotonic(), switches=switches)
        LOG.info(
            "switched route %s -> %s (%s)",
            old.name if old else "<none>", new.name, reason,
        )
