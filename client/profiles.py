"""Game profiles — UDP destination ports + name hints used by divert.py to build
filters and by the GUI to render the game picker.

Add a game by appending to GAMES. Ports come from public docs / packet captures.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class GameProfile:
    id: str
    name: str
    # list of (lo, hi) inclusive UDP port ranges the game uses for live gameplay
    dst_ports: tuple[tuple[int, int], ...]
    # optional process name (for future per-process filtering)
    exe: str = ""


GAMES: list[GameProfile] = [
    GameProfile(
        id="valorant",
        name="Valorant",
        dst_ports=((7000, 7500),),
        exe="VALORANT-Win64-Shipping.exe",
    ),
    GameProfile(
        id="cs2",
        name="Counter-Strike 2",
        dst_ports=((27000, 27050),),
        exe="cs2.exe",
    ),
    GameProfile(
        id="lol",
        name="League of Legends",
        dst_ports=((5000, 5500),),
        exe="League of Legends.exe",
    ),
    GameProfile(
        id="fortnite",
        name="Fortnite",
        dst_ports=((9000, 9100), (5060, 5071)),
        exe="FortniteClient-Win64-Shipping.exe",
    ),
    GameProfile(
        id="cod",
        name="Call of Duty (Warzone / MW)",
        dst_ports=((3074, 3074), (3478, 3480)),
        exe="cod.exe",
    ),
    GameProfile(
        id="pubg",
        name="PUBG",
        dst_ports=((7000, 8000),),
        exe="TslGame.exe",
    ),
    GameProfile(
        id="rl",
        name="Rocket League",
        dst_ports=((7000, 9000),),
        exe="RocketLeague.exe",
    ),
    GameProfile(
        id="apex",
        name="Apex Legends",
        dst_ports=((37000, 40000),),
        exe="r5apex.exe",
    ),
    GameProfile(
        id="dota2",
        name="Dota 2",
        dst_ports=((27000, 27050),),
        exe="dota2.exe",
    ),
    GameProfile(
        id="overwatch",
        name="Overwatch 2",
        dst_ports=((3478, 3479), (5060, 5062), (6113, 6114)),
        exe="Overwatch.exe",
    ),
    GameProfile(
        id="custom",
        name="Custom (all UDP)",
        dst_ports=((1, 65535),),
    ),
]


def by_id(game_id: str) -> GameProfile | None:
    for g in GAMES:
        if g.id == game_id:
            return g
    return None
