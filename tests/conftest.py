"""Shared fixtures.

The suite is split by dependency, not by subject: anything touching the
lsof-parsing path is marked `needs_pandas` so CI can run everything else on an
interpreter with pandas genuinely absent. That run is the contract -- see
`test_bare_interpreter_contract` in test_classify.py.
"""

import pytest


@pytest.fixture
def socket_paths():
    """A synthetic /proc/net/unix inode -> path map.

    Hand-built rather than read from the host so the folding rules can be
    asserted against sockets that may not exist on the machine running the
    tests (a CI runner has no wayland display and no libei sessions).
    """
    return {
        "100": "/run/user/1000/wayland-1",       # display socket: number is identity
        "101": "",                                # accepted peer: no path
        "102": "/run/user/1000/eis-7",            # libei session
        "103": "/run/user/1000/.flatpak/wl/wayland-QHEWT3",  # per-sandbox proxy
        "104": "@/tmp/.X11-unix/X0",              # abstract namespace
        "105": "/run/user/1000/bus",
    }


@pytest.fixture
def classify_series(tmp_path):
    """Write a two-sample --classify series and return its path.

    `shm_deleted` grows, `dmabuf` is flat, and `eventpoll` is absent from the
    first sample entirely -- the case that distinguishes "started at zero" from
    "not seen", which is exactly what a leak appearing mid-run looks like.
    """
    path = tmp_path / "series.csv"
    path.write_text(
        "ts,COMMAND,PID,CLASS,count\n"
        "2026-01-01T00:00:00+0000,Hyprland,42,shm_deleted,10\n"
        "2026-01-01T00:00:00+0000,Hyprland,42,dmabuf,5\n"
        "2026-01-01T00:05:00+0000,Hyprland,42,shm_deleted,31\n"
        "2026-01-01T00:05:00+0000,Hyprland,42,dmabuf,5\n"
        "2026-01-01T00:05:00+0000,Hyprland,42,eventpoll,7\n"
    )
    return path
