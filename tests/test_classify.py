"""Tests for the /proc-reading classification path (--classify)."""

import os
import subprocess
import sys

import pytest

import lsofa


# --- the dependency contract ------------------------------------------------


def test_importing_lsofa_does_not_pull_pandas():
    """--classify must run on a bare interpreter.

    fdwatch invokes it from a systemd timer every few minutes; a module-level
    `import pandas` would silently make that too expensive to run and nothing
    else would notice. Checked in a subprocess rather than against sys.modules
    directly, so the result does not depend on whether an earlier test in this
    session already imported pandas.
    """
    probe = (
        "import sys; import lsofa; "
        "sys.exit(1 if ('pandas' in sys.modules or 'numpy' in sys.modules) else 0)"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "importing lsofa pulled in pandas/numpy at module scope -- the lsof "
        "paths must import them lazily, inside the functions that use them"
    )


# --- socket folding ---------------------------------------------------------


def test_wayland_display_socket_keeps_its_number(socket_paths):
    """wayland-1 is the compositor's listening socket: the number is identity.

    Folding it to wayland-* would merge it with the per-sandbox proxies that
    share its prefix, hiding the one socket actually worth watching.
    """
    assert lsofa.classify_fd("socket:[100]", socket_paths) == "unix:wayland-1"


def test_session_sockets_fold_into_one_class(socket_paths):
    # A sequence number (libei mints one socket per input-capture session) and a
    # random nonce (flatpak mints one wayland proxy per sandbox) both vary per
    # session; left alone each becomes its own count-1 class and the series
    # stops being trendable.
    assert lsofa.classify_fd("socket:[102]", socket_paths) == "unix:eis-*"
    assert lsofa.classify_fd("socket:[103]", socket_paths) == "unix:wayland-*"


def test_unnamed_and_non_unix_sockets(socket_paths):
    # Accepted peers carry no path. Their count exceeding the number of live
    # clients is itself the leak signal, so they need their own class.
    assert lsofa.classify_fd("socket:[101]", socket_paths) == "unix_unnamed"
    # An inode absent from /proc/net/unix is not a unix socket at all.
    assert lsofa.classify_fd("socket:[999]", socket_paths) == "socket_other"


def test_abstract_namespace_marker_is_stripped(socket_paths):
    # The leading @ would otherwise ride along into the CSV.
    assert lsofa.classify_fd("socket:[104]", socket_paths) == "unix:X0"


# --- non-socket targets -----------------------------------------------------


@pytest.mark.parametrize(
    "target,expected",
    [
        # Ordering matters: the deleted rule must win over the plain /dev/shm
        # rule, or every leaked buffer lands in the wrong bucket.
        ("/dev/shm/abc-123 (deleted)", "shm_deleted"),
        ("/dev/shm/abc-123", "shm"),
        ("/dmabuf:", "dmabuf"),
        ("anon_inode:[eventpoll]", "eventpoll"),
        ("anon_inode:[timerfd]", "timerfd"),
        ("anon_inode:inotify", "inotify"),
        ("anon_inode:something-else", "anon_other"),
        ("pipe:[12345]", "pipe"),
        ("/dev/input/event3", "input"),
        ("/dev/dri/renderD128", "dri"),
        ("/dev/nvidia0", "gpu"),
        ("/memfd:foo", "memfd"),
        ("/var/log/syslog (deleted)", "deleted_other"),
        ("/etc/hosts", "file"),
        ("some-unrecognised-thing", "other"),
    ],
)
def test_non_socket_targets(target, expected):
    assert lsofa.classify_fd(target, {}) == expected


# --- /proc readers ----------------------------------------------------------


def test_resolve_targets_finds_self_by_pid():
    pid = str(os.getpid())
    assert pid in [found_pid for _, found_pid in lsofa.resolve_targets(pid)]


def test_resolve_targets_finds_self_by_comm():
    with open("/proc/self/comm") as handle:
        comm = handle.read().strip()
    found = lsofa.resolve_targets(comm)
    assert str(os.getpid()) in [pid for _, pid in found]


def test_resolve_targets_ignores_unknown_names():
    assert lsofa.resolve_targets("definitely-not-a-running-process") == []


def test_class_counts_sum_to_the_real_fd_total():
    """The invariant that proves the bucketing neither drops nor double-counts.

    Tolerance is deliberate: fds legitimately open and close between listing the
    directory and reading each link, so an exact match would be flaky. Anything
    beyond a couple of fds means a whole class is being lost.
    """
    pid = str(os.getpid())
    rows = lsofa.classify_pids(pid)
    bucketed = sum(row["count"] for row in rows)
    actual = len(os.listdir(f"/proc/{pid}/fd"))
    assert abs(bucketed - actual) <= 3, f"bucketed {bucketed} vs {actual} real fds"


def test_classify_pids_top_limits_rows():
    rows = lsofa.classify_pids(str(os.getpid()), top=2)
    assert len(rows) <= 2
