#!/usr/bin/env python3

"""
Tool to parse lsof output and group by fields
example: lsof | python3 lsofa.py -g COMMAND,TASCMD,NAME -t 10
example: python3 lsofa.py lsof_output.txt -g COMMAND,TASCMD,NAME -t 10

requirements:
    pandas
    numpy
    tabulate
"""

import atexit
import argparse
import csv
import itertools
import os
import re
import subprocess
import sys
import time

# pandas/numpy are imported lazily by the lsof-parsing paths only. --classify
# reads /proc directly and must stay dependency-free: it is called every few
# minutes from fdwatch.sh on an atomic host where the deps only exist behind
# `uv run`, and paying a pandas import there would make sampling too expensive
# to run on an interval.


# fmt: off
COLUMNS = ("COMMAND", "PID", "TID", "TASCMD", "USER", "FD", "TYPE", "DEVICE", "SIZE/OFF", "NODE", "NAME")
# fmt: on

# Define a custom formatter class
class CustomFormatter(argparse.RawTextHelpFormatter):
    pass

def get_args():
    parser = argparse.ArgumentParser(
        description="Parse lsof output and show top results\n"
                    "example: lsof | python3 lsofa.py -g COMMAND,TASCMD,NAME -t 10\n"
                    "example: python3 lsofa.py lsof_output.txt -g COMMAND,TASCMD,NAME -t 10",
        formatter_class=CustomFormatter
    )
    parser.add_argument(
        "lsof_output_file", nargs="?", default=None, help="file containing lsof output"
    )
    parser.add_argument(
        "-g",
        "--groupings",
        default=None,
        help=f"fields to group by, separated by commas\n"
        f"available fields: {','.join(COLUMNS)}\n"
        f"example: -g COMMAND,TASCMD,NAME",
    )
    parser.add_argument(
        "-t", "--top", default=None, help="number of top results to show"
    )
    parser.add_argument(
        "-o", "--output", default=None, help="output file (csv)"
    )
    parser.add_argument(
        "--handles", action="store_true", help="show number of file handles per process (counting towards ulimit)"
    )
    parser.add_argument(
        "--limits",
        action="store_true",
        help="show handles used vs the process's soft RLIMIT_NOFILE, sorted by\n"
        "percent consumed. implies --handles. linux only (reads /proc).\n"
        "the soft limit is also what the kernel compares the per-user\n"
        "in-flight SCM_RIGHTS fd count against in too_many_unix_fds(), so\n"
        "a process sitting near its limit is the one about to see ENFILE\n"
        "or ETOOMANYREFS",
    )
    parser.add_argument(
        "--diff",
        nargs=2,
        metavar=("BEFORE", "AFTER"),
        default=None,
        help="compare two csv snapshots written by -o and show what grew,\n"
        "sorted by delta descending. the core leak-hunting question",
    )
    parser.add_argument(
        "--classify",
        default=None,
        metavar="PIDS|NAMES",
        help="bucket each process's fds by what they point at (shm, dmabuf,\n"
        "eventpoll, unix sockets, ...) by reading /proc directly. answers\n"
        "'which KIND of fd is growing', which a bare handle count cannot.\n"
        "accepts pids and/or comm names, comma separated; names re-resolve\n"
        "each sample so --watch follows a process across a restart.\n"
        "needs no pandas/numpy, so it is cheap enough to run on a timer.\n"
        "example: --classify Hyprland,dbus-broker",
    )
    parser.add_argument(
        "--trend",
        default=None,
        metavar="SERIES_CSV",
        help="read a --classify series (one file, many timestamps) and show\n"
        "first/last/delta per class, sorted by growth. this is the payoff\n"
        "question for a leak: which KIND of fd grew while you were away.\n"
        "use --diff instead when comparing two standalone snapshots",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="append to -o instead of overwriting, writing the header only when\n"
        "the file is new. for building a time series from an external timer\n"
        "(systemd, cron) that invokes us once per sample rather than using\n"
        "--watch. classify only",
    )
    parser.add_argument(
        "--watch",
        type=int,
        default=None,
        metavar="SECONDS",
        help="sample repeatedly every SECONDS, running lsof itself and\n"
        "appending timestamped rows. use with -o to build a time series.\n"
        "composes with --classify",
    )
    parser.add_argument(
        "--lsof-args",
        default="",
        help="extra args passed to lsof when it is run for us (--watch, or no\n"
        "input given). must use the = form so argparse does not eat the\n"
        "leading dash: --lsof-args=-U  (unix sockets only)",
    )

    return parser.parse_args()


def parse(lsof_output):
    import numpy
    import pandas

    head = next(lsof_output, None)
    if head is None:
        sys.exit("error: no lsof output to parse (empty input)")

    # Column offsets are read from the header rather than assumed, because lsof
    # sizes columns to its content: TID/TASKCMD only exist under -K, and `+c 0`
    # widens COMMAND past its default 9-char truncation. A header field that is
    # absent yields find() == -1, which must not be treated as an offset.
    pid_end = head.find("PID") + 4
    tid_start = head.find("TID")
    tid_end = tid_start + 4 if tid_start >= 0 else pid_end
    tascmd_start = head.find("TASKCMD")
    tascmd_end = tascmd_start + 10 if tascmd_start >= 0 else tid_end
    user_end = head.find("USER") + 5
    fd_end = head.find("FD") - 1 + 4
    type_end = head.find("TYPE") + 5
    device_end = head.find("DEVICE") + 7
    size_of_end = head.find("SIZE/OFF") + 8
    node_end = head.find("NODE") + 5
    name_start = head.find("NAME")

    tid_chars = (pid_end, tid_end)
    taskcmd_chars = (tid_end, tascmd_end)
    user_chars = (tascmd_end, user_end)
    fd_chars = (user_end, fd_end)
    type_chars = (fd_end, type_end)
    device_chars = (type_end, device_end)
    size_of_chars = (device_end, size_of_end)
    node_chars = (size_of_end, node_end)

    def parse_line(line: str):
        # COMMAND has no fixed width and may itself contain spaces under `+c 0`,
        # so split it off by taking everything up to the end of the (right-
        # aligned) PID column and peeling the last token -- that token is the
        # pid, whatever remains to its left is the command.
        head_field = line[:pid_end].rsplit(None, 1)
        if len(head_field) == 2:
            command, pid = head_field[0].strip(), head_field[1].strip()
        else:
            command, pid = head_field[0].strip() if head_field else "", ""
        tid = line[tid_chars[0] : tid_chars[1]].strip()
        taskcmd = line[taskcmd_chars[0] : taskcmd_chars[1]].strip()
        user = line[user_chars[0] : user_chars[1]].strip()
        fd = line[fd_chars[0] : fd_chars[1]].strip()
        type_ = line[type_chars[0] : type_chars[1]].strip()
        device = line[device_chars[0] : device_chars[1]].strip()
        size_of = line[size_of_chars[0] : size_of_chars[1]].strip()
        node = line[node_chars[0] : node_chars[1]].strip()
        name = line[name_start:].strip()
        return numpy.array(
            [command, pid, tid, taskcmd, user, fd, type_, device, size_of, node, name]
        )

    rows = [parse_line(line) for line in lsof_output if line.strip()]
    return pandas.DataFrame(data=rows, columns=list(COLUMNS))


def only_handles(lsof_dataframe):
    """Keep only the rows that count towards a process's RLIMIT_NOFILE."""
    lsof_types = ['REG', 'DIR', 'CHR', 'BLK', 'FIFO', 'SOCK', 'a_inode', 'unix', 'netlink', 'IPv4', 'IPv6']
    lsof_fd_special_types = ['cwd', 'rtd', 'txt', 'mem', 'DEL', 'anon_inode']
    lsof_dataframe = lsof_dataframe[lsof_dataframe['TYPE'].isin(lsof_types)]
    lsof_dataframe = lsof_dataframe[~lsof_dataframe['FD'].isin(lsof_fd_special_types)]
    # Drop rows with a TID (likely other threads)
    return lsof_dataframe[lsof_dataframe['TID'] == '']


def soft_nofile(pid):
    """Soft RLIMIT_NOFILE for a pid, or None if it cannot be read.

    This is the number worth watching. Besides capping how many files the
    process may open, the kernel compares the *per-user* in-flight SCM_RIGHTS
    fd count against the sending process's soft limit in too_many_unix_fds()
    -- so a low soft limit here turns someone else's fd leak into this
    process's ETOOMANYREFS failure.
    """
    try:
        with open(f"/proc/{pid}/limits") as limits:
            for line in limits:
                if line.startswith("Max open files"):
                    value = line.split()[3]
                    return None if value == "unlimited" else int(value)
    except (OSError, ValueError, IndexError):
        return None
    return None


def with_limits(lsof_dataframe, top=None):
    """Per-process handle counts joined against each process's soft limit."""
    import numpy

    counts = (
        only_handles(lsof_dataframe)
        .groupby(["COMMAND", "PID"])
        .size()
        .reset_index(name="used")
    )
    counts["soft_limit"] = counts["PID"].map(soft_nofile)
    # Processes whose limits we cannot read (not ours, or already gone) still
    # have a meaningful used count -- keep them, just without a percentage.
    counts["pct"] = numpy.where(
        counts["soft_limit"].notna() & (counts["soft_limit"] > 0),
        (counts["used"] / counts["soft_limit"] * 100).round(1),
        numpy.nan,
    )
    counts = counts.sort_values(by=["pct", "used"], ascending=False, na_position="last")
    return counts.head(int(top)) if top else counts


# --- fd classification (--classify) -----------------------------------------
#
# `lsofa --limits` answers "who is near their limit", but a compositor sitting
# at 1025 fds tells you nothing about *what* those fds are. A leak shows up as
# one class growing while the rest stay flat, so bucketing by what the
# /proc/PID/fd symlink points at is the measurement that actually localises it.
#
# This reads /proc directly rather than going through lsof: it must be cheap
# enough to run on a short interval, and lsof cannot distinguish a dmabuf from
# any other anon_inode anyway.

# Ordered longest/most-specific first -- the first match wins.
FD_CLASS_RULES = (
    (re.compile(r"^/dev/shm/.*\(deleted\)$"), "shm_deleted"),
    (re.compile(r"^/dev/shm/"), "shm"),
    (re.compile(r"^/dmabuf:?"), "dmabuf"),
    (re.compile(r"^anon_inode:\[?eventpoll\]?"), "eventpoll"),
    (re.compile(r"^anon_inode:\[?timerfd\]?"), "timerfd"),
    (re.compile(r"^anon_inode:\[?eventfd\]?"), "eventfd"),
    (re.compile(r"^anon_inode:\[?signalfd\]?"), "signalfd"),
    (re.compile(r"^anon_inode:\[?inotify\]?"), "inotify"),
    (re.compile(r"^anon_inode:.*sync_file"), "sync_file"),
    (re.compile(r"^anon_inode:"), "anon_other"),
    (re.compile(r"^pipe:"), "pipe"),
    (re.compile(r"^/dev/input/event"), "input"),
    (re.compile(r"^/dev/dri/"), "dri"),
    (re.compile(r"^/dev/nvidia"), "gpu"),
    (re.compile(r"^/memfd:"), "memfd"),
)

SOCKET_INODE = re.compile(r"^socket:\[(\d+)\]$")

# Per-session socket paths carry a varying suffix -- flatpak mints one wayland
# proxy per sandbox (wayland-QHEWT3, ...) and libei one socket per input-capture
# session (eis-0, eis-1, ... 40+ of them here). Left alone each becomes its own
# one-off class and the series stops being trendable, so fold the varying tail
# into a single "-*" class. Counting them together is what you actually want:
# "eis-* went from 43 to 61" is the signal, not which numbers exist.
SOCKET_NONCE = re.compile(r"-[A-Z0-9]{5,8}$")
SOCKET_SEQ = re.compile(r"-\d+$")
# ...except the wayland display socket, where the number IS the identity:
# wayland-1 is the compositor's listening socket and must not be folded in with
# the per-sandbox proxies it would otherwise share a class with.
SOCKET_KEEP_SEQ = re.compile(r"^wayland-\d+$")


def unix_socket_paths():
    """inode -> bound path for every unix socket, from /proc/net/unix.

    Accepted (connected) sockets carry no path, so they come back as unnamed.
    That distinction is the point: a compositor should hold one *named* listening
    socket and one unnamed peer per live client, so unnamed sockets outnumbering
    live clients is itself the leak signal.
    """
    paths = {}
    try:
        with open("/proc/net/unix") as handle:
            next(handle, None)  # header
            for line in handle:
                fields = line.split()
                # Num RefCount Protocol Flags Type St Inode [Path]
                if len(fields) >= 7:
                    paths[fields[6]] = fields[7] if len(fields) > 7 else ""
    except OSError:
        pass
    return paths


def classify_fd(target, socket_paths):
    """Bucket one /proc/PID/fd symlink target."""
    match = SOCKET_INODE.match(target)
    if match:
        path = socket_paths.get(match.group(1))
        if path is None:
            return "socket_other"  # not a unix socket (tcp/udp/netlink)
        if not path:
            return "unix_unnamed"
        # Identity of a bound socket matters (the wayland display socket is the
        # one worth watching), but only its basename is stable -- the directory
        # carries the uid and the hyprland instance signature. Strip the
        # abstract-namespace marker too so the label survives a CSV round-trip.
        name = os.path.basename(path.lstrip("@")) or path.lstrip("@")
        if not SOCKET_KEEP_SEQ.match(name):
            name = SOCKET_SEQ.sub("-*", name)
        return "unix:" + SOCKET_NONCE.sub("-*", name)
    for pattern, name in FD_CLASS_RULES:
        if pattern.match(target):
            return name
    if target.endswith("(deleted)"):
        return "deleted_other"
    if target.startswith("/"):
        return "file"
    return "other"


def resolve_targets(spec):
    """Turn a --classify spec into [(comm, pid)].

    Accepts pids and/or comm names, comma separated. Names are resolved fresh on
    every call so a --watch series keeps following a process across a restart,
    which a pid captured once would not.
    """
    wanted_pids, wanted_names = set(), set()
    for item in (s.strip() for s in spec.split(",")):
        if not item:
            continue
        (wanted_pids if item.isdigit() else wanted_names).add(item)

    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/comm") as handle:
                comm = handle.read().strip()
        except OSError:
            continue  # raced with process exit
        # comm is truncated to 15 chars by the kernel, so accept a prefix match
        # for longer names (xdg-desktop-portal-hyprland -> xdg-desktop-por).
        if entry in wanted_pids or comm in wanted_names or any(
            name.startswith(comm) and len(comm) == 15 for name in wanted_names
        ):
            found.append((comm, entry))
    return sorted(found, key=lambda item: int(item[1]))


def classify_pids(spec, top=None):
    """Per-class fd counts for each matching process."""
    socket_paths = unix_socket_paths()
    rows = []
    for comm, pid in resolve_targets(spec):
        counts = {}
        fd_dir = f"/proc/{pid}/fd"
        try:
            entries = os.listdir(fd_dir)
        except OSError:
            continue  # gone, or not ours to read
        for entry in entries:
            try:
                target = os.readlink(f"{fd_dir}/{entry}")
            except OSError:
                continue  # fd closed mid-scan; skip rather than miscount
            klass = classify_fd(target, socket_paths)
            counts[klass] = counts.get(klass, 0) + 1
        for klass, count in counts.items():
            rows.append(
                {"COMMAND": comm, "PID": pid, "CLASS": klass, "count": count}
            )
    rows.sort(key=lambda row: row["count"], reverse=True)
    return rows[: int(top)] if top else rows


def trend(series_path, top=None):
    """Per-class growth across a --classify time series.

    --diff compares two standalone snapshots, but a series written by --append
    is one file with many timestamps, so diffing it needs the first and last
    observation of each class picked out. That is the question you actually ask
    of a leak sample: which class grew, and by how much.

    A class absent from the first sample starts at 0 rather than being skipped --
    fds that appeared partway through are exactly what a leak looks like.
    """
    first, last, seen = {}, {}, set()
    first_ts = None
    try:
        with open(series_path, newline="") as handle:
            for row in csv.DictReader(handle):
                try:
                    key = (row["COMMAND"], row["PID"], row["CLASS"])
                    count = int(row["count"])
                except (KeyError, TypeError, ValueError):
                    sys.exit(
                        f"error: {series_path} is not a --classify series "
                        f"(expected COMMAND,PID,CLASS,count columns)"
                    )
                stamp = row.get("ts", "")
                if first_ts is None:
                    first_ts = stamp
                seen.add(stamp)
                if key not in first:
                    # Baseline a class at its own first reading only if that
                    # reading is from the first sample. A class that shows up
                    # later started at zero -- seeding it with its debut value
                    # would report delta 0 for the row most likely to be the
                    # leak.
                    first[key] = count if stamp == first_ts else 0
                last[key] = count
    except OSError as problem:
        sys.exit(f"error: cannot read {series_path}: {problem}")

    if not last:
        sys.exit(f"error: {series_path} has no rows")

    rows = [
        {
            "COMMAND": key[0],
            "PID": key[1],
            "CLASS": key[2],
            "first": first[key],
            "last": last[key],
            "delta": last[key] - first[key],
        }
        for key in last
    ]
    # Growth first, then absolute size -- so a quiet series (every delta 0) still
    # reads usefully as "here is what this process is holding", biggest first.
    rows.sort(key=lambda row: (row["delta"], row["last"]), reverse=True)
    print(f"# {len(seen)} samples in {series_path}", file=sys.stderr)
    return rows[: int(top)] if top else rows


def emit_rows(rows, output_path, append=False):
    """Write plain dict rows as csv/markdown, without pandas.

    --classify deliberately avoids the dataframe path so it stays runnable on a
    bare python3; emit() is only for the lsof side.
    """
    if not rows:
        return
    # Preferred column order, then anything else the caller added, so --classify
    # and --trend can share this writer without it knowing their schemas.
    preferred = ["ts", "COMMAND", "PID", "CLASS", "count", "first", "last", "delta"]
    fields = [f for f in preferred if f in rows[0]]
    fields += [f for f in rows[0] if f not in fields]
    if output_path:
        new = not append or not os.path.exists(output_path)
        with open(output_path, "a" if append else "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            if new:
                writer.writeheader()
            writer.writerows(rows)
        return
    widths = [
        max(len(f), *(len(str(row[f])) for row in rows)) for f in fields
    ]
    line = lambda cells: "| " + " | ".join(
        str(c).ljust(w) for c, w in zip(cells, widths)
    ) + " |"
    print(line(fields))
    print("|" + "|".join("-" * (w + 2) for w in widths) + "|")
    for row in rows:
        print(line([row[f] for f in fields]))


# Columns that are measurements rather than identity. They must never be used
# as join keys in --diff: soft_limit and pct move between snapshots, and joining
# on them makes an unchanged process look like it vanished and a new one
# appeared.
VALUE_COLUMNS = ("count", "used", "soft_limit", "pct", "ts")


def diff_snapshots(before_path, after_path, top=None):
    """Show what grew between two csv snapshots written by -o."""
    import pandas

    before = pandas.read_csv(before_path)
    after = pandas.read_csv(after_path)

    value_col = "count" if "count" in after.columns else "used"
    if value_col not in before.columns:
        sys.exit(
            f"error: {before_path} has no '{value_col}' column -- both snapshots "
            f"must come from the same kind of lsofa run"
        )
    keys = [
        c
        for c in after.columns
        if c in before.columns and c not in VALUE_COLUMNS
    ]
    if not keys:
        sys.exit("error: snapshots share no grouping columns to join on")

    merged = before[keys + [value_col]].merge(
        after[keys + [value_col]], on=keys, how="outer", suffixes=("_before", "_after")
    )
    before_col, after_col = f"{value_col}_before", f"{value_col}_after"
    merged[[before_col, after_col]] = merged[[before_col, after_col]].fillna(0)
    merged["delta"] = merged[after_col] - merged[before_col]
    merged = merged[merged["delta"] != 0].sort_values(by="delta", ascending=False)
    return merged.head(int(top)) if top else merged


def run_lsof(extra_args):
    """Run lsof and return its output as an iterator of lines."""
    command = ["lsof"] + (extra_args.split() if extra_args else [])
    # lsof exits non-zero when some paths are unreadable, which is routine when
    # unprivileged -- take whatever it did manage to produce.
    result = subprocess.run(command, capture_output=True, text=True)
    if not result.stdout.strip():
        sys.exit(f"error: lsof produced no output ({result.stderr.strip()})")
    return iter(result.stdout.splitlines(keepends=True))


def stdin_or_lsof(extra_args):
    """Read piped lsof output, or run lsof ourselves if nothing was piped in.

    isatty() alone is not enough: run from cron, a systemd unit, or any harness
    that hands us /dev/null, stdin is neither a tty nor has any data. So peek at
    the first line and fall back to running lsof when there is nothing there.
    """
    if not sys.stdin.isatty():
        first = sys.stdin.readline()
        if first:
            return itertools.chain([first], sys.stdin)
    return run_lsof(extra_args)


def emit(frame, output_path, append=False):
    if output_path:
        frame.to_csv(
            output_path,
            index=False,
            mode="a" if append else "w",
            header=not append,
        )
    else:
        print(frame.to_markdown(index=False))


def summarize(args, lsof_dataframe):
    """Apply the requested filtering/grouping to one parsed lsof snapshot."""
    if args.limits:
        return with_limits(lsof_dataframe, args.top)

    if args.handles:
        lsof_dataframe = only_handles(lsof_dataframe)

    if args.groupings:
        lsof_dataframe = (
            lsof_dataframe.groupby(args.groupings.split(","))
            .size()
            .reset_index(name="count")
            .sort_values(by="count", ascending=False)
        )
    if args.top:
        lsof_dataframe = lsof_dataframe.head(int(args.top))
    return lsof_dataframe


def main():
    args = get_args()

    if args.trend:
        emit_rows(trend(args.trend, args.top), args.output)
        return

    if args.diff:
        emit(diff_snapshots(args.diff[0], args.diff[1], args.top), args.output)
        return

    if args.classify:
        appending = args.append
        while True:
            rows = classify_pids(args.classify, args.top)
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            for row in rows:
                row["ts"] = stamp
            emit_rows(rows, args.output, append=appending)
            if not args.watch:
                return
            if not args.output:
                print()
            appending = bool(args.output)
            time.sleep(args.watch)

    if args.watch:
        appending = False
        while True:
            frame = summarize(args, parse(run_lsof(args.lsof_args)))
            frame.insert(0, "ts", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
            emit(frame, args.output, append=appending)
            if not args.output:
                print()
            appending = bool(args.output)
            time.sleep(args.watch)

    if args.lsof_output_file:
        lsof_output_file = open(args.lsof_output_file)
        atexit.register(lsof_output_file.close)
        lsof_output = iter(lsof_output_file)
    else:
        lsof_output = stdin_or_lsof(args.lsof_args)

    emit(summarize(args, parse(lsof_output)), args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        # e.g. piped into `head`
        os._exit(0)

