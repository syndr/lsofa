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
import itertools
import os
import subprocess
import sys
import time

import numpy
import pandas


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
        "--watch",
        type=int,
        default=None,
        metavar="SECONDS",
        help="sample repeatedly every SECONDS, running lsof itself and\n"
        "appending timestamped rows. use with -o to build a time series",
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


# Columns that are measurements rather than identity. They must never be used
# as join keys in --diff: soft_limit and pct move between snapshots, and joining
# on them makes an unchanged process look like it vanished and a new one
# appeared.
VALUE_COLUMNS = ("count", "used", "soft_limit", "pct", "ts")


def diff_snapshots(before_path, after_path, top=None):
    """Show what grew between two csv snapshots written by -o."""
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

    if args.diff:
        emit(diff_snapshots(args.diff[0], args.diff[1], args.top), args.output)
        return

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

