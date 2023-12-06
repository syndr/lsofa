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
import sys

import numpy
import pandas


# fmt: off
COLUMNS = ("COMMAND", "PID", "TID", "TASCMD", "USER", "FD", "TYPE", "DEVICE", "SIZE/OFF", "NODE", "NAME")
# fmt: on


def get_args():
    parser = argparse.ArgumentParser(
        description="Parse lsof output and show top results\n"
                    "example: lsof | python3 lsofa.py -g COMMAND,TASCMD,NAME -t 10\n"
                    "example: python3 lsofa.py lsof_output.txt -g COMMAND,TASCMD,NAME -t 10"

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

    return parser.parse_args()


def parse(lsof_output):
    head = next(lsof_output)
    command_start = 0
    command_end = 10
    pid_start = head.find("PID")
    pid_end = pid_start + 4
    tid_start = head.find("TID")
    tid_end = tid_start + 4
    tascmd_start = head.find("TASKCMD")
    tascmd_end = tascmd_start + 10
    user_start = head.find("USER")
    user_end = user_start + 5
    fd_start = head.find("FD") - 1
    fd_end = fd_start + 4
    type_start = head.find("TYPE")
    type_end = type_start + 5
    device_start = head.find("DEVICE")
    device_end = device_start + 7
    size_of_start = head.find("SIZE/OFF")
    size_of_end = size_of_start + 8
    node_start = head.find("NODE")
    node_end = node_start + 5
    name_start = head.find("NAME")
    name_end = -1

    command_chars = (command_start, command_end)
    pid_chars = (command_end, pid_end)
    tid_chars = (pid_end, tid_end)
    taskcmd_chars = (tid_end, tascmd_end)
    user_chars = (tascmd_end, user_end)
    fd_chars = (user_end, fd_end)
    type_chars = (fd_end, type_end)
    device_chars = (type_end, device_end)
    size_of_chars = (device_end, size_of_end)
    node_chars = (size_of_end, node_end)
    name_chars = (name_start, name_end)

    def parse_line(line: str):
        command = line[command_chars[0] : command_chars[1]].strip()
        pid = line[pid_chars[0] : pid_chars[1]].strip()
        tid = line[tid_chars[0] : tid_chars[1]].strip()
        taskcmd = line[taskcmd_chars[0] : taskcmd_chars[1]].strip()
        user = line[user_chars[0] : user_chars[1]].strip()
        fd = line[fd_chars[0] : fd_chars[1]].strip()
        type_ = line[type_chars[0] : type_chars[1]].strip()
        device = line[device_chars[0] : device_chars[1]].strip()
        size_of = line[size_of_chars[0] : size_of_chars[1]].strip()
        node = line[node_chars[0] : node_chars[1]].strip()
        name = line[name_chars[0] : name_chars[1]].strip()
        return numpy.array(
            [command, pid, tid, taskcmd, user, fd, type_, device, size_of, node, name]
        )

    return pandas.DataFrame(
        data=list(map(parse_line, lsof_output)),
        columns=list(COLUMNS),
    )


def main():
    args = get_args()
    if args.lsof_output_file:
        lsof_output_file = open(args.lsof_output_file)
        atexit.register(lsof_output_file.close)
        lsof_output = iter(lsof_output_file)
    else:
        lsof_output = iter(sys.stdin)

    lsof_dataframe = parse(lsof_output)

    if args.groupings:
        groupings = args.groupings.split(",")
        lsof_dataframe = (
            lsof_dataframe.groupby(groupings)
            .size()
            .reset_index(name="count")
            .sort_values(by="count", ascending=False)
        )
    if args.top:
        lsof_dataframe = lsof_dataframe.head(int(args.top))

    print(lsof_dataframe.to_markdown(index=False))


if __name__ == "__main__":
    main()
