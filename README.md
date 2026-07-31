# lsofa
Tool to parse lsof output and group by fields

## Installation
```
pip3 install pandas numpy tabulate
sudo cp lsofa.py /usr/local/bin/lsofa
sudo chmod uog=rx /usr/local/bin/lsofa
```

On an immutable/atomic host where you cannot install the deps, run it through `uv`:
```
uv run --with pandas --with numpy --with tabulate python lsofa.py --limits
```

## examples of usage
using pipe:
```
lsof | python3 lsofa -g COMMAND,TASCMD,NAME -t 10
```
using saved output:
```
lsof > ./lsof.txt
lsofa ./lsof.txt -g COMMAND,TASCMD,NAME -t 10
```
with no file and no pipe, lsofa runs `lsof` itself.

## hunting a file descriptor leak

**who is closest to their limit** — not who has the most handles, but who has the
most *relative to what they are allowed*:
```
lsofa --limits -t 15
```
```
| COMMAND   |   PID |   used |   soft_limit |   pct |
|:----------|------:|-------:|-------------:|------:|
| dbus-brok |  3441 |    143 |         1024 |  14   |
| waybar    |  3852 |     98 |         1024 |   9.6 |
```
The soft limit matters for more than just "too many open files". The kernel also
compares the **per-user in-flight SCM_RIGHTS fd count** against the *sending*
process's soft limit in `too_many_unix_fds()` — so one process leaking fds makes
every low-limit process on the session start failing with `ETOOMANYREFS`
("Too many references: cannot splice"), regardless of who actually leaked.

**what grew between two points in time** — the core leak-hunting question:
```
lsofa --limits -o before.csv
sleep 3600
lsofa --limits -o after.csv
lsofa --diff before.csv after.csv -t 20
```
```
| COMMAND   |  PID |   used_before |   used_after |   delta |
|:----------|-----:|--------------:|-------------:|--------:|
| waybar    | 3852 |            98 |          101 |       3 |
```

**build a time series** — sample on an interval, appending timestamped rows:
```
lsofa --watch 300 --limits -o timeseries.csv
```

Note `--handles` and `--limits` drop rows carrying a TID, because when lsof is
showing tasks it lists each fd once per thread — a process with 50 threads and
100 fds otherwise appears to hold 5000.

## usage

```
usage: lsofa.py [-h] [-g GROUPINGS] [-t TOP] [-o OUTPUT] [--handles] [--limits]
                [--diff BEFORE AFTER] [--watch SECONDS] [--lsof-args LSOF_ARGS]
                [lsof_output_file]

Parse lsof output and show top results
example: lsof | python3 lsofa.py -g COMMAND,TASCMD,NAME -t 10
example: python3 lsofa.py lsof_output.txt -g COMMAND,TASCMD,NAME -t 10

positional arguments:
  lsof_output_file      file containing lsof output

options:
  -h, --help            show this help message and exit
  -g GROUPINGS, --groupings GROUPINGS
                        fields to group by, separated by commas
                        available fields: COMMAND,PID,TID,TASCMD,USER,FD,TYPE,DEVICE,SIZE/OFF,NODE,NAME
                        example: -g COMMAND,TASCMD,NAME
  -t TOP, --top TOP     number of top results to show
  -o OUTPUT, --output OUTPUT
                        output file (csv)
  --handles             show number of file handles per process (counting towards ulimit)
  --limits              show handles used vs the process's soft RLIMIT_NOFILE, sorted by
                        percent consumed. implies --handles. linux only (reads /proc).
  --diff BEFORE AFTER   compare two csv snapshots written by -o and show what grew,
                        sorted by delta descending
  --watch SECONDS       sample repeatedly every SECONDS, running lsof itself and
                        appending timestamped rows. use with -o to build a time series
  --lsof-args LSOF_ARGS extra args passed to lsof when it is run for us. must use the
                        = form so argparse does not eat the leading dash: --lsof-args=-U
```
