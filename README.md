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

**what KIND of fd is growing** — a handle count tells you a process sits at 1025
fds; it cannot tell you whether that is buffers, sockets or epolls. `--classify`
buckets fds by what the `/proc/PID/fd` symlink points at:
```
lsofa --classify Hyprland
```
```
| COMMAND  |  PID | CLASS          | count |
|:---------|-----:|:---------------|------:|
| Hyprland | 4877 | shm_deleted    |   392 |
| Hyprland | 4877 | dmabuf         |   122 |
| Hyprland | 4877 | unix_unnamed   |   112 |
| Hyprland | 4877 | eventpoll      |   105 |
| Hyprland | 4877 | unix:wayland-1 |    46 |
```
`eventpoll` at 105 against 18 threads, or `unix_unnamed` far exceeding the number
of live clients, is the shape of a leak — neither is visible in a total.

Takes pids and/or comm names. Names re-resolve every sample, so a `--watch`
series keeps following a process across a restart. Unlike the rest of lsofa this
reads `/proc` directly and imports no pandas/numpy, so it is cheap enough to run
on a timer — see `--append`.

Per-session socket paths are folded into one class (`unix:eis-*`,
`unix:wayland-*`) so 40+ one-off sockets do not each become their own class. The
wayland display socket keeps its number (`unix:wayland-1`), because there the
number is the identity.

**sample from a systemd timer / cron** — `--append` writes the header only when
the file is new, so each invocation adds one sample:
```
lsofa --classify Hyprland,dbus-broker --append -o fd-classes.csv
```

**read the series back** — `--diff` compares two standalone snapshots; for one
appended series use `--trend`:
```
lsofa --trend fd-classes.csv -t 15
```
```
| COMMAND  |  PID | CLASS        | first | last | delta |
|:---------|-----:|:-------------|------:|-----:|------:|
| Hyprland | 4877 | shm_deleted  |   354 |  392 |    38 |
| Hyprland | 4877 | eventpoll    |    88 |  105 |    17 |
```
Classes absent from the first sample start at 0 rather than being skipped — fds
that appeared partway through are exactly what a leak looks like.

Note `--handles` and `--limits` drop rows carrying a TID, because when lsof is
showing tasks it lists each fd once per thread — a process with 50 threads and
100 fds otherwise appears to hold 5000.

## usage

```
usage: lsofa.py [-h] [-g GROUPINGS] [-t TOP] [-o OUTPUT] [--handles] [--limits]
                [--diff BEFORE AFTER] [--classify PIDS|NAMES] [--trend SERIES_CSV]
                [--append] [--watch SECONDS] [--lsof-args LSOF_ARGS]
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
  --classify PIDS|NAMES bucket each process's fds by what they point at (shm, dmabuf,
                        eventpoll, unix sockets, ...) by reading /proc directly.
                        needs no pandas/numpy, so it is cheap enough for a timer
  --trend SERIES_CSV    read a --classify series and show first/last/delta per class
  --append              append to -o instead of overwriting, header only when new.
                        for an external timer that invokes us once per sample
  --watch SECONDS       sample repeatedly every SECONDS, running lsof itself and
                        appending timestamped rows. use with -o to build a time series
  --lsof-args LSOF_ARGS extra args passed to lsof when it is run for us. must use the
                        = form so argparse does not eat the leading dash: --lsof-args=-U
```
