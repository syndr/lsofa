# lsofa
Tool to parse lsof output and group by fields

## Installation
```
pip3 install pandas numpy tabulate
sudo cp lsofa.py /usr/local/bin/lsofa
sudo chmod uog=rx /usr/local/bin/lsofa
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

## usage
lsofa [-h] [-g GROUPINGS] [-t TOP] [lsof_output_file]

Parse lsof output and show top results example: lsof | python3 lsofa.py -g COMMAND,TASCMD,NAME -t 10 example: python3 lsofa.py lsof_output.txt -g COMMAND,TASCMD,NAME -t 10

positional arguments:\
  lsof_output_file      file containing lsof output

options:\
  -h, --help            show this help message and exit\
  -g GROUPINGS, --groupings GROUPINGS\
                        fields to group by, separated by commas available fields: COMMAND,PID,TID,TASCMD,USER,FD,TYPE,DEVICE,SIZE/OFF,NODE,NAME example: -g COMMAND,TASCMD,NAME\
  -t TOP, --top TOP     number of top results to show



