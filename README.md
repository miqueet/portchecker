# portchecker

A small tool for checking whether TCP ports are open. It works for a single
port, a full port range, a fleet of hosts, a deploy script that needs to wait
for a database, or a Nagios/Icinga check.

It needs only Python 3.9 or newer and has no third-party dependencies.

```
$ python portopen.py 1.1.1.1 80
HOST     PORT  STATE  SERVICE  LATENCY
1.1.1.1  80    open   http     11.8 ms
```

## Install

Run `portopen.py` directly, or install it to get a `portopen` command:

```
pip install .
```

## Usage

```
portopen.py [options] TARGET [TARGET ...] [PORTS]
```

A target is `HOST`, `HOST:PORTS`, or `[IPv6]:PORTS`. Ports can be single
numbers, ranges, or service names, mixed freely: `22,80,8000-8100,https`.
Hosts given without ports use the ports from `-p` or the trailing port
argument. This is why the original `portopen.py HOST PORT` form still works.

```
portopen.py example.com 22,80,443               # several ports
portopen.py example.com 1-1024 --open-only      # scan a range, show only what's open
portopen.py db:5432 cache:6379 web:https        # host:port pairs
portopen.py web1 web2 web3 -p 80,443            # same ports on many hosts
portopen.py example.com --common                # 26 commonly used ports
portopen.py mail.example.com -p 25,587 -b       # show service banners
portopen.py -f hosts.txt -p 22 -o json          # targets from a file, JSON output
portopen.py '[2606:4700:4700::1111]:53'         # IPv6
```

### States

Unlike the original script, which only said open or closed, each port gets
one of four states:

| State      | Meaning                                                                 |
|------------|-------------------------------------------------------------------------|
| `open`     | The TCP connection succeeded.                                           |
| `closed`   | The host actively refused the connection, so nothing is listening there. |
| `filtered` | There was no answer before the timeout, usually because a firewall dropped it. |
| `error`    | DNS failed, there was no route to the host, and so on. The reason appears in the NOTE column. |

### Options

| Option | Description |
|--------|-------------|
| `-p, --ports PORTS` | Ports for hosts given without ports. |
| `--common` | Also check a built-in list of common ports. |
| `-f, --file FILE` | Read more targets from a file (`-` for stdin). Separate them with whitespace or newlines; `#` starts a comment. |
| `-4` / `-6` | Use only IPv4 or only IPv6. |
| `-t, --timeout SECONDS` | Timeout for each connection attempt (default 2). |
| `-r, --retries N` | Retry ports that timed out or errored. Refused connections are never retried. |
| `--workers N` | Number of concurrent connections (default 100). A full 1-65535 scan of localhost takes a few seconds. |
| `-b, --banner` | Show what a service sends on connect, such as SSH, SMTP or FTP greetings. |
| `--wait SECONDS` | Keep checking until every port is open or the time runs out. |
| `--interval SECONDS` | Pause between `--wait` rounds (default 1). |
| `-o, --output text\|json\|csv` | Output format. |
| `--open-only` | List only open ports. Exit status still covers every port. |
| `-q, --quiet` | Print nothing and rely on the exit status. |
| `--nagios`, `-w`, `-c` | Nagios plugin mode. See below. |

### Exit status

The command exits with `0` when every port checked is open, `1` when at least
one isn't, and `2` on a usage error. This makes it useful in scripts:

```
# Block a deploy until the database accepts connections (up to 60s)
python portopen.py db:5432 --wait 60 -q && ./run-migrations
```

### Nagios / Icinga

With `--nagios` the tool behaves like a standard monitoring plugin. It prints
a single status line with performance data and exits `0` (OK), `1` (WARNING)
or `2` (CRITICAL). Any port that isn't open is CRITICAL. `-w` and `-c` set
thresholds for connect time in seconds:

```
$ python portopen.py example.com -p 443 --nagios -w 0.5 -c 1
PORT OK - example.com:443 open in 0.012s | 'example.com:443'=0.012034s;0.5;1;0;2
```

```
define command {
    command_name  check_portopen
    command_line  /usr/bin/python3 /opt/portchecker/portopen.py $HOSTADDRESS$ -p $ARG1$ --nagios -w $ARG2$ -c $ARG3$
}
```

## Tests

```
python -m unittest -v
```
