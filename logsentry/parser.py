import ipaddress
import re
from datetime import datetime

_LINE = re.compile(r'^(\S+) \S+ \S+ \[([^]]+)\] "(\S+) (.*?) (HTTP/[^" ]+)" (\d{3}) (\S+)(?: "(.*?)" "(.*?)")?\s*$')

def parse_line(line):
    match = _LINE.match(line.rstrip("\r\n"))
    if not match: return None
    ip, stamp, method, path, protocol, status, size, referrer, agent = match.groups()
    try:
        ipaddress.ip_address(ip)
        timestamp = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z")
        status = int(status)
        if size != "-": size = int(size)
    except (ValueError, OverflowError): return None
    return {"ip":ip,"timestamp":timestamp,"method":method,"endpoint":path,"protocol":protocol,"status":status,"size":None if size == "-" else size,"referrer":referrer,"user_agent":agent}

def parse_lines(text):
    rows, invalid = [], 0
    for line in text.splitlines():
        row = parse_line(line)
        if row is None: invalid += 1
        else: rows.append(row)
    return rows, {"total_lines":len(text.splitlines()),"parsed_lines":len(rows),"invalid_lines":invalid}
