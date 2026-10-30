from datetime import datetime,timezone,timedelta
from logsentry.parser import parse_line,parse_lines
from logsentry.analyzer import analyze
from logsentry.detection import detect

def line(ip="192.0.2.1",stamp="10/Oct/2025:13:55:36 +0000",method="GET",path="/",status=200,size=12):
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "pytest"'
def test_parser():
    assert parse_line(line())["ip"]=="192.0.2.1" and parse_line(line(size="-"))["size"] is None
    rows,counts=parse_lines(line()+"\nmalformed\n"); assert len(rows)==1 and counts["invalid_lines"]==1
    assert parse_line(line(ip="999.1.2.3")) is None and parse_line(line(stamp="bad")) is None
def test_analytics():
    assert analyze([])["total_requests"]==0
    out=analyze([parse_line(line(status=200)),parse_line(line(status=404)),parse_line(line(status=503))])
    assert (out["successful"],out["client_errors"],out["server_errors"])==(1,1,1)
    assert out["top_ips"][0]["count"]==3 and out["top_endpoints"][0]["endpoint"]=="/"
def test_detection_rules_and_window():
    base=datetime(2025,1,1,tzinfo=timezone.utc)
    rows=[{"timestamp":base+timedelta(seconds=i),"ip":"192.0.2.5","endpoint":"/login","method":"POST","status":401} for i in range(5)]
    rows += [{"timestamp":base,"ip":"192.0.2.5","endpoint":"/.env","method":"GET","status":404}]
    rows += [{"timestamp":base+timedelta(seconds=i),"ip":"192.0.2.7","endpoint":"/oops","method":"GET","status":500} for i in range(10)]
    assert {x["rule"] for x in detect(rows)} >= {"Repeated Failed Login Attempts","Sensitive Endpoint Access","Repeated Server Errors"}
    outside=[{**r,"timestamp":base+timedelta(seconds=i*20)} for i,r in enumerate(rows[:5])]
    assert not any(x["rule"]=="Repeated Failed Login Attempts" for x in detect(outside))
