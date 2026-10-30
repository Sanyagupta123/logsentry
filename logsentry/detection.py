from collections import defaultdict, deque

DEFAULTS={"login_count":5,"burst_count":100,"window_seconds":60,"server_error_count":10}
SENSITIVE=("/admin","/wp-admin","/.env","/config","/phpmyadmin")

def detect(rows, thresholds=None):
    t={**DEFAULTS,**(thresholds or {})}; findings=[]
    login,bursts,servers=defaultdict(deque),defaultdict(deque),defaultdict(deque); seen=set()
    def add(rule,severity,source,count,stamp,description,evidence,ip=None,endpoint=None):
        findings.append({"rule":rule,"severity":severity,"ip":ip,"endpoint":endpoint,"source":source,"event_count":count,"timestamp":stamp.isoformat(),"description":description,"evidence":evidence})
    for r in sorted(rows,key=lambda x:x["timestamp"]):
        ts,ip,path,status=r["timestamp"],r["ip"],r["endpoint"],int(r["status"])
        q=bursts[ip]; q.append(ts)
        while q and (ts-q[0]).total_seconds()>t["window_seconds"]: q.popleft()
        if len(q)==t["burst_count"]+1: add("Request Burst","MEDIUM",ip,len(q),ts,f"More than {t['burst_count']} requests within {t['window_seconds']} seconds.",f"Observed {len(q)} requests in the active window.",ip=ip)
        if status in (401,403):
            q=login[ip]; q.append(ts)
            while q and (ts-q[0]).total_seconds()>t["window_seconds"]: q.popleft()
            if len(q)==t["login_count"]: add("Repeated Failed Login Attempts","HIGH",ip,len(q),ts,f"At least {t['login_count']} failed responses within {t['window_seconds']} seconds.","HTTP 401/403 responses in the active window.",ip=ip)
        if any(path==p or path.startswith(p+"/") for p in SENSITIVE) and (ip,path) not in seen:
            seen.add((ip,path)); add("Sensitive Endpoint Access","MEDIUM",ip,1,ts,f"Request to sensitive path {path}.",f"Requested {r['method']} {path}, HTTP {status}.",ip=ip,endpoint=path)
        if 500<=status<=599:
            q=servers[path]; q.append(ts)
            while q and (ts-q[0]).total_seconds()>t["window_seconds"]: q.popleft()
            if len(q)==t["server_error_count"]: add("Repeated Server Errors","MEDIUM",path,len(q),ts,f"At least {t['server_error_count']} server errors for {path} within {t['window_seconds']} seconds.",f"HTTP 5xx responses observed: {len(q)}.",endpoint=path)
    return findings
