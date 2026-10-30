try:
    import pandas as pd
except ImportError:  # Keep the core usable before optional local dependencies are installed.
    pd = None

def analyze(rows):
    if not rows: return {"total_requests":0,"successful":0,"client_errors":0,"server_errors":0,"redirects":0,"unique_ips":0,"top_ips":[],"top_endpoints":[],"error_endpoints":[],"status_counts":{},"requests_over_time":[]}
    if pd is None:
        from collections import Counter
        from datetime import timezone
        status=Counter(int(r["status"]) for r in rows); ips=Counter(r["ip"] for r in rows); paths=Counter(r["endpoint"] for r in rows)
        errors=Counter(r["endpoint"] for r in rows if int(r["status"])>=400); hours=Counter(r["timestamp"].astimezone(timezone.utc).replace(minute=0,second=0,microsecond=0).isoformat() for r in rows)
        return {"total_requests":len(rows),"successful":sum(v for k,v in status.items() if 200<=k<300),"client_errors":sum(v for k,v in status.items() if 400<=k<500),"server_errors":sum(v for k,v in status.items() if 500<=k<600),"redirects":sum(v for k,v in status.items() if 300<=k<400),"unique_ips":len(ips),"top_ips":[{"ip":k,"count":v} for k,v in ips.most_common(10)],"top_endpoints":[{"endpoint":k,"count":v} for k,v in paths.most_common(10)],"error_endpoints":[{"endpoint":k,"count":v} for k,v in errors.most_common(10)],"status_counts":{str(k):v for k,v in sorted(status.items())},"requests_over_time":[{"time":k,"count":v} for k,v in sorted(hours.items())]}
    df=pd.DataFrame(rows); s=df.status.astype(int); errors=df[s>=400]
    activity=df.assign(hour=pd.to_datetime(df.timestamp,utc=True).dt.floor("h").astype(str)).groupby("hour").size()
    return {"total_requests":len(df),"successful":int(s.between(200,299).sum()),"client_errors":int(s.between(400,499).sum()),"server_errors":int(s.between(500,599).sum()),"redirects":int(s.between(300,399).sum()),"unique_ips":int(df.ip.nunique()),"top_ips":[{"ip":str(k),"count":int(v)} for k,v in df.ip.value_counts().head(10).items()],"top_endpoints":[{"endpoint":str(k),"count":int(v)} for k,v in df.endpoint.value_counts().head(10).items()],"error_endpoints":[{"endpoint":str(k),"count":int(v)} for k,v in errors.endpoint.value_counts().head(10).items()],"status_counts":{str(k):int(v) for k,v in s.value_counts().sort_index().items()},"requests_over_time":[{"time":k,"count":int(v)} for k,v in activity.items()]}
