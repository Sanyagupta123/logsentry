import json
import sqlite3
from pathlib import Path

def connect(path):
    db=sqlite3.connect(str(path)); db.row_factory=sqlite3.Row; db.execute("PRAGMA foreign_keys=ON"); return db
def initialize(path):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    with connect(path) as db:
        db.executescript("CREATE TABLE IF NOT EXISTS analyses(id INTEGER PRIMARY KEY,filename TEXT NOT NULL,total_lines INTEGER,parsed_lines INTEGER,invalid_lines INTEGER,total_requests INTEGER,summary TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY,analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,rule TEXT,severity TEXT,ip TEXT,endpoint TEXT,description TEXT,event_count INTEGER,created_at TEXT);")
def save(path,filename,counts,summary,findings):
    with connect(path) as db:
        cur=db.execute("INSERT INTO analyses(filename,total_lines,parsed_lines,invalid_lines,total_requests,summary) VALUES(?,?,?,?,?,?)",(filename,counts["total_lines"],counts["parsed_lines"],counts["invalid_lines"],summary["total_requests"],json.dumps(summary)))
        aid=cur.lastrowid
        db.executemany("INSERT INTO findings(analysis_id,rule,severity,ip,endpoint,description,event_count,created_at) VALUES(?,?,?,?,?,?,?,?)",[(aid,f["rule"],f["severity"],f["ip"],f["endpoint"],f["description"],f["event_count"],f["timestamp"]) for f in findings])
    return aid
def get_analysis(path,aid):
    with connect(path) as db: row=db.execute("SELECT * FROM analyses WHERE id=?",(aid,)).fetchone()
    if not row:return None
    out=dict(row); out["summary"]=json.loads(out["summary"]); return out
def history(path):
    with connect(path) as db:return [dict(x) for x in db.execute("SELECT id,filename,total_requests,created_at FROM analyses ORDER BY id DESC LIMIT 50")]
def get_findings(path,aid):
    with connect(path) as db:return [dict(x) for x in db.execute("SELECT rule,severity,ip,endpoint,description,event_count,created_at FROM findings WHERE analysis_id=? ORDER BY id",(aid,))]
