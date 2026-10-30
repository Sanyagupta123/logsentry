import io
from app import create_app

def test_api(tmp_path):
    app=create_app({"TESTING":True,"DATABASE":str(tmp_path/"test.db")}); c=app.test_client()
    assert c.get("/api/health").status_code==200
    assert c.get("/api/analysis/123").status_code==404
    assert c.post("/api/analyze",data={"file":(io.BytesIO(b"x"),"x.csv")}).status_code==415
    assert c.post("/api/analyze",data={"file":(io.BytesIO(b""),"x.log")}).status_code==400
    line=b'192.0.2.1 - - [10/Oct/2025:13:55:36 +0000] "GET / HTTP/1.1" 200 10 "-" "test"\n'
    r=c.post("/api/analyze",data={"file":(io.BytesIO(line),"demo.log")}); assert r.status_code==201
    aid=r.json["id"]; assert c.get("/api/analysis/"+str(aid)).status_code==200
    assert len(c.get("/api/history").json["items"])==1
    assert c.get(f"/api/analysis/{aid}/findings").status_code==200
    assert c.post("/api/analyze",data={"file":(io.BytesIO(b"x"*(5*1024*1024+1)),"big.log")}).status_code==413
