import os
from flask import Flask,jsonify,render_template,request
from logsentry.parser import parse_lines
from logsentry.analyzer import analyze
from logsentry.detection import detect
from logsentry import database

def create_app(test_config=None):
    app=Flask(__name__); app.config.update(MAX_CONTENT_LENGTH=5*1024*1024,DATABASE=os.environ.get("LOGSENTRY_DB","logsentry.db"))
    if test_config:app.config.update(test_config)
    database.initialize(app.config["DATABASE"])
    @app.get("/")
    def index():return render_template("index.html")
    @app.get("/api/health")
    def health():return jsonify(status="ok",service="LogSentry")
    @app.post("/api/analyze")
    def upload():
        f=request.files.get("file")
        if not f:return jsonify(error="Choose a .log or .txt file."),400
        if not f.filename or "." not in f.filename or f.filename.rsplit(".",1)[1].lower() not in ("log","txt"):return jsonify(error="Only .log and .txt files are accepted."),415
        raw=f.read(app.config["MAX_CONTENT_LENGTH"]+1)
        if len(raw)>app.config["MAX_CONTENT_LENGTH"]:return jsonify(error="File exceeds the 5 MB limit."),413
        try:content=raw.decode("utf-8-sig")
        except UnicodeDecodeError:return jsonify(error="File must contain valid UTF-8 text."),400
        if len(content.splitlines())>100000:return jsonify(error="File exceeds the 100,000 line limit."),413
        if not content.strip():return jsonify(error="File is empty."),400
        rows,counts=parse_lines(content)
        if not rows:return jsonify(error="No valid combined access log entries found.",counts=counts),400
        summary=analyze(rows); findings=detect(rows); name=os.path.basename(f.filename.replace("\\","/"))[:255]
        aid=database.save(app.config["DATABASE"],name,counts,summary,findings)
        return jsonify(id=aid,filename=name,counts=counts,summary=summary,findings=findings),201
    @app.get("/api/history")
    def get_history():return jsonify(items=database.history(app.config["DATABASE"]))
    @app.get("/api/analysis/<int:aid>")
    def analysis(aid):
        item=database.get_analysis(app.config["DATABASE"],aid)
        return (jsonify(item),200) if item else (jsonify(error="Analysis not found."),404)
    @app.get("/api/analysis/<int:aid>/findings")
    def findings(aid):
        if not database.get_analysis(app.config["DATABASE"],aid):return jsonify(error="Analysis not found."),404
        return jsonify(items=database.get_findings(app.config["DATABASE"],aid))
    @app.errorhandler(413)
    def too_large(_):return jsonify(error="Upload exceeds the 5 MB limit."),413
    return app

app=create_app()
if __name__=="__main__":app.run(debug=False)
