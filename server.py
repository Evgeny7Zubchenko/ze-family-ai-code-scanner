import io
import json
import os
import uuid
from datetime import datetime

from flask import Flask, request, jsonify, send_file
from agent import run_agent, run_agent_from_zip

app = Flask(__name__)

HISTORY_FILE = "scans_history.json"


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_history(history):
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)


def build_summary(vulnerabilities):
    summary = {
        "total": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }

    if not isinstance(vulnerabilities, list):
        return summary

    summary["total"] = len(vulnerabilities)

    for item in vulnerabilities:
        severity = str(item.get("severity", "UNKNOWN")).upper()
        if severity in summary:
            summary[severity] += 1
        else:
            summary["UNKNOWN"] += 1

    return summary


def store_scan(scan_name, source_label, repo_url, vulnerabilities):
    summary = build_summary(vulnerabilities)

    record = {
        "id": str(uuid.uuid4()),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "scan_name": scan_name if scan_name else "Untitled scan",
        "source_label": source_label,
        "repo_url": repo_url,
        "summary": summary,
        "report": vulnerabilities
    }

    history = load_history()
    history.insert(0, record)
    history = history[:30]
    save_history(history)

    return record


@app.route("/", methods=["GET"])
def home():
    return send_file("index.html")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "Z.E Family AI Code Security Scanner"
    })


@app.route("/scan", methods=["POST"])
def scan_repo():
    try:
        data = request.get_json() or {}
        repo_url = str(data.get("repo_url", "")).strip()
        scan_name = str(data.get("scan_name", "")).strip()

        if not repo_url:
            return jsonify({
                "status": "error",
                "report": "repo_url is required"
            }), 400

        report = run_agent(repo_url)

        try:
            vulnerabilities = json.loads(report)
        except Exception:
            vulnerabilities = []

        record = store_scan(
            scan_name=scan_name,
            source_label="GitHub",
            repo_url=repo_url,
            vulnerabilities=vulnerabilities
        )

        return jsonify({
            "status": "completed",
            "report": json.dumps(vulnerabilities, ensure_ascii=False),
            "summary": record["summary"],
            "scan_id": record["id"]
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "report": f"Scan failed: {str(e)}"
        }), 500


@app.route("/scan-zip", methods=["POST"])
def scan_zip():
    try:
        uploaded_file = request.files.get("file")
        scan_name = str(request.form.get("scan_name", "")).strip()

        if uploaded_file is None:
            return jsonify({
                "status": "error",
                "report": "ZIP file is required"
            }), 400

        if not uploaded_file.filename.lower().endswith(".zip"):
            return jsonify({
                "status": "error",
                "report": "Only .zip files are supported"
            }), 400

        report = run_agent_from_zip(uploaded_file)

        try:
            vulnerabilities = json.loads(report)
        except Exception:
            vulnerabilities = []

        record = store_scan(
            scan_name=scan_name,
            source_label="ZIP Upload",
            repo_url=uploaded_file.filename,
            vulnerabilities=vulnerabilities
        )

        return jsonify({
            "status": "completed",
            "report": json.dumps(vulnerabilities, ensure_ascii=False),
            "summary": record["summary"],
            "scan_id": record["id"]
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "report": f"ZIP scan failed: {str(e)}"
        }), 500


@app.route("/history", methods=["GET"])
def history_list():
    return jsonify({
        "status": "ok",
        "history": load_history()
    })


@app.route("/history/<scan_id>", methods=["GET"])
def history_item(scan_id):
    history = load_history()

    for item in history:
        if item.get("id") == scan_id:
            return jsonify({
                "status": "ok",
                "item": item
            })

    return jsonify({
        "status": "error",
        "message": "Scan not found"
    }), 404


@app.route("/history/clear", methods=["POST"])
def clear_history():
    save_history([])
    return jsonify({
        "status": "ok",
        "message": "History cleared"
    })


@app.route("/export/<scan_id>", methods=["GET"])
def export_scan(scan_id):
    history = load_history()

    for item in history:
        if item.get("id") == scan_id:
            content = json.dumps(item, ensure_ascii=False, indent=2)
            buffer = io.BytesIO(content.encode("utf-8"))

            return send_file(
                buffer,
                as_attachment=True,
                download_name=f"scan_{scan_id}.json",
                mimetype="application/json"
            )

    return jsonify({
        "status": "error",
        "message": "Scan not found"
    }), 404


if __name__ == "__main__":
    if not os.path.exists(HISTORY_FILE):
        save_history([])

    app.run(host="0.0.0.0", port=8000, debug=True)
