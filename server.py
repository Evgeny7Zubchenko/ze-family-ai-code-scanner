import io
import json
import os
import uuid
from datetime import datetime, timezone

import stripe
from flask import Flask, request, jsonify, send_file

from agent import run_agent, run_agent_from_zip

app = Flask(__name__)

# -----------------------------
# Files
# -----------------------------
HISTORY_FILE = "scans_history.json"
PRO_USERS_FILE = "pro_users.json"
FREE_USAGE_FILE = "free_usage.json"

# -----------------------------
# Environment
# -----------------------------
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

STRIPE_PRICE_ID_WEEK = os.getenv("STRIPE_PRICE_ID_WEEK", "")
STRIPE_PRICE_ID_MONTH = os.getenv("STRIPE_PRICE_ID_MONTH", "")
STRIPE_PRICE_ID_6MONTHS = os.getenv("STRIPE_PRICE_ID_6MONTHS", "")

FREE_SCANS_PER_DAY = 2

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY


# -----------------------------
# Helpers
# -----------------------------
def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def today_key():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def load_json_file(path, default_value):
    if not os.path.exists(path):
        return default_value

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default_value


def save_json_file(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def ensure_files_exist():
    if not os.path.exists(HISTORY_FILE):
        save_json_file(HISTORY_FILE, [])
    if not os.path.exists(PRO_USERS_FILE):
        save_json_file(PRO_USERS_FILE, {})
    if not os.path.exists(FREE_USAGE_FILE):
        save_json_file(FREE_USAGE_FILE, {})


def load_history():
    data = load_json_file(HISTORY_FILE, [])
    return data if isinstance(data, list) else []


def save_history(history):
    save_json_file(HISTORY_FILE, history)


def load_pro_users():
    data = load_json_file(PRO_USERS_FILE, {})
    return data if isinstance(data, dict) else {}


def save_pro_users(data):
    save_json_file(PRO_USERS_FILE, data)


def load_free_usage():
    data = load_json_file(FREE_USAGE_FILE, {})
    return data if isinstance(data, dict) else {}


def save_free_usage(data):
    save_json_file(FREE_USAGE_FILE, data)


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


def calculate_security_score(vulnerabilities):
    score = 100

    for item in vulnerabilities:
        sev = str(item.get("severity", "UNKNOWN")).upper()
        if sev == "HIGH":
            score -= 25
        elif sev == "MEDIUM":
            score -= 10
        elif sev == "LOW":
            score -= 3

    return max(score, 0)


def normalize_email(email):
    return str(email or "").strip().lower()


def normalize_language(language):
    return str(language or "auto").strip().lower()


def get_price_id_for_plan(plan_key):
    mapping = {
        "week": STRIPE_PRICE_ID_WEEK,
        "month": STRIPE_PRICE_ID_MONTH,
        "6months": STRIPE_PRICE_ID_6MONTHS
    }
    return mapping.get(str(plan_key).strip().lower(), "")


def require_stripe_config():
    if not STRIPE_SECRET_KEY:
        raise Exception("STRIPE_SECRET_KEY is not configured.")
    if not APP_BASE_URL:
        raise Exception("APP_BASE_URL is not configured.")


def get_user_plan(email):
    email = normalize_email(email)

    if not email:
        return {
            "plan": "free",
            "active": False
        }

    pro_users = load_pro_users()
    user = pro_users.get(email)

    if not user:
        return {
            "plan": "free",
            "active": False
        }

    status = str(user.get("status", "")).lower()
    active = status == "active"

    return {
        "plan": user.get("plan", "free") if active else "free",
        "active": active,
        "stripe_customer_id": user.get("stripe_customer_id"),
        "stripe_subscription_id": user.get("stripe_subscription_id")
    }


def can_run_scan(email):
    email = normalize_email(email)
    plan_info = get_user_plan(email)

    if plan_info["active"]:
        return True, None, plan_info

    usage = load_free_usage()
    key = email if email else "anonymous"
    today = today_key()

    if key not in usage:
        usage[key] = {}

    count_today = int(usage[key].get(today, 0))

    if count_today >= FREE_SCANS_PER_DAY:
        return False, f"Free limit reached: {FREE_SCANS_PER_DAY} scans per day.", plan_info

    return True, None, plan_info


def increment_free_scan_usage(email):
    email = normalize_email(email)
    usage = load_free_usage()
    key = email if email else "anonymous"
    today = today_key()

    if key not in usage:
        usage[key] = {}

    usage[key][today] = int(usage[key].get(today, 0)) + 1
    save_free_usage(usage)


def store_scan(scan_name, source_label, repo_url, email, language, result_data):
    vulnerabilities = result_data.get("vulnerabilities", [])
    ai_summary = result_data.get("summary", "")
    score = result_data.get("score", calculate_security_score(vulnerabilities))
    summary = build_summary(vulnerabilities)

    record = {
        "id": str(uuid.uuid4()),
        "created_at": utc_now_iso(),
        "scan_name": scan_name if scan_name else "Untitled scan",
        "source_label": source_label,
        "repo_url": repo_url,
        "email": normalize_email(email),
        "language": normalize_language(language),
        "score": score,
        "ai_summary": ai_summary,
        "summary": summary,
        "report": vulnerabilities
    }

    history = load_history()
    history.insert(0, record)
    history = history[:100]
    save_history(history)

    return record


def find_scan_by_id(scan_id):
    history = load_history()
    for item in history:
        if item.get("id") == scan_id:
            return item
    return None


def user_can_export_current(email):
    plan = get_user_plan(email)
    return plan["active"]


# -----------------------------
# Routes
# -----------------------------
@app.route("/", methods=["GET"])
def home():
    return send_file("index.html")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "Z.E Family AI Code Security Scanner"
    })


@app.route("/plan-status", methods=["POST"])
def plan_status():
    data = request.get_json() or {}
    email = normalize_email(data.get("email", ""))

    plan = get_user_plan(email)
    can_scan, reason, _ = can_run_scan(email)

    return jsonify({
        "status": "ok",
        "email": email,
        "plan": plan["plan"],
        "pro_active": plan["active"],
        "can_scan": can_scan,
        "reason": reason
    })


@app.route("/scan", methods=["POST"])
def scan_repo():
    try:
        data = request.get_json() or {}
        repo_url = str(data.get("repo_url", "")).strip()
        scan_name = str(data.get("scan_name", "")).strip()
        email = normalize_email(data.get("email", ""))
        language = normalize_language(data.get("language", "auto"))

        if not repo_url:
            return jsonify({
                "status": "error",
                "report": "repo_url is required"
            }), 400

        allowed, reason, plan_info = can_run_scan(email)
        if not allowed:
            return jsonify({
                "status": "error",
                "report": reason,
                "upgrade_required": True
            }), 403

        result_data = run_agent(repo_url, language=language)

        if not plan_info["active"]:
            increment_free_scan_usage(email)

        record = store_scan(
            scan_name=scan_name,
            source_label="GitHub",
            repo_url=repo_url,
            email=email,
            language=language,
            result_data=result_data
        )

        return jsonify({
            "status": "completed",
            "report": json.dumps(record["report"], ensure_ascii=False),
            "summary": record["summary"],
            "score": record["score"],
            "ai_summary": record["ai_summary"],
            "scan_id": record["id"],
            "plan": get_user_plan(email)["plan"],
            "language": record["language"]
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
        email = normalize_email(request.form.get("email", ""))
        language = normalize_language(request.form.get("language", "auto"))

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

        allowed, reason, plan_info = can_run_scan(email)
        if not allowed:
            return jsonify({
                "status": "error",
                "report": reason,
                "upgrade_required": True
            }), 403

        result_data = run_agent_from_zip(uploaded_file, language=language)

        if not plan_info["active"]:
            increment_free_scan_usage(email)

        record = store_scan(
            scan_name=scan_name,
            source_label="ZIP Upload",
            repo_url=uploaded_file.filename,
            email=email,
            language=language,
            result_data=result_data
        )

        return jsonify({
            "status": "completed",
            "report": json.dumps(record["report"], ensure_ascii=False),
            "summary": record["summary"],
            "score": record["score"],
            "ai_summary": record["ai_summary"],
            "scan_id": record["id"],
            "plan": get_user_plan(email)["plan"],
            "language": record["language"]
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "report": f"ZIP scan failed: {str(e)}"
        }), 500


@app.route("/create-checkout-session", methods=["POST"])
def create_checkout_session():
    try:
        require_stripe_config()

        data = request.get_json() or {}
        email = normalize_email(data.get("email", ""))
        plan_key = str(data.get("plan", "")).strip().lower()

        if not email:
            return jsonify({
                "status": "error",
                "message": "Email is required."
            }), 400

        price_id = get_price_id_for_plan(plan_key)
        if not price_id:
            return jsonify({
                "status": "error",
                "message": "Invalid plan selected."
            }), 400

        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[
                {
                    "price": price_id,
                    "quantity": 1
                }
            ],
            customer_email=email,
            success_url=f"{APP_BASE_URL}/?checkout=success",
            cancel_url=f"{APP_BASE_URL}/?checkout=cancel",
            metadata={
                "email": email,
                "plan": plan_key
            }
        )

        return jsonify({
            "status": "ok",
            "url": session.url
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "")

    if not STRIPE_WEBHOOK_SECRET:
        return jsonify({
            "status": "error",
            "message": "Missing webhook secret."
        }), 500

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Webhook error: {str(e)}"
        }), 400

    pro_users = load_pro_users()

    event_type = event["type"]
    obj = event["data"]["object"]

    if event_type == "checkout.session.completed":
        customer_email = (obj.get("customer_details", {}) or {}).get("email") or obj.get("customer_email")
        customer_id = obj.get("customer")
        subscription_id = obj.get("subscription")
        metadata = obj.get("metadata", {}) or {}
        plan_key = metadata.get("plan", "month")

        email = normalize_email(customer_email)
        if email:
            pro_users[email] = {
                "status": "active",
                "plan": plan_key,
                "stripe_customer_id": customer_id,
                "stripe_subscription_id": subscription_id,
                "updated_at": utc_now_iso()
            }
            save_pro_users(pro_users)

    elif event_type == "customer.subscription.updated":
        customer_id = obj.get("customer")
        subscription_id = obj.get("id")
        status = str(obj.get("status", "")).lower()

        for email, user in pro_users.items():
            if user.get("stripe_customer_id") == customer_id or user.get("stripe_subscription_id") == subscription_id:
                user["status"] = "active" if status in {"active", "trialing"} else "inactive"
                user["updated_at"] = utc_now_iso()
                save_pro_users(pro_users)
                break

    elif event_type == "customer.subscription.deleted":
        customer_id = obj.get("customer")
        subscription_id = obj.get("id")

        for email, user in pro_users.items():
            if user.get("stripe_customer_id") == customer_id or user.get("stripe_subscription_id") == subscription_id:
                user["status"] = "inactive"
                user["updated_at"] = utc_now_iso()
                save_pro_users(pro_users)
                break

    return jsonify({"status": "ok"})


@app.route("/history", methods=["GET"])
def history_list():
    return jsonify({
        "status": "ok",
        "history": load_history()
    })


@app.route("/history/<scan_id>", methods=["GET"])
def history_item(scan_id):
    item = find_scan_by_id(scan_id)

    if not item:
        return jsonify({
            "status": "error",
            "message": "Scan not found"
        }), 404

    return jsonify({
        "status": "ok",
        "item": item
    })


@app.route("/history/clear", methods=["POST"])
def clear_history():
    save_history([])
    return jsonify({
        "status": "ok",
        "message": "History cleared"
    })


@app.route("/export/<scan_id>", methods=["GET"])
def export_scan(scan_id):
    item = find_scan_by_id(scan_id)

    if not item:
        return jsonify({
            "status": "error",
            "message": "Scan not found"
        }), 404

    content = json.dumps(item, ensure_ascii=False, indent=2)
    buffer = io.BytesIO(content.encode("utf-8"))

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"scan_{scan_id}.json",
        mimetype="application/json"
    )


@app.route("/export-current", methods=["POST"])
def export_current():
    data = request.get_json() or {}
    email = normalize_email(data.get("email", ""))
    report = data.get("report", [])
    ai_summary = str(data.get("ai_summary", ""))
    score = data.get("score", 0)
    language = normalize_language(data.get("language", "auto"))

    if not user_can_export_current(email):
        return jsonify({
            "status": "error",
            "message": "Current export is available only for Pro users."
        }), 403

    payload = {
        "exported_at": utc_now_iso(),
        "email": email,
        "language": language,
        "score": score,
        "ai_summary": ai_summary,
        "summary": build_summary(report if isinstance(report, list) else []),
        "report": report if isinstance(report, list) else []
    }

    content = json.dumps(payload, ensure_ascii=False, indent=2)
    buffer = io.BytesIO(content.encode("utf-8"))

    return send_file(
        buffer,
        as_attachment=True,
        download_name="current_scan_report.json",
        mimetype="application/json"
    )


if __name__ == "__main__":
    ensure_files_exist()
    app.run(host="0.0.0.0", port=8000, debug=True)
