import io
import os
import uuid
import json
import shutil
import zipfile
import subprocess
import requests


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

MAX_PY_FILES = 30
MAX_TOTAL_CHARS = 160000


def validate_openai_key():
    if not OPENAI_API_KEY:
        raise Exception("OPENAI_API_KEY is not set on the server.")


def validate_repo_url(repo_url):
    if not repo_url.startswith("https://github.com/"):
        raise Exception("Only public GitHub URLs are supported.")

    parts = repo_url.replace("https://github.com/", "").strip("/").split("/")
    if len(parts) < 2:
        raise Exception("Invalid GitHub repository URL.")


def clone_repo(repo_url):
    folder_name = f"cloned_repo_{uuid.uuid4().hex[:8]}"

    result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, folder_name],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise Exception(f"Git clone failed: {result.stderr}")

    return folder_name


def extract_zip_to_temp(uploaded_file):
    folder_name = f"uploaded_repo_{uuid.uuid4().hex[:8]}"
    os.makedirs(folder_name, exist_ok=True)

    file_bytes = uploaded_file.read()
    zip_buffer = io.BytesIO(file_bytes)

    try:
        with zipfile.ZipFile(zip_buffer, "r") as zip_ref:
            zip_ref.extractall(folder_name)
    except Exception as e:
        raise Exception(f"Invalid ZIP file: {str(e)}")

    return folder_name


def find_python_files(folder):
    python_files = []

    for root, dirs, files in os.walk(folder):
        dirs[:] = [
            d for d in dirs
            if d not in {".git", "node_modules", ".venv", "venv", "__pycache__"}
        ]

        for file in files:
            if file.endswith(".py"):
                python_files.append(os.path.join(root, file))

    return python_files


def collect_project_code(files, max_files=MAX_PY_FILES, max_chars=MAX_TOTAL_CHARS):
    combined_code = ""
    count = 0

    for file_path in files:
        if count >= max_files:
            break

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            block = f"\n\n# FILE: {file_path}\n{content}"

            if len(combined_code) + len(block) > max_chars:
                break

            combined_code += block
            count += 1
        except Exception:
            pass

    return combined_code, count


def severity_rank(severity):
    mapping = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0
    }
    return mapping.get(str(severity).upper(), 0)


def deduplicate_vulnerabilities(items):
    seen = set()
    result = []

    for item in items:
        key = (
            str(item.get("vulnerability", "")).strip().lower(),
            str(item.get("file", "")).strip().lower(),
            str(item.get("line", "")).strip().lower()
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

    result.sort(key=lambda x: severity_rank(x.get("severity", "UNKNOWN")), reverse=True)
    return result


def call_openai_for_report(project_code, source_name, file_count):
    validate_openai_key()

    url = "https://api.openai.com/v1/chat/completions"

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }

    prompt = f"""
You are a senior security engineer.

Analyze this Python repository sample and return ONLY valid JSON.

Source:
{source_name}

Analyzed Python files count:
{file_count}

Rules:
1. Return a JSON array
2. If no vulnerabilities, return []
3. No markdown
4. No explanations outside JSON
5. Focus on real security issues, not generic style issues
6. Avoid duplicates
7. Sort more severe issues first

Each item MUST contain:
- vulnerability
- severity (LOW, MEDIUM, HIGH)
- file
- line (number or "unknown")
- confidence (LOW, MEDIUM, HIGH)
- source (LLM)
- explanation
- fix

Repository code:
{project_code}
"""

    payload = {
        "model": "gpt-4.1-mini",
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }

    response = requests.post(url, headers=headers, json=payload, timeout=180)

    if response.status_code != 200:
        raise Exception(f"OpenAI API error: {response.status_code} {response.text}")

    data = response.json()
    return data["choices"][0]["message"]["content"].strip()


def generate_security_report(project_code, source_name, file_count):
    content = call_openai_for_report(project_code, source_name, file_count)

    try:
        parsed = json.loads(content)

        if not isinstance(parsed, list):
            parsed = []

        normalized = []

        for item in parsed:
            if not isinstance(item, dict):
                continue

            normalized.append({
                "vulnerability": str(item.get("vulnerability", "Unknown vulnerability")),
                "severity": str(item.get("severity", "UNKNOWN")).upper(),
                "file": str(item.get("file", "Unknown file")),
                "line": str(item.get("line", "unknown")),
                "confidence": str(item.get("confidence", "MEDIUM")).upper(),
                "source": str(item.get("source", "LLM")),
                "explanation": str(item.get("explanation", "No explanation provided.")),
                "fix": str(item.get("fix", "No fix provided."))
            })

        normalized = deduplicate_vulnerabilities(normalized)

        return json.dumps(normalized, ensure_ascii=False)

    except json.JSONDecodeError:
        fallback = [
            {
                "vulnerability": "ParsingError",
                "severity": "LOW",
                "file": "unknown",
                "line": "unknown",
                "confidence": "LOW",
                "source": "LLM",
                "explanation": "Model returned non-JSON output.",
                "fix": content
            }
        ]
        return json.dumps(fallback, ensure_ascii=False)


def cleanup_folder(folder_path):
    try:
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path, ignore_errors=True)
    except Exception:
        pass


def analyze_folder(folder_path, source_name):
    files = find_python_files(folder_path)

    if not files:
        raise Exception("No Python files found in the project.")

    project_code, file_count = collect_project_code(files)

    if file_count == 0 or not project_code.strip():
        raise Exception("Could not read project code.")

    if file_count >= MAX_PY_FILES:
        source_name = f"{source_name} (truncated to first {MAX_PY_FILES} Python files)"

    return generate_security_report(project_code, source_name, file_count)


def run_agent(repo_url):
    validate_repo_url(repo_url)
    project_folder = clone_repo(repo_url)

    try:
        return analyze_folder(project_folder, repo_url)
    finally:
        cleanup_folder(project_folder)


def run_agent_from_zip(uploaded_file):
    project_folder = extract_zip_to_temp(uploaded_file)

    try:
        return analyze_folder(project_folder, uploaded_file.filename)
    finally:
        cleanup_folder(project_folder)
