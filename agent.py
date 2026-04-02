import io
import os
import uuid
import json
import shutil
import zipfile
import requests


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

MAX_FILES = 50
MAX_CHARS = 220000
HEADERS = {"User-Agent": "ZE-Family-Scanner"}

SUPPORTED_LANGUAGES = {
    "auto": [".py", ".js", ".ts"],
    "python": [".py"],
    "javascript": [".js"],
    "typescript": [".ts"],
    "multi": [".py", ".js", ".ts"]
}


def validate_key():
    if not OPENAI_API_KEY:
        raise Exception("OPENAI_API_KEY not set")


def validate_repo_url(repo_url):
    if not repo_url.startswith("https://github.com/"):
        raise Exception("Only public GitHub URLs are supported.")

    parts = repo_url.replace("https://github.com/", "").strip("/").split("/")
    if len(parts) < 2:
        raise Exception("Invalid GitHub repository URL.")


def validate_language(language):
    if language not in SUPPORTED_LANGUAGES:
        raise Exception("Unsupported language selection.")


def parse_repo(url):
    clean = url.replace(".git", "").strip()
    parts = clean.replace("https://github.com/", "").strip("/").split("/")
    return parts[0], parts[1]


def download_repo_zip(owner, repo, branch):
    zip_url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"
    response = requests.get(zip_url, headers=HEADERS, timeout=60, allow_redirects=True)
    if response.status_code == 200:
        return response.content
    return None


def clone_repo(url):
    owner, repo = parse_repo(url)

    api_response = requests.get(
        f"https://api.github.com/repos/{owner}/{repo}",
        headers=HEADERS,
        timeout=30
    )

    branches_to_try = []

    if api_response.status_code == 200:
        default_branch = api_response.json().get("default_branch")
        if default_branch:
            branches_to_try.append(default_branch)

    for candidate in ["main", "master"]:
        if candidate not in branches_to_try:
            branches_to_try.append(candidate)

    zip_bytes = None
    for branch in branches_to_try:
        zip_bytes = download_repo_zip(owner, repo, branch)
        if zip_bytes:
            break

    if not zip_bytes:
        if api_response.status_code == 404:
            raise Exception("Repository not found or is private.")
        if api_response.status_code == 403:
            raise Exception("GitHub API rate limit reached. Try again later.")
        raise Exception(
            f"Failed to download repository archive. Tried branches: {', '.join(branches_to_try)}"
        )

    folder = f"repo_{uuid.uuid4().hex[:6]}"
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        z.extractall(folder)
    return folder


def extract_zip_to_temp(uploaded_file):
    folder = f"uploaded_repo_{uuid.uuid4().hex[:8]}"
    os.makedirs(folder, exist_ok=True)

    file_bytes = uploaded_file.read()
    zip_buffer = io.BytesIO(file_bytes)

    try:
        with zipfile.ZipFile(zip_buffer, "r") as zip_ref:
            zip_ref.extractall(folder)
    except Exception as e:
        raise Exception(f"Invalid ZIP file: {str(e)}")

    return folder


def get_extensions_for_language(language):
    validate_language(language)
    return SUPPORTED_LANGUAGES[language]


def find_files(folder, language="auto"):
    extensions = get_extensions_for_language(language)
    files = []

    for root, dirs, fs in os.walk(folder):
        dirs[:] = [
            d for d in dirs
            if d not in {".git", "node_modules", ".venv", "venv", "__pycache__", ".next", "dist", "build"}
        ]

        for f in fs:
            if any(f.endswith(ext) for ext in extensions):
                files.append(os.path.join(root, f))

    return files


def collect_code(files):
    code = ""
    count = 0

    for f in files:
        if count >= MAX_FILES:
            break

        try:
            with open(f, encoding="utf-8") as handle:
                content = handle.read()

            block = f"\n# FILE: {f}\n{content}"

            if len(code) + len(block) > MAX_CHARS:
                break

            code += block
            count += 1
        except Exception:
            pass

    return code, count


def build_language_prompt(language):
    mapping = {
        "auto": "Auto-detect relevant issues across Python, JavaScript, and TypeScript.",
        "python": "Focus only on Python security issues and Python-specific fixes.",
        "javascript": "Focus only on JavaScript security issues and JavaScript-specific fixes.",
        "typescript": "Focus only on TypeScript security issues and TypeScript-specific fixes.",
        "multi": "Analyze across Python, JavaScript, and TypeScript with language-appropriate fixes."
    }
    return mapping.get(language, "Analyze the selected codebase safely.")


def call_ai(code, source_name, file_count, language):
    validate_key()

    language_prompt = build_language_prompt(language)

    prompt = f"""
You are a senior security engineer.

Analyze this repository and return ONLY valid JSON.

Return this exact JSON shape:
{{
  "summary": "short executive summary",
  "vulnerabilities": [
    {{
      "vulnerability": "name",
      "severity": "HIGH|MEDIUM|LOW",
      "file": "path",
      "line": "number or unknown",
      "confidence": "HIGH|MEDIUM|LOW",
      "source": "LLM",
      "explanation": "what is wrong",
      "fix": "how to fix it with a small practical example"
    }}
  ]
}}

Rules:
- If no vulnerabilities, return:
  {{
    "summary": "No significant security issues found.",
    "vulnerabilities": []
  }}
- No markdown
- No explanations outside JSON
- Focus on real security issues, not style issues
- Avoid duplicates
- Sort more severe issues first
- Keep fixes practical and specific
- Mention safe alternatives where useful

Language mode:
{language_prompt}

Source:
{source_name}

Analyzed files count:
{file_count}

CODE:
{code}
"""

    r = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2
        },
        timeout=180
    )

    if r.status_code != 200:
        raise Exception(f"OpenAI error: {r.status_code} {r.text}")

    return r.json()["choices"][0]["message"]["content"]


def calc_score(vulns):
    score = 100
    for v in vulns:
        sev = str(v.get("severity", "")).upper()
        if sev == "HIGH":
            score -= 25
        elif sev == "MEDIUM":
            score -= 10
        elif sev == "LOW":
            score -= 3
    return max(score, 0)


def severity_rank(severity):
    return {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}.get(str(severity).upper(), 0)


def dedupe(vulns):
    seen = set()
    result = []

    for item in vulns:
        key = (
            str(item.get("vulnerability", "")).lower().strip(),
            str(item.get("file", "")).lower().strip(),
            str(item.get("line", "")).lower().strip()
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)

    result.sort(key=lambda x: severity_rank(x.get("severity", "UNKNOWN")), reverse=True)
    return result


def normalize_response(raw_text):
    try:
        data = json.loads(raw_text)
    except Exception:
        return {
            "summary": "The model returned non-JSON output.",
            "score": 0,
            "vulnerabilities": [
                {
                    "vulnerability": "ParsingError",
                    "severity": "LOW",
                    "file": "unknown",
                    "line": "unknown",
                    "confidence": "LOW",
                    "source": "LLM",
                    "explanation": "Model returned non-JSON output.",
                    "fix": raw_text
                }
            ]
        }

    summary = str(data.get("summary", "No summary provided."))
    vulns = data.get("vulnerabilities", [])

    if not isinstance(vulns, list):
        vulns = []

    normalized = []
    for item in vulns:
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

    normalized = dedupe(normalized)

    return {
        "summary": summary,
        "score": calc_score(normalized),
        "vulnerabilities": normalized
    }


def analyze_folder(folder_path, source_name, language="auto"):
    files = find_files(folder_path, language=language)
    code, count = collect_code(files)

    if count == 0 or not code.strip():
        raise Exception("Could not read project code for the selected language.")

    raw = call_ai(code, source_name, count, language)
    return normalize_response(raw)


def run_agent(repo_url, language="auto"):
    validate_repo_url(repo_url)
    validate_language(language)
    folder = clone_repo(repo_url)

    try:
        return analyze_folder(folder, repo_url, language=language)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def run_agent_from_zip(uploaded_file, language="auto"):
    validate_language(language)
    folder = extract_zip_to_temp(uploaded_file)

    try:
        return analyze_folder(folder, uploaded_file.filename, language=language)
    finally:
        shutil.rmtree(folder, ignore_errors=True)
