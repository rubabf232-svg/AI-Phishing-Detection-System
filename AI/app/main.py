
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from urllib.parse import urlparse
import re

app = FastAPI(title="AI Phishing Detection System")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

class URLRequest(BaseModel):
    url: str

def analyze_url(url):
    original = url.strip()
    test_url = original if re.match(r"^https?://", original, re.I) else "http://" + original
    parsed = urlparse(test_url)
    host = parsed.hostname or ""
    path = parsed.path.lower()
    score = 0
    reasons = []

    if parsed.scheme != "https":
        score += 20
        reasons.append("Website is not using HTTPS.")
    if "@" in test_url:
        score += 25
        reasons.append("URL contains @.")
    if len(original) > 75:
        score += 15
        reasons.append("URL is unusually long.")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 25
        reasons.append("URL uses an IP address.")
    words = ["login","verify","verification","secure","account","update","password","signin","bank","confirm"]
    found = [w for w in words if w in host + path]
    if found:
        score += min(25, len(found) * 5)
        reasons.append("Suspicious account/security keywords found.")
    if host.count("-") >= 3:
        score += 10
        reasons.append("Domain contains many hyphens.")
    if host.count(".") >= 4:
        score += 10
        reasons.append("Many subdomains detected.")
    if host.lower() in ["bit.ly","tinyurl.com","t.co","is.gd","cutt.ly"]:
        score += 20
        reasons.append("URL shortener detected.")

    score = min(score, 100)
    verdict = "Likely Phishing" if score >= 60 else "Suspicious" if score >= 30 else "Likely Safe"
    if not reasons:
        reasons.append("No obvious phishing indicators detected.")
    return {"url": original, "score": score, "verdict": verdict, "reasons": reasons}

@app.get("/", response_class=HTMLResponse)
def home():
    return open("app/static/index.html", encoding="utf-8").read()

@app.post("/analyze")
def analyze(data: URLRequest):
    return analyze_url(data.url)
