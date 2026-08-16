# AI Phishing Detection System

Defensive cybersecurity project for checking common phishing indicators in URLs.

## Run
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000

Educational heuristic detector; results are not a guarantee of safety.
