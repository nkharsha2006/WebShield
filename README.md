# WebShield

**Evidence-Based Web Vulnerability Verification and Regression Detection Platform**

WebShield is a web application security platform designed to help developers and small web development teams identify security weaknesses, review findings, verify remediation, and detect potential security regressions.

## Features

- Application registration and management
- HTTPS and security-header checks
- OWASP ZAP spider and active-scan integration
- Centralized vulnerability findings
- Finding status and remediation verification
- Potential security regression detection
- Application security reports
- React dashboard and FastAPI backend
- SQLite-based data storage

## Technology Stack

- **Frontend:** React, Vite, JavaScript
- **Backend:** Python, FastAPI
- **Database:** SQLite, SQLAlchemy
- **Security scanning:** OWASP ZAP
- **Testing:** pytest

## Project Architecture

React frontend → FastAPI backend → SQLite database

The backend performs security checks, coordinates supported OWASP ZAP scans, stores findings, and supports verification and regression workflows.

## Requirements

- Python 3
- Node.js and npm
- OWASP ZAP
- Git

## Installation

Clone the repository:

```bash
git clone https://github.com/nkharsha2006/WebShield.git
cd WebShield
```

Create and activate a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Install frontend dependencies:

```bash
cd frontend
npm ci
cd ..
```

## Configuration

Configure the backend environment using the project's expected environment variables and local OWASP ZAP connection settings.

Do not commit `.env` files, API keys, credentials, or local databases to Git.

## Running the Project

Start the backend using the entry point and configuration defined by the project:

```bash
source .venv/bin/activate
uvicorn app.main:app --reload
```

Start the frontend in a separate terminal:

```bash
cd frontend
npm run dev
```

Open the frontend URL printed by Vite. The backend API is normally available at `http://127.0.0.1:8000`.

**Note:** OWASP ZAP must be installed, running, and configured for scan functionality. Verify the project's environment settings before running scans.

## Testing

From the project root:

```bash
.venv/bin/python -m pytest -q
```

## Responsible Use

Only scan web applications that you own or have explicit authorization to test. Active scans may affect application availability or data. Use local test applications for development and demonstrations.

## Project Status

WebShield is an actively developed prototype. Additional hardening and deployment configuration may be required before production use.

## Author

**GitHub:** [nkharsha2006](https://github.com/nkharsha2006)
