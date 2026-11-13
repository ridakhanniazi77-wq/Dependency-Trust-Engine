
# Dependency Trust Engine

## Project Overview

Dependency Trust Engine is a Python-based application that analyzes software dependencies and assigns them a risk-priority score.

It helps developers review packages by examining different risk signals, including security advisories, maintenance, provenance, license policy, and dependency exposure.

## Features

- Upload and validate a JSON dependency manifest.
- Detect duplicate packages.
- Identify missing dependencies.
- Display a package inventory.
- Calculate package risk scores.
- Classify packages by review priority.
- Search and filter packages.
- View individual package risk breakdowns.
- Visualize dependency relationships using a graph.
- Export package results as a CSV file.

## Technology Stack

- Python
- Streamlit
- Pydantic
- Pandas
- NetworkX
- Plotly
- Pytest

## Risk Scoring System

The application calculates a score from 0 to 100 using five categories:

| Category | Maximum Points |
|---|---:|
| Security Advisories | 35 |
| Maintenance | 20 |
| Provenance and Integrity | 20 |
| License Policy | 15 |
| Dependency Exposure | 10 |
| **Total** | **100** |

### Risk Priority Levels

| Score | Priority |
|---|---|
| 0–24 | Routine review |
| 25–49 | Review |
| 50–74 | High priority |
| 75–100 | Urgent review |

A higher score means a package should receive more review attention.

## Installation

1. Clone or download this project.
2. Open the project folder in VS Code.
3. Open the terminal.
4. Create a virtual environment:

```powershell
python -m venv venv
```

5. Activate the environment:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\venv\Scripts\Activate.ps1
```

6. Install the required libraries:

```powershell
pip install -r requirements.txt
```

## Run the Application

Run this command in the terminal:

```powershell
streamlit run app.py
```

The application will open in your web browser.

## Run Tests

To run the automated tests:

```powershell
python -m pytest -v
```

## Project Structure

```text
Dependency-Trust-Engine/
│
├── app.py
├── data/
│   └── sample_manifest.json
├── tests/
│   └── test_scoring.py
├── src/
├── requirements.txt
└── README.md
```

## Important Note

The current project uses demonstration risk signals supplied through the JSON manifest. These scores are illustrative review-priority indicators, not live vulnerability scan results, proof of compromise, or certification that a package is safe.

## Author

Software Engineering Semester Project
