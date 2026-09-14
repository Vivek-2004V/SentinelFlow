# SentinelFlow

## Passive AI Threat Intelligence for One-Way Networks

SentinelFlow is an open-source prototype for detecting and correlating
cybersecurity threats from passively observed network telemetry.

## Core Principle

> Observe. Correlate. Explain. Never Respond.

## Problem

Critical infrastructure monitoring environments may use one-way
network paths or data diodes to isolate monitoring infrastructure
from production networks.

SentinelFlow is designed to operate under that constraint.

## Threat Classes

- DDoS
- C2 Beaconing
- DGA
- DNS Tunnelling
- Encrypted Traffic Anomalies
- Reconnaissance
- Data Exfiltration

## Architecture

```text
Passive Traffic
      ↓
Telemetry
      ↓
Feature Extraction
      ↓
Threat Detection
      ↓
Adaptive Baseline
      ↓
Threat Fusion
      ↓
Attack Chain
      ↓
Evidence
      ↓
Alert
```

## Security Boundary

SentinelFlow does not:

- probe hosts
- initiate handshakes
- decrypt payloads
- block traffic
- send commands to production systems

## Development

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## Status

Prototype under active development.
