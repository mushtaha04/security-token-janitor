# 🧹 Security Token Janitor

A local dashboard that scans any folder for exposed `.env` files and leaked credentials — API keys, AWS/GitHub/Slack/Stripe/Google tokens, private keys, and hardcoded secrets in Docker/Kubernetes configs — and helps you clean them up before they hit git.

## Features

- **Secret scanning** — detects leaked AWS, GitHub, OpenAI/Anthropic, Slack, Discord, Stripe, and Google credentials, plus private keys and generic `key=value` secrets across your codebase.
- **Container/infra aware** — dedicated detectors for `Dockerfile` `ENV`/`ARG` secrets, `docker-compose.yml` passwords, and Kubernetes manifest `stringData`/`env` blocks.
- **One-click fixes** — add exposed `.env` files to `.gitignore`, or redact a leaked value in place.
- **Git pre-commit hook** — installs a hook that blocks commits containing detected secrets before they're ever pushed.
- **Custom regex rules** — define your own detectors (name, pattern, severity, category) for internal/proprietary secret formats.
- **Allowlist / suppress false positives** — ignore a specific finding or an entire file, with one click to un-ignore later.
- **Live watching** — auto-rescans as files change, with desktop notifications for critical/high findings.
- **Export reports** — Markdown, structured JSON audit, or a formatted PDF security report.

## Stack

- **Backend:** Node.js + Express (`server/`)
- **Frontend:** React + Vite (`client/`)

## Getting started

```bash
# backend
cd server
npm install
npm start          # http://localhost:4790

# frontend (separate terminal)
cd client
npm install
npm run dev         # http://localhost:5173
```

Point the dashboard at any local folder path and hit **Scan**.

## Project structure

```
server/
  src/index.js      # Express routes
  src/scanner.js     # detection, redaction, hook install, custom rules, allowlist
  data/              # local config: custom-rules.json, allowlist.json
client/
  src/App.jsx        # dashboard UI
  src/jsonReport.js  # JSON audit export
  src/pdfReport.js   # PDF audit export
  src/alerts.js      # desktop notifications
```

## Disclaimer

This is a personal project for learning/local use. It's a helper for catching *accidental* leaks during development — not a substitute for secret managers, rotation policies, or a full security audit.
