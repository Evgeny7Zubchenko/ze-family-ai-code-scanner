# Z.E Family AI Code Security Scanner

AI-powered SaaS scanner for public GitHub repositories and ZIP uploads.

This project analyzes source code, generates an AI security summary, calculates a security score, highlights vulnerabilities, suggests fixes, supports multiple languages, and includes a Pro-ready monetization flow.

## Live Demo

[Open Live App](https://ze-family-ai-code-scanner-production.up.railway.app)

## What it does

- Scans public GitHub repositories
- Scans uploaded ZIP archives
- Supports language-focused analysis:
  - Auto
  - Python
  - JavaScript
  - TypeScript
  - Multi-language
- Generates:
  - AI Summary
  - Security Score
  - Structured vulnerability report
  - Practical fix suggestions
- Keeps scan history
- Includes Free vs Pro product logic
- Stripe-ready subscription flow:
  - Week
  - Month
  - 6 Months

## Why this project matters

This is not just a script. It is a working SaaS-style product that combines:

- AI analysis
- product UX
- monetization logic
- deployment
- GitHub workflow
- real-world portfolio value

It was built as a practical product for developers, founders, and security-conscious teams who want fast code-level risk visibility.

## Tech Stack

- Python
- Flask
- OpenAI API
- Stripe
- Railway
- HTML / CSS / JavaScript
- Git / GitHub

## Key Features

### 1. GitHub repository scanning
Users can scan public repositories directly from GitHub.

### 2. ZIP upload scanning
Users can upload ZIP files and scan projects without connecting GitHub.

### 3. Multi-language filtering
The scanner supports:
- Python
- JavaScript
- TypeScript
- Auto / mixed mode

### 4. Security scoring
Each scan returns a Security Score based on detected issue severity.

### 5. AI-generated summary
The app produces a concise AI summary of the codebase security posture.

### 6. Structured vulnerability output
Each vulnerability includes:
- title
- severity
- file
- line
- explanation
- fix recommendation

### 7. SaaS monetization logic
The product includes:
- Free plan
- Pro plans
- Stripe checkout integration design
- export restrictions for Free users
- unlimited usage for Pro users

## Product Positioning

**Free**
- 2 scans/day
- basic usage
- limited export

**Pro**
- unlimited scans
- premium export
- stronger product workflow
- expanded SaaS value

## Screenshots

Add screenshots here after you capture:
- home page
- pricing section
- scan result
- vulnerability cards
- mobile layout

## Project Architecture

### Backend
- `server.py` handles API routes, history, plan checks, exports, and Stripe-related endpoints
- `agent.py` handles repository/ZIP processing, language selection, AI prompts, and result normalization

### Frontend
- `index.html` contains the full responsive UI
- SaaS-oriented UX
- responsive layout for mobile and desktop
- pricing, comparison, history, score, summary, and result rendering

## Example Workflow

1. User enters email
2. User selects scan source:
   - GitHub repo
   - ZIP file
3. User selects language mode
4. App scans selected files
5. AI returns:
   - security summary
   - score
   - vulnerability list
6. User reviews results
7. Pro user can export full current result

## Deployment

Deployed on Railway.

### Required environment variables

```env
OPENAI_API_KEY=...
APP_BASE_URL=https://your-app.up.railway.app
STRIPE_SECRET_KEY=...
STRIPE_WEBHOOK_SECRET=...
STRIPE_PRICE_ID_WEEK=...
STRIPE_PRICE_ID_MONTH=...
STRIPE_PRICE_ID_6MONTHS=...