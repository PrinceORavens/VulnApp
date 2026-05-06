# ACME Store — Sentinel SCA Test Application

A deliberately vulnerable e-commerce application for testing **Sentinel SCA**.
Contains a Node.js/Express API and a Python/Django worker, with carefully chosen
dependency versions that have known CVEs — and varied usage patterns so the AI
reachability analysis has something interesting to assess.

> ⚠ **DO NOT DEPLOY TO PRODUCTION.** This app is intentionally insecure.

---

## Quick start

### Scan without running (recommended for SCA testing)

```bash
# Scan the Node.js API
sentinel-sca scan --path ./api

# Scan the Python worker
sentinel-sca scan --path ./worker

# Scan both and emit HTML report
sentinel-sca scan --path ./api --output html --file api-report.html
sentinel-sca scan --path ./worker --output html --file worker-report.html
```

### Run the app (optional)
```bash
docker-compose up
# API: http://localhost:3000
# Worker: http://localhost:8000
```

---

## What to expect from the scan

The app is designed to exercise all three AI reachability verdicts:

### 🔴 CONFIRMED REACHABLE (AI should flag these)

| Component | Version | CVE | Where | Why reachable |
|-----------|---------|-----|-------|---------------|
| `lodash` | 4.17.20 | CVE-2021-23337 | `routes/products.js:PUT /:id` | `_.merge(product, req.body)` — user input directly merged |
| `lodash` | 4.17.20 | CVE-2021-23337 | `routes/products.js:POST /` | Same — `_.merge(newProduct, req.body)` |
| `jsonwebtoken` | 8.5.1 | CVE-2022-23529 | `routes/auth.js` | `jwt.verify()` without `algorithms` option |
| `multer` | 1.4.3 | CVE-2022-24434 | `routes/upload.js:POST /image` | Public endpoint, no auth, no boundary limits |
| `handlebars` | 4.5.3 | CVE-2021-23369 | `routes/reports.js:POST /custom` | User supplies **both** template AND data |
| `minimist` | 1.2.5 | CVE-2021-44906 | `routes/reports.js:GET /parse-options` | `minimist(args.split(' '))` on user query param |
| `serialize-javascript` | 2.1.1 | CVE-2020-7660 | `routes/upload.js:GET /config` | Serialized output embedded in `<script>` tag |
| `django` | 3.2.12 | CVE-2022-28346 | `views.py:ReportsView` | `queryset.annotate(**request.GET.dict())` |
| `pyyaml` | 5.4.1 | CVE-2020-14343 | `views.py:ConfigLoaderView` | `yaml.load()` without `SafeLoader` on user input |

### 🟡 UNCERTAIN (AI should flag for manual review)

| Component | Version | CVE | Where | Why uncertain |
|-----------|---------|-----|-------|---------------|
| `axios` | 0.21.1 | CVE-2021-3749 | `routes/orders.js` | Only calls internal services, but requires TLS cert control |
| `node-fetch` | 2.6.5 | CVE-2022-0235 | `routes/orders.js:GET /tracking` | Internal service with auth header — redirect behaviour uncertain |
| `requests` | 2.27.0 | CVE-2023-32681 | `views.py:ExternalFetchView` | Proxy config from env var — deployment-dependent |
| `marked` | 2.0.0 | CVE-2022-21681 | `routes/products.js:POST /:id/review` | User input rendered as markdown — depends on output context |
| `ws` | 7.4.5 | CVE-2021-32640 | `services/websocket.js` | Public WS endpoint — header parsing ReDoS exposure |

### 🟢 NOT REACHABLE — Suppressed by AI

| Component | Version | CVE | Where | Why safe |
|-----------|---------|-----|-------|----------|
| `lodash` | 4.17.20 | CVE-2021-23337 | `routes/users.js` | Only `_.pick()`, `_.orderBy()`, `_.omit()` — no merge with user input |
| `moment` | 2.29.1 | CVE-2022-24785 | `routes/orders.js` | `moment.locale('en-GB')` — hardcoded, no user locale input |
| `handlebars` | 4.5.3 | CVE-2021-23369 | `routes/reports.js:GET /order-summary` | Template is hardcoded in server code, not user-supplied |
| `pillow` | 9.0.0 | CVE-2022-22817 | `views.py:ImageProcessView` | Only `Image.open()` + `Image.thumbnail()` — `ImageMath.eval()` never called |
| `django` | 3.2.12 | CVE-2022-28346 | `views.py:SafeReportsView` | Hardcoded annotation keys — no user input to `annotate()` |
| `pyyaml` | 5.4.1 | CVE-2020-14343 | `views.py:SafeConfigLoaderView` | Uses `yaml.safe_load()` — safe variant |

---

## Vulnerability details

### CVE-2021-23337 — lodash Prototype Pollution (CRITICAL, CVSS 7.2)
`_.merge()` allows an attacker to pollute the prototype chain via JSON with `__proto__` keys.
**Attack:** `PUT /api/products/1` with body `{"__proto__": {"isAdmin": true}}`

### CVE-2022-23529 — jsonwebtoken Algorithm Confusion (HIGH, CVSS 7.6)
`jwt.verify()` without `algorithms` option allows RS256→HS256 downgrade, forging tokens.
**Attack:** Sign a token with the server's public key using HS256, verify passes.

### CVE-2021-23369 — Handlebars RCE (CRITICAL, CVSS 9.8)
User-controlled Handlebars templates can achieve arbitrary code execution.
**Attack:** `POST /api/reports/custom` with template `{{#with "constructor"}}{{#with split as |a|}}...{{/with}}{{/with}}`

### CVE-2020-14343 — PyYAML Arbitrary Code Execution (CRITICAL, CVSS 9.8)
`yaml.load()` without `Loader=yaml.SafeLoader` executes arbitrary Python.
**Attack:** `POST /worker/config` with body `!!python/object/apply:os.system ['id']`

### CVE-2022-28346 — Django SQL Injection (CRITICAL, CVSS 9.8)
`QuerySet.annotate(**user_input)` allows SQL injection via crafted alias names.
**Attack:** `GET /reports/?select+1+from+django_user--=x`

---

## Project structure

```
sentinel-test-app/
├── api/                        # Node.js / Express
│   ├── package.json            # ← SCAN THIS (npm)
│   └── src/
│       ├── server.js
│       ├── routes/
│       │   ├── auth.js         # jsonwebtoken (REACHABLE)
│       │   ├── products.js     # lodash + marked (mixed)
│       │   ├── upload.js       # multer + serialize-js (REACHABLE)
│       │   ├── orders.js       # axios + moment + node-fetch (mixed)
│       │   ├── reports.js      # handlebars + minimist (REACHABLE)
│       │   └── users.js        # lodash (SAFE)
│       └── services/
│           └── websocket.js    # ws (UNCERTAIN)
├── worker/                     # Python / Django
│   ├── requirements.txt        # ← SCAN THIS (PyPI)
│   └── views.py                # Django + Pillow + requests + pyyaml (mixed)
├── docker-compose.yml
└── docker/
```
