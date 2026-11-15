# Database Security: SQL Injection and Role-Based Access Control

A small, **local-only** Python + SQLite demonstration focusing on two security objectives:
1. **Confidentiality:** prevent unauthorized data reads using parameterized queries and role checks.
2. **Integrity:** prevent unauthorized updates using role-based access control (RBAC).

This deliberately narrows the original proposal to address the professor's feedback. It uses SQLite instead of MySQL/PostgreSQL to make the experiment easy to reproduce without a server. This is a teaching prototype, **not** a production authentication or authorization service.

## Requirements
- Python 3.9+ (no third-party packages)

## Run
```bash
python security_demo.py --demo
python -m unittest discover -s tests -v
```
Windows may require `py` instead of `python`.

## Expected demo results
```
BEFORE - unsafe query returns 3 rows
AFTER  - parameterized query returns 0 rows
AFTER  - viewer unauthorized update: BLOCKED
AFTER  - editor authorized update: ALLOWED
AFTER  - updated account: [(1, 'alice', 125)]
```

## Threat model and scope
- Assets: three **synthetic** account rows; no real personal data.
- Attacker: someone able to supply a search string, or a logged-in viewer attempting an update.
- Vulnerabilities: SQL query string concatenation and missing authorization for writes.
- Defenses: SQL parameter placeholders and centralized role permission checks.
- Out of scope: network access, availability/DoS, encryption, logging, production credential management, and database-server roles.

## Test matrix
| Test | Before / vulnerable | After / protected |
|---|---|---|
| Injection input `alice' OR '1'='1` | Returns all 3 rows | Returns 0 rows |
| Viewer attempts account update | Hypothetical missing role check would permit it | Blocked |
| Editor performs valid update | Not applicable | Allowed |
| Invalid password | Not applicable | Rejected |

**Important:** the unsafe lookup is included solely to illustrate the vulnerability. Never use it with real data or expose it on a network. The role checks here are implemented in the application layer; SQLite is not configured with native database roles. The before/after RBAC case compares an absent-check threat scenario with an implemented check; only the protected behavior is executable in this repo.

## Files
- `security_demo.py` — local database, authentication, vulnerable/safe queries, RBAC, demo.
- `tests/test_security.py` — five repeatable tests.
- `Threat_Analysis.pdf` — ~600-word threat/security analysis.

## Reproducibility
`--demo` **resets** `demo.db` and inserts synthetic records. Do not store valuable data in `demo.db`. Passwords in this demo are documented sample passwords, not secrets.
