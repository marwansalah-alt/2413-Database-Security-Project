# Database Security: SQL Injection and Role-Based Access Control

A Python + SQLite demonstration focusing on two security objectives:
1. **Confidentiality:** prevent unauthorized data reads using parameterized queries and role checks.
2. **Integrity:** prevent unauthorized updates using role-based access control (RBAC).

## Requirements
- Python 3.9+

## Run
```bash
python security_demo.py --demo
python -m unittest discover -s tests -v
```
## Expected demo results
```
BEFORE - unsafe query returns 3 rows
AFTER  - parameterized query returns 0 rows
AFTER  - viewer unauthorized update: BLOCKED
AFTER  - editor authorized update: ALLOWED
AFTER  - updated account: [(1, 'alice', 125)]
```

## Test matrix
| Test | Before / vulnerable | After / protected |
|---|---|---|
| Injection input `alice' OR '1'='1` | Returns all 3 rows | Returns 0 rows |
| Viewer attempts account update | Hypothetical missing role check would permit it | Blocked |
| Editor performs valid update | Not applicable | Allowed |
| Invalid password | Not applicable | Rejected |

## Files
- `security_demo.py` : local database, authentication, vulnerable/safe queries, RBAC, demo.
- `tests/test_security.py` : five repeatable tests.
