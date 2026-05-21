# OSDO Test Fixtures

Test fixtures for validating security scanning accuracy.

## Vulnerable Code Samples

These samples contain intentional security vulnerabilities for testing detection capabilities.

### SQL Injection (Python)
```python
# test/fixtures/vulnerable/sql_injection.py
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    # VULNERABLE: SQL Injection
    cursor = conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
```

### Command Injection (Python)
```python
# test/fixtures/vulnerable/command_injection.py
import os

def run_command(user_input):
    # VULNERABLE: Command Injection
    os.system("ls " + user_input)
```

### XSS (JavaScript)
```javascript
// test/fixtures/vulnerable/xss.js
function displayName(name) {
    // VULNERABLE: Cross-Site Scripting
    document.innerHTML = name;
}
```

### Path Traversal (Go)
```go
// test/fixtures/vulnerable/path_traversal.go
package main

import (
    "io/ioutil"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    // VULNERABLE: Path Traversal
    filename := r.URL.Query().Get("file")
    data, _ := ioutil.ReadFile("/data/" + filename)
    w.Write(data)
}
```

## Expected Findings

| File | Vulnerability | Rule | Severity |
|------|--------------|------|----------|
| sql_injection.py | SQL Injection | python.lang.security.audit.formatted-sql-query | ERROR |
| command_injection.py | Command Injection | python.lang.security.audit.dangerous-system-call | ERROR |
| xss.js | XSS | javascript.browser.security.insecure-document-method | WARNING |
| path_traversal.go | Path Traversal | go.lang.security.filepath.path-traversal | ERROR |

## Clean Code Samples

Reference implementations without vulnerabilities.

### Safe SQL (Python)
```python
# test/fixtures/clean/safe_sql.py
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    # SAFE: Parameterized query
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
```

### Safe Command (Python)
```python
# test/fixtures/clean/safe_command.py
import subprocess

def run_command(allowed_cmd):
    # SAFE: Allowlisted commands only
    ALLOWED = ["ls", "pwd", "whoami"]
    if allowed_cmd in ALLOWED:
        subprocess.run([allowed_cmd], capture_output=True)
```

## Secrets Fixtures

### Leaked Secret (Should Detect)
```
# test/fixtures/secrets/leaked.env
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_PASSWORD=super_secret_password_123
```

### Safe Config (Should NOT Detect)
```
# test/fixtures/secrets/safe.env
AWS_ACCESS_KEY_ID=${AWS_KEY}
DATABASE_URL=postgresql://localhost:5432/db
LOG_LEVEL=debug
```

## Container Fixtures

### Vulnerable Dockerfile
```dockerfile
# test/fixtures/containers/vulnerable.Dockerfile
FROM ubuntu:18.04
# VULNERABLE: Running as root
# VULNERABLE: Old base image
RUN apt-get update && apt-get install -y curl wget
CMD ["bash"]
```

### Secure Dockerfile
```dockerfile
# test/fixtures/containers/secure.Dockerfile
FROM alpine:3.19
RUN addgroup -S app && adduser -S app -G app
USER app
HEALTHCHECK --interval=30s CMD wget -q --spider http://localhost:8080/health
CMD ["./app"]
```

## Usage

```bash
# Run SAST on vulnerable fixtures
semgrep --config auto test/fixtures/vulnerable/

# Expected: Multiple findings

# Run SAST on clean fixtures
semgrep --config auto test/fixtures/clean/

# Expected: No findings
```
