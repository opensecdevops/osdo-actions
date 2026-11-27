# osdo-llm-scan test fixtures

- `malicious/`: each file triggers at least one check (prompt-injection prose, hidden Unicode, MCP manifest, tool scope, shell, code patterns). The test asserts on categories, not exact counts.
- `clean/`: must produce no prose, hidden-Unicode, MCP, tool-scope or shell findings.
