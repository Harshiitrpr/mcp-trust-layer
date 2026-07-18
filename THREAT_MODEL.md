# Threat Model

## Assets
- **System Files**: Host OS configuration, binary files, or sensitive directories (`/etc/`, `C:\Windows\`).
- **Internal Secrets**: API keys, passwords, AWS tokens, or JWTs legitimately written into application logs.
- **Host Compute Resources**: CPU and memory allocations for the host OS or container.

## Attackers
- **Compromised AI Agents**: The primary threat vector. An agent (or a prompt-injected LLM) attempting to misuse the MCP tools to read files outside the designated boundary, exfiltrate data, or crash the server.

## Assumptions
- The application executes with the standard privileges of the local user running the MCP server.
- The `mock_logs` directory is not world-writable, meaning untrusted local users cannot create malicious symlinks inside it after startup.

## Out of Scope
- **Network-Level Attacks**: DDoS attacks on the MCP protocol or Claude Desktop/Inspector connections.
- **Host OS Escapes**: Privilege escalation vulnerabilities within the host OS or container runtime itself.

## Mitigations

| Threat | Mitigation |
| :--- | :--- |
| **Path Traversal** | Enforces an input allowlist, canonicalizes the path via `.resolve()`, and strictly verifies containment using `is_relative_to()`. Explicitly rejects absolute and nested paths. |
| **Symlink TOCTOU** | Uses `os.O_NOFOLLOW` (Unix) and handle-based fallback heuristics (Windows) to verify files immediately upon opening to prevent time-of-check to time-of-use race conditions. |
| **Credential Exfiltration** | Dynamic, real-time regex redaction engine masks Google API keys, AWS credentials, JWTs, and inline key-value secrets in tool responses. |
| **Resource Exhaustion** | Strict runtime configuration limits (`MAX_FILE_SIZE_BYTES`, `MAX_SEARCH_PAYLOAD_CHARS`) and line-by-line file streaming prevents out-of-memory crashes. |
